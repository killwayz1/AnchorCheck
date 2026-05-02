import os
import sys
import re
import json
import gzip
import zlib
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from flask import Flask, render_template, request, send_from_directory, redirect, url_for, jsonify
import pandas as pd
from bs4 import BeautifulSoup

# curl_cffi имитирует TLS-fingerprint реального Chrome — обходит Cloudflare/DDoS-Guard.
try:
    from curl_cffi import requests as cffi_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    CURL_CFFI_AVAILABLE = False

# Brotli-декомпрессия (опционально)
try:
    import brotli
    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Пути
# ---------------------------------------------------------------------------

def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


base_dir = get_base_path()
app = Flask(__name__, template_folder=os.path.join(base_dir, 'templates'))


@app.route('/fadding-cat.gif')
def serve_gif():
    return send_from_directory(base_dir, 'fadding-cat.gif')


# ---------------------------------------------------------------------------
# Система логов
# ---------------------------------------------------------------------------

_log_messages = []
_log_lock = threading.Lock()
_log_id_counter = 0


def clear_logs():
    global _log_messages, _log_id_counter
    with _log_lock:
        _log_messages = []
        _log_id_counter = 0


def add_log(message, level='INFO'):
    global _log_id_counter
    ts = datetime.now().strftime('%H:%M:%S')
    with _log_lock:
        _log_id_counter += 1
        _log_messages.append({
            'id':    _log_id_counter,
            'ts':    ts,
            'level': level,
            'msg':   message,
        })


@app.route('/get-logs')
def get_logs():
    since = int(request.args.get('since', 0))
    with _log_lock:
        new_msgs = [m for m in _log_messages if m['id'] > since]
        total = _log_id_counter
    return jsonify({'messages': new_msgs, 'total': total})


# ---------------------------------------------------------------------------
# Прокси
# ---------------------------------------------------------------------------

def parse_proxy_line(line):
    line = line.strip()
    if not line:
        return None
    parts = line.split(':')
    if len(parts) == 4:
        ip, port, login, password = parts
        return f"http://{login}:{password}@{ip}:{port}"
    return None


def load_proxies():
    proxies = []
    seen = set()

    def add_proxy(url):
        if url and url not in seen:
            seen.add(url)
            proxies.append(url)

    env_proxies = os.environ.get('PROXY_LIST', '')
    if env_proxies:
        for line in env_proxies.replace(',', '\n').replace(';', '\n').split('\n'):
            add_proxy(parse_proxy_line(line))

    filepath = os.path.join(get_exe_dir(), 'proxy.txt')
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                add_proxy(parse_proxy_line(line))

    return proxies


_proxy_cycle = None
_proxy_lock = threading.Lock()


def init_proxy_cycle(proxies_list):
    global _proxy_cycle
    with _proxy_lock:
        _proxy_cycle = itertools.cycle(proxies_list) if proxies_list else None


def get_next_proxy(proxies_list):
    global _proxy_cycle
    with _proxy_lock:
        if not proxies_list or _proxy_cycle is None:
            return None
        return next(_proxy_cycle)


# ---------------------------------------------------------------------------
# HTTP-заголовки
# НЕ включаем Accept-Encoding — пусть библиотека сама управляет сжатием,
# иначе brotli-ответ может прийти нераспакованным (каша в байтах).
# ---------------------------------------------------------------------------

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': (
        'text/html,application/xhtml+xml,application/xml;'
        'q=0.9,image/avif,image/webp,*/*;q=0.8'
    ),
    'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'Referer':         'https://www.google.com/',
    'DNT':             '1',
    'Connection':      'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

CAPTCHA_MARKERS = [
    'just a moment',
    'checking your browser',
    'ddos-guard',
    'ddos guard',
]


# ---------------------------------------------------------------------------
# Надёжное декодирование ответа (декомпрессия + charset)
# ---------------------------------------------------------------------------

def _decompress_bytes(raw: bytes, content_encoding: str) -> bytes:
    """
    Явная декомпрессия на случай, если HTTP-библиотека не справилась сама.
    Порядок: br → gzip → deflate → raw.
    """
    enc = (content_encoding or '').lower()

    # Brotli
    if 'br' in enc and BROTLI_AVAILABLE:
        try:
            return brotli.decompress(raw)
        except Exception:
            pass

    # Gzip — также проверяем магические байты 0x1f 0x8b
    if 'gzip' in enc or raw[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(raw)
        except Exception:
            pass

    # Deflate
    if 'deflate' in enc:
        for wbits in (15, -15):
            try:
                return zlib.decompress(raw, wbits)
            except Exception:
                pass

    return raw


def _detect_charset(raw: bytes, content_type: str) -> str:
    """
    Определяет кодировку из:
    1) заголовка Content-Type
    2) мета-тегов HTML (первые 8 КБ)
    3) BOM
    4) chardet / charset_normalizer (если установлены)
    5) fallback → utf-8
    """
    # 1. Content-Type header
    if content_type:
        m = re.search(r'charset\s*=\s*([^\s;,"\'>]+)', content_type, re.IGNORECASE)
        if m:
            return m.group(1).strip().strip('"\'')

    # 2. HTML <meta charset=...> / <meta http-equiv="Content-Type" ...>
    try:
        snippet = raw[:8192].decode('ascii', errors='ignore')
        # <meta charset="utf-8"> или <meta charset=utf-8>
        m = re.search(r'<meta[^>]+charset\s*=\s*["\']?\s*([a-zA-Z0-9\-_]+)',
                      snippet, re.IGNORECASE)
        if m:
            return m.group(1)
        # <?xml version="1.0" encoding="windows-1251"?>
        m = re.search(r'encoding\s*=\s*["\']([a-zA-Z0-9\-_]+)["\']',
                      snippet, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass

    # 3. BOM
    if raw[:3] == b'\xef\xbb\xbf':
        return 'utf-8-sig'
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return 'utf-16'

    # 4. chardet / charset_normalizer
    for detector_name in ('charset_normalizer', 'chardet'):
        try:
            mod = __import__(detector_name)
            result = mod.detect(raw[:20000])
            if result and result.get('encoding') and (result.get('confidence') or 0) >= 0.65:
                return result['encoding']
        except Exception:
            pass

    return 'utf-8'


def _decode_response(response) -> str:
    """
    Преобразует HTTP-ответ в строку HTML.
    Всегда работает с байтами — обходит все проблемы auto-decode в curl_cffi/requests.
    """
    raw = response.content  # bytes, всегда

    # Явная декомпрессия (страховка)
    content_encoding = response.headers.get('content-encoding', '')
    raw = _decompress_bytes(raw, content_encoding)

    # Определяем кодировку
    content_type = response.headers.get('content-type', '')
    charset = _detect_charset(raw, content_type)

    # Декодируем с заменой нераспознанных символов (не падаем)
    try:
        return raw.decode(charset, errors='replace')
    except (LookupError, UnicodeDecodeError):
        return raw.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# HTTP-запрос
# ---------------------------------------------------------------------------

def _fetch_page(target_url, proxies_dict):
    """
    Выполняет GET-запрос и возвращает (html_text, None) или (None, error_str).
    html_text — всегда нормальная читаемая строка, без кракозябров.
    """
    try:
        if CURL_CFFI_AVAILABLE:
            session = cffi_requests.Session(impersonate="chrome124")
            response = session.get(
                target_url,
                headers=HEADERS,
                proxies=proxies_dict,
                timeout=30,
                verify=False,
                allow_redirects=True,
            )
        else:
            session = requests.Session()
            response = session.get(
                target_url,
                headers=HEADERS,
                proxies=proxies_dict,
                timeout=30,
                verify=False,
                allow_redirects=True,
            )

        response.raise_for_status()

        html_text = _decode_response(response)
        return html_text, None

    except Exception as e:
        err_str = str(e).lower()

        resp = getattr(e, 'response', None)
        if resp is not None:
            try:
                status = resp.status_code
                if status == 403:
                    return None, 'Блок защиты (Ош. 403)'
                if status == 404:
                    return None, 'Страница не найдена (404)'
                if status == 429:
                    return None, 'Капча / Лимит (Ош. 429)'
                if status >= 500:
                    return None, f'Сайт лежит (Ош. {status})'
                return None, f'HTTP Ошибка {status}'
            except Exception:
                pass

        if any(kw in err_str for kw in ('proxy', 'tunnel connection', 'cannot connect to proxy')):
            return None, '__PROXY_ERROR__'
        if any(kw in err_str for kw in ('timeout', 'timed out', 'time out')):
            return None, 'Долго отвечает'
        if any(kw in err_str for kw in ('ssl', 'certificate')):
            return None, f'SSL ошибка: {str(e)[:60]}'
        if any(kw in err_str for kw in ('connection', 'connect', 'name or service')):
            return None, f'Ошибка подключения: {str(e)[:60]}'

        return None, f'Ошибка: {str(e)[:80]}'


# ---------------------------------------------------------------------------
# Поиск в сыром HTML
# ---------------------------------------------------------------------------

def find_in_raw_html(needle: str, html: str) -> bool:
    """
    Ищет needle в сыром HTML-коде страницы.
    - Регистронезависимо
    - Без нормализации, без удаления тегов
    - Ищет ВЕЗДЕ: тексты, атрибуты, href, скрипты, комментарии
    """
    if not needle or not html:
        return False
    needle = needle.strip()
    if not needle:
        return False
    return needle.lower() in html.lower()


# ---------------------------------------------------------------------------
# Проверка страницы
# ---------------------------------------------------------------------------

def check_page_content(url, anchor, keys, proxy=None, proxies_list=None):
    if pd.isna(url) or str(url).strip() == '':
        return False, 'Пустой URL'

    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    anchor_valid = pd.notna(anchor) and str(anchor).strip() != ''
    keys_valid   = pd.notna(keys)   and str(keys).strip()   != ''

    if not anchor_valid and not keys_valid:
        return False, 'Пустые значения (C и D)'

    max_proxy_retries = min(3, len(proxies_list)) if proxies_list else 0
    current_proxy = proxy
    proxy_label = current_proxy.split('@')[-1] if current_proxy else 'без прокси'

    add_log(f'Запрос: {target_url} [{proxy_label}]')

    for attempt in range(max_proxy_retries + 1):
        proxies_dict = {'http': current_proxy, 'https': current_proxy} if current_proxy else None
        html, error = _fetch_page(target_url, proxies_dict)

        if error == '__PROXY_ERROR__':
            add_log(f'Ошибка прокси {proxy_label}, переключаем...', 'WARN')
            if proxies_list and attempt < max_proxy_retries:
                current_proxy = get_next_proxy(proxies_list)
                proxy_label = current_proxy.split('@')[-1] if current_proxy else 'без прокси'
                continue
            else:
                add_log(f'Все попытки прокси исчерпаны: {target_url}', 'ERROR')
                return False, 'Ошибка прокси (все попытки исчерпаны)'

        if error:
            add_log(f'Ошибка загрузки [{target_url}]: {error}', 'ERROR')
            return False, error

        break
    else:
        return False, 'Ошибка прокси (все попытки исчерпаны)'

    # Быстрая проверка капчи / DDoS-защиты (только первые 5000 символов текста)
    soup = BeautifulSoup(html, 'html.parser')
    quick_text = soup.get_text(separator=' ')[:5000].lower()
    for marker in CAPTCHA_MARKERS:
        if marker in quick_text:
            add_log(f'Обнаружена защита на {target_url}: {marker}', 'WARN')
            return False, f'Скрытая защита: {marker}'

    # Поиск в СЫРОМ HTML — регистронезависимо, без нормализации
    anchor_found = anchor_valid and find_in_raw_html(str(anchor).strip(), html)
    keys_found   = keys_valid   and find_in_raw_html(str(keys).strip(),   html)

    if anchor_found or keys_found:
        found_what = []
        if anchor_found:
            found_what.append('анкор')
        if keys_found:
            found_what.append('ключ')
        status = 'Найдено (' + ', '.join(found_what) + ')'
        add_log(f'✓ {status}: {target_url}', 'OK')
        return True, status

    add_log(f'✗ Не найдено: {target_url}')
    return False, 'Не найдено'


# ---------------------------------------------------------------------------
# Просмотр исходного кода страницы
# ---------------------------------------------------------------------------

@app.route('/source')
def view_source():
    url     = request.args.get('url', '').strip()
    keyword = request.args.get('kw', '').strip()

    if not url:
        return "URL не указан", 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    html_src, error = _fetch_page(url, None)

    if html_src:
        safe_json = (
            json.dumps(html_src)
            .replace('</script>', r'<\/script>')
            .replace('<!--',      r'<\!--')
        )
    else:
        safe_json = '""'

    return render_template(
        'source.html',
        url=url,
        keyword=keyword,
        source_json=safe_json,
        error=error,
        size_kb=round(len(html_src) / 1024, 1) if html_src else 0,
    )


# ---------------------------------------------------------------------------
# Обёртка для потока
# ---------------------------------------------------------------------------

def process_row(row_index, row_data, proxies_list):
    row_list = list(row_data)
    if len(row_list) < 7:
        row_list.extend([''] * (7 - len(row_list)))

    order_date     = row_list[0]
    project_link   = row_list[1]
    anchor         = row_list[2]
    col_d          = row_list[3]
    target_url     = row_list[4]
    placement_date = row_list[5]
    link_type      = row_list[6]

    current_proxy = get_next_proxy(proxies_list)

    is_found, status_msg = check_page_content(
        target_url, anchor, col_d,
        proxy=current_proxy,
        proxies_list=proxies_list,
    )

    def safe(v):
        return v if pd.notna(v) else ''

    result = {
        'order_date':     safe(order_date),
        'project_link':   safe(project_link),
        'anchor':         safe(anchor),
        'col_d':          safe(col_d),
        'target_url':     safe(target_url),
        'placement_date': safe(placement_date),
        'link_type':      safe(link_type),
        'found':          is_found,
        'status':         status_msg,
        'proxy_used':     current_proxy.split('@')[-1] if current_proxy else 'Без прокси',
    }
    return row_index, result


# ---------------------------------------------------------------------------
# Маршруты Flask
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    proxies_list = load_proxies()
    filename = None

    if request.method == 'POST':
        file     = request.files.get('file')
        raw_text = request.form.get('raw_text', '').strip()
        df = None

        clear_logs()

        if raw_text:
            filename = 'Вставленный текст (буфер обмена)'
            rows = []
            for line in raw_text.split('\n'):
                if not line.strip():
                    continue
                rows.append(line.split('\t'))
            df = pd.DataFrame(rows)

        elif file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            filename = file.filename
            df = pd.read_excel(file, header=None)

        if df is not None:
            valid_rows = []
            for index, row in df.iterrows():
                row_list = list(row)
                if len(row_list) < 5:
                    row_list.extend([''] * (5 - len(row_list)))
                anchor     = row_list[2]
                col_d      = row_list[3]
                target_url = row_list[4]
                if (pd.isna(target_url) or str(target_url).strip() == '') and \
                   (pd.isna(anchor)     or str(anchor).strip() == '')     and \
                   (pd.isna(col_d)      or str(col_d).strip() == ''):
                    continue
                valid_rows.append((index, row))

            if valid_rows:
                proxy_info = f'{len(proxies_list)} прокси' if proxies_list else 'без прокси'
                add_log(f'Начало проверки: {len(valid_rows)} строк, {proxy_info}')

                init_proxy_cycle(proxies_list)

                num_workers = max(1, min(len(proxies_list) if proxies_list else 4, 20))
                add_log(f'Запущено потоков: {num_workers}')

                ordered_results = {}

                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    futures = {
                        executor.submit(process_row, idx, row, proxies_list): idx
                        for idx, row in valid_rows
                    }
                    completed = 0
                    for future in as_completed(futures):
                        try:
                            row_index, result = future.result()
                            ordered_results[row_index] = result
                            completed += 1
                            add_log(
                                f'Обработано {completed}/{len(valid_rows)}'
                                f' — {result["target_url"][:60]}'
                            )
                        except Exception as e:
                            orig_idx = futures[future]
                            ordered_results[orig_idx] = {
                                'order_date': '', 'project_link': '',
                                'anchor': '', 'col_d': '',
                                'target_url': '', 'placement_date': '',
                                'link_type': '', 'found': False,
                                'status': f'Ошибка потока: {str(e)[:80]}',
                                'proxy_used': '—',
                            }
                            add_log(f'Ошибка потока: {str(e)[:80]}', 'ERROR')

                results = [ordered_results[idx] for idx, _ in valid_rows if idx in ordered_results]
                found_count = sum(1 for r in results if r['found'])
                add_log(
                    f'Готово! Найдено: {found_count}/{len(results)} '
                    f'| Не найдено: {len(results) - found_count}',
                    'DONE'
                )

    return render_template(
        'index.html',
        results=results,
        proxy_count=len(proxies_list),
        filename=filename,
    )


@app.route('/reset')
def reset():
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)