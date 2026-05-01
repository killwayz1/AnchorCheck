import os
import sys
import re
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, send_from_directory, redirect, url_for
import pandas as pd
import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
# Прокси
# ---------------------------------------------------------------------------

def parse_proxy_line(line):
    """Парсит строку ip:port:login:password → URL прокси."""
    line = line.strip()
    if not line:
        return None
    parts = line.split(':')
    if len(parts) == 4:
        ip, port, login, password = parts
        return f"http://{login}:{password}@{ip}:{port}"
    return None


def load_proxies():
    """
    Собирает прокси из переменной окружения PROXY_LIST и файла proxy.txt.
    Дубликаты исключаются.
    """
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


# Потокобезопасный round-robin
_proxy_cycle = None
_proxy_lock = threading.Lock()


def init_proxy_cycle(proxies_list):
    """Сбрасывает и инициализирует цикл прокси (вызывать перед пакетной обработкой)."""
    global _proxy_cycle
    with _proxy_lock:
        _proxy_cycle = itertools.cycle(proxies_list) if proxies_list else None


def get_next_proxy(proxies_list):
    """Потокобезопасно возвращает следующий прокси по round-robin."""
    global _proxy_cycle
    with _proxy_lock:
        if not proxies_list or _proxy_cycle is None:
            return None
        return next(_proxy_cycle)


# ---------------------------------------------------------------------------
# Нормализация текста
# ---------------------------------------------------------------------------

def normalize_text(text):
    """
    Нормализует текст для надёжного поиска:
    - нижний регистр
    - ё → е
    - вся пунктуация → пробел
    - схлопывание множественных пробелов
    """
    if pd.isna(text) or str(text).strip() == '':
        return ''
    text = str(text).lower()
    text = text.replace('ё', 'е')
    text = re.sub(r'[^\w\s]', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def extract_all_text(soup):
    """
    Извлекает текст из всех возможных источников страницы:
    видимый текст, alt, title, placeholder, meta[content], noscript.
    Возвращает список нормализованных строк (каждая своя «версия»).
    """
    parts = []

    # 1. Видимый текст БЕЗ разделителя (слова внутри тегов не разбиваются пробелом)
    parts.append(soup.get_text(separator=''))

    # 2. Видимый текст С разделителем (для фраз из разных тегов)
    parts.append(soup.get_text(separator=' '))

    # 3. alt у изображений
    for tag in soup.find_all(True):
        for attr in ('alt', 'title', 'placeholder', 'aria-label'):
            val = tag.get(attr, '')
            if val:
                parts.append(val)

    # 4. meta content
    for meta in soup.find_all('meta'):
        content = meta.get('content', '')
        if content:
            parts.append(content)

    # 5. noscript
    for ns in soup.find_all('noscript'):
        parts.append(ns.get_text(separator=' '))

    return [normalize_text(p) for p in parts if p.strip()]


def keyword_in_texts(keyword, text_variants):
    """
    Ищет нормализованный keyword в списке нормализованных текстов.
    Поддерживает как точное вхождение, так и вхождение без учёта
    лишних внутренних пробелов (на случай переноса строки внутри тега).
    """
    norm_kw = normalize_text(keyword)
    if not norm_kw:
        return False

    for text in text_variants:
        if norm_kw in text:
            return True

    # Дополнительная проверка: схлопываем пробелы в keyword до одного
    # и ищем по частям (каждое слово должно быть рядом).
    # Это помогает, когда текст разбит тегами: "ключ<span></span>евое слово"
    words = norm_kw.split()
    if len(words) > 1:
        pattern = r'\s{0,5}'.join(re.escape(w) for w in words)
        for text in text_variants:
            if re.search(pattern, text):
                return True

    return False


# ---------------------------------------------------------------------------
# Проверка страницы
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
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'https://www.google.com/',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

CAPTCHA_MARKERS = [
    'just a moment', 'checking your browser', 'ddos-guard',
    'ddos guard', 'cloudflare', 'please wait', 'enable javascript',
    'access denied', 'robot or human', 'are you a robot',
]


def check_page_content(url, anchor, keys, proxy=None):
    """
    Загружает страницу и ищет anchor и/или keys в тексте.
    Возвращает (bool, str).
    """
    if pd.isna(url) or str(url).strip() == '':
        return False, 'Пустой URL'

    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    anchor_valid = pd.notna(anchor) and str(anchor).strip() != ''
    keys_valid   = pd.notna(keys)   and str(keys).strip()   != ''

    if not anchor_valid and not keys_valid:
        return False, 'Пустые значения (C и D)'

    proxies_dict = {'http': proxy, 'https': proxy} if proxy else None

    try:
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

        # Явно определяем кодировку: сначала из заголовков, потом apparent
        if response.encoding and response.encoding.lower() not in ('iso-8859-1', 'latin-1'):
            html = response.text
        else:
            # requests часто ошибается с кодировкой — берём apparent
            response.encoding = response.apparent_encoding or 'utf-8'
            html = response.text

        soup = BeautifulSoup(html, 'html.parser')

        # Убираем теги, которые не несут видимого текста
        for tag in soup(['script', 'style', 'head']):
            tag.decompose()

        # Проверка капчи / блокировки (по первым 3 000 символов видимого текста)
        quick_text = normalize_text(soup.get_text(separator=' ')[:3000])
        for marker in CAPTCHA_MARKERS:
            if normalize_text(marker) in quick_text:
                return False, f'Защита / Капча ({marker[:20]})'

        # Полный набор текстовых вариантов страницы
        text_variants = extract_all_text(soup)

        anchor_found = anchor_valid and keyword_in_texts(anchor, text_variants)
        keys_found   = keys_valid   and keyword_in_texts(keys,   text_variants)

        if anchor_found or keys_found:
            found_what = []
            if anchor_found:
                found_what.append('анкор')
            if keys_found:
                found_what.append('ключ')
            return True, 'Найдено (' + ', '.join(found_what) + ')'

        return False, 'Не найдено'

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 403:
            return False, 'Блок защиты (Ош. 403)'
        if status == 404:
            return False, 'Страница не найдена (404)'
        if status == 429:
            return False, 'Капча / Лимит (Ош. 429)'
        if status >= 500:
            return False, f'Сайт лежит (Ош. {status})'
        return False, f'HTTP Ошибка {status}'
    except requests.exceptions.ProxyError:
        return False, 'Ошибка прокси'
    except requests.exceptions.Timeout:
        return False, 'Долго отвечает'
    except requests.RequestException as e:
        return False, f'Ошибка подключения: {str(e)[:60]}'
    except Exception as e:
        return False, f'Неизвестная ошибка: {str(e)[:60]}'


# ---------------------------------------------------------------------------
# Обёртка для потока
# ---------------------------------------------------------------------------

def process_row(row_index, row_data, proxies_list):
    """
    Обрабатывает одну строку таблицы в отдельном потоке.
    Возвращает (row_index, result_dict).
    """
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
        target_url, anchor, col_d, current_proxy
    )

    result = {
        'order_date':     order_date     if pd.notna(order_date)     else '',
        'project_link':   project_link   if pd.notna(project_link)   else '',
        'anchor':         anchor         if pd.notna(anchor)         else '',
        'col_d':          col_d          if pd.notna(col_d)          else '',
        'target_url':     target_url     if pd.notna(target_url)     else '',
        'placement_date': placement_date if pd.notna(placement_date) else '',
        'link_type':      link_type      if pd.notna(link_type)      else '',
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
            # Фильтрация пустых строк ДО отправки в пул
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
                # Инициализируем round-robin один раз перед пулом
                init_proxy_cycle(proxies_list)

                # Кол-во потоков: если есть прокси — по одному потоку на прокси
                # (но не более 20 и не менее 1)
                num_workers = max(1, min(len(proxies_list) if proxies_list else 4, 20))

                # Словарь для сборки результатов по исходному порядку
                ordered_results = {}

                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    futures = {
                        executor.submit(process_row, idx, row, proxies_list): idx
                        for idx, row in valid_rows
                    }
                    for future in as_completed(futures):
                        try:
                            row_index, result = future.result()
                            ordered_results[row_index] = result
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

                # Восстанавливаем исходный порядок строк
                results = [ordered_results[idx] for idx, _ in valid_rows if idx in ordered_results]

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