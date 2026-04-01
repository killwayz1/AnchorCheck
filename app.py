import os
import sys
import random
from flask import Flask, render_template, request, send_from_directory, redirect, url_for
import pandas as pd
import requests
import urllib3

# Отключаем предупреждения об SSL (полезно при работе через серверные прокси)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def load_proxies():
    proxies = []
    
    # Сначала проверяем переменные окружения Render
    env_proxies = os.environ.get('PROXY_LIST')
    if env_proxies:
        lines = env_proxies.replace(',', '\n').replace(';', '\n').split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if len(parts) == 4:
                ip, port, login, password = parts
                proxy_url = f"http://{login}:{password}@{ip}:{port}"
                proxies.append(proxy_url)
        
        if proxies:
            return proxies

    # Локальный fallback
    filepath = os.path.join(get_exe_dir(), 'proxy.txt')
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(':')
                if len(parts) == 4:
                    ip, port, login, password = parts
                    proxy_url = f"http://{login}:{password}@{ip}:{port}"
                    proxies.append(proxy_url)
                    
    return proxies

import re
from bs4 import BeautifulSoup

def normalize_text(text):
    """Очищает текст от пунктуации и мусора для жесткого поиска"""
    if pd.isna(text) or str(text).strip() == '':
        return ""
    
    text = str(text).lower()
    text = text.replace('ё', 'е') # Унифицируем букву ё
    # Удаляем все знаки препинания, заменяя их на пробелы
    text = re.sub(r'[^\w\s]', ' ', text)
    # Сжимаем любые множественные пробелы и переносы в один пробел
    return re.sub(r'\s+', ' ', text).strip()

def check_page_content(url, anchor, keys, proxy=None):
    if pd.isna(url) or str(url).strip() == '':
        return False, "Пустой URL"
    
    target_url = str(url).strip()
    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'https://' + target_url
    
    anchor_valid = pd.notna(anchor) and str(anchor).strip() != ''
    keys_valid = pd.notna(keys) and str(keys).strip() != ''
    
    if not anchor_valid and not keys_valid:
        return False, "Пустые значения (C и D)"

    proxies_dict = {"http": proxy, "https": proxy} if proxy else None

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': 'https://google.com/'
        }
        
        response = requests.get(target_url, headers=headers, proxies=proxies_dict, timeout=30, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for script in soup(["script", "style"]):
            script.extract()
            
        # Получаем чистый текст со страницы и жестко его нормализуем
        raw_page_text = soup.get_text(separator=' ')
        normalized_page = normalize_text(raw_page_text)
        
        # Проверка на скрытую заглушку (когда сайт отдает ОК, но по факту там защита)
        if "just a moment" in normalized_page or "checking your browser" in normalized_page or "ddos guard" in normalized_page:
            return False, "Скрытая защита (Капча)"
        
        anchor_found = False
        if anchor_valid:
            norm_anchor = normalize_text(anchor)
            if norm_anchor in normalized_page:
                anchor_found = True
            
        keys_found = False
        if keys_valid:
            norm_keys = normalize_text(keys)
            if norm_keys in normalized_page:
                keys_found = True

        if anchor_found or keys_found:
            return True, "Найдено"
        else:
            return False, "Не найдено"
            
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 403: return False, "Блок защиты (Ош. 403)"
        elif status == 404: return False, "Страница не найдена (404)"
        elif status == 429: return False, "Капча / Лимит (Ош. 429)"
        elif status >= 500: return False, f"Сайт лежит (Ош. {status})"
        return False, f"HTTP Ошибка {status}"
        
    except requests.exceptions.ProxyError:
        return False, "Ошибка прокси"
    except requests.exceptions.Timeout:
        return False, "Долго отвечает"
    except requests.RequestException:
        return False, "Ошибка подключения"

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    proxies_list = load_proxies()
    filename = None

    if request.method == 'POST':
        file = request.files.get('file')
        raw_text = request.form.get('raw_text', '').strip()
        
        df = None
        
        if raw_text:
            filename = "Вставленный текст (буфер обмена)"
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
            for index, row in df.iterrows():
                row_list = list(row)
                
                if len(row_list) < 7:
                    row_list.extend([''] * (7 - len(row_list)))
                
                order_date = row_list[0]       
                project_link = row_list[1]     
                anchor = row_list[2]           
                col_d = row_list[3]            
                target_url = row_list[4]       
                placement_date = row_list[5]   
                link_type = row_list[6]        
                
                if (pd.isna(target_url) or str(target_url).strip() == '') and \
                   (pd.isna(anchor) or str(anchor).strip() == '') and \
                   (pd.isna(col_d) or str(col_d).strip() == ''):
                    continue

                current_proxy = random.choice(proxies_list) if proxies_list else None
                
                is_found, status_msg = check_page_content(
                    target_url, anchor, col_d, current_proxy
                )
                
                results.append({
                    'order_date': order_date if pd.notna(order_date) else '',
                    'project_link': project_link if pd.notna(project_link) else '',
                    'anchor': anchor if pd.notna(anchor) else '',
                    'col_d': col_d if pd.notna(col_d) else '',
                    'target_url': target_url if pd.notna(target_url) else '',
                    'placement_date': placement_date if pd.notna(placement_date) else '',
                    'link_type': link_type if pd.notna(link_type) else '',
                    'found': is_found,            
                    'status': status_msg          
                })
                
    return render_template('index.html', results=results, proxy_count=len(proxies_list), filename=filename)

# Маршрут для починки кнопки очистки
@app.route('/reset')
def reset():
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Оставлено только для локальных тестов. Gunicorn на Render игнорирует этот блок.
    app.run(host='0.0.0.0', port=5000, debug=False)