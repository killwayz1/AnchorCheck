import os
import sys
import random
import threading
import webbrowser
from flask import Flask, render_template, request, send_from_directory
import pandas as pd
import requests

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
    
    # 1. Сначала проверяем переменные окружения (для серверов типа Render)
    # Предполагаем, что прокси будут записаны через запятую или с новой строки
    env_proxies = os.environ.get('PROXY_LIST')
    if env_proxies:
        # Разбиваем строку по запятым или пробелам/переносам
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
        
        # Если загрузили из окружения, возвращаем их и игнорируем текстовый файл
        if proxies:
            return proxies

    # 2. Если мы запускаем локально, читаем из файла proxy.txt
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

def check_page_content(url, anchor, keys, proxy=None):
    if pd.isna(url) or str(url).strip() == '':
        return False, "Пустой URL"
    
    anchor_valid = pd.notna(anchor) and str(anchor).strip() != ''
    keys_valid = pd.notna(keys) and str(keys).strip() != ''
    
    if not anchor_valid and not keys_valid:
        return False, "Пустые значения (C и D)"

    proxies_dict = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(
            str(url).strip(), 
            headers=headers, 
            proxies=proxies_dict, 
            timeout=15
        )
        response.raise_for_status()
        
        page_text = response.text.lower()
        
        anchor_found = False
        if anchor_valid:
            anchor_found = str(anchor).strip().lower() in page_text
            
        keys_found = False
        if keys_valid:
            keys_found = str(keys).strip().lower() in page_text

        # Если найдено либо то, либо другое (или оба)
        if anchor_found or keys_found:
            return True, "Найдено"
        else:
            return False, "Не найдено"
            
    except requests.RequestException as e:
        return False, "Ошибка доступа"

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
                
                # Теперь функция возвращает только один статус
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

def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == '__main__':
    threading.Timer(1.5, open_browser).start()
    app.run(port=5000, debug=False)