from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from parsers.log_parser import parse_log
from ioc.abuseipdb_client import check_ip
from ioc.virustotal_client import check_hash
from ioc.url_checker import check_url_or_domain
from ioc.cisa_kev_client import search_cve_in_kev
from ioc.circl_cve_client import search_cve, get_severity_from_cvss
from ioc.nvd_cve_client import search_cve_by_id as search_nvd, fetch_recent_cves as fetch_nvd_recent
from datetime import datetime
import json
import os
import traceback

# Importar tradutor
try:
    from googletrans import Translator
    translator = Translator()
    TRANSLATION_ENABLED = True
except ImportError:
    print("[AVISO] googletrans não instalado. Tradução automática desabilitada.")
    print("Instale com: pip install googletrans==4.0.0-rc1")
    TRANSLATION_ENABLED = False

app = Flask(__name__)

# Configuração de upload
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Criar pasta de uploads se não existir
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def translate_to_portuguese(text):
    if not TRANSLATION_ENABLED or not text or text is None:
        return text
    if text is None or text.strip() == '':
        return text
    try:
        translated = translator.translate(text, src='en', dest='pt')
        return translated.text if translated and translated.text else text
    except Exception as e:
        print(f"[ERRO] Falha na tradução: {e}")
        return text

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

IOC_DATABASE_FILE = 'data/ioc_database.json'
CVE_DATABASE_FILE = 'data/cve_database.json'

def load_ioc_database():
    if os.path.exists(IOC_DATABASE_FILE):
        with open(IOC_DATABASE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_ioc_database(data):
    os.makedirs('data', exist_ok=True)
    with open(IOC_DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_cve_database():
    if os.path.exists(CVE_DATABASE_FILE):
        with open(CVE_DATABASE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_cve_database(data):
    os.makedirs('data', exist_ok=True)
    with open(CVE_DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/dashboard/stats')
def dashboard_stats():
    try:
        ioc_db = load_ioc_database()
        cve_db = load_cve_database()
        ioc_by_type = {}
        ioc_by_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for ioc in ioc_db:
            ioc_type = ioc.get('type', 'Unknown')
            ioc_by_type[ioc_type] = ioc_by_type.get(ioc_type, 0) + 1
            severity = ioc.get('severity', 'Low')
            if severity in ioc_by_severity:
                ioc_by_severity[severity] += 1
        cve_by_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for cve in cve_db:
            severity = cve.get('severity', 'Low')
            if severity in cve_by_severity:
                cve_by_severity[severity] += 1
        return jsonify({
            'total_iocs': len(ioc_db),
            'total_cves': len(cve_db),
            'ioc_by_type': ioc_by_type,
            'ioc_by_severity': ioc_by_severity,
            'cve_by_severity': cve_by_severity
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['GET'])
def upload_page():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'Nenhum arquivo enviado'}), 400
        files = request.files.getlist('files')
        all_iocs = []
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                iocs = parse_log(log_content)
                ioc_db = load_ioc_database()
                for ioc in iocs:
                    ioc_entry = {
                        'id': datetime.now().strftime('%Y%m%d%H%M%S%f'),
                        'type': ioc['type'],
                        'value': ioc['value'],
                        'source': f'Upload: {filename}',
                        'severity': 'Medium',
                        'description': f'Extraído automaticamente do arquivo {filename}',
                        'date_added': datetime.now().isoformat()
                    }
                    ioc_db.append(ioc_entry)
                    all_iocs.append(ioc)
                save_ioc_database(ioc_db)
                os.remove(filepath)
        return jsonify({'success': True, 'total_iocs': len(all_iocs), 'iocs': all_iocs})
    except Exception as e:
        print(f"[ERRO] Upload: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/ioc')
def ioc_panel():
    return render_template('ioc_panel.html')

@app.route('/ioc/list')
def ioc_list():
    try:
        iocs = load_ioc_database()
        return jsonify(iocs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ioc/add', methods=['POST'])
def ioc_add():
    try:
        data = request.get_json()
        ioc = {
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'type': data.get('type'),
            'value': data.get('value'),
            'source': data.get('source'),
            'severity': data.get('severity'),
            'description': data.get('description'),
            'date_added': datetime.now().isoformat()
        }
        iocs = load_ioc_database()
        iocs.append(ioc)
        save_ioc_database(iocs)
        return jsonify({'success': True, 'ioc': ioc})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ioc/delete/<ioc_id>', methods=['DELETE'])
def ioc_delete(ioc_id):
    try:
        iocs = load_ioc_database()
        iocs = [ioc for ioc in iocs if ioc['id'] != ioc_id]
        save_ioc_database(iocs)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ioc/update/<ioc_id>', methods=['PUT'])
def ioc_update(ioc_id):
    try:
        data = request.get_json()
        iocs = load_ioc_database()
        for ioc in iocs:
            if ioc['id'] == ioc_id:
                ioc['type'] = data.get('type', ioc['type'])
                ioc['value'] = data.get('value', ioc['value'])
                ioc['source'] = data.get('source', ioc['source'])
                ioc['severity'] = data.get('severity', ioc['severity'])
                ioc['description'] = data.get('description', ioc['description'])
                ioc['date_modified'] = datetime.now().isoformat()
                break
        save_ioc_database(iocs)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve')
def cve_panel():
    return render_template('cve_panel.html')

@app.route('/cve/list')
def cve_list():
    try:
        cves = load_cve_database()
        return jsonify(cves)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/search', methods=['POST'])
def cve_search():
    try:
        data = request.get_json()
        cve_id = data.get('cve_id', '').strip().upper()
        if not cve_id:
            return jsonify({'error': 'CVE ID não fornecido'}), 400
        results = {'cve_id': cve_id, 'found': False, 'sources': []}
        print(f"[INFO] Buscando {cve_id} no NVD...")
        nvd_result = search_nvd(cve_id)
        if nvd_result.get('found'):
            results['found'] = True
            results['severity'] = nvd_result.get('severity', 'Unknown')
            results['cvss_score'] = nvd_result.get('cvss_score', 'N/A')
            results['description'] = nvd_result.get('description', '')
            results['description_pt'] = translate_to_portuguese(nvd_result.get('description', ''))
            results['published_date'] = nvd_result.get('published_date', 'N/A')
            results['references'] = nvd_result.get('references', [])
            results['sources'].append('NVD')
            return jsonify(results)
        print(f"[INFO] NVD não retornou. Tentando CIRCL...")
        circl_result = search_cve(cve_id)
        if circl_result.get('found'):
            results['found'] = True
            cvss_score = circl_result.get('cvss', 'N/A')
            results['severity'] = get_severity_from_cvss(cvss_score)
            results['cvss_score'] = cvss_score
            results['description'] = circl_result.get('summary', '')
            results['description_pt'] = translate_to_portuguese(circl_result.get('summary', ''))
            results['published_date'] = circl_result.get('Published', 'N/A')
            results['references'] = circl_result.get('references', [])
            results['sources'].append('CIRCL')
        print(f"[INFO] Verificando CISA KEV...")
        kev_result = search_cve_in_kev(cve_id)
        if kev_result.get('found'):
            if not results['found']:
                results['found'] = True
                results['description'] = kev_result.get('vulnerabilityName', 'CVE explorada ativamente')
                results['description_pt'] = f"⚠️ ATENÇÃO: {kev_result.get('vulnerabilityName', 'CVE explorada ativamente')}"
            results['exploited'] = True
            results['cisa_info'] = {
                'vulnerability_name': kev_result.get('vulnerabilityName'),
                'date_added': kev_result.get('dateAdded'),
                'due_date': kev_result.get('dueDate'),
                'required_action': kev_result.get('requiredAction')
            }
            results['sources'].append('CISA KEV')
        return jsonify(results)
    except Exception as e:
        print(f"[ERRO] Exceção em /cve/search: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/cve/add', methods=['POST'])
def cve_add():
    try:
        data = request.get_json()
        cve = {
            'id': datetime.now().strftime('%Y%m%d%H%M%S%f'),
            'cve_id': data.get('cve_id'),
            'severity': data.get('severity'),
            'cvss_score': data.get('cvss_score'),
            'description': data.get('description'),
            'description_pt': data.get('description_pt'),
            'published_date': data.get('published_date'),
            'sources': data.get('sources', []),
            'references': data.get('references', []),
            'exploited': data.get('exploited', False),
            'cisa_info': data.get('cisa_info'),
            'date_added': datetime.now().isoformat()
        }
        cves = load_cve_database()
        cves.append(cve)
        save_cve_database(cves)
        return jsonify({'success': True, 'cve': cve})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/delete/<cve_id>', methods=['DELETE'])
def cve_delete(cve_id):
    try:
        cves = load_cve_database()
        cves = [cve for cve in cves if cve['id'] != cve_id]
        save_cve_database(cves)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/fetch-recent', methods=['POST'])
def cve_fetch_recent():
    try:
        data = request.get_json() or {}
        hours = data.get('hours', 24)
        print(f"[INFO] Buscando CVEs das últimas {hours} horas...")
        result = fetch_nvd_recent(hours=hours)
        if not result.get('success'):
            return jsonify({'success': False, 'error': result.get('error', 'Erro desconhecido'), 'count': 0, 'cves': []})
        cves_found = result.get('cves', [])
        count = len(cves_found)
        print(f"[INFO] {count} CVEs encontradas")
        for cve in cves_found:
            desc = cve.get('description')
            if desc and desc.strip():
                cve['description_pt'] = translate_to_portuguese(desc)
            else:
                cve['description_pt'] = desc
        auto_save = data.get('auto_save', False)
        saved_count = 0
        if auto_save:
            cve_db = load_cve_database()
            existing_cve_ids = {cve.get('cve_id') for cve in cve_db}
            for cve_data in cves_found:
                cve_id = cve_data.get('cve_id')
                if cve_id not in existing_cve_ids:
                    cve = {
                        'id': datetime.now().strftime('%Y%m%d%H%M%S%f'),
                        'cve_id': cve_id,
                        'severity': cve_data.get('severity'),
                        'cvss_score': cve_data.get('cvss_score'),
                        'description': cve_data.get('description'),
                        'description_pt': cve_data.get('description_pt'),
                        'published_date': cve_data.get('published_date'),
                        'sources': ['NVD'],
                        'references': cve_data.get('references', []),
                        'exploited': False,
                        'date_added': datetime.now().isoformat()
                    }
                    cve_db.append(cve)
                    saved_count += 1
            save_cve_database(cve_db)
            print(f"[INFO] {saved_count} CVEs salvas")
        return jsonify({'success': True, 'count': count, 'saved': saved_count if auto_save else 0, 'cves': cves_found})
    except Exception as e:
        print(f"[ERRO] Exceção em /cve/fetch-recent: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e), 'count': 0, 'cves': []}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  IOC Analyzer - Blue Team Platform")
    print("=" * 60)
    print("✅ Servidor iniciado")
    print("📊 Dashboard: http://localhost:5000")
    print("📤 Upload: http://localhost:5000/upload")
    print("🔍 IOC Panel: http://localhost:5000/ioc")
    print("🛡️  CVE Panel: http://localhost:5000/cve")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)