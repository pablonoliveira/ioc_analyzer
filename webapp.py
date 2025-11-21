# --- Garante a leitura do .env corretamente - desde o início do scrip
from dotenv import load_dotenv
load_dotenv()

# --- Início das funções e imports
from flask import Flask, request, render_template, jsonify
from flask import redirect, url_for
from werkzeug.utils import secure_filename
from parsers.log_parser import parse_log
from ioc.abuseipdb_client import check_ip, fetch_reports
from ioc.virustotal_client import check_hash
from ioc.url_checker import check_url_or_domain
from ioc.cisa_kev_client import search_cve_in_kev
from ioc.circl_cve_client import search_cve, get_severity_from_cvss
from ioc.nvd_cve_client import search_cve_by_id as search_nvd, fetch_recent_cves as fetch_nvd_recent
from utils.datetime_utils import format_datetime_br
from datetime import datetime, timedelta, timezone
import json
import os
import traceback
import csv
import pandas as pd

# --- Dicionário de categorias AbuseIPDB para tradução PT-BR ---
abuseipdb_category_map = {
    3: "Fraude",
    4: "DDoS",
    5: "NSA envenenamento",
    6: "Escaneamento",
    7: "Botnet",
    8: "Spam",
    9: "Phishing",
    10: "Malware",
    11: "Spam de login",
    12: "Exploração",
    13: "Vazamento de dados",
    14: "Exfiltração",
    15: "Scan web",
    16: "Pharming",
    17: "Abuso SSH",
    18: "Força bruta",
    19: "Ataque Web",
    20: "Vulnerabilidade",
    21: "Ataque à Aplicação",
    22: "Proxy",
    # ... pode adicionar outras categorias conforme necessário
}

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
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'xlsx', 'json', ''}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Criar pasta de uploads se não existir
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def translate_to_portuguese(text):
    # Só traduz se estiver habilitado e for string válida
    if not TRANSLATION_ENABLED or not isinstance(text, str) or not text.strip():
        return text
    try:
        translated = translator.translate(text, src='en', dest='pt')
        return translated.text if translated and translated.text else text
    except Exception as e:
        print(f"[ERRO] Falha na tradução: {e}")
        return text

# Função para conversão de data em UTC-3
def format_datetime_br(iso_str, modo_relativo=False):
    if not iso_str:
        return "-"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        # Ajuste para horário de Brasília UTC-3
        dt_br = dt - timedelta(hours=3)
        if modo_relativo:
            return humanize_timedelta(dt)
        return dt_br.strftime('%d/%m/%Y %H:%M') + " (UTC-3)"
    except Exception:
        return iso_str

def humanize_timedelta(dt):
    if not dt:
        return "-"
    ago = datetime.now(timezone.utc) - dt
    minutes = int(ago.total_seconds() // 60)
    hours = minutes // 60
    days = hours // 24
    if days > 0:
        return f"há {days} dia{'s' if days>1 else ''}"
    elif hours > 0:
        return f"há {hours} hora{'s' if hours>1 else ''}"
    elif minutes > 0:
        return f"há {minutes} minuto{'s' if minutes>1 else ''}"
    else:
        return "agora"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

IOC_DATABASE_FILE = 'data/ioc_database.json'
CVE_DATABASE_FILE = 'data/cve_database.json'

def universal_file_parser(filepath, extension):
    results = []
    if extension in ["txt", "log"]:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                results.append(parse_log(line))
    elif extension == "csv":
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                line = " ".join(row)
                results.append(parse_log(line))
    elif extension == "xlsx":
        df = pd.read_excel(filepath)
        for _, row in df.iterrows():
            line = " ".join(str(val) for val in row.values)
            results.append(parse_log(line))
    # --- Deduplicação dos resultados ---
    # Junta todos os resultados (cada resultado é um dict de tipo -> lista)
    unique = {'ips': set(), 'urls': set(), 'domains': set(), 'hashes': set()}
    for ioc_dict in results:
        for ioc_type, values in ioc_dict.items():
            unique[ioc_type].update(values)
    # Converte novamente para listas e cria um único dict para retornar
    deduped = {k: list(v) for k, v in unique.items()}
    return [deduped]
        
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
            try:
                content = f.read().strip()
                if not content:
                    return []  # Arquivo vazio, retorna lista vazia
                return json.loads(content)
            except Exception as e:
                print(f"[ERRO] Falha ao ler CVE DB: {e}")
                return []
    return []


def save_cve_database(data):
    os.makedirs('data', exist_ok=True)
    with open(CVE_DATABASE_FILE, 'w', encoding='utf-8') as f:
        # Se data for None ou não lista, salva lista vazia
        if not data or not isinstance(data, list):
            data = []
        json.dump(data, f, indent=2, ensure_ascii=False)

def analisar_classificacao(results):
    status = []
    detalhes = []
    for r in results:
        if not r:
            continue
        fonte = r.get("source", "Desconhecida")
        if fonte.lower().startswith("abuse"):
            score = int(r.get("abuseConfidenceScore", 0))
            reports = r.get("totalReports", 0)
            # Pegue nome correto para fontes distintas; ajuste conforme nome real do campo!
            distinct = r.get("distinct") or r.get("uniqueReports") or "-"
            first_seen = r.get("firstSeen", "")
            last_report = r.get("lastReportedAt", "")

            first_seen_fmt = format_datetime_br(first_seen) if first_seen else "-"
            last_report_fmt = format_datetime_br(last_report) if last_report else "-"
            last_report_rel = format_datetime_br(last_report, modo_relativo=True) if last_report else "-"
            
            url = r.get("url", "#")  # Pega o campo url, se não vier, usa "#"

            msg1 = (f"<b>AbuseIPDB:</b> Este endereço IP foi reportado um total de <b>{reports}</b> vezes.")
            msg2 = f"O reporte mais recente em <b>{last_report_fmt}</b>."
            msg2 += f' | <a href="{url}" target="_new" rel="noopener"><b>Acesse diretamente no AbuseIPDB</b></a>.'

            if last_report_rel != "-":
                msg2 += f" ({last_report_rel})"
            if score >= 90 or reports > 100:
                status.append("Malicioso")
            elif score >= 50 or reports > 10:
                status.append("Suspeito")
            else:
                status.append("Não Malicioso")
            detalhes += [msg1, msg2]

        # ...VirusTotal e outros igual anterior...

    if "Malicioso" in status:
        resumo = "Malicioso"
    elif "Suspeito" in status:
        resumo = "Suspeito"
    else:
        resumo = "Não Malicioso"
    return resumo, detalhes
    
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
                extension = filename.rsplit('.', 1)[1].lower()
                results = universal_file_parser(filepath, extension)
                deduped = results[0]
                classified = []
                for ioc_type, values in deduped.items():
                    for value in values:
                        results_enrich = []
                        try:
                            if ioc_type == "ips":
                                abuse = check_ip(value)
                                if abuse: abuse["source"] = "AbuseIPDB"
                                vt = check_hash(value)
                                if vt: vt["source"] = "VirusTotal"
                                results_enrich = [abuse, vt]
                            elif ioc_type in ["urls", "domains"]:
                                vt = check_url_or_domain(value)
                                if vt: vt["source"] = "VirusTotal"
                                results_enrich = [vt]
                            elif ioc_type == "hashes":
                                vt = check_hash(value)
                                if vt: vt["source"] = "VirusTotal"
                                results_enrich = [vt]
                        except Exception as e:
                            results_enrich = [{"source": "Erro", "classification": str(e)}]
                        resumo, detalhes = analisar_classificacao(results_enrich)
                        classified.append({
                            "type": ioc_type[:-1].capitalize(),
                            "value": value,
                            "severity": resumo,
                            "classification": detalhes[0] if detalhes else "Desconhecido"
                        })

    
                os.remove(filepath)
                return jsonify({'success': True, 'total_iocs': len(classified), 'iocs': classified})

    except Exception as e:
        print(f"[ERRO] Upload: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/ioc')
def ioc_panel():
    iocs = load_ioc_database()
    page = int(request.args.get('page', 1))
    per_page = 20
    start = (page - 1) * per_page
    end = start + per_page
    iocs_paginated = iocs[start:end]
    total = len(iocs)
    total_pages = ((total - 1) // per_page) + 1
    return render_template(
        'ioc_panel.html',
        iocs=iocs_paginated,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        total=total,
        request=request
    )

@app.route('/ioc/search', methods=['POST'])
def ioc_search():
    ioc_value = request.form.get('ioc_value', '').strip()
    error = None

    if not ioc_value:
        return render_template('ioc_panel.html', error="Informe o valor do IOC", iocs=load_ioc_database())

    abuse = None
    vt = None
    try:
        if "." in ioc_value:
            abuse = check_ip(ioc_value)
            if abuse: abuse["source"] = "AbuseIPDB"
            if abuse is not None and isinstance(abuse, dict):
                abuse["type"] = "IP"
                
            vt = check_hash(ioc_value)
            if vt: vt["source"] = "VirusTotal"
            if vt is not None and isinstance(vt, dict):
                vt["type"] = "IP"
        else:
            vt = check_hash(ioc_value)
            if vt: vt["source"] = "VirusTotal"
            if vt is not None and isinstance(vt, dict):
                # deduza o tipo: "Hash", "URL", "Domain"
                vt_type = "-"
                if len(ioc_value) in (32,40,64): vt_type = "Hash"
                elif "://" in ioc_value or ioc_value.startswith("www."): vt_type = "URL"
                elif "@" in ioc_value or "." in ioc_value: vt_type = "Domain"
                vt["type"] = vt_type

    except Exception as exc:
        error = f"Erro em consultas externas: {exc}"  

    resumo, detalhes = analisar_classificacao([abuse, vt])
    tipo = "-"
    if abuse and isinstance(abuse, dict):
        tipo = abuse["type"]
    elif vt and isinstance(vt, dict):
        tipo = vt["type"]

    result = {
        "type": tipo,
        "severity": resumo,
        "description": "<br>".join(detalhes) if detalhes else "-",
        "source": ", ".join(
            s for s in [
                abuse["source"] if abuse and isinstance(abuse, dict) and "source" in abuse else None,
                vt["source"] if vt and isinstance(vt, dict) and "source" in vt else None
            ] if s
        ),
        "date_added": datetime.now().strftime('%d/%m/%Y %H:%M'),
    }
    api_limitation_msg = (
    "<b>Aviso:</b> Os dados exibidos refletem apenas o valor retornado pela AbuseIPDB API, "
    "podendo ser diferentes do total apresentado no site oficial. Para o histórico completo e contagens agregadas, utilize o site do AbuseIPDB."
    )

    return render_template(
        'ioc_panel.html', 
        iocs=load_ioc_database(),
        ioc_result=result, 
        ioc_value=ioc_value, 
        error=error,
        api_limitation_msg=api_limitation_msg,
    )

@app.route('/ioc/reportshistory', methods=['POST'])
def ioc_reportshistory():
    """
    Rota para consulta avançada do histórico de reports de um IP via endpoint /reports da AbuseIPDB.
    
    - Recebe o valor do IOC (IP) via POST (formulário oculto).
    - Invoca fetch_reports (método da client wrapper) que realiza a consulta detalhada.
    - Retorna lista com todos os reports do IP (limitado por quota diária da API AbuseIPDB).
    - Os dados são enviados ao template como 'reports_history' para exibição.
    - Caso haja muitos reports, pode ser implementada paginação ou aviso ao usuário.
    - Aviso: Consulta avançada consome quota de /reports (100/dia em conta gratuita AbuseIPDB).
    """
    ioc_value = request.form.get('ioc_value', '').strip()
    error = None
    reports = []
    try:
        reports = fetch_reports(ioc_value, max_age=365, per_page=10)
    except Exception as exc:
        error = f"Erro na consulta avançada: {exc}"
    # Garante que 'reports' seja lista
    if not reports or not isinstance(reports, list):
        reports = []

    return render_template(
        'ioc_panel.html',
        iocs=load_ioc_database(),
        reports_history=reports,      # nunca None!
        ioc_value=ioc_value,
        abuseipdb_category_map=abuseipdb_category_map,
        error=error
    )

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
        data = request.form
        valor = data.get('value')
        tipo = data.get('type') or "-"
        # Dedução automática do tipo, se tipo ficou vazio ou traço
        if not tipo or tipo.strip() == "-" or tipo.strip() == "":
            if valor:
                import re
                # IP v4
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", valor):
                    tipo = "IP"
                # URL
                elif "://" in valor or valor.startswith("www."):
                    tipo = "URL"
                # Hash
                elif len(valor) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in valor):
                    tipo = "Hash"
                # Domain
                elif re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", valor):
                    tipo = "Domain"
                else:
                    tipo = "Outro"
            else:
                tipo = "Outro"
        ioc = {
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'type': tipo,
            'value': valor,
            'source': data.get('source'),
            'severity': data.get('severity'),
            'description': data.get('description'),
        }
        iocs = load_ioc_database()
        iocs.append(ioc)
        save_ioc_database(iocs)
        return redirect(url_for('ioc_panel'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ioc/delete/<ioc_id>', methods=['DELETE', 'POST'])
def ioc_delete(ioc_id):
    try:
        iocs = load_ioc_database()
        iocs = [ioc for ioc in iocs if str(ioc['id']) != str(ioc_id)]
        save_ioc_database(iocs)
        if request.method == 'POST':
            return redirect(url_for('ioc_panel'))
        return jsonify({'success': True})
    except Exception as e:
        if request.method == 'POST':
            return redirect(url_for('ioc_panel', error=str(e)))
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
        cve_id = data.get('cve_id')
        # Verificação de duplicidade
        cve_db = load_cve_database()
        if any(str(cve.get('cve_id')).strip().lower() == str(cve_id).strip().lower() for cve in cve_db):
            return jsonify({'success': False, 'error': 'CVE já registrada!'})
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
        cves = [cve for cve in cves if str(cve['id']) != str(cve_id)]
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
            if isinstance(desc, str) and desc.strip():
                cve['description_pt'] = translate_to_portuguese(desc)
            else:
                cve['description_pt'] = ""  # ou simplesmente desc se quiser preservar original
        auto_save = data.get('auto_save', False)
        saved_count = 0
        if auto_save:
            cve_db = load_cve_database()
            existing_cve_ids = {cve.get('cve_id') for cve in cve_db}
            for cve_data in cves_found:
                cve_id = cve_data.get('cve_id')
                # print(f"[DEBUG] cve_id={cve_id}, type={type(cve_id)}, desc={cve_data.get('description')}")
                if not cve_id or not isinstance(cve_id, str):
                    continue  # ignora registros inválidos
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
