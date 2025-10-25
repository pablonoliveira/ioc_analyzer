from flask import Flask, request, render_template_string, render_template, jsonify
from parsers.log_parser import parse_log
from ioc.abuseipdb_client import check_ip
from ioc.virustotal_client import check_hash
from ioc.url_checker import check_url_or_domain
from ioc.cisa_kev_client import search_cve_in_kev
from ioc.circl_cve_client import search_cve, get_severity_from_cvss
from datetime import datetime
import json
import os

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

# ============================================================================
# FUNÇÃO DE TRADUÇÃO
# ============================================================================

def traduzir(texto_en):
    """Traduz texto do inglês para português"""
    if not TRANSLATION_ENABLED:
        return texto_en
    
    if texto_en and texto_en.strip():
        try:
            resultado = translator.translate(texto_en, src='en', dest='pt')
            return resultado.text
        except Exception as e:
            print(f"[ERRO] Tradução falhou: {e}")
            return texto_en
    return ""

# ============================================================================
# PERSISTÊNCIA DE DADOS - IOCs
# ============================================================================

IOC_DATABASE_FILE = "data/ioc_database.json"
os.makedirs("data", exist_ok=True)

def load_ioc_database():
    if os.path.exists(IOC_DATABASE_FILE):
        try:
            with open(IOC_DATABASE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_ioc_database():
    with open(IOC_DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(ioc_database, f, indent=2, ensure_ascii=False)

ioc_database = load_ioc_database()

# ============================================================================
# PERSISTÊNCIA DE DADOS - CVEs
# ============================================================================

CVE_DATABASE_FILE = "data/cve_database.json"

def load_cve_database():
    if os.path.exists(CVE_DATABASE_FILE):
        try:
            with open(CVE_DATABASE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_cve_database():
    with open(CVE_DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cve_database, f, indent=2, ensure_ascii=False)

cve_database = load_cve_database()

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

def classificar_score(score):
    if score is None:
        return "Sem dados"
    if score >= 70:
        return "Malicioso"
    elif score >= 30:
        return "Suspeito"
    else:
        return "Não malicioso"

def get_severity_from_score(score):
    if score is None:
        return "Low"
    if score >= 70:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"

def save_ioc_to_database(tipo, valor, score, resumo):
    exists = any(ioc['value'] == valor and ioc['type'] == tipo for ioc in ioc_database)
    
    if not exists:
        new_ioc = {
            "id": len(ioc_database) + int(datetime.now().timestamp() * 1000),
            "type": tipo,
            "value": valor,
            "severity": get_severity_from_score(score),
            "status": "Active" if score and score >= 30 else "Monitored",
            "source": "Log Analysis - Automated Detection",
            "firstSeen": datetime.now().strftime("%Y-%m-%d"),
            "lastSeen": datetime.now().strftime("%Y-%m-%d"),
            "campaign": "",
            "description": f"Detectado automaticamente via análise de logs. {resumo}",
            "createdAt": datetime.now().isoformat()
        }
        ioc_database.append(new_ioc)
        save_ioc_database()
        return True
    return False

# ============================================================================
# TEMPLATE HTML - PÁGINA DE UPLOAD
# ============================================================================

HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>IOC Analyzer - Upload de Logs</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #0f3460 0%, #533483 100%);
            min-height: 100vh;
        }
        .container {
            background: #16213e;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            border: 1px solid rgba(255,255,255,0.1);
        }
        h1 {
            color: #00adb5;
            text-align: center;
            text-shadow: 0 0 20px rgba(0,173,181,0.3);
        }
        h2 {
            color: #eaeaea;
        }
        .nav-links {
            text-align: center;
            margin: 20px 0;
        }
        .nav-links a {
            margin: 0 10px;
            padding: 10px 20px;
            background: linear-gradient(135deg, #00adb5 0%, #00d4ff 100%);
            color: #1a1a2e;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s;
            font-weight: 600;
        }
        .nav-links a:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,173,181,0.4);
        }
        form {
            margin: 30px 0;
        }
        input[type="file"] {
            padding: 10px;
            border: 2px solid rgba(255,255,255,0.2);
            border-radius: 5px;
            width: 100%;
            margin-bottom: 15px;
            background: #0f3460;
            color: #eaeaea;
        }
        input[type="file"]::file-selector-button {
            padding: 8px 16px;
            background: #00adb5;
            color: #1a1a2e;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            margin-right: 10px;
        }
        input[type="submit"] {
            background: linear-gradient(135deg, #e94560 0%, #ff6b6b 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        input[type="submit"]:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(233,69,96,0.4);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #0f3460;
            border-radius: 10px;
            overflow: hidden;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            color: #eaeaea;
        }
        th {
            background: linear-gradient(135deg, #00adb5 0%, #00d4ff 100%);
            color: #1a1a2e;
            font-weight: 600;
        }
        tbody tr:hover {
            background: rgba(0,173,181,0.1);
        }
        .success-message {
            background: rgba(0,173,181,0.2);
            border: 1px solid #00adb5;
            color: #00d4ff;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            text-align: center;
        }
        .success-message a {
            color: #00d4ff;
            font-weight: bold;
            text-decoration: underline;
        }
        .success-message a:hover {
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 IOC Analyzer - Upload de Logs</h1>
        
        <div class="nav-links">
            <a href="/ioc_panel">🔍 IOC Panel</a>
            <a href="/cve_panel">🛡️ CVE Panel</a>
            <a href="/dashboard">📊 Dashboard</a>
        </div>

        <h2>Envie um arquivo de log para análise:</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="logfile" required>
            <input type="submit" value="🚀 Analisar Log">
        </form>

        {% if saved_count %}
        <div class="success-message">
            ✅ <strong>{{ saved_count }} IOCs detectados foram salvos automaticamente no banco de dados!</strong><br>
            <a href="/ioc_panel">Ver IOCs no Painel</a>
        </div>
        {% endif %}

        {% if rows %}
        <h2>Resultados:</h2>
        <table>
            <thead>
                <tr>
                    <th>Tipo</th>
                    <th>Valor</th>
                    <th>Score</th>
                    <th>Classificação</th>
                    <th>Resumo</th>
                </tr>
            </thead>
            <tbody>
                {% for row in rows %}
                <tr>
                    <td>{{ row.tipo }}</td>
                    <td>{{ row.valor }}</td>
                    <td>{{ row.score }}</td>
                    <td><strong>{{ row.classificacao }}</strong></td>
                    <td>{{ row.resumo }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>
</body>
</html>
"""

# ============================================================================
# ROTAS - UPLOAD E ANÁLISE
# ============================================================================

@app.route("/", methods=["GET", "POST"])
def upload_and_analyze():
    rows = []
    saved_count = 0
    
    if request.method == "POST":
        log_file = request.files["logfile"]
        log_lines = log_file.stream.read().decode("utf-8").splitlines()
        
        for line in log_lines:
            iocs = parse_log(line)
            
            for ip in iocs.get("ips", []):
                result = check_ip(ip)
                score = result.get("abuseConfidenceScore")
                resumo = f"{result.get('countryCode','')} | {result.get('usageType','')}"
                rows.append({
                    "tipo": "IP",
                    "valor": ip,
                    "score": score,
                    "classificacao": classificar_score(score),
                    "resumo": resumo
                })
                if save_ioc_to_database("IP", ip, score, resumo):
                    saved_count += 1
            
            for url in iocs.get("urls", []):
                result = check_url_or_domain(url)
                score = result.get("malicious", 0) * 10
                resumo = f"Malicious:{result.get('malicious',0)} Suspicious:{result.get('suspicious',0)}"
                rows.append({
                    "tipo": "URL",
                    "valor": url,
                    "score": score,
                    "classificacao": classificar_score(score),
                    "resumo": resumo
                })
                if save_ioc_to_database("URL", url, score, resumo):
                    saved_count += 1
            
            for domain in iocs.get("domains", []):
                result = check_url_or_domain(domain)
                score = result.get("malicious", 0) * 10
                resumo = f"Malicious:{result.get('malicious',0)} Suspicious:{result.get('suspicious',0)}"
                rows.append({
                    "tipo": "DOMAIN",
                    "valor": domain,
                    "score": score,
                    "classificacao": classificar_score(score),
                    "resumo": resumo
                })
                if save_ioc_to_database("Domain", domain, score, resumo):
                    saved_count += 1
            
            for file_hash in iocs.get("hashes", []):
                result = check_hash(file_hash)
                score = result.get("malicious")
                resumo = f"Malicious:{result.get('malicious',0)} Suspicious:{result.get('suspicious',0)}"
                rows.append({
                    "tipo": "HASH",
                    "valor": file_hash,
                    "score": score,
                    "classificacao": classificar_score(score),
                    "resumo": resumo
                })
                if save_ioc_to_database("Hash", file_hash, score, resumo):
                    saved_count += 1
        
    return render_template_string(HTML_FORM, rows=rows, saved_count=saved_count)

# ============================================================================
# ROTAS - IOC PANEL
# ============================================================================

@app.route("/ioc_panel")
def ioc_panel_interface():
    return render_template("ioc_panel.html")

@app.route("/api/iocs", methods=["GET"])
def get_iocs():
    return jsonify(ioc_database)

@app.route("/api/iocs", methods=["POST"])
def add_ioc():
    data = request.get_json()
    ioc_database.append(data)
    save_ioc_database()
    return jsonify({"success": True, "data": data})

@app.route("/api/iocs/<int:ioc_id>", methods=["PUT"])
def update_ioc(ioc_id):
    data = request.get_json()
    for ioc in ioc_database:
        if ioc.get("id") == ioc_id:
            ioc.update(data)
            save_ioc_database()
            return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route("/api/iocs/<int:ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    global ioc_database
    ioc_database = [ioc for ioc in ioc_database if ioc.get("id") != ioc_id]
    save_ioc_database()
    return jsonify({"success": True})

@app.route("/api/iocs/search", methods=["POST"])
def search_ioc_external():
    data = request.get_json()
    ioc_type = data.get("type")
    ioc_value = data.get("value")
    
    result = {"success": False, "data": None}
    
    try:
        if ioc_type == "IP":
            api_result = check_ip(ioc_value)
            result = {
                "success": True,
                "type": "IP",
                "value": ioc_value,
                "score": api_result.get("abuseConfidenceScore"),
                "country": api_result.get("countryCode"),
                "usage_type": api_result.get("usageType"),
                "isp": api_result.get("isp"),
                "total_reports": api_result.get("totalReports"),
                "num_distinct_users": api_result.get("numDistinctUsers"),
                "last_reported_at": api_result.get("lastReportedAt"),
                "classification": classificar_score(api_result.get("abuseConfidenceScore")),
                "severity": get_severity_from_score(api_result.get("abuseConfidenceScore")),
                "source": "AbuseIPDB"
            }
        elif ioc_type in ["Domain", "URL"]:
            api_result = check_url_or_domain(ioc_value)
            score = api_result.get("malicious", 0) * 10
            result = {
                "success": True,
                "type": ioc_type,
                "value": ioc_value,
                "score": score,
                "malicious": api_result.get("malicious", 0),
                "suspicious": api_result.get("suspicious", 0),
                "harmless": api_result.get("harmless", 0),
                "classification": classificar_score(score),
                "severity": get_severity_from_score(score),
                "source": "VirusTotal"
            }
        elif ioc_type == "Hash":
            api_result = check_hash(ioc_value)
            score = api_result.get("malicious", 0) * 10
            result = {
                "success": True,
                "type": "Hash",
                "value": ioc_value,
                "score": score,
                "malicious": api_result.get("malicious", 0),
                "suspicious": api_result.get("suspicious", 0),
                "classification": classificar_score(score),
                "severity": get_severity_from_score(score),
                "source": "VirusTotal"
            }
    except Exception as e:
        result = {"success": False, "error": str(e)}
    
    return jsonify(result)

# ============================================================================
# ROTAS - CVE PANEL
# ============================================================================

@app.route("/cve_panel")
def cve_panel_interface():
    return render_template("cve_panel.html")

@app.route("/api/cves", methods=["GET"])
def get_cves():
    return jsonify(cve_database)

@app.route("/api/cves", methods=["POST"])
def add_cve():
    data = request.get_json()
    cve_database.append(data)
    save_cve_database()
    return jsonify({"success": True, "data": data})

@app.route("/api/cves/<int:cve_id>", methods=["PUT"])
def update_cve(cve_id):
    data = request.get_json()
    for cve in cve_database:
        if cve.get("id") == cve_id:
            cve.update(data)
            save_cve_database()
            return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route("/api/cves/<int:cve_id>", methods=["DELETE"])
def delete_cve(cve_id):
    global cve_database
    cve_database = [cve for cve in cve_database if cve.get("id") != cve_id]
    save_cve_database()
    return jsonify({"success": True})

@app.route("/api/cves/search/<cve_id>", methods=["GET"])
def search_external_cve(cve_id):
    try:
        kev_result = {"found": False, "exploited": False}
        circl_result = {"found": False}
        
        try:
            kev_result = search_cve_in_kev(cve_id)
            print(f"[INFO] CISA KEV result: {kev_result}")
        except Exception as kev_error:
            print(f"[ERRO] CISA KEV: {kev_error}")
        
        try:
            circl_result = search_cve(cve_id)
            print(f"[INFO] CIRCL result: {circl_result}")
        except Exception as circl_error:
            print(f"[ERRO] CIRCL: {circl_error}")
        
        combined = {
            "cve_id": cve_id.upper(),
            "found": kev_result.get("found", False) or circl_result.get("found", False),
            "exploited": kev_result.get("exploited", False),
            "kev_data": kev_result if kev_result.get("found") else None,
            "circl_data": circl_result if circl_result.get("found") else None
        }
        
        # TRADUÇÃO DOS CAMPOS DO CISA KEV
        if kev_result.get("found"):
            vuln_name = kev_result.get("vulnerabilityName", kev_result.get("vulnerability_name", ""))
            short_desc = kev_result.get("shortDescription", kev_result.get("short_description", ""))
            req_action = kev_result.get("requiredAction", kev_result.get("required_action", ""))
            
            combined["vulnerability_name"] = traduzir(vuln_name)
            combined["short_description"] = traduzir(short_desc)
            combined["required_action"] = traduzir(req_action)
            combined["known_ransomware"] = kev_result.get("knownRansomwareCampaignUse", kev_result.get("known_ransomware_campaign_use", "Unknown"))
            combined["date_added"] = kev_result.get("dateAdded", kev_result.get("date_added", ""))
        
        # TRADUÇÃO DOS CAMPOS DO CIRCL
        if circl_result.get("found"):
            cvss_score = circl_result.get("cvss", circl_result.get("cvss_score", 0))
            summary = circl_result.get("summary", "")
            
            combined["severity"] = get_severity_from_cvss(cvss_score) if cvss_score else "Unknown"
            combined["cvss_score"] = cvss_score
            combined["summary"] = traduzir(summary)
            combined["references"] = circl_result.get("references", [])
            combined["published"] = circl_result.get("Published", circl_result.get("published", ""))
            combined["modified"] = circl_result.get("Modified", circl_result.get("modified", ""))
        else:
            combined["severity"] = "Critical" if combined["exploited"] else "Unknown"
        
        print(f"[INFO] Combined result (traduzido): {combined}")
        return jsonify(combined)
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ERRO CRÍTICO] search_external_cve: {e}")
        print(error_trace)
        return jsonify({
            "found": False, 
            "error": f"Erro interno ao processar CVE: {str(e)}",
            "cve_id": cve_id.upper()
        }), 500

# ============================================================================
# ROTAS - DASHBOARD
# ============================================================================

@app.route("/dashboard")
def dashboard_interface():
    return render_template("dashboard.html")

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Retorna estatísticas consolidadas para o dashboard"""
    
    # Estatísticas de IOCs
    ioc_stats = {
        "total": len(ioc_database),
        "by_severity": {
            "Critical": len([i for i in ioc_database if i.get("severity") == "Critical"]),
            "High": len([i for i in ioc_database if i.get("severity") == "High"]),
            "Medium": len([i for i in ioc_database if i.get("severity") == "Medium"]),
            "Low": len([i for i in ioc_database if i.get("severity") == "Low"])
        },
        "by_status": {
            "Active": len([i for i in ioc_database if i.get("status") == "Active"]),
            "Monitored": len([i for i in ioc_database if i.get("status") == "Monitored"]),
            "Mitigated": len([i for i in ioc_database if i.get("status") == "Mitigated"])
        },        
        "by_type": {
            "IP": len([i for i in ioc_database if i.get("type") == "IP"]),
            "Domain": len([i for i in ioc_database if i.get("type") == "Domain"]),
            "URL": len([i for i in ioc_database if i.get("type") == "URL"]),
            "Hash": len([i for i in ioc_database if i.get("type") == "Hash"]),
            "Other": len([i for i in ioc_database if i.get("type") not in ["IP", "Domain", "URL", "Hash"]])
        }
    }
    
    # Estatísticas de CVEs
    cve_stats = {
        "total": len(cve_database),
        "by_severity": {
            "Critical": len([c for c in cve_database if c.get("severity") == "Critical"]),
            "High": len([c for c in cve_database if c.get("severity") == "High"]),
            "Medium": len([c for c in cve_database if c.get("severity") == "Medium"]),
            "Low": len([c for c in cve_database if c.get("severity") == "Low"]),
            "Unknown": len([c for c in cve_database if c.get("severity") == "Unknown"])
        },
        "exploited": len([c for c in cve_database if c.get("exploited", False)]),
        "not_exploited": len([c for c in cve_database if not c.get("exploited", False)])
    }
    
    # Estatísticas combinadas
    combined_stats = {
        "iocs": ioc_stats,
        "cves": cve_stats,
        "total_threats": ioc_stats["total"] + cve_stats["total"],
        "critical_total": ioc_stats["by_severity"]["Critical"] + cve_stats["by_severity"]["Critical"]
    }
    
    return jsonify(combined_stats)

if __name__ == "__main__":
    app.run(debug=True)
