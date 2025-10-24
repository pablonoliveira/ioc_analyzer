from flask import Flask, request, render_template_string, render_template, jsonify
from parsers.log_parser import parse_log
from ioc.abuseipdb_client import check_ip
from ioc.virustotal_client import check_hash
from ioc.url_checker import check_url_or_domain
from datetime import datetime
import json
import os

app = Flask(__name__)

# Arquivo para persistência dos dados do CRUD
IOC_DATABASE_FILE = "data/ioc_database.json"

# Garantir que a pasta data existe
os.makedirs("data", exist_ok=True)

# Carregar IOCs do arquivo ao iniciar
def load_ioc_database():
    if os.path.exists(IOC_DATABASE_FILE):
        try:
            with open(IOC_DATABASE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

# Salvar IOCs no arquivo
def save_ioc_database():
    with open(IOC_DATABASE_FILE, 'w', encoding='utf-8') as f:
        json.dump(ioc_database, f, indent=2, ensure_ascii=False)

# Banco de dados em memória + persistência
ioc_database = load_ioc_database()

# Função para classificar o score em veredito textual
def classificar_score(score):
    if score is None:
        return "Sem dados"
    if score >= 70:
        return "Malicioso"
    elif score >= 30:
        return "Suspeito"
    else:
        return "Não malicioso"

# Função para determinar severidade baseada no score
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

# Função para salvar IOC automaticamente no banco
def save_ioc_to_database(tipo, valor, score, resumo):
    """
    Salva IOC detectado automaticamente no banco de dados do CRUD.
    Verifica se já existe para evitar duplicatas.
    """
    # Verificar se já existe
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
        save_ioc_database()  # Salvar no arquivo
        return True
    return False

HTML_FORM = """
<!doctype html>
<html>
<head>
    <title>IOC Analyzer - Upload de Logs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        nav { margin-bottom: 20px; padding: 15px; background: #fff; border-radius: 8px; }
        nav a { margin-right: 20px; text-decoration: none; color: #21808d; font-weight: 600; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; }
        h2 { color: #13343b; }
        .success-message { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 12px; text-align: left; }
        th { background-color: #21808d; color: white; }
        input[type="file"] { margin: 10px 0; }
        input[type="submit"], .btn { background: #21808d; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
        input[type="submit"]:hover, .btn:hover { background: #1d7480; }
    </style>
</head>
<body>
    <nav>
        <a href="/">📊 Upload de Logs</a>
        <a href="/crud">🛡️ Gerenciar IOCs</a>
    </nav>
    <div class="container">
        <h2>Envie um arquivo de log para análise:</h2>
        <form method=post enctype=multipart/form-data>
            <input type=file name=logfile required>
            <input type=submit value="Analisar">
        </form>
        {% if saved_count %}
            <div class="success-message">
                ✅ <strong>{{ saved_count }} IOCs detectados foram salvos automaticamente no banco de dados!</strong>
                <br><a href="/crud" class="btn" style="margin-top: 10px;">Ver IOCs no Gerenciador</a>
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
                    <tr style="background: {% if row.score is not none and row.score >=70 %} #ffe0e0 {% elif row.score is not none and row.score >=30 %} #fffacc {% else %} #e0ffe0 {% endif %}">
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

@app.route("/", methods=["GET", "POST"])
def upload_and_analyze():
    rows = []
    saved_count = 0
    
    if request.method == "POST":
        log_file = request.files["logfile"]
        log_lines = log_file.stream.read().decode("utf-8").splitlines()
        
        for line in log_lines:
            iocs = parse_log(line)
            
            # DEBUG: Ver o que está sendo extraído
            print(f"[DEBUG] IOCs extraídos: {iocs}")

            # Processar IPs
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

            # Processar URLs
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

            # Processar Domínios
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

            # Processar Hashes
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

# Rota para o CRUD de IOCs
@app.route("/crud")
def crud_interface():
    return render_template("crud.html")

# API endpoints para o CRUD
@app.route("/api/iocs", methods=["GET"])
def get_iocs():
    return jsonify(ioc_database)

@app.route("/api/iocs", methods=["POST"])
def add_ioc():
    data = request.get_json()
    ioc_database.append(data)
    save_ioc_database()  # Salvar após adicionar
    return jsonify({"success": True, "data": data})

@app.route("/api/iocs/<int:ioc_id>", methods=["PUT"])
def update_ioc(ioc_id):
    data = request.get_json()
    for ioc in ioc_database:
        if ioc.get("id") == ioc_id:
            ioc.update(data)
            save_ioc_database()  # Salvar após atualizar
            return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route("/api/iocs/<int:ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    global ioc_database
    ioc_database = [ioc for ioc in ioc_database if ioc.get("id") != ioc_id]
    save_ioc_database()  # Salvar após excluir
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)