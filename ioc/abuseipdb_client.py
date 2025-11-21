import requests
from abuseipdb_wrapper import AbuseIPDB
from dotenv import load_dotenv
from utils.json_utils import save_to_json
from utils.datetime_utils import format_datetime_br
import os


# Carrega a chave da variável de ambiente
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

api = AbuseIPDB(api_key=API_KEY, db_file='abuseipdb_cache.json')

def check_ip(ip):
    """Consulta reputação de IP no AbuseIPDB e salva em cache local JSON."""
    try:
        result = api.check_ip(ip)
        save_to_json({ip: result}, "abuseipdb_cache.json")
        return result
    except Exception as e:
        return {"error": str(e)}

def fetch_reports(ip, max_age=365, page=1, per_page=10):
    url = "https://api.abuseipdb.com/api/v2/reports"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age,
        "page": page,
        "perPage": per_page
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("data", {}).get("results", [])
        for rpt in results:
            rpt["reportedAt_br"] = format_datetime_br(rpt["reportedAt"])
        return results
    except Exception as err:
        print(f"[Erro] fetch_reports: {err}")      
        return []


