import os
import requests
from dotenv import load_dotenv
from abuseipdb_wrapper import AbuseIPDB
from utils.json_utils import save_to_json
from utils.datetime_utils import format_datetime_br

load_dotenv()

def get_abuseipdb_client():
    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        return None
    try:
        return AbuseIPDB(api_key=api_key, db_file="abuseipdb_cache.json")
    except Exception:
        return None

def check_ip(ip):
    """Consulta reputação de IP no AbuseIPDB e salva em cache local JSON."""
    api = get_abuseipdb_client()

    if not api:
        return {
            "source": "AbuseIPDB",
            "error": "ABUSEIPDB_KEY não configurada ou cliente não pôde ser inicializado"
        }

    try:
        result = api.check_ip(ip)
        save_to_json({ip: result}, "abuseipdb_cache.json")
        return result
    except Exception as e:
        return {
            "source": "AbuseIPDB",
            "error": str(e)
        }

def fetch_reports(ip, max_age=365, page=1, per_page=10):
    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        return []

    url = "https://api.abuseipdb.com/api/v2/reports"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age,
        "page": page,
        "perPage": per_page
    }
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("data", {}).get("results", [])

        for rpt in results:
            if rpt.get("reportedAt"):
                rpt["reportedAt_br"] = format_datetime_br(rpt["reportedAt"])

        return results
    except Exception as err:
        print(f"[Erro] fetch_reports: {err}")
        return []