import os
import requests
from dotenv import load_dotenv

load_dotenv()

def get_virustotal_api_key():
    return os.getenv("VIRUSTOTAL_API_KEY")

def check_url_or_domain(value):
    """
    Verifica reputação de URL ou domínio no VirusTotal.
    """
    api_key = get_virustotal_api_key()
    if not api_key:
        return {
            "error": "API Key não configurada",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key
    }
    data = {
        "url": value
    }

    try:
        response = requests.post(submit_url, headers=headers, data=data, timeout=15)
        response.raise_for_status()

        result = response.json()
        analysis_id = result.get("data", {}).get("id")

        if not analysis_id:
            return {
                "error": "ID de análise não retornado pelo VirusTotal",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers, timeout=15)
        analysis_response.raise_for_status()

        analysis_data = analysis_response.json()
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }