import requests
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_or_domain(value):
    """
    Verifica reputação de URL ou domínio no VirusTotal.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "API Key não configurada", "malicious": 0, "suspicious": 0}
    
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    # Enviar URL para análise
    data = {"url": value}
    
    try:
        response = requests.post(url, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get("data", {}).get("id")
            
            # Consultar resultado da análise
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
        
        return {"error": "Erro na consulta", "status_code": response.status_code, "malicious": 0, "suspicious": 0}
    
    except Exception as e:
        return {"error": str(e), "malicious": 0, "suspicious": 0}