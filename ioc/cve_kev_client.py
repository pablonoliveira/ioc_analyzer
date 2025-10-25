"""
Cliente para consulta de CVEs na base CISA KEV (Known Exploited Vulnerabilities)
API gratuita e sem necessidade de chave
"""

import requests
from utils.logger import log_info, log_error

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_all_kev_cves():
    """
    Retorna todas as CVEs exploitadas conhecidas da CISA
    """
    try:
        log_info(f"Consultando CISA KEV para CVEs exploitadas...")
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "success": True,
            "vulnerabilities": data.get("vulnerabilities", []),
            "count": len(data.get("vulnerabilities", []))
        }
    except requests.exceptions.RequestException as e:
        log_error(f"Erro ao consultar CISA KEV: {e}")
        return {
            "success": False,
            "error": str(e),
            "vulnerabilities": [],
            "count": 0
        }

def search_cve_in_kev(cve_id):
    """
    Busca uma CVE específica na base CISA KEV
    Retorna dados se a CVE está sendo exploitada ativamente
    """
    try:
        result = get_all_kev_cves()
        if not result["success"]:
            return {"found": False, "exploited": False, "error": result.get("error")}
        
        # Normalizar CVE ID (remover espaços, forçar maiúsculas)
        cve_id_normalized = cve_id.strip().upper()
        
        # Buscar CVE na lista
        for vuln in result["vulnerabilities"]:
            if vuln.get("cveID", "").upper() == cve_id_normalized:
                log_info(f"CVE {cve_id} encontrada na CISA KEV (exploitada ativamente)")
                return {
                    "found": True,
                    "exploited": True,
                    "cve_id": vuln.get("cveID"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "date_added": vuln.get("dateAdded"),
                    "short_description": vuln.get("shortDescription"),
                    "required_action": vuln.get("requiredAction"),
                    "due_date": vuln.get("dueDate"),
                    "source": "CISA KEV"
                }
        
        log_info(f"CVE {cve_id} não encontrada na CISA KEV (não está sendo exploitada ativamente)")
        return {"found": False, "exploited": False}
        
    except Exception as e:
        log_error(f"Erro ao buscar CVE {cve_id} na CISA KEV: {e}")
        return {"found": False, "exploited": False, "error": str(e)}

def is_cve_exploited(cve_id):
    """
    Verifica rapidamente se uma CVE está sendo exploitada
    Retorna True/False
    """
    result = search_cve_in_kev(cve_id)
    return result.get("exploited", False)
