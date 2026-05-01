"""
Cliente para consulta de CVEs na base CISA KEV (Known Exploited Vulnerabilities)
API gratuita e sem necessidade de chave
"""

import requests

try:
    from utils.logger import log_info, log_error
except Exception:
    def log_info(msg): 
        print(f"[INFO] {msg}")

    def log_error(msg): 
        print(f"[ERRO] {msg}")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_all_kev_cves():
    """
    Retorna todas as CVEs exploradas conhecidas da CISA
    """
    try:
        log_info("Consultando CISA KEV para CVEs exploradas...")
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities)
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
    Retorna dados se a CVE está sendo explorada ativamente
    """
    try:
        result = get_all_kev_cves()
        if not result["success"]:
            return {
                "found": False,
                "exploited": False,
                "error": result.get("error")
            }

        cve_id_normalized = cve_id.strip().upper()

        for vuln in result["vulnerabilities"]:
            if vuln.get("cveID", "").upper() == cve_id_normalized:
                log_info(f"CVE {cve_id} encontrada na CISA KEV")
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

        log_info(f"CVE {cve_id} não encontrada na CISA KEV")
        return {
            "found": False,
            "exploited": False
        }

    except Exception as e:
        log_error(f"Erro ao buscar CVE {cve_id} na CISA KEV: {e}")
        return {
            "found": False,
            "exploited": False,
            "error": str(e)
        }

def is_cve_exploited(cve_id):
    """
    Verifica rapidamente se uma CVE está sendo explorada
    """
    result = search_cve_in_kev(cve_id)
    return result.get("exploited", False)