import requests

def search_cve_in_kev(cve_id):
    """
    Busca CVE no CISA KEV (Known Exploited Vulnerabilities Catalog)
    """
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            if vuln.get("cveID", "").upper() == cve_id.upper():
                return {
                    "found": True,
                    "exploited": True,
                    "cveID": vuln.get("cveID"),
                    "vendorProject": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerabilityName": vuln.get("vulnerabilityName"),
                    "shortDescription": vuln.get("shortDescription"),
                    "requiredAction": vuln.get("requiredAction"),
                    "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse"),
                    "dateAdded": vuln.get("dateAdded"),
                    "vendor": vuln.get("vendorProject", "Unknown")
                }
        
        return {
            "found": False,
            "exploited": False
        }
    
    except Exception as e:
        print(f"[ERRO] CISA KEV Client: {e}")
        return {
            "found": False,
            "exploited": False,
            "error": str(e)
        }
