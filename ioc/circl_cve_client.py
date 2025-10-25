import requests

def search_cve(cve_id):
    """
    Busca CVE no CIRCL CVE Search
    """
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 404:
            return {
                "found": False
            }
        
        response.raise_for_status()
        data = response.json()
        
        cvss_score = None
        if "cvss" in data:
            cvss_score = data.get("cvss")
        elif "impact" in data:
            if "baseMetricV3" in data["impact"]:
                cvss_score = data["impact"]["baseMetricV3"].get("cvssV3", {}).get("baseScore")
            elif "baseMetricV2" in data["impact"]:
                cvss_score = data["impact"]["baseMetricV2"].get("cvssV2", {}).get("baseScore")
        
        references = []
        if "references" in data:
            for ref in data["references"][:10]:
                if isinstance(ref, dict):
                    references.append(ref.get("url", ""))
                elif isinstance(ref, str):
                    references.append(ref)
        
        return {
            "found": True,
            "cve_id": data.get("id"),
            "summary": data.get("summary", ""),
            "cvss_score": cvss_score,
            "published": data.get("Published", ""),
            "modified": data.get("Modified", ""),
            "references": references
        }
    
    except Exception as e:
        print(f"[ERRO] CIRCL Client: {e}")
        return {
            "found": False,
            "error": str(e)
        }

def get_severity_from_cvss(cvss_score):
    """
    Converte CVSS Score em classificação de severidade
    """
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    except:
        return "Unknown"
