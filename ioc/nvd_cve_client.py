"""
Cliente para buscar CVEs via API do NIST NVD
"""

import os
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _build_headers():
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers

def _get_severity(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
    except Exception:
        pass
    return "Unknown"

def _extract_description(cve_item):
    descriptions = cve_item.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""

def _format_date(date_str):
    if not date_str:
        return ""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str

def _extract_cvss(metrics):
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    cvss_v2 = metrics.get("cvssMetricV2", [])

    if cvss_v31:
        data = cvss_v31[0].get("cvssData", {})
        return data.get("baseScore"), data.get("vectorString", "")
    if cvss_v30:
        data = cvss_v30[0].get("cvssData", {})
        return data.get("baseScore"), data.get("vectorString", "")
    if cvss_v2:
        data = cvss_v2[0].get("cvssData", {})
        return data.get("baseScore"), data.get("vectorString", "")
    return None, None

def search_cve_by_id(cve_id):
    params = {"cveId": cve_id}

    try:
        response = requests.get(
            NVD_BASE_URL,
            headers=_build_headers(),
            params=params,
            timeout=15
        )

        if response.status_code == 403:
            return {"found": False, "error": "API Key inválida ou sem permissão"}

        if response.status_code == 404:
            return {"found": False, "cve_id": cve_id}

        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return {"found": False, "cve_id": cve_id}

        cve_item = vulnerabilities[0].get("cve", {})
        metrics = cve_item.get("metrics", {})
        cvss_score, cvss_vector = _extract_cvss(metrics)

        references = [
            ref.get("url", "")
            for ref in cve_item.get("references", [])[:5]
            if ref.get("url")
        ]

        cwe_list = []
        for weakness in cve_item.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_list.append(cwe_id)

        return {
            "found": True,
            "cve_id": cve_id,
            "severity": _get_severity(cvss_score),
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "cvss_vector": cvss_vector,
            "description": _extract_description(cve_item),
            "published": _format_date(cve_item.get("published", "")),
            "modified": _format_date(cve_item.get("lastModified", "")),
            "references": references,
            "cwe": cwe_list,
            "source": "NVD"
        }

    except requests.exceptions.Timeout:
        return {"found": False, "error": "Timeout ao conectar com NVD API (15s)"}
    except Exception as e:
        return {"found": False, "error": str(e)}

def fetch_recent_cves(hours=24):
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(hours=hours)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    try:
        response = requests.get(
            NVD_BASE_URL,
            headers=_build_headers(),
            params=params,
            timeout=30
        )
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        cves = []

        for item in vulnerabilities:
            cve_item = item.get("cve", {})
            metrics = cve_item.get("metrics", {})
            cvss_score, _ = _extract_cvss(metrics)

            cves.append({
                "cve_id": cve_item.get("id"),
                "cveId": cve_item.get("id"),
                "severity": _get_severity(cvss_score),
                "cvss_score": float(cvss_score) if cvss_score is not None else None,
                "description": _extract_description(cve_item),
                "datePublished": _format_date(cve_item.get("published", "")),
                "published": _format_date(cve_item.get("published", "")),
                "exploited": False,
                "product": "Diversos",
                "source": "NVD",
                "is_new": True
            })

        return {"success": True, "cves": cves, "total": len(cves)}

    except Exception as e:
        return {"success": False, "error": str(e)}