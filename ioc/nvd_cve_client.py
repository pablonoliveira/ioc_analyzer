"""
Cliente para buscar CVEs via API do NIST NVD (National Vulnerability Database)
Com suporte a API Key para melhor performance e dados completos
"""
import requests
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv('NVD_API_KEY', '')
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve_by_id(cve_id):
    """
    Busca uma CVE específica por ID no NVD
    
    Args:
        cve_id (str): CVE-ID no formato CVE-YYYY-NNNN
        
    Returns:
        dict: Resultado com dados completos da CVE ou erro
    """
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
    
    params = {'cveId': cve_id}
    
    try:
        print(f"[INFO] NVD: Buscando {cve_id}...")
        
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                print(f"[INFO] NVD: {cve_id} não encontrado")
                return {"found": False, "cve_id": cve_id}
            
            cve_item = vulnerabilities[0].get("cve", {})
            
            # Extrai CVSS v3.1 ou v3.0
            metrics = cve_item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v3 = metrics.get("cvssMetricV30", [])
            
            cvss_score = None
            cvss_vector = None
            
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
            elif cvss_v3:
                cvss_data = cvss_v3[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
            
            # Classifica severidade baseado no CVSS
            severity = "Unknown"
            if cvss_score is not None:
                cvss_score = float(cvss_score)
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                elif cvss_score > 0:
                    severity = "Low"
            
            # Descrição em inglês
            descriptions = cve_item.get("descriptions", [])
            description_en = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value", "")
                    break
            
            if not description_en and descriptions:
                description_en = descriptions[0].get("value", "")
            
            # Data de publicação
            published = cve_item.get("published", "")
            if published:
                try:
                    published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    published = published_dt.strftime("%Y-%m-%d")
                except:
                    published = published[:10] if len(published) >= 10 else published
            
            # Data de última modificação
            modified = cve_item.get("lastModified", "")
            if modified:
                try:
                    modified_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                    modified = modified_dt.strftime("%Y-%m-%d")
                except:
                    modified = modified[:10] if len(modified) >= 10 else modified
            
            # Referências (primeiras 5)
            references = cve_item.get("references", [])
            ref_list = []
            for ref in references[:5]:
                url = ref.get("url", "")
                if url:
                    ref_list.append(url)
            
            # Weaknesses (CWE)
            weaknesses = cve_item.get("weaknesses", [])
            cwe_list = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_list.append(cwe_id)
            
            result = {
                "found": True,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "description": description_en,
                "published": published,
                "modified": modified,
                "references": ref_list,
                "cwe": cwe_list,
                "source": "NVD"
            }
            
            print(f"[INFO] NVD: {cve_id} encontrado - Severidade: {severity} (CVSS: {cvss_score})")
            return result
        
        elif response.status_code == 403:
            print(f"[ERRO] NVD: Acesso negado - Verifique a API Key")
            return {"found": False, "error": "API Key inválida ou sem permissão"}
        
        elif response.status_code == 404:
            print(f"[INFO] NVD: {cve_id} não encontrado")
            return {"found": False, "cve_id": cve_id}
        
        else:
            error_msg = f"HTTP {response.status_code}"
            print(f"[ERRO] NVD: {error_msg}")
            return {"found": False, "error": error_msg}
    
    except requests.exceptions.Timeout:
        error_msg = "Timeout ao conectar com NVD API (15s)"
        print(f"[ERRO] {error_msg}")
        return {"found": False, "error": error_msg}
    
    except Exception as e:
        error_msg = str(e)
        print(f"[ERRO] NVD: {error_msg}")
        return {"found": False, "error": error_msg}


def fetch_recent_cves(hours=24):
    """
    Busca CVEs publicadas nas últimas X horas via NVD API
    
    Args:
        hours (int): Número de horas retroativas para buscar CVEs
        
    Returns:
        dict: Resultado com sucesso, lista de CVEs e total
    """
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(hours=hours)
    
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    }
    
    try:
        print(f"[INFO] NVD: Buscando CVEs de {start_date.strftime('%Y-%m-%d %H:%M')} até {end_date.strftime('%Y-%m-%d %H:%M')}")
        
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cves = []
            
            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id")
                
                # Extrai CVSS
                metrics = cve_item.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v3 = metrics.get("cvssMetricV30", [])
                
                cvss_score = None
                if cvss_v31:
                    cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore")
                elif cvss_v3:
                    cvss_score = cvss_v3[0].get("cvssData", {}).get("baseScore")
                
                # Classifica severidade
                severity = "Unknown"
                if cvss_score is not None:
                    cvss_score = float(cvss_score)
                    if cvss_score >= 9.0:
                        severity = "Critical"
                    elif cvss_score >= 7.0:
                        severity = "High"
                    elif cvss_score >= 4.0:
                        severity = "Medium"
                    elif cvss_score > 0:
                        severity = "Low"
                
                # Descrição
                descriptions = cve_item.get("descriptions", [])
                description_en = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description_en = desc.get("value", "")
                        break
                
                if not description_en and descriptions:
                    description_en = descriptions[0].get("value", "")
                
                # Data de publicação
                published = cve_item.get("published", "")
                if published:
                    try:
                        published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                        published = published_dt.strftime("%Y-%m-%d")
                    except:
                        published = published[:10] if len(published) >= 10 else published
                
                cves.append({
                    "cve_id": cve_id,
                    "cveId": cve_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "description": description_en,
                    "datePublished": published,
                    "published": published,
                    "exploited": False,
                    "product": "Diversos",
                    "source": "NVD",
                    "is_new": True
                })
            
            print(f"[INFO] NVD: Total de CVEs encontradas: {len(cves)}")
            return {"success": True, "cves": cves, "total": len(cves)}
        
        else:
            error_msg = f"HTTP {response.status_code}"
            print(f"[ERRO] NVD: {error_msg}")
            return {"success": False, "error": error_msg}
    
    except Exception as e:
        error_msg = str(e)
        print(f"[ERRO] NVD: {error_msg}")
        return {"success": False, "error": error_msg}


if __name__ == "__main__":
    # Teste local
    print("=== Teste do Cliente NVD ===\n")
    
    # Teste 1: Buscar CVE específica
    print("1. Testando busca por CVE-ID específica...")
    result = search_cve_by_id("CVE-2024-21413")
    if result["found"]:
        print(f"\n✅ CVE encontrada:")
        print(f"  ID: {result['cve_id']}")
        print(f"  Severidade: {result['severity']} (CVSS: {result['cvss_score']})")
        print(f"  Descrição: {result['description'][:150]}...")
    else:
        print(f"\n❌ CVE não encontrada: {result.get('error', 'N/A')}")
    
    print("\n" + "="*50 + "\n")
    
    # Teste 2: Buscar CVEs recentes
    print("2. Testando busca de CVEs recentes (últimas 24h)...")
    result = fetch_recent_cves(24)
    if result["success"]:
        print(f"\n✅ {result['total']} CVEs encontradas nas últimas 24h")
        for cve in result["cves"][:3]:
            print(f"\n  {cve['cve_id']} - {cve['severity']} (CVSS: {cve['cvss_score']})")
    else:
        print(f"\n❌ Erro: {result['error']}")
