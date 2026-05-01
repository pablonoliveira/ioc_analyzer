import os
from dotenv import load_dotenv
from OTXv2 import OTXv2, IndicatorTypes

load_dotenv()

def get_otx_client():
    api_key = os.getenv("ALIENVAULT_API_KEY")
    if not api_key:
        return None
    try:
        return OTXv2(api_key)
    except Exception:
        return None

def check_ip(ip):
    """Consulta detalhes de um IP no OTX."""
    otx = get_otx_client()
    if not otx:
        return {"source": "AlienVault OTX", "error": "OTXv2 não configurado"}
    try:
        return otx.get_indicator_details_full(IndicatorTypes.IPV4, ip)
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

def check_domain(domain):
    """Consulta detalhes de um domínio no OTX."""
    otx = get_otx_client()
    if not otx:
        return {"source": "AlienVault OTX", "error": "OTXv2 não configurado"}
    try:
        return otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

def check_url(url):
    """Consulta detalhes de uma URL no OTX."""
    otx = get_otx_client()
    if not otx:
        return {"source": "AlienVault OTX", "error": "OTXv2 não configurado"}
    try:
        return otx.get_indicator_details_full(IndicatorTypes.URL, url)
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

def check_hash(hash_value, hash_type="md5"):
    """Consulta detalhes de um hash (MD5, SHA1, SHA256) no OTX."""
    otx = get_otx_client()
    if not otx:
        return {"source": "AlienVault OTX", "error": "OTXv2 não configurado"}

    type_map = {
        "md5": IndicatorTypes.FILE_HASH_MD5,
        "sha1": IndicatorTypes.FILE_HASH_SHA1,
        "sha256": IndicatorTypes.FILE_HASH_SHA256
    }

    indicator_type = type_map.get(hash_type.lower(), IndicatorTypes.FILE_HASH_MD5)

    try:
        return otx.get_indicator_details_full(indicator_type, hash_value)
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

def get_recent_iocs(limit=3):
    otx = get_otx_client()
    if not otx:
        return []

    indicators = []

    try:
        pulses = otx.getall()
        for pulse in pulses[:limit]:
            indics = otx.get_pulse_indicators(pulse["id"])
            for ioc in indics:
                indicators.append({
                    "type": ioc.get("type"),
                    "indicator": ioc.get("indicator"),
                    "description": pulse.get("name", ""),
                    "source": "AlienVault OTX"
                })
        return indicators
    except Exception as e:
        return [{"source": "AlienVault OTX", "error": str(e)}]