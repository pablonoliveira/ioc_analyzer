# ioc/alienvault_client.py

import os
from OTXv2 import OTXv2, IndicatorTypes

# Carrega a API KEY via variável ambiente (.env)
API_KEY = os.getenv("ALIENVAULT_API_KEY")
otx = OTXv2(API_KEY) if API_KEY else None

def check_ip(ip):
    """Consulta detalhes de um IP no OTX."""
    if not otx:
        return {"error": "OTXv2 não configurado"}
    return otx.get_indicator_details_full(IndicatorTypes.IPV4, ip)

def check_domain(domain):
    """Consulta detalhes de um domínio no OTX."""
    if not otx:
        return {"error": "OTXv2 não configurado"}
    return otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)

def check_url(url):
    """Consulta detalhes de uma URL no OTX."""
    if not otx:
        return {"error": "OTXv2 não configurado"}
    return otx.get_indicator_details_full(IndicatorTypes.URL, url)

def check_hash(hash_value, hash_type="md5"):
    """Consulta detalhes de um hash (MD5, SHA1, SHA256) no OTX."""
    if not otx:
        return {"error": "OTXv2 não configurado"}
    type_map = {
        "md5": IndicatorTypes.FILE_HASH_MD5,
        "sha1": IndicatorTypes.FILE_HASH_SHA1,
        "sha256": IndicatorTypes.FILE_HASH_SHA256
    }
    indicator_type = type_map.get(hash_type.lower(), IndicatorTypes.FILE_HASH_MD5)
    return otx.get_indicator_details_full(indicator_type, hash_value)

def get_recent_iocs(limit=3):
    print("Entrou em get_recent_iocs")
    if not otx:
        print("OTX não foi inicializado")
        return []
    indicators = []
    try:
        pulses = otx.getall()
        print("Pulses recebidos:", pulses)
        print("Qtde de pulses:", len(pulses))
        for pulse in pulses[:limit]:
            print("Pulse:", pulse)
            indics = otx.get_pulse_indicators(pulse['id'])
            print("Indicators desse pulse:", indics)
            for ioc in indics:
                indicators.append({
                    "type": ioc.get("type"),
                    "indicator": ioc.get("indicator"),
                    "description": pulse.get("name", ""),
                    "source": "AlienVault OTX"
                })
        print("Retornando", len(indicators), "IOCs")
        return indicators
    except Exception as e:
        print("Erro:", e)
        return [{"error": str(e)}]