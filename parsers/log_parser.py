import re

def parse_log(log_line):
    """
    Extrai IPs, URLs, domínios e hashes de uma linha de log.
    """
    iocs = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": []
    }

    # Regex para IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    iocs["ips"] = re.findall(ip_pattern, log_line)

    # Regex para URLs (com protocolo http/https)
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs["urls"] = re.findall(url_pattern, log_line)

    # Regex para domínios/FQDNs (sem protocolo)
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    potential_domains = re.findall(domain_pattern, log_line, re.IGNORECASE)
    
    # Filtrar IPs que podem ser capturados como domínios
    iocs["domains"] = [d for d in potential_domains if not re.match(ip_pattern, d)]

    # Regex para hashes (MD5, SHA1, SHA256)
    hash_pattern = r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b'
    iocs["hashes"] = re.findall(hash_pattern, log_line, re.IGNORECASE)

    return iocs