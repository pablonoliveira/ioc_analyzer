import re
import ipaddress

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

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    raw_ips = re.findall(ip_pattern, log_line)

    valid_ips = []
    for ip in raw_ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    iocs["ips"] = valid_ips

    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs["urls"] = re.findall(url_pattern, log_line)

    sanitized_line = log_line
    for url in iocs["urls"]:
        sanitized_line = sanitized_line.replace(url, " ")

    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    potential_domains = re.findall(domain_pattern, sanitized_line, re.IGNORECASE)
    iocs["domains"] = list({
        d.lower() for d in potential_domains
        if d not in valid_ips
    })

    hash_pattern = r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b'
    iocs["hashes"] = re.findall(hash_pattern, log_line, re.IGNORECASE)

    return iocs