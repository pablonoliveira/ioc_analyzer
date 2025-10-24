# utils/process_log.py
from ioc.abuseipdb_client import check_ip
from ioc.virustotal_client import check_hash

def process_log_lines(log_lines, parse_log):
    results = {"ips": [], "hashes": [], "reports": []}
    for line in log_lines:
        iocs = parse_log(line)
        for ip in iocs.get("ips", []):
            result_ip = check_ip(ip)
            results["reports"].append({"ioc_type": "ip", "ioc": ip, "data": result_ip})
        for file_hash in iocs.get("hashes", []):
            result_hash = check_hash(file_hash)
            results["reports"].append({"ioc_type": "hash", "ioc": file_hash, "data": result_hash})
    return results