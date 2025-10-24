from parsers.log_parser import parse_log  # Função que extrai IoCs dos logs
from ioc.abuseipdb_client import check_ip
from ioc.virustotal_client import check_hash
from utils.logger import log_event

def process_log(log_file):
    iocs = parse_log(log_file)  # retorna lista de IoCs
    for ioc in iocs.get("ips", []):
        result = check_ip(ioc)
        log_event(f"Consulta IP: {ioc} | Resultado: {result}")
    for ioc in iocs.get("hashes", []):
        result = check_hash(ioc)
        log_event(f"Consulta Hash: {ioc} | Resultado: {result}")

if __name__ == "__main__":
    process_log("caminho/do/seu/log.txt")