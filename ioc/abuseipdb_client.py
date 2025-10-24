from abuseipdb_wrapper import AbuseIPDB
from dotenv import load_dotenv
import os
from utils.json_utils import save_to_json

# Carrega a chave da variável de ambiente
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

api = AbuseIPDB(api_key=API_KEY, db_file='abuseipdb_cache.json')

def check_ip(ip):
    """Consulta reputação de IP no AbuseIPDB e salva em cache local JSON."""
    try:
        result = api.check_ip(ip)
        save_to_json({ip: result}, "abuseipdb_cache.json")
        return result
    except Exception as e:
        return {"error": str(e)}