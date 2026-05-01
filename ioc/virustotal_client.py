from virustotal_python import Virustotal
from dotenv import load_dotenv
import os
from utils.json_utils import save_to_json

load_dotenv()

def get_vt_client():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        return Virustotal(API_KEY=api_key)
    except Exception:
        return None

def check_hash(file_hash):
    """
    Consulta reputação de um hash no VirusTotal (API v3)
    e salva em cache local JSON.
    Retorna o JSON completo do VT.
    """
    vt = get_vt_client()

    if not vt:
        return {
            "source": "VirusTotal",
            "error": "VIRUSTOTAL_API_KEY não configurada ou cliente não pôde ser inicializado"
        }

    try:
        result = vt.request(f"files/{file_hash}", None)
        data = result.json()
        save_to_json({file_hash: data}, "virustotal_cache.json")
        return data
    except Exception as e:
        return {
            "source": "VirusTotal",
            "error": str(e)
        }