from virustotal_python import Virustotal
from dotenv import load_dotenv
import os
from utils.json_utils import save_to_json

# Carrega a chave da variável de ambiente
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

vt = Virustotal(API_KEY=API_KEY)


def check_hash(file_hash):
    """
    Consulta reputação de um hash no VirusTotal (API v3)
    e salva em cache local JSON.
    Retorna o JSON completo do VT.
    """
    try:
        result = vt.request(f"files/{file_hash}", None)
        data = result.json()
        # cache local (mantém o mesmo formato que você já usa)
        save_to_json({file_hash: data}, "virustotal_cache.json")
        return data
    except Exception as e:
        return {"error": str(e)}
