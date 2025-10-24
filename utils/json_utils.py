import json
import os

def save_to_json(data, filename):
    """Salva resultados de consultas de API em cache local JSON."""
    try:
        os.makedirs("data", exist_ok=True)
        path = os.path.join("data", filename)

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        else:
            cache = {}

        cache.update(data)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4, ensure_ascii=False)
        print(f"Resultados salvos em {path}")
    except Exception as e:
        print("Erro ao salvar JSON:", e)