# em utils/datetime_utils.py
from datetime import datetime, timedelta

def format_datetime_br(iso_str, modo_relativo=False):
    if not iso_str:
        return "-"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        dt_br = dt - timedelta(hours=3)
        if modo_relativo:
            return dt_br.strftime('%d/%m/%Y %H:%M') + " (UTC-3)"
        return dt_br.strftime('%d/%m/%Y %H:%M') + " (UTC-3)"
    except Exception:
        return iso_str
