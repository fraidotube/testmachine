# /opt/netprobe/app/util/audit.py
from __future__ import annotations
import os, json, time, uuid, socket, fcntl

AUDIT_DIR  = os.environ.get("NETPROBE_AUDIT_DIR", "/var/lib/netprobe/logs")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.jsonl")
_MAX_BYTES = 5 * 1024 * 1024  # rotazione semplice interna se >5MB (failsafe)

def _ensure_path():
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
    except Exception:
        pass

def _rotate_simple(path: str, keep: int = 3):
    try:
        if not os.path.exists(path): return
        if os.path.getsize(path) <= _MAX_BYTES: return
        for i in range(keep, 0, -1):
            src = f"{path}.{i}"
            dst = f"{path}.{i+1}"
            if os.path.exists(src):
                try: os.replace(src, dst)
                except Exception: pass
        try: os.replace(path, f"{path}.1")
        except Exception: pass
    except Exception:
        pass

def log_event(action: str, ok: bool, actor: str | None = None, ip: str | None = None,
              detail: str | None = None, req_path: str | None = None, extra: dict | None = None) -> str:
    """
    Scrive una riga JSON d'audit. Non solleva eccezioni; ritorna event_id.
    """
    _ensure_path()
    event_id = str(uuid.uuid4())
    rec = {
        "ts": int(time.time()),
        "host": socket.gethostname(),
        "event_id": event_id,
        "action": action,
        "ok": bool(ok),
        "actor": actor or "anonymous",
        "ip": ip or None,
        "detail": (detail or "")[:2000],
        "req_path": req_path or None,
        "extra": extra or {},
    }
    line = json.dumps(rec, ensure_ascii=False)
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(line + "\n")
                f.flush()
            finally:
                try: fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception: pass
        _rotate_simple(AUDIT_FILE)
    except Exception:
        pass
    return event_id
