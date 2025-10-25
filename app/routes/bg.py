# routes/bg.py
from fastapi import APIRouter, Body
from pathlib import Path
import json, os, re

router = APIRouter(prefix="/bg", tags=["background"])

# Cartella immagini (risoluzione robusta)
def _img_dir() -> Path:
    env = os.getenv("STATIC_IMG_DIR")
    if env and Path(env).exists():
        return Path(env)
    for cand in [
        Path(__file__).resolve().parent.parent / "static" / "img",  # app/static/img
        Path("static/img").resolve(),
        Path("/opt/netprobe/app/static/img"),
    ]:
        if cand.exists():
            return cand
    return Path("static/img").resolve()

IMG_DIR = _img_dir()

STATE_FILE = Path(os.getenv("UI_STATE_FILE", "/var/lib/netprobe/ui.json"))
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

DEFAULT_BG = "/static/img/sfondo.png"

def _read_state():
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text() or "{}")
    except Exception:
        pass
    return {"bg": DEFAULT_BG}

def _write_state(d):
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d))
    tmp.replace(STATE_FILE)

def _list_files():
    if not IMG_DIR.exists():
        return []
    files = list(IMG_DIR.glob("sfondo*.png")) + list(IMG_DIR.glob("sfondo*.jpg"))
    files.sort(key=lambda p: p.name.lower())
    return [f"/static/img/{p.name}" for p in files]

@router.get("/list")
def list_bg():
    files = _list_files()
    cur = _read_state().get("bg", DEFAULT_BG)

    # CORREZIONE: se la scelta è "solid:#xxxxxx" NON sovrascrivere.
    # Sovrascrivi solo se è un'immagine che non esiste più nella lista.
    if isinstance(cur, str) and cur.startswith("/static/img/"):
        if files and cur not in files:
            cur = files[0]
    # altrimenti (solid:...) lascia com'è

    # Etichette “Sfondo 1..n”
    labels = {f: f"Sfondo {i+1}" for i, f in enumerate(files)}
    return {"ok": True, "files": files, "labels": labels, "current": cur}

@router.post("/set")
def set_bg(file: str = Body(..., embed=True)):
    files = _list_files()
    # Accetta: 1) file tra i candidati  2) tinta unita "solid:#RRGGBB"
    if file in files:
        choice_ok = True
    else:
        choice_ok = bool(re.fullmatch(r"solid:#([0-9a-fA-F]{6})", file))
    if not choice_ok:
        return {"ok": False, "error": "Scelta non valida"}

    st = _read_state()
    st["bg"] = file
    _write_state(st)
    return {"ok": True, "current": file}

@router.get("/current")
def bg_current():
    try:
        if STATE_FILE.exists():
            d = json.loads(STATE_FILE.read_text() or "{}")
            cur = d.get("bg", DEFAULT_BG)
        else:
            cur = DEFAULT_BG
    except Exception:
        cur = DEFAULT_BG
    # normalizza: se il file immagine non esiste più, torna default
    if isinstance(cur, str) and cur.startswith("/static/img/"):
        p = IMG_DIR / cur.split("/")[-1]
        if not p.exists():
            cur = DEFAULT_BG
    return {"ok": True, "current": cur}
