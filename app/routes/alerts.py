# /opt/netprobe/app/routes/alerts.py
from __future__ import annotations
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from pathlib import Path
import json, time

from routes.auth import verify_session_cookie, _load_users
from util.audit import log_event

router = APIRouter(tags=["alerts"])

CFG_FILE  = Path("/etc/netprobe/alerts.json")
STATE_FILE = Path("/var/lib/netprobe/tmp/alertd.state.json")

DEFAULT_CFG = {
  "channels": {
    "telegram": {"enabled": False, "token": "", "chat_id": ""},
    "slack":    {"enabled": False, "webhook_url": ""},
    "email":    {"enabled": False, "smtp": "localhost", "from": "testmachine@localhost", "to": []}
  },
  "checks": {
    "smokeping": {"enabled": True, "rrd_fresh_min": 10, "database_file": "/etc/smokeping/config.d/Database"},
    "disk":      {"enabled": True, "paths": ["/","/var"], "warn_pct": 90},
    "services":  {"enabled": True, "list": ["netprobe-api.socket","apache2","smokeping","netprobe-flow-collector"]},
    "speedtest": {"enabled": True, "down_min_mbps": 50, "up_min_mbps": 10, "ping_max_ms": 80},
    "cacti":     {"enabled": True, "url": "http://127.0.0.1:8080/cacti/", "log_dir": "/usr/share/cacti/site/log", "log_stale_min": 10},
    "flow":      {"enabled": True, "dir": "/var/lib/netprobe/flows", "stale_min": 10},
    "auth":      {"enabled": True, "fail_threshold": 3, "window_min": 5}
  },
  # nuova opzione per ritmo reminder (minuti)
  "throttle_min": 30,
  "silence_until": 0
}

def _ensure_cfg()->dict:
    CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not CFG_FILE.exists():
        CFG_FILE.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")
    try:
        cfg = json.loads(CFG_FILE.read_text("utf-8") or "{}")
        # merge minimo per nuove chiavi
        if "throttle_min" not in cfg: cfg["throttle_min"] = DEFAULT_CFG["throttle_min"]
        return cfg
    except Exception:
        return DEFAULT_CFG.copy()

def _save_cfg(cfg:dict):
    tmp = CFG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    Path(tmp).replace(CFG_FILE)

def _require_admin(request: Request) -> bool:
    user = verify_session_cookie(request)
    if not user: return False
    roles = (_load_users().get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

def _head(title:str)->str:
    return ("<!doctype html><html><head><meta charset='utf-8'/>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
            "<div class='container'><div class='nav'>"
            "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
            "<div class='title-center'>TestMachine</div>"
            "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
            "</div>")

@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    if not _require_admin(request):
        return HTMLResponse(_head("Alerting") + "<div class='card'><h2 class='err'>Operazione non permessa</h2></div></div></body></html>", status_code=403)
    cfg = _ensure_cfg()
    tg  = cfg["channels"]["telegram"]
    sv  = cfg["checks"]["services"]["list"]
    services_text = "\n".join(sv)

    html = _head("Alerting") + f"""
<div class='grid'>
  <div class='card'>
    <h2>Alerting</h2>
    <p class='muted'>Configura canali e controlli. Il motore gira via systemd timer.</p>
    <form method='post' action='/alerts/config'>
      <h3>Telegram</h3>
      <div class='row' style='gap:8px;flex-wrap:wrap'>
        <label>Token</label><input name='tg_token' value='{escape(tg.get('token',''))}' style='min-width:320px'/>
        <label>Chat ID</label><input name='tg_chat' value='{escape(str(tg.get('chat_id','')))}' style='min-width:200px'/>
        <label class='row' style='gap:6px;align-items:center'><input type='checkbox' name='tg_enabled' {'checked' if tg.get('enabled') else ''}/> Abilitato</label>
        <button class='btn secondary' formaction='/alerts/test' formmethod='post'>Invia test</button>
      </div>

      <h3>Controlli</h3>
      <div class='row' style='gap:16px;flex-wrap:wrap'>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_services' {'checked' if cfg['checks']['services']['enabled'] else ''}/> Servizi</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_disk' {'checked' if cfg['checks']['disk']['enabled'] else ''}/> Disk full</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_smoke' {'checked' if cfg['checks']['smokeping']['enabled'] else ''}/> Smokeping</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_speed' {'checked' if cfg['checks']['speedtest']['enabled'] else ''}/> Speedtest soglie</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_cacti' {'checked' if cfg['checks']['cacti']['enabled'] else ''}/> Cacti</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_flow' {'checked' if cfg['checks']['flow']['enabled'] else ''}/> Flussi</label>
        <label class='row' style='gap:6px'><input type='checkbox' name='chk_auth' {'checked' if cfg['checks']['auth']['enabled'] else ''}/> Accesso UI</label>
      </div>

      <h4>Servizi monitorati</h4>
      <textarea name='services' rows='3' style='width:100%;font-family:monospace'>{escape(services_text)}</textarea>

      <div class='row' style='gap:12px;flex-wrap:wrap;margin-top:8px'>
        <label>Disk warn % <input name='disk_pct' type='number' min='50' max='99' value='{int(cfg["checks"]["disk"]["warn_pct"])}' style='width:90px'/></label>
        <label>Speed min down (Mb/s) <input name='spd_down' type='number' min='1' value='{int(cfg["checks"]["speedtest"]["down_min_mbps"])}' style='width:110px'/></label>
        <label>Speed min up (Mb/s) <input name='spd_up' type='number' min='1' value='{int(cfg["checks"]["speedtest"]["up_min_mbps"])}' style='width:110px'/></label>
        <label>Ping max (ms) <input name='spd_ping' type='number' min='1' value='{int(cfg["checks"]["speedtest"]["ping_max_ms"])}' style='width:90px'/></label>
        <label>Flussi bloccati (min) <input name='flow_stale' type='number' min='1' value='{int(cfg["checks"]["flow"]["stale_min"])}' style='width:120px'/></label>
        <label>Smokeping RRD bloccati (min) <input name='sp_rrd' type='number' min='1' value='{int(cfg["checks"]["smokeping"]["rrd_fresh_min"])}' style='width:160px'/></label>
        <label>Cacti log bloccati (min) <input name='cacti_stale' type='number' min='1' value='{int(cfg["checks"]["cacti"]["log_stale_min"])}' style='width:150px'/></label>
      </div>

      <h4 style='margin-top:10px'>Accesso UI</h4>
      <div class='row' style='gap:12px;flex-wrap:wrap;margin-top:4px'>
        <label>Tentativi falliti (soglia)
          <input name='auth_threshold' type='number' min='1' value='{int(cfg["checks"]["auth"]["fail_threshold"])}' style='width:90px'/>
        </label>
        <label>Finestra (min)
          <input name='auth_window' type='number' min='1' value='{int(cfg["checks"]["auth"]["window_min"])}' style='width:90px'/>
        </label>
      </div>

      <h3 style='margin-top:12px'>Notifiche</h3>
      <div class='row' style='gap:12px;flex-wrap:wrap;margin-top:4px'>
        <label>Reminder ogni (min)
          <input name='thr_min' type='number' min='0' value='{int(cfg.get("throttle_min",30))}' style='width:100px'/>
        </label>
        <button class='btn danger' formaction='/alerts/reset' formmethod='post' title='Azzera lo stato dedupe: ri-consente invio della stessa anomalia subito'>Reset dedupe</button>
      </div>

      <h4>Silenzia fino a (epoch sec)</h4>
      <input name='silence' value='{int(cfg.get("silence_until",0))}' style='max-width:220px'/>
      <button class='btn secondary' type='button' onclick="document.querySelector('[name=silence]').value=Math.floor(Date.now()/1000)+3600">+1h</button>

      <div style='margin-top:12px'>
        <button class='btn' type='submit'>Salva</button>
      </div>
    </form>
  </div>
</div>
</div>
<script src="/static/bg.js"></script>
</body></html>
"""
    return HTMLResponse(html)

@router.post("/alerts/config")
def alerts_save(request: Request,
    tg_token: str = Form(""), tg_chat: str = Form(""), tg_enabled: str | None = Form(None),
    chk_services: str | None = Form(None), chk_disk: str | None = Form(None), chk_smoke: str | None = Form(None),
    chk_speed: str | None = Form(None), chk_cacti: str | None = Form(None), chk_flow: str | None = Form(None),
    chk_auth: str | None = Form(None),
    services: str = Form(""), disk_pct: int = Form(90),
    spd_down: int = Form(50), spd_up: int = Form(10), spd_ping: int = Form(80),
    flow_stale: int = Form(10), sp_rrd: int = Form(10), cacti_stale: int = Form(10),
    auth_threshold: int = Form(3), auth_window: int = Form(5),
    thr_min: int = Form(30),
    silence: int = Form(0),
):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    cfg = _ensure_cfg()
    cfg["channels"]["telegram"].update({"enabled": bool(tg_enabled), "token": tg_token.strip(), "chat_id": tg_chat.strip()})
    cfg["checks"]["services"]["enabled"] = bool(chk_services)
    cfg["checks"]["disk"]["enabled"]     = bool(chk_disk)
    cfg["checks"]["smokeping"]["enabled"]= bool(chk_smoke)
    cfg["checks"]["speedtest"]["enabled"]= bool(chk_speed)
    cfg["checks"]["cacti"]["enabled"]    = bool(chk_cacti)
    cfg["checks"]["flow"]["enabled"]     = bool(chk_flow)
    cfg["checks"]["auth"]["enabled"]     = bool(chk_auth)
    cfg["checks"]["services"]["list"] = [s.strip() for s in services.splitlines() if s.strip()]
    cfg["checks"]["disk"]["warn_pct"] = int(disk_pct)
    cfg["checks"]["speedtest"]["down_min_mbps"] = int(spd_down)
    cfg["checks"]["speedtest"]["up_min_mbps"]   = int(spd_up)
    cfg["checks"]["speedtest"]["ping_max_ms"]   = int(spd_ping)
    cfg["checks"]["flow"]["stale_min"]   = int(flow_stale)
    cfg["checks"]["smokeping"]["rrd_fresh_min"] = int(sp_rrd)
    cfg["checks"]["cacti"]["log_stale_min"]     = int(cacti_stale)
    cfg["checks"]["auth"]["fail_threshold"] = int(auth_threshold)
    cfg["checks"]["auth"]["window_min"]     = int(auth_window)
    cfg["throttle_min"] = max(0, int(thr_min))
    cfg["silence_until"] = int(silence) if str(silence).strip().isdigit() else 0
    _save_cfg(cfg)
    actor = verify_session_cookie(request) or "unknown"
    log_event("alerts/config", ok=True, actor=actor, detail="saved")
    return HTMLResponse("<script>location.replace('/alerts');</script>")

@router.post("/alerts/reset", response_class=HTMLResponse)
def alerts_reset(request: Request):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
        msg = "Stato dedupe azzerato."
        ok = True
    except Exception as e:
        msg = f"Errore reset: {e}"
        ok = False
    actor = verify_session_cookie(request) or "unknown"
    log_event("alerts/reset", ok=ok, actor=actor, detail=msg)
    return HTMLResponse(f"<script>alert('{escape(msg)}');location.replace('/alerts');</script>")

@router.get("/alerts/config", response_class=JSONResponse)
def alerts_get():
    return JSONResponse(_ensure_cfg())

@router.post("/alerts/test", response_class=HTMLResponse)
def alerts_test(request: Request):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    from util.notify import send_telegram
    cfg = _ensure_cfg()
    tg = cfg["channels"]["telegram"]
    ok, msg = send_telegram(tg.get("token",""), str(tg.get("chat_id","")), f"TestMachine: test notifica {int(time.time())}")
    note = "OK" if ok else ("ERR: " + msg)
    return HTMLResponse(f"<script>alert('Telegram: {escape(note)}');history.back();</script>")
