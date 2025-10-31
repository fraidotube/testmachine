# /opt/netprobe/app/routes/dhcpsentinel.py
from __future__ import annotations
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from pathlib import Path
import os, json, subprocess, time
from fastapi.responses import FileResponse

from routes.auth import verify_session_cookie, _load_users
from util.audit import log_event

router = APIRouter(prefix="/dhcpsentinel", tags=["dhcpsentinel"])

# --- paths ---
CFG   = Path("/etc/netprobe/dhcpsentinel.json")
LAST  = Path("/var/lib/netprobe/dhcpsentinel/last.json")
EVT   = Path("/var/lib/netprobe/dhcpsentinel/events.jsonl")
CLR   = Path("/var/lib/netprobe/dhcpsentinel/alerts.clear.ts")  # marker “svuota”

DEFAULT = {
    "enabled": True,
    "iface": "ens4",
    "allow": [],
    "listen_sec": 6,
    "retries": 1,
    "retry_delay_sec": 2,
}


@router.get("/api/events/download")
def api_events_download():
    if not EVT.exists():
        return JSONResponse({"ok": False, "err": "no_log"}, status_code=404)
    return FileResponse(str(EVT), media_type="text/plain", filename="dhcpsentinel-events.jsonl")

# ---------------- helpers ----------------

def _require_admin(request: Request) -> bool:
    user = verify_session_cookie(request)
    if not user:
        return False
    roles = (_load_users().get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

def _load_cfg() -> dict:
    try:
        d = json.loads(CFG.read_text("utf-8"))
    except Exception:
        d = {}
    # merge default + normalize
    out = {**DEFAULT, **d}
    out["enabled"] = bool(out.get("enabled"))
    out["iface"] = (out.get("iface") or "ens4").strip()
    out["listen_sec"] = int(out.get("listen_sec") or 6)
    out["retries"] = int(out.get("retries") or 1)
    out["retry_delay_sec"] = int(out.get("retry_delay_sec") or 2)
    out["allow"] = [str(x).strip() for x in (out.get("allow") or []) if str(x).strip()]
    return out

def _save_cfg(obj: dict):
    CFG.parent.mkdir(parents=True, exist_ok=True)
    tmp = CFG.with_suffix(".tmp")
    data = json.dumps(obj, indent=2)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(CFG)

def _read_json_file(p: Path, fallback):
    try:
        return json.loads(p.read_text("utf-8"))
    except Exception:
        return fallback

def _ifaces_list() -> list[str]:
    """Ritorna interfacce “utili” (nmcli connected → fallback ip link)."""
    names: list[str] = []
    try:
        out = subprocess.run(
            ["bash", "-lc", "command -v nmcli >/dev/null 2>&1 && nmcli -t -f DEVICE,STATE d || true"],
            capture_output=True, text=True, check=False
        ).stdout.strip().splitlines()
        for ln in out:
            if not ln:
                continue
            dev, _, state = (ln + "::").split(":")[:3]
            if dev and state.strip().lower() == "connected":
                names.append(dev.strip())
    except Exception:
        pass

    if not names:
        try:
            out = subprocess.run(["bash","-lc","ip -o link show | awk -F': ' '{print $2}'"],
                                 capture_output=True, text=True).stdout
            for dev in out.splitlines():
                dev = dev.strip()
                if (not dev) or dev == "lo": continue
                if dev.startswith(("veth","docker","br-","virbr","wg","tun")): continue
                names.append(dev)
        except Exception:
            pass

    # de-dup
    seen, res = set(), []
    for n in names:
        if n not in seen:
            seen.add(n); res.append(n)
    return res or ["ens4"]

def _fmt_ts(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except Exception:
        return str(ts)

def _read_events_raw(limit:int=200) -> list[dict]:
    rows=[]
    try:
        lines = EVT.read_text("utf-8", errors="ignore").splitlines()
    except Exception:
        lines = []
    for ln in lines[-max(1,limit):]:
        ln = ln.strip()
        if not ln: continue
        try:
            o = json.loads(ln)
            if isinstance(o.get("ts"), (int,float)):
                o["ts_str"] = _fmt_ts(o["ts"])
            rows.append(o)
        except Exception:
            pass
    return rows

def _events_last_n(n:int=50) -> list[dict]:
    raw = _read_events_raw(max(200, n*3))
    out=[]
    for r in raw:
        typ = r.get("type")
        if typ in (None, "dhcpsentinel_result"):
            out.append({
                "ts": r.get("ts"),
                "ts_str": r.get("ts_str"),
                "iface": r.get("iface"),
                "seen": r.get("seen", []),
                "ok": r.get("ok"),
                "reason": r.get("reason",""),
            })
    return out[-n:]

def _alerts_only(n:int=200) -> list[dict]:
    since = _alerts_clear_mark_read()
    raw = _read_events_raw(max(500, n*5))
    out=[]
    for r in raw:
        typ = r.get("type")
        ts  = int(r.get("ts") or 0)
        if ts <= since: 
            continue
        if typ == "dhcpsentinel_alert_try":
            out.append({
                "ts": ts, "ts_str": r.get("ts_str"),
                "iface": r.get("iface"), "seen": r.get("seen", []),
                "reason": r.get("note","alert"),
            })
        elif typ == "dhcpsentinel_fatal":
            out.append({
                "ts": ts, "ts_str": r.get("ts_str"),
                "iface": r.get("iface"), "seen": [],
                "reason": r.get("err","fatal"),
            })
        elif typ in (None, "dhcpsentinel_result") and r.get("ok") is False:
            out.append({
                "ts": ts, "ts_str": r.get("ts_str"),
                "iface": r.get("iface"), "seen": r.get("seen", []),
                "reason": r.get("reason","alert"),
            })
    return out[-n:]

def _alerts_clear_mark(ts:int|None=None)->None:
    CLR.parent.mkdir(parents=True, exist_ok=True)
    CLR.write_text(str(int(ts or time.time())), encoding="utf-8")

def _alerts_clear_mark_read()->int:
    try:
        return int(CLR.read_text("utf-8").strip())
    except Exception:
        return 0

# ---------------- HTML ----------------

def _head(title:str)->str:
    return ("<!doctype html><html><head><meta charset='utf-8'/>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
            "<div class='container'><div class='nav'>"
            "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
            "<div class='title-center'>TestMachine</div>"
            "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
            "</div>")

@router.get("", response_class=HTMLResponse)
def page(request: Request):
    if not _require_admin(request):
        return HTMLResponse(_head("DHCP Sentinel") + "<div class='card'><h2 class='err'>Operazione non permessa</h2></div></div></body></html>", status_code=403)

    c = _load_cfg()
    allow_text = "\n".join(c.get("allow") or [])
    last = _read_json_file(LAST, {})

    badge = "<span class='badge success'>OK</span>" if last.get("ok") else "<span class='badge warn'>ALERT</span>"
    last_compact = {
        "ts": last.get("ts_str") or ( _fmt_ts(last.get("ts")) if last.get("ts") else "" ),
        "iface": last.get("iface") or "",
        "seen": ", ".join(last.get("seen") or []),
        "ok": "true" if last.get("ok") else "false",
        "reason": last.get("reason") or "",
    }

    # opzioni interfacce
    ifaces = _ifaces_list()
    if c.get("iface") not in ifaces: ifaces = [c.get("iface")] + [x for x in ifaces if x!=c.get("iface")]
    options_html = "".join(
        f"<option value='{escape(n)}' {'selected' if n==c.get('iface') else ''}>{escape(n)}</option>"
        for n in ifaces
    )

    raw_html = _head("DHCP Sentinel") + """
<style>
.grid-2 { display:grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 1100px) { .grid-2 { grid-template-columns: 1fr; } }
.table-sm table { width:100%; border-collapse: collapse; }
.table-sm th, .table-sm td { padding:8px 10px; border-bottom:1px solid #2a2f3a; font-size:14px; }
.badge { padding:3px 8px; border-radius:999px; background:#344; font-weight:600; }
.badge.success { background:#1f6f43; }
.badge.warn { background:#7a2d2d; }
.kv { display:flex; gap:10px; flex-wrap:wrap; }
.kv .item { background:#10151e; border:1px solid #263043; border-radius:10px; padding:8px 10px; }
.btn.inline { margin-left:8px; }
</style>

<div class="grid-2">
  <div class="card">
    <h2>DHCP Sentinel</h2>
    <p class='muted'>Sonda periodica DHCP (DISCOVER/OFFER). Registra i server visti e allerta se fuori allowlist o se l’allowlist è vuota.</p>

    <form method='post' action='/dhcpsentinel/save' id='cfgForm'>
      <div class='kv'>
        <div class='item'>
          <strong>Stato</strong><br/>
          __BADGE__
          <button class='btn inline' formaction='/dhcpsentinel/toggle' formmethod='post'>__TOGGLE_LABEL__</button>
        </div>
        <div class='item'>
          <label>Interfaccia<br/>
            <select name='iface' style='min-width:140px'>__IFACE_OPTIONS__</select>
          </label>
        </div>
        <div class='item'>
          <label>Finestra ascolto (s)<br/>
            <input type='number' name='listen_sec' min='1' value='__LISTEN__' style='width:120px'/>
          </label>
        </div>
        <div class='item'>
          <label>Retries<br/>
            <input type='number' name='retries' min='0' value='__RETRIES__' style='width:100px'/>
          </label>
        </div>
        <div class='item'>
          <label>Ritardo retry (s)<br/>
            <input type='number' name='retry_delay_sec' min='0' value='__RETRY_DELAY__' style='width:130px'/>
          </label>
        </div>
      </div>

      <h4 style='margin-top:14px'>DHCP consentiti (uno per riga). Vuoto = allerta sempre.</h4>
      <textarea name='allow' rows='4' style='width:100%;font-family:monospace'>__ALLOW_TEXT__</textarea>

      <div class='row' style='gap:10px;margin-top:12px'>
        <button class='btn' type='submit'>Salva</button>
        <button class='btn secondary' formaction='/dhcpsentinel/run' formmethod='post' id='runBtn'>Esegui ora</button>
        <a class='btn secondary' href='/alerts'>Alerts</a>
      </div>
    </form>
  </div>

  <div class="card">
    <div class='row' style='align-items:center; justify-content:space-between'>
      <h3>Ultimo esito</h3>
      <div id='lastBadge'>__BADGE__</div>
    </div>
    <div id='lastCompact' class='kv' style='margin-top:6px'>
      <div class='item'><b>ts</b>: __LAST_TS__</div>
      <div class='item'><b>iface</b>: __LAST_IFACE__</div>
      <div class='item'><b>seen</b>: __LAST_SEEN__</div>
      <div class='item'><b>ok</b>: __LAST_OK__</div>
      <div class='item'><b>reason</b>: __LAST_REASON__</div>
    </div>
    <pre id='lastRaw' style='white-space:pre-wrap; display:none'>__LAST_JSON__</pre>
  </div>
</div>

<div class="card table-sm" style="margin-top:16px">
  <h3>Storico recente</h3>
  <table id='histTbl'>
    <thead><tr><th>ts</th><th>esito</th><th>iface</th><th>seen</th><th>reason</th></tr></thead>
    <tbody><tr><td colspan='5' class='muted'>Caricamento…</td></tr></tbody>
  </table>
</div>

<div class="card table-sm" style="margin-top:12px">
  <div class='row' style='justify-content:space-between; align-items:center'>
    <h3>Solo alert</h3>
    <form method='post' action='/dhcpsentinel/api/clear_alerts'>
      <button class='btn secondary' type='submit' title='Resetta il cursore di visualizzazione'>Svuota</button>
      <a class='btn' href='/dhcpsentinel/api/events/download'>Scarica log completo</a>

    </form>
  </div>
  <table id='alertTbl'>
    <thead><tr><th>ts</th><th>iface</th><th>seen</th><th>reason</th></tr></thead>
    <tbody><tr><td colspan='4' class='muted'>Caricamento…</td></tr></tbody>
  </table>
</div>

<script>
async function fetchJSON(url){ const r = await fetch(url, {cache:'no-store'}); if(!r.ok) return null; return r.json(); }
function esc(s){ return (s??'').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

function renderTable(tblId, rows, cols){
  const tb = document.querySelector(`#${tblId} tbody`);
  if(!rows || !rows.length){ tb.innerHTML = "<tr><td colspan='"+cols+"' class='muted'>Nessun evento</td></tr>"; return; }
  tb.innerHTML = rows.map(r=>{
    const seen = (r.seen||[]).join(', ');
    const ok = r.ok===true ? 'OK' : (r.ok===false ? 'ALERT' : '');
    return "<tr>"
         + "<td>"+esc(r.ts_str||r.ts||'')+"</td>"
         + "<td>"+esc(ok)+"</td>"
         + "<td>"+esc(r.iface||'')+"</td>"
         + "<td>"+esc(seen)+"</td>"
         + "<td>"+esc(r.reason||'')+"</td>"
         + "</tr>";
  }).join('');
}

async function refreshAll(){
  const hist = await fetchJSON('/dhcpsentinel/api/history?n=10');
  renderTable('histTbl', hist||[], 5);
  const alerts = await fetchJSON('/dhcpsentinel/api/alerts?n=10');
  renderTable('alertTbl', alerts||[], 4);
}
setInterval(refreshAll, 3000);
document.addEventListener('DOMContentLoaded', refreshAll);
</script>

<script src="/static/bg.js"></script>
</body></html>
"""
    html = (raw_html
            .replace("__BADGE__", badge)
            .replace("__TOGGLE_LABEL__", "Disabilita" if c.get("enabled") else "Abilita")
            .replace("__IFACE_OPTIONS__", options_html)
            .replace("__LISTEN__", str(int(c.get("listen_sec", 6))))
            .replace("__RETRIES__", str(int(c.get("retries", 1))))
            .replace("__RETRY_DELAY__", str(int(c.get("retry_delay_sec", 2))))
            .replace("__ALLOW_TEXT__", escape(allow_text))
            .replace("__LAST_TS__", escape(last_compact["ts"]))
            .replace("__LAST_IFACE__", escape(last_compact["iface"]))
            .replace("__LAST_SEEN__", escape(last_compact["seen"]))
            .replace("__LAST_OK__", escape(last_compact["ok"]))
            .replace("__LAST_REASON__", escape(last_compact["reason"]))
            .replace("__LAST_JSON__", escape(json.dumps(last, indent=2))))
    return HTMLResponse(html)

# ---------------- actions ----------------

@router.post("/save", response_class=HTMLResponse)
def save(request: Request,
         iface: str = Form("ens4"),
         listen_sec: int = Form(6),
         retries: int = Form(1),
         retry_delay_sec: int = Form(2),
         allow: str = Form("")):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    c = _load_cfg()
    c["iface"] = (iface or "").strip() or c["iface"]
    c["listen_sec"] = max(1, int(listen_sec))
    c["retries"] = max(0, int(retries))
    c["retry_delay_sec"] = max(0, int(retry_delay_sec))
    c["allow"] = [ln.strip() for ln in (allow or "").splitlines() if ln.strip()]
    _save_cfg(c)
    log_event("dhcpsentinel/save", ok=True, actor=verify_session_cookie(request) or "unknown", detail="saved")
    return HTMLResponse("<script>location.replace('/dhcpsentinel');</script>")

@router.post("/toggle", response_class=HTMLResponse)
def toggle(request: Request):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    c = _load_cfg()
    c["enabled"] = not bool(c.get("enabled"))
    _save_cfg(c)
    log_event("dhcpsentinel/toggle", ok=True, actor=verify_session_cookie(request) or "unknown",
              detail=f"enabled={c['enabled']}")
    return HTMLResponse("<script>location.replace('/dhcpsentinel');</script>")

@router.post("/run", response_class=HTMLResponse)
def run_now(request: Request):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)

    attempts = [
        ["sudo","-n","/bin/systemctl","start","netprobe-dhcpsentinel.service"],
        ["/bin/systemctl","start","netprobe-dhcpsentinel.service"],
    ]
    rc, out, err, used = 1, "", "", []
    for cmd in attempts:
        used = cmd
        r = subprocess.run(cmd, capture_output=True, text=True)
        rc, out, err = r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
        if rc == 0:
            break

    log_event("dhcpsentinel/run", ok=(rc==0),
              actor=verify_session_cookie(request) or "unknown",
              detail=f"cmd={' '.join(used)} rc={rc} out={out} err={err}")

    msg = "Esecuzione avviata" if rc==0 else f"Errore avvio: rc={rc} — {(err or out or 'permesso negato: aggiungi sudoers')[:200]}"
    import json as _json
    return HTMLResponse(f"<script>alert({_json.dumps(msg)});location.replace('/dhcpsentinel');</script>")


# ---------------- API JSON ----------------

@router.get("/api/cfg", response_class=JSONResponse)
def api_cfg():
    return JSONResponse(_load_cfg())

@router.get("/api/last", response_class=JSONResponse)
def api_last():
    raw = _read_json_file(LAST, {})
    ts = int(raw.get("ts") or 0) if isinstance(raw.get("ts"), (int,float,str)) else 0
    res = {
        "ts": ts,
        "ts_str": _fmt_ts(ts) if ts else "",
        "iface": raw.get("iface", ""),
        "seen": raw.get("seen", []),
        "ok": raw.get("ok", None),
        "reason": raw.get("reason", "")
    }
    return JSONResponse(res)

@router.get("/api/history", response_class=JSONResponse)
def api_history(n: int = 10):
    n = max(1, min(50, int(n)))
    rows = _events_last_n(n*2)
    rows = sorted(rows, key=lambda x: int(x.get("ts") or 0), reverse=True)
    return JSONResponse(rows[:n])

@router.get("/api/alerts", response_class=JSONResponse)
def api_alerts(n: int = 10):
    n = max(1, min(50, int(n)))
    rows = _alerts_only(n*5)
    rows = sorted(rows, key=lambda x: int(x.get("ts") or 0), reverse=True)
    return JSONResponse(rows[:n])

@router.post("/api/clear_alerts", response_class=HTMLResponse)
def api_clear_alerts(request: Request):
    if not _require_admin(request):
        return HTMLResponse("Accesso negato", status_code=403)
    _alerts_clear_mark()
    return HTMLResponse("<script>location.replace('/dhcpsentinel');</script>")
