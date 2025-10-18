from fastapi import APIRouter, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from pathlib import Path
from html import escape
import subprocess, os, json, time

router = APIRouter(prefix="/speedtest", tags=["speedtest"])

SPEED_DIR   = Path("/var/lib/netprobe/speedtest")
STATE_FILE  = SPEED_DIR / "state.json"     # {"pid":int|null, "started":ts, "result":{...}|null, "tool":"ookla|pycli"}
LOG_FILE    = SPEED_DIR / "last.log"
HIST_FILE   = SPEED_DIR / "history.jsonl"  # 1 riga JSON per test (append-only)

# ----------------- helpers -----------------
def _ensure_dir():
    SPEED_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps({"pid": None, "started": None, "result": None, "tool": None}, indent=2), encoding="utf-8")
    if not HIST_FILE.exists():
        HIST_FILE.write_text("", encoding="utf-8")

def _load_state():
    _ensure_dir()
    try:
        return json.loads(STATE_FILE.read_text("utf-8"))
    except Exception:
        return {"pid": None, "started": None, "result": None, "tool": None}

def _save_state(st: dict):
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_FILE)

def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def _append_history(entry: dict):
    """Scrive una riga JSON nello storico in modo atomico (best-effort)."""
    _ensure_dir()
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    tmp = HIST_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(line)
    # append atomico (rename non atomico cross-filesystem, ma qui è stesso FS)
    with open(HIST_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    try:
        tmp.unlink(missing_ok=True)
    except Exception:
        pass

def _read_history(limit: int = 100) -> list[dict]:
    _ensure_dir()
    if not HIST_FILE.exists():
        return []
    rows = []
    try:
        with open(HIST_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    pass
    except Exception:
        return []
    # ultimi prima
    rows.reverse()
    return rows[: max(1, min(1000, int(limit)))]

# ----------------- UI -----------------
def _page_head(title: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'>"
        "<div class='nav'>"
          "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
          "<div class='title-center'>TestMachine</div>"
          "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
        "</div>"
    )

def _pick_cmd() -> tuple[list[str], str]:
    """Ritorna (cmd, toolname). Preferisce Ookla CLI se disponibile."""
    import shutil
    # 1) Ookla CLI
    if shutil.which("speedtest"):
        return (
            ["/usr/bin/speedtest",
             "-f", "json", "-p", "no",
             "--accept-license", "--accept-gdpr"],
            "ookla"
        )
    # 2) Python speedtest-cli (fallback)
    py = shutil.which("python3") or "python3"
    code = (
        "import json,sys; "
        "import speedtest as s; "
        "st=s.Speedtest(); st.get_servers(); st.get_best_server(); "
        "d=st.download(); u=st.upload(pre_allocate=False); "
        "p=st.results.ping; sv=st.results.server or {}; "
        "print(json.dumps({'ping':p,'download':d,'upload':u,'server':sv}))"
    )
    return ([py, "-c", code], "pycli")

import signal

@router.get("/", response_class=HTMLResponse)
def page():
    html = _page_head("Speedtest") + """
<style>
  :root{ --st-a:#10b981; --st-b:#059669; }
  .card--st{ background:linear-gradient(160deg, rgba(16,185,129,.22), rgba(5,150,105,.10)); border:1px solid rgba(16,185,129,.30); }
  .hero{display:flex;gap:14px;align-items:center;justify-content:space-between}
  .pill{padding:4px 10px;border-radius:999px;background:rgba(255,255,255,.08);font-size:.9rem;border:1px solid rgba(255,255,255,.1)}
  .kv{display:grid;grid-template-columns:120px 1fr;gap:6px;margin-top:10px}
  .big{font-size:1.8rem;font-weight:700}
  .meter{height:10px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;position:relative}
  .meter .bar{position:absolute;left:0;top:0;height:100%;width:28%;background:linear-gradient(90deg,var(--st-a),var(--st-b));filter:saturate(120%);animation:pulse 1.1s ease-in-out infinite}
  @keyframes pulse {0%{transform:translateX(-40%)}50%{transform:translateX(120%)}100%{transform:translateX(-40%)}}
  .phase{display:inline-flex;gap:6px;align-items:center;margin-top:6px}
  .dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.25)} .on{background:var(--st-a)}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .table{overflow-x:auto} table{width:100%;border-collapse:collapse} th,td{padding:6px 8px;white-space:nowrap}
  .small{font-size:.92em;opacity:.95}
</style>

<div class='grid'>
  <div class='card card--st'>
    <div class='hero'>
      <h2>Speedtest</h2>
      <div id="state-pill" class="pill">Pronto</div>
    </div>
    <p class='muted'>Misura ping, download e upload.</p>

    <div id="pre-box">
      <button class='btn' onclick='startTest()'>Avvia test</button>
    </div>

    <div id="run-box" style="display:none">
      <div class="meter" style="margin:10px 0 6px"><div class="bar"></div></div>
      <div class="phase"><span id="ph1" class="dot"></span><span>Ping</span></div>
      <div class="phase"><span id="ph2" class="dot"></span><span>Download</span></div>
      <div class="phase"><span id="ph3" class="dot"></span><span>Upload</span></div>
      <button class='btn secondary' style="margin-top:10px" onclick='cancelTest()'>Annulla</button>
    </div>

    <div id="res-box" style="display:none;margin-top:12px">
      <div class="kv"><div>Server</div><div id="sv"></div></div>
      <div class="kv"><div>ISP</div><div id="isp"></div></div>
      <div class="kv"><div>IP</div><div id="ips"></div></div>
      <div class="kv"><div>Ping</div><div class="big" id="pg">-</div></div>
      <div class="kv"><div>Jitter</div><div id="jit">-</div></div>
      <div class="kv"><div>Loss</div><div id="pl">-</div></div>
      <div class="kv"><div>Download</div><div class="big" id="dl">-</div></div>
      <div class="kv"><div>Upload</div><div class="big" id="ul">-</div></div>
      <button class='btn' style="margin-top:10px" onclick='startTest()'>Riesegui</button>
    </div>

    <div class='muted' id='tool-note' style="margin-top:10px"></div>
  </div>

  <div class='card'>
    <div class='row' style='justify-content:space-between'>
      <h3 style='margin:0'>Storico test</h3>
      <div class='row'>
        <button class='btn small' onclick='histRefresh()'>Aggiorna</button>
        <a class='btn small' href='/speedtest/history/export.csv'>Esporta CSV</a>
        <a class='btn small secondary' href='/speedtest/history/export.jsonl'>JSONL</a>
        <button class='btn small danger' onclick='histDeleteSel()'>Elimina selezionati</button>
        <button class='btn small danger' onclick='histClear()'>Svuota</button>
      </div>
    </div>
    <div class='table' style='margin-top:8px'>
      <table id="histTbl">
        <thead>
          <tr><th></th><th>Quando</th><th>Ping</th><th>Jitter</th><th>Loss</th><th>Download</th><th>Upload</th><th>Server</th><th>ISP</th><th>IP</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class='small muted' id='histNote' style='margin-top:6px'></div>
  </div>
</div>

</div>
<script>
let timer=null, phase=0;

/* formattatori */
function humanBitsps(bps){ if(!bps) return "-"; const u=["bps","Kbps","Mbps","Gbps","Tbps"]; let i=0,v=Number(bps); while(v>=1000 && i<u.length-1){ v/=1000; i++; } return v.toFixed(2)+" "+u[i]; }
function setPhase(p){ phase=p; for(let i=1;i<=3;i++){ document.getElementById('ph'+i).classList.toggle('on', i<=p); }}

/* stato */
async function status(){
  const r = await fetch('/speedtest/status');
  if(!r.ok) return;
  const js = await r.json();
  const running = !!js.running;
  document.getElementById('tool-note').textContent = js.tool ? ("Tool: "+js.tool) : "";
  document.getElementById('state-pill').textContent = running ? "In esecuzione" : "Pronto";
  document.getElementById('state-pill').style.background = running ? "rgba(16,185,129,.2)" : "rgba(255,255,255,.08)";
  document.getElementById('pre-box').style.display = running ? "none":""; 
  document.getElementById('run-box').style.display = running ? "":"none";

  if(running){
    const t = Date.now() % 9000;
    if(t<1000) setPhase(1);
    else if(t<5000) setPhase(2);
    else setPhase(3);
  }

  if(js.result){
    setPhase(3);
    const res = js.result;
    if(res.server){
      const s = res.server;
      document.getElementById('sv').textContent = [s.name, s.location].filter(Boolean).join(" · ");
    }
    document.getElementById('isp').textContent = res.isp || "-";
    const iface = res.interface || {};
    const iptxt = [iface.internalIp, iface.externalIp].filter(Boolean).join(" → ");
    document.getElementById('ips').textContent = iptxt || "-";

    const pingMs = (res.ping?.latency ?? res.ping ?? res.ping_ms ?? null);
    document.getElementById('pg').textContent = pingMs!=null ? pingMs.toFixed(2)+" ms" : "-";
    document.getElementById('jit').textContent = res.ping?.jitter!=null ? res.ping.jitter.toFixed(2)+" ms" : "-";
    document.getElementById('pl').textContent  = (res.packetLoss!=null) ? (res.packetLoss+" %") : "-";

    let d = res.download?.bandwidth!=null ? res.download.bandwidth*8 : (res.download ?? null);
    let u = res.upload?.bandwidth!=null   ? res.upload.bandwidth*8   : (res.upload   ?? null);
    document.getElementById('dl').textContent = humanBitsps(d);
    document.getElementById('ul').textContent = humanBitsps(u);

    document.getElementById('res-box').style.display = "";
    // aggiorna storico appena arriva un risultato
    histRefresh();
  } else {
    document.getElementById('res-box').style.display = "none";
  }
}

/* storico */
function histRow(tr, it){
  const iptxt = [it.internalIp, it.externalIp].filter(Boolean).join(" → ");
  const sv = [it.server_name, it.server_loc].filter(Boolean).join(" · ");
  tr.innerHTML = `
    <td><input type="checkbox" data-ts="${it.ts}"></td>
    <td class="mono">${new Date(it.ts*1000).toLocaleString()}</td>
    <td class="mono" style="text-align:right">${it.ping_ms!=null ? it.ping_ms.toFixed(2)+' ms' : '-'}</td>
    <td class="mono" style="text-align:right">${it.jitter_ms!=null ? it.jitter_ms.toFixed(2)+' ms' : '-'}</td>
    <td class="mono" style="text-align:right">${it.loss_pct!=null ? it.loss_pct+' %' : '-'}</td>
    <td class="mono" style="text-align:right">${humanBitsps(it.down_bps)}</td>
    <td class="mono" style="text-align:right">${humanBitsps(it.up_bps)}</td>
    <td class="mono">${sv || '-'}</td>
    <td class="mono">${it.isp || '-'}</td>
    <td class="mono">${iptxt || '-'}</td>
  `;
}

async function histRefresh(){
  try{
    const r = await fetch('/speedtest/history?limit=50'); if(!r.ok) return;
    const js = await r.json();
    const tb = document.querySelector('#histTbl tbody'); tb.innerHTML='';
    js.items.forEach(it=>{
      const tr = document.createElement('tr'); histRow(tr, it); tb.appendChild(tr);
    });
    document.getElementById('histNote').textContent = 'Totale: '+js.total+' (mostrati: '+js.items.length+')';
  }catch(e){}
}

async function histClear(){
  if(!confirm('Svuotare tutto lo storico?')) return;
  await fetch('/speedtest/history/clear', {method:'POST'});
  histRefresh();
}

async function histDeleteSel(){
  const cbs = Array.from(document.querySelectorAll('#histTbl input[type=checkbox]:checked'));
  if(!cbs.length){ alert('Seleziona almeno un elemento'); return; }
  if(!confirm('Eliminare '+cbs.length+' elementi selezionati?')) return;
  const ids = cbs.map(cb=>Number(cb.dataset.ts));
  await fetch('/speedtest/history/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ts: ids})});
  histRefresh();
}

async function startTest(){ await fetch('/speedtest/start',{method:'POST'}); setPhase(1); if(!timer){ timer=setInterval(status, 1000); } status(); }
async function cancelTest(){ await fetch('/speedtest/cancel',{method:'POST'}); setPhase(0); status(); }

timer=setInterval(status, 1000);
status(); histRefresh();
</script>
</body></html>
"""
    return HTMLResponse(html)

# ----------------- API di stato -----------------
@router.get("/status", response_class=JSONResponse)
def st_status():
    st = _load_state()
    running = _alive(st.get("pid"))
    if not running and st.get("pid"):
        st["pid"] = None
        _save_state(st)
    return {"running": running, "result": st.get("result"), "tool": st.get("tool")}

def _start_subprocess_and_detach(cmd:list[str]):
    with open(LOG_FILE, "w") as log:
        return subprocess.Popen(cmd, stdout=log, stderr=log, preexec_fn=os.setsid)

# ----------------- start/cancel -----------------
@router.post("/start", response_class=JSONResponse)
def start():
    _ensure_dir()
    st = _load_state()
    if _alive(st.get("pid")):
        return {"ok": True, "running": True}

    st["result"] = None
    st["started"] = int(time.time())
    _save_state(st)

    cmd, tool = _pick_cmd()
    st["tool"] = tool
    _save_state(st)

    # wrapper che esegue il test, aggiorna state.json e appende allo storico
    wrapper = SPEED_DIR / "run_speedtest.py"
    wrapper_code = f"""
import json, subprocess, pathlib, sys, os, time
STATE = pathlib.Path({json.dumps(str(STATE_FILE))})
LOG   = pathlib.Path({json.dumps(str(LOG_FILE))})
HIST  = pathlib.Path({json.dumps(str(HIST_FILE))})
CMD   = {json.dumps(cmd)}

def _w(txt):
    try:
        with open(HIST, "a", encoding="utf-8") as f: f.write(txt)
    except Exception: pass

# esegui comando e cattura stdout/stderr
try:
    p = subprocess.run(CMD, capture_output=True, text=True, timeout=600)
    OUT = (p.stdout or "")
    ERR = (p.stderr or "")
except Exception as e:
    OUT, ERR = "", str(e)

# salva log completo
try:
    LOG.write_text(OUT + ("\\n" if OUT else "") + ERR)
except Exception:
    pass

# parse JSON da stdout; se fallisce, risultato vuoto ma log pieno
try:
    result = json.loads(OUT.strip() or "{{}}")
except Exception:
    result = {{}}

# aggiorna state.json
try:
    st = json.loads(STATE.read_text())
except Exception:
    st = {{"pid": None, "started": None, "result": None, "tool": None}}
st["result"] = result
st["pid"] = None
STATE.write_text(json.dumps(st, indent=2))

# appende allo storico (entry "compatta")
try:
    now = int(time.time())
    ping_ms = None
    jitter_ms = None
    if isinstance(result.get("ping"), dict):
        ping_ms = result.get("ping",{{}}).get("latency")
        jitter_ms = result.get("ping",{{}}).get("jitter")
    elif isinstance(result.get("ping"), (int,float)):
        ping_ms = result.get("ping")
    elif "ping_ms" in result:
        ping_ms = result.get("ping_ms")

    down_bps = None
    if isinstance(result.get("download"), dict) and "bandwidth" in result.get("download"):
        down_bps = (result["download"]["bandwidth"] or 0) * 8
    elif isinstance(result.get("download"), (int,float)):
        down_bps = result.get("download")

    up_bps = None
    if isinstance(result.get("upload"), dict) and "bandwidth" in result.get("upload"):
        up_bps = (result["upload"]["bandwidth"] or 0) * 8
    elif isinstance(result.get("upload"), (int,float)):
        up_bps = result.get("upload")

    server = result.get("server") or {{}}
    iface  = result.get("interface") or {{}}
    rid    = (result.get("result") or {{}}).get("id")

    entry = {{
        "ts": now,
        "tool": st.get("tool"),
        "ok": bool(result),
        "ping_ms": ping_ms,
        "jitter_ms": jitter_ms,
        "loss_pct": result.get("packetLoss"),
        "down_bps": down_bps,
        "up_bps": up_bps,
        "server_name": server.get("name"),
        "server_loc": server.get("location"),
        "server_id": server.get("id"),
        "isp": result.get("isp"),
        "internalIp": iface.get("internalIp"),
        "externalIp": iface.get("externalIp"),
        "uuid": rid
    }}
    with open(HIST, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\\n")
except Exception:
    pass
"""
    wrapper.write_text(wrapper_code, encoding="utf-8")

    proc = subprocess.Popen(
        ["/usr/bin/env", "python3", str(wrapper)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    st["pid"] = proc.pid
    _save_state(st)
    return {"ok": True, "running": True, "pid": proc.pid, "tool": tool}

@router.post("/cancel", response_class=JSONResponse)
def cancel():
    st = _load_state()
    pid = st.get("pid")
    if _alive(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try: os.kill(pid, signal.SIGTERM)
            except Exception: pass
    st["pid"] = None
    _save_state(st)
    return {"ok": True}

# ----------------- API storico -----------------
@router.get("/history", response_class=JSONResponse)
def history(limit: int = 100):
    items = _read_history(limit=limit)
    # metto totale reale (righe file)
    try:
        total = sum(1 for _ in open(HIST_FILE, "r", encoding="utf-8"))
    except Exception:
        total = len(items)
    return {"items": items, "total": total}

@router.post("/history/clear", response_class=JSONResponse)
def history_clear():
    _ensure_dir()
    try:
        HIST_FILE.write_text("", encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@router.post("/history/delete", response_class=JSONResponse)
def history_delete(ts: dict = Body(default={"ts": []})):
    """ts = {"ts":[timestamp_int,...]}"""
    _ensure_dir()
    ids = set(int(x) for x in (ts or {}).get("ts", []) if isinstance(x, (int, float, str)))
    if not ids:
        return {"ok": True, "deleted": 0}
    try:
        lines = []
        with open(HIST_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                try:
                    obj = json.loads(ln)
                    if int(obj.get("ts", -1)) in ids:
                        continue
                except Exception:
                    pass
                lines.append(ln)
        tmp = HIST_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines)
        os.replace(tmp, HIST_FILE)
        return {"ok": True, "deleted": len(ids)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@router.get("/history/export.jsonl")
def history_export_jsonl():
    _ensure_dir()
    if not HIST_FILE.exists():
        HIST_FILE.write_text("", encoding="utf-8")
    return FileResponse(str(HIST_FILE), media_type="application/json", filename="speedtest-history.jsonl")

@router.get("/history/export.csv")
def history_export_csv():
    items = _read_history(limit=1000000)
    # CSV semplice
    head = ["timestamp","iso","tool","ok","ping_ms","jitter_ms","loss_pct","down_bps","up_bps","server_name","server_loc","server_id","isp","internalIp","externalIp","uuid"]
    rows = [",".join(head)]
    from datetime import datetime
    for it in reversed(items):  # CSV in ordine cronologico
        ts = int(it.get("ts",0))
        iso = datetime.utcfromtimestamp(ts).isoformat()+"Z" if ts else ""
        vals = [
            str(ts), iso, it.get("tool",""), str(bool(it.get("ok"))).lower(),
            str(it.get("ping_ms") if it.get("ping_ms") is not None else ""),
            str(it.get("jitter_ms") if it.get("jitter_ms") is not None else ""),
            str(it.get("loss_pct") if it.get("loss_pct") is not None else ""),
            str(it.get("down_bps") if it.get("down_bps") is not None else ""),
            str(it.get("up_bps") if it.get("up_bps") is not None else ""),
            (it.get("server_name") or ""), (it.get("server_loc") or ""), str(it.get("server_id") or ""),
            (it.get("isp") or ""), (it.get("internalIp") or ""), (it.get("externalIp") or ""), (it.get("uuid") or "")
        ]
        # escape minimale per virgole/virgolette
        vals = [('"'+v.replace('"','""')+'"') if ("," in v or '"' in v or " " in v) else v for v in vals]
        rows.append(",".join(vals))
    csv = "\n".join(rows) + "\n"
    return Response(content=csv, media_type="text/csv", headers={"Content-Disposition":"attachment; filename=speedtest-history.csv"})
