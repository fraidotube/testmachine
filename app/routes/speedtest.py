from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
from html import escape
import subprocess, os, json, time, shlex

router = APIRouter(prefix="/speedtest", tags=["speedtest"])

SPEED_DIR = Path("/var/lib/netprobe/speedtest")
STATE_FILE = SPEED_DIR / "state.json"   # {"pid":int|null, "started":ts, "result":{...}|null, "tool":"ookla|pycli"}
LOG_FILE   = SPEED_DIR / "last.log"

def _ensure_dir():
    SPEED_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps({"pid": None, "started": None, "result": None, "tool": None}, indent=2), encoding="utf-8")

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
        # -f json = output JSON
        # -p no   = no progress bar su stdout
        # --accept-license/--accept-gdpr = niente prompt interattivi
        return (
            ["/usr/bin/env", "speedtest",
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


import shutil, signal

@router.get("/", response_class=HTMLResponse)
def page():
    html = _page_head("Speedtest") + """
<style>
  /* palette verde */
  :root{
    --st-a:#10b981; /* teal/green */
    --st-b:#059669;
  }
  .card--st{
    background: linear-gradient(160deg, rgba(16,185,129,.22), rgba(5,150,105,.10));
    border:1px solid rgba(16,185,129,.30);
  }
  .hero {display:flex;gap:14px;align-items:center;justify-content:space-between}
  .pill{padding:4px 10px;border-radius:999px;background:rgba(255,255,255,.08);font-size:.9rem;border:1px solid rgba(255,255,255,.1)}
  .kv{display:grid;grid-template-columns:120px 1fr;gap:6px;margin-top:10px}
  .big{font-size:1.8rem;font-weight:700}

  /* progress “finto” a fasi (indeterminato, ma con step: ping->down->up) */
  .meter{height:10px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;position:relative}
  .meter .bar{
    position:absolute;left:0;top:0;height:100%;width:28%;
    background:linear-gradient(90deg, var(--st-a), var(--st-b));
    filter:saturate(120%);
    animation:pulse 1.1s ease-in-out infinite;
  }
  @keyframes pulse { 
    0%{transform:translateX(-40%)} 
    50%{transform:translateX(120%)} 
    100%{transform:translateX(-40%)} 
  }

  /* badge fasi */
  .phase{display:inline-flex;gap:6px;align-items:center;margin-top:6px}
  .dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.25)}
  .on{background:var(--st-a)}
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
  const js = await r.json();
  const running = !!js.running;
  document.getElementById('tool-note').textContent = js.tool ? ("Tool: "+js.tool) : "";
  document.getElementById('state-pill').textContent = running ? "In esecuzione" : "Pronto";
  document.getElementById('state-pill').style.background = running ? "rgba(16,185,129,.2)" : "rgba(255,255,255,.08)";
  document.getElementById('pre-box').style.display = running ? "none":""; 
  document.getElementById('run-box').style.display = running ? "":"none";

  // fasi "simulate": 1s ping, 4s download, 4s upload (se non abbiamo progress reali)
  if(running){
    const t = Date.now() % 9000;
    if(t<1000) setPhase(1);
    else if(t<5000) setPhase(2);
    else setPhase(3);
  }

  if(js.result){
    setPhase(3);
    const res = js.result;
    // server
    if(res.server){
      const s = res.server;
      document.getElementById('sv').textContent = [s.name, s.location].filter(Boolean).join(" · ");
    }
    // ISP e IP
    document.getElementById('isp').textContent = res.isp || "-";
    const iface = res.interface || {};
    const iptxt = [iface.internalIp, iface.externalIp].filter(Boolean).join(" → ");
    document.getElementById('ips').textContent = iptxt || "-";

    // ping/jitter/loss
    const pingMs = (res.ping?.latency ?? res.ping ?? res.ping_ms ?? null);
    document.getElementById('pg').textContent = pingMs!=null ? pingMs.toFixed(2)+" ms" : "-";
    document.getElementById('jit').textContent = res.ping?.jitter!=null ? res.ping.jitter.toFixed(2)+" ms" : "-";
    document.getElementById('pl').textContent  = (res.packetLoss!=null) ? (res.packetLoss+" %") : "-";

    // velocità (Ookla JSON: bandwidth in byte/s)
    let d = res.download?.bandwidth!=null ? res.download.bandwidth*8 : (res.download ?? null);
    let u = res.upload?.bandwidth!=null   ? res.upload.bandwidth*8   : (res.upload   ?? null);
    document.getElementById('dl').textContent = humanBitsps(d);
    document.getElementById('ul').textContent = humanBitsps(u);

    document.getElementById('res-box').style.display = "";
  } else {
    document.getElementById('res-box').style.display = "none";
  }
}

async function startTest(){ await fetch('/speedtest/start',{method:'POST'}); setPhase(1); if(!timer){ timer=setInterval(status, 1000); } status(); }
async function cancelTest(){ await fetch('/speedtest/cancel',{method:'POST'}); setPhase(0); status(); }

timer=setInterval(status, 1000);
status();
</script>
</body></html>
"""


    return HTMLResponse(html)


@router.get("/status", response_class=JSONResponse)
def st_status():
    st = _load_state()
    running = _alive(st.get("pid"))
    if not running and st.get("pid"):
        # se processo terminato, azzera il pid
        st["pid"] = None
        _save_state(st)
    return {"running": running, "result": st.get("result"), "tool": st.get("tool")}

def _start_subprocess_and_detach(cmd:list[str]):
    with open(LOG_FILE, "w") as log:
        # avvia processo che al termine scrive il risultato nel file stato
        return subprocess.Popen(cmd, stdout=log, stderr=log, preexec_fn=os.setsid)

@router.post("/start", response_class=JSONResponse)
def start():
    _ensure_dir()
    st = _load_state()
    if _alive(st.get("pid")):
        return {"ok": True, "running": True}

    # reset stato
    st["result"] = None
    st["started"] = int(time.time())
    _save_state(st)

    cmd, tool = _pick_cmd()
    st["tool"] = tool
    _save_state(st)

    # scrive un wrapper python che esegue il test e aggiorna state.json
    wrapper = SPEED_DIR / "run_speedtest.py"
    wrapper_code = f"""
import json, subprocess, pathlib, sys, os, time
STATE = pathlib.Path({json.dumps(str(STATE_FILE))})
LOG   = pathlib.Path({json.dumps(str(LOG_FILE))})
CMD   = {json.dumps(cmd)}

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
"""
    wrapper.write_text(wrapper_code, encoding="utf-8")

    # lancia wrapper in background (sessione dedicata)
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
