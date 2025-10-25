from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from html import escape
from pathlib import Path
import os, json, time, subprocess, re, signal
from stat import S_IMODE


router = APIRouter(prefix="/pcap", tags=["pcap"])
from util.audit import log_event

CAP_DIR   = Path("/var/lib/netprobe/pcap")
META_FILE = CAP_DIR / "captures.json"

CONFIG_PATH = Path("/etc/netprobe/pcap.json")
DEFAULT_CFG = {
    "duration_max": 3600,   # s (limite superiore UI e backend)
    "quota_gb": 5,          # spazio massimo in /var/lib/netprobe/pcap
    "policy": "rotate",     # "rotate" = elimina più vecchi, "block" = blocca nuovi
    "poll_ms": 1000,        # refresh stato UI (ms)
    "allow_bpf": True       # consenti filtri BPF custom
}

# ---- BPF sanitize ----
_BPF_OK = r"a-zA-Z0-9_ \.\:\-\/\(\)<>="
_BPF_RE = re.compile(rf"^[{_BPF_OK}]+$")

def _sanitize_bpf(bpf: str, allow_bpf: bool, max_len: int = 256) -> str:
    """
    Consente solo un sottoinsieme sicuro della sintassi tcpdump/tshark.
    Taglia lunghezze e rimuove caratteri pericolosi. Se non valido, torna "".
    """
    if not allow_bpf:
        return ""
    s = (bpf or "").strip()
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]
    # vieta backtick, quote, semicolons, pipe, ampersand ecc.
    if any(c in s for c in ['`', '"', "'", ';', '|', '&', '#', '$', '\\']):
        return ""
    if not _BPF_RE.match(s):
        return ""
    return s


def _ensure_cfg():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")

def _load_cfg():
    _ensure_cfg()
    try:
        data = json.loads(CONFIG_PATH.read_text("utf-8"))
    except Exception:
        data = {}
    # merge con default per chiavi mancanti
    cfg = {**DEFAULT_CFG, **(data or {})}
    return cfg

def _save_cfg(cfg: dict):
    _ensure_cfg()
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, CONFIG_PATH)

def _capdir_size() -> int:
    total = 0
    for p in CAP_DIR.glob("*.pcapng"):
        try:
            total += p.stat().st_size
        except Exception:
            pass
    return total

def _apply_quota_rotation(quota_bytes: int) -> int:
    """
    Se la dir supera quota, elimina i file più vecchi finché rientra.
    Rimuove anche i metadati associati.
    Ritorna quanti file sono stati cancellati.
    """
    total = _capdir_size()
    if total <= quota_bytes:
        return 0
    # ordina per mtime crescente
    files = sorted(CAP_DIR.glob("*.pcapng"), key=lambda p: p.stat().st_mtime)
    removed = 0
    meta = _load_meta()
    for p in files:
        try:
            sz = p.stat().st_size
            p.unlink()
            removed += 1
            total -= sz
            # pulisci metadati
            meta["captures"] = [c for c in meta.get("captures", []) if c.get("file") != p.name]
            if total <= quota_bytes:
                break
        except Exception:
            pass
    _save_meta(meta)
    return removed

# ---------- utils ----------
def _run(cmd:list[str], timeout:int|None=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def _ensure_dirs():
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    if not META_FILE.exists():
        META_FILE.write_text(json.dumps({"captures":[]}, indent=2), encoding="utf-8")

def _load_meta():
    _ensure_dirs()
    try:
        return json.loads(META_FILE.read_text("utf-8"))
    except Exception:
        return {"captures":[]}

def _save_meta(meta:dict):
    tmp = META_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, META_FILE)

def _alive(pid:int)->bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def _list_ifaces():
    rc, out, _ = _run(["/usr/bin/dumpcap","-D"])
    if rc == 0 and out.strip():
        items = []
        for line in out.splitlines():
            m = re.match(r"\s*\d+\.\s+([^\s]+)", line)
            if m: items.append(m.group(1))
        if items: return items
    rc, out, _ = _run(["/usr/bin/nmcli","-t","-f","DEVICE,TYPE,STATE","dev","status"])
    devs=[]
    if rc==0 and out.strip():
        for line in out.strip().splitlines():
            parts=line.split(":")
            if len(parts)>=3:
                dev, typ, state = parts[:3]
                if dev and dev!="lo" and typ in ("ethernet","wifi"):
                    devs.append(dev)
    else:
        rc, out, _ = _run(["/usr/sbin/ip","-o","link","show"])
        if rc==0:
            for line in out.splitlines():
                try:
                    name=line.split(":")[1].strip().split("@")[0]
                    if name and name!="lo":
                        devs.append(name)
                except Exception:
                    pass
    seen=[]
    for d in devs:
        if d not in seen: seen.append(d)
    return seen

def _list_files():
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    files=[]
    for p in sorted(CAP_DIR.glob("*.pcapng")):
        st=p.stat()
        files.append({"name":p.name,"size":st.st_size,"mtime":int(st.st_mtime)})
    return files

# ---------- parsing analisi ----------
def _capinfos_overview(path:Path):
    rc, out, _ = _run(["/usr/bin/capinfos","-Tm","-a","-c",str(path)], timeout=20)
    if rc!=0:
        rc2, out2, _ = _run(["/usr/bin/tshark","-r",str(path),"-T","fields","-e","frame.len"], timeout=30)
        if rc2==0:
            lens = [int(x) for x in out2.split() if x.isdigit()]
            return {"packets":len(lens),"bytes":sum(lens),"duration_s":None}
        return {}
    pkts = re.search(r"Number of packets:\s+([\d,]+)", out)
    bytes_ = re.search(r"File size:\s+([\d,]+)\s+bytes", out)
    dur = re.search(r"Capture duration:\s+([0-9.]+)\s+seconds", out)
    return {
        "packets": int(pkts.group(1).replace(",","")) if pkts else None,
        "bytes": int(bytes_.group(1).replace(",","")) if bytes_ else path.stat().st_size,
        "duration_s": float(dur.group(1)) if dur else None
    }

def _tshark_table(cmd:list[str], header_regex:str):
    rc, out, err = _run(cmd, timeout=40)
    if rc != 0:
        return {"raw": out+err}
    lines = [l for l in out.splitlines() if l.strip()]
    hdr_idx=None
    for i,l in enumerate(lines):
        if re.search(header_regex, l):
            hdr_idx=i; break
    if hdr_idx is None:
        return {"rows":[]}
    rows=[]
    for l in lines[hdr_idx+1:]:
        if re.match(r"[-=]+\s*$", l): continue
        if l.strip()=="": break
        rows.append(re.sub(r"\s{2,}","\t", l.strip()).split("\t"))
    return {"rows":rows}

def _top_list(cmd:list[str], field:str, n:int=10):
    rc, out, _ = _run(cmd, timeout=30)
    if rc != 0: return []
    counts={}
    for line in out.splitlines():
        s=line.strip()
        if not s: continue
        counts[s]=counts.get(s,0)+1
    ranked=sorted(counts.items(), key=lambda x:x[1], reverse=True)[:n]
    return [{"value":k,"count":v} for k,v in ranked]

def _top_ports(path:Path, n:int=10):
    rc, out, _ = _run(
        ["/usr/bin/tshark","-r",str(path),
         "-T","fields",
         "-e","tcp.srcport","-e","tcp.dstport",
         "-e","udp.srcport","-e","udp.dstport"], timeout=30)
    if rc!=0: return []
    counts={}
    for line in out.splitlines():
        for v in line.strip().split("\t"):
            if v and v.isdigit():
                counts[v]=counts.get(v,0)+1
    top=sorted(counts.items(), key=lambda x:x[1], reverse=True)[:n]
    return [{"port":k,"count":v} for k,v in top]

# ---------- HTML helpers ----------
def _page_head(title:str)->str:
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

# ---------- Pagine ----------
@router.get("/", response_class=HTMLResponse)
def page():
    cfg = _load_cfg()
    ifaces=_list_ifaces()
    opt="".join(f"<option value='{escape(i)}'>{escape(i)}</option>" for i in ifaces)
    files=_list_files()

    rows=[]
    for f in reversed(files):
        rows.append(
f"""<div class='pcap-row'>
  <div class='pcap-meta'>
    <b class='pcap-name'>{escape(f['name'])}</b>
    <div class='pcap-when'>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f['mtime']))}</div>
  </div>
  <div class='pcap-size'>{f['size']:,} B</div>
  <div class='pcap-actions'>
    <a class='btn secondary' href='/pcap/download?file={escape(f["name"])}'>Scarica</a>
    <a class='btn' href='/pcap/analyze?file={escape(f["name"])}'>Analizza</a>
    <form class='inline-form' method='post' action='/pcap/delete' onsubmit="return confirm('Eliminare {escape(f['name'])}?');">
      <input type='hidden' name='file' value='{escape(f["name"])}'/>
      <button class='btn danger' type='submit'>Elimina</button>
    </form>
  </div>
</div>"""
        )
    list_html="".join(rows) or "<div class='muted'>Nessun file.</div>"

    html = _page_head("Packet Capture") + """
<style>
  .pcap-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
  @media (max-width:1000px){.pcap-grid{grid-template-columns:1fr}}

  .pcap-list{width:100%;display:flex;flex-direction:column;gap:10px}
  .pcap-row{
    display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center;
    padding:12px;border-radius:14px;
    background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.07)
  }
  .pcap-meta{min-width:0}
  .pcap-name{color:#e9eefc}
  .pcap-when{font-size:.92rem;opacity:.85}
  .pcap-size{white-space:nowrap;justify-self:end;opacity:.95}
  .pcap-actions{display:flex;gap:8px;flex-wrap:wrap;justify-self:end}
  .inline-form{display:inline}
  @media (max-width:1100px){
    .pcap-row{grid-template-columns:1fr auto}
    .pcap-actions{grid-column:1/-1;justify-self:start}
  }
  @media (max-width:700px){
    .pcap-row{grid-template-columns:1fr}
    .pcap-size,.pcap-actions{justify-self:start}
  }
  .tiny{font-size:.9rem;opacity:.85}
  code{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
  .bullets li{margin:4px 0}
</style>

<div class='pcap-grid'>

  <div class='card'>
    <h2>Nuova cattura <a class="btn secondary" href="/pcap/settings" style="float:right">Impostazioni</a></h2>
    <form method='post' action='/pcap/start' id='startForm'>
      <label>Interfaccia</label>
      <select name='iface'>__OPT__</select>

      <div class='row'>
        <div>
          <label>Durata (s)</label>
          <input name='duration' value='10' type='number' min='1' max='3600' required/>
        </div>
        <div>
          <label>Snaplen (byte/pacchetto)</label>
          <input name='snaplen' value='262144' type='number' min='64'/>
          <div class='muted tiny'>Byte massimi salvati per pacchetto. 262144 ≈ pacchetto completo.</div>
        </div>
      </div>

      <label>Filtro BPF (opz.)</label>
      <input name='bpf' placeholder='es. host 8.8.8.8 or port 53'/>
      <button class='btn' type='submit'>Avvia</button>
    </form>

    <div id='activeBox' class='notice' style='margin-top:12px; display:none'>
      ⏱️ Cattura in corso… resta <b><span id='remain'>-</span>s</b> — file: <code id='actfile'>-</code>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
        <button class='btn danger' type='button' onclick='stopNow()'>Stop</button>
        <span class='muted' id='actsize'>(0 B)</span>
      </div>
      <form id="stopForm" method="post" action="/pcap/stop" class="inline-form" style="display:none">
        <input type="hidden" name="file" id="stopFile" value="">
      </form>
    </div>
  </div>

  <div class='card'>
    <h2>Catture recenti</h2>
    <div class='pcap-list'>__LIST__</div>
  </div>

  <div class='card' style='grid-column:1/-1'>
    <h2>Filtri BPF – guida rapida</h2>
    <ul class='bullets'>
      <li><b>Host</b>: <code>host 8.8.8.8</code> — <code>src host 192.168.1.10</code> — <code>dst host 1.1.1.1</code></li>
      <li><b>Rete</b>: <code>net 192.168.1.0/24</code></li>
      <li><b>Porta</b>: <code>port 53</code>, <code>tcp port 443</code>, range <code>portrange 1000-2000</code></li>
      <li><b>Protocollo</b>: <code>icmp</code>, <code>arp</code>, <code>tcp</code>, <code>udp</code>, <code>vlan</code></li>
      <li><b>Combinazioni</b>: <code>and</code>, <code>or</code>, <code>not</code> — es. <code>tcp and port 80 and host 1.2.3.4</code></li>
      <li><b>HTTP/DNS/TLS</b>: <code>port 80 or port 443</code>, <code>port 53</code></li>
      <li><b>Escludere se stesso</b>: <code>and not host 192.168.1.5</code></li>
    </ul>
    <p class='muted tiny'>Sintassi tcpdump/tshark. Lascia vuoto per catturare tutto.</p>
  </div>

</div>
</div>

<script>
async function stopNow(){
  const file = document.getElementById('stopFile').value;
  if(!file) return;
  try{
    await fetch('/pcap/stop', {
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body: 'file=' + encodeURIComponent(file)
    });
  }catch(e){}
  setTimeout(()=>location.reload(), 500);
}

function fmtBytes(b){
  if(!b) return "0 B";
  const u=["B","KB","MB","GB","TB"];
  let i=0,v=Number(b);
  while(v>=1024 && i<u.length-1){v/=1024;i++;}
  return v.toFixed(1)+" "+u[i];
}

async function pollStatus(){
  try{
    const r = await fetch('/pcap/status');
    if(!r.ok) throw new Error('status http '+r.status);
    const js = await r.json();
    const box = document.getElementById('activeBox');
    if(js.active && js.active.length > 0){
      const a = js.active[0];
      box.style.display = '';
      document.getElementById('remain').textContent = Math.max(0, Math.floor(a.remaining_s));
      document.getElementById('actfile').textContent = a.file;
      document.getElementById('actsize').textContent = fmtBytes(a.size || 0);
      document.getElementById('stopFile').value = a.file;
      if(a.remaining_s <= 0){
        box.style.display = 'none';
        setTimeout(()=>location.reload(), 600);
      }
    } else {
      box.style.display = 'none';
    }
  } catch(e) {}
}
setInterval(pollStatus, __POLL__);
pollStatus();
</script>
<script src="/static/bg.js"></script>
</body></html>
"""
    html = html.replace("__OPT__", opt).replace("__LIST__", list_html)
    html = html.replace("__POLL__", str(int(cfg.get("poll_ms", 1000))))
    return HTMLResponse(html)

@router.get("/analyze", response_class=HTMLResponse)
def analyze(file: str = Query(...)):
    file = os.path.basename(file)
    path = CAP_DIR / file
    if not path.exists():
        return HTMLResponse("<h3 style='margin:2rem'>File inesistente</h3>", status_code=404)

    html = _page_head("Analisi cattura") + """
<style>
  .grid2{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}
  .kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
  .kpi .card{padding:12px}
  .card{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.22);box-shadow:0 6px 20px rgba(0,0,0,.20)}
  .table{overflow-x:auto;-webkit-overflow-scrolling:touch}
  .table table{width:100%;border-collapse:collapse;table-layout:auto}
  .table th,.table td{white-space:nowrap;padding:8px 10px}
  .table thead th{position:sticky;top:0;background:rgba(255,255,255,.08);backdrop-filter:saturate(120%)}
</style>

<div class='grid'>
  <div class='card'>
    <h2>Analisi: __FILE__</h2>
    <p class='muted'>Panoramica, gerarchia protocolli, endpoint, conversazioni, DNS/HTTP/SNI, top porte.</p>
    <div id='loading' class='muted'>Analisi in corso…</div>
    <div id='content' style='display:none'></div>
  </div>
</div>

<script>
function humanBytes(b){
  if(b==null) return "-";
  const u=["B","KB","MB","GB","TB"]; let i=0,v=Number(b);
  while(v>=1024 && i<u.length-1){v/=1024;i++;}
  return v.toFixed(1)+" "+u[i];
}
function humanInt(x){ if(x==null) return "-"; return Number(x).toLocaleString(); }

function tbl(title, headers, rows){
  let h = "<div class='card'><h3>"+title+"</h3><div class='table'><table><thead><tr>";
  for(const th of headers) h += "<th>"+th+"</th>";
  h += "</tr></thead><tbody>";
  for(const row of rows) h += "<tr>"+row.map(x=>"<td>"+x+"</td>").join("")+"</tr>";
  h += "</tbody></table></div></div>";
  return h;
}

async function loadSummary(){
  const r = await fetch('/pcap/summary?file=' + encodeURIComponent('__FILE__'));
  const js = await r.json();
  const cont = document.getElementById('content');
  const loading = document.getElementById('loading');
  loading.style.display='none'; cont.style.display='';

  let html = "";
  html += "<div class='kpi'>"
       +  "<div class='card'><b>Pacchetti</b><div class='muted'>"+humanInt(js.overview?.packets)+"</div></div>"
       +  "<div class='card'><b>Dimensione</b><div class='muted'>"+humanBytes(js.overview?.bytes)+"</div></div>"
       +  "<div class='card'><b>Durata</b><div class='muted'>"+(js.overview?.duration_s ?? '-')+" s</div></div>"
       +  "</div>";

  html += "<div class='grid2'>";
  if(js.phs?.rows?.length){ html += tbl("Protocol hierarchy", ["Layer/Proto","Percent","Pkts"], js.phs.rows); }
  if(js.endpoints?.rows?.length){ html += tbl("Top endpoints", ["Endpoint","Pkts","Bytes","TxPkts","TxBytes","RxPkts","RxBytes"], js.endpoints.rows.slice(0,10)); }
  if(js.conversations?.rows?.length){ html += tbl("Top conversations", ["Peers","Pkts","Bytes","Rel Start","Duration"], js.conversations.rows.slice(0,10)); }
  if(js.ports?.length){ html += tbl("Top porte (TCP/UDP)", ["Porta","Count"], js.ports.map(x=>[x.port, String(x.count)])); }
  if(js.dns?.length){ html += tbl("Top DNS queries", ["Name","Count"], js.dns.map(x=>[x.value, String(x.count)])); }
  if(js.http?.length){ html += tbl("Top HTTP Host", ["Host","Count"], js.http.map(x=>[x.value, String(x.count)])); }
  if(js.sni?.length){ html += tbl("Top TLS SNI", ["Server Name","Count"], js.sni.map(x=>[x.value, String(x.count)])); }
  html += "</div>";
  cont.innerHTML = html;
}
loadSummary();
</script>
</body></html>
"""
    html = html.replace("__FILE__", escape(file))
    return HTMLResponse(html)

# ---------- API ----------
@router.get("/ifaces", response_class=JSONResponse)
def ifaces():
    return {"ifaces": _list_ifaces()}

def _has_active_capture(meta: dict | None = None) -> bool:
    meta = meta or _load_meta()
    now = int(time.time())
    for c in meta.get("captures", []):
        pid = c.get("pid")
        dur = int(c.get("duration_s", 0) or 0)
        start = int(c.get("start_ts", 0) or 0)
        if pid and _alive(pid) and (now - start) < dur:
            return True
    return False

@router.post("/start")
def start_capture(request: Request, iface: str = Form(...), duration: int = Form(...), bpf: str = Form(""), snaplen: int = Form(262144)):
    _ensure_dirs()

    meta = _load_meta()
    if _has_active_capture(meta):
        return HTMLResponse("<script>alert('C’è già una cattura in corso. Ferma quella prima di avviarne un’altra.');window.location.href='/pcap';</script>")

    cfg = _load_cfg()
    duration_max = int(cfg.get("duration_max", DEFAULT_CFG["duration_max"]))
    quota_bytes  = int(float(cfg.get("quota_gb", DEFAULT_CFG["quota_gb"])) * (1024**3))
    policy       = str(cfg.get("policy", DEFAULT_CFG["policy"]))
    allow_bpf    = bool(cfg.get("allow_bpf", True))

    if iface not in _list_ifaces():
        return HTMLResponse("<script>history.back();alert('Interfaccia non valida');</script>")

    duration = max(1, min(int(duration), duration_max))
    snaplen  = max(64, min(int(snaplen), 262144))
    bpf = _sanitize_bpf(bpf, allow_bpf)
    if not allow_bpf:
        bpf = ""

    # quota: rotate/block
    current = _capdir_size()
    if current >= quota_bytes:
        if policy == "rotate":
            _apply_quota_rotation(quota_bytes)
        else:
            return HTMLResponse("<script>alert('Quota PCAP piena: cattura bloccata (policy=block).');window.location.href='/pcap';</script>")

    ts = int(time.time())
    fname = f"{ts}_{iface}.pcapng"
    path = CAP_DIR / fname

    cmd = ["/usr/bin/dumpcap","-i",iface,"-P","-s",str(snaplen),"-w",str(path),"-a",f"duration:{duration}"]
    if bpf.strip():
        cmd += ["-f", bpf.strip()]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

    meta["captures"].append({
        "file": fname, "iface": iface, "start_ts": ts, "duration_s": duration,
        "pid": proc.pid, "filter": bpf.strip(),
    })
    _save_meta(meta)
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("pcap/start", ok=True, actor=actor or "unknown", ip=ip,
              detail=f"iface={iface},duration={duration}", req_path=str(request.url),
              extra={"snaplen": snaplen, "bpf": bpf.strip() or None, "file": fname})
    return RedirectResponse(url="/pcap", status_code=303)


@router.post("/stop")
def stop_capture(request: Request, file: str = Form(None)):
    meta = _load_meta()
    stopped = 0
    for c in meta.get("captures", []):
        if file and c.get("file") != file:
            continue
        pid = c.get("pid")
        if pid and _alive(pid):
            try:
                # abbiamo usato setsid: il pgid è il pid
                os.killpg(pid, signal.SIGTERM)
            except Exception:
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
            stopped += 1
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("pcap/stop", ok=True, actor=actor or "unknown", ip=ip,
              detail=f"target={file or '*'}", req_path=str(request.url), extra={"stopped": stopped})
    return JSONResponse({"stopped": stopped})
    

@router.get("/status", response_class=JSONResponse)
def status():
    now = int(time.time())
    meta = _load_meta()
    active = []
    changed = False

    for c in meta.get("captures", []):
        pid = c.get("pid")
        dur = int(c.get("duration_s", 0) or 0)
        start = int(c.get("start_ts", 0) or 0)
        remaining = max(0, dur - (now - start))
        p = CAP_DIR / c["file"]
        size = p.stat().st_size if p.exists() else 0

        if pid and _alive(pid) and remaining > 0:
            active.append({"file": c["file"], "iface": c["iface"], "remaining_s": remaining, "size": size})
        else:
            # non più attivo: pulizia pid
            if c.get("pid"):
                c["pid"] = None
                changed = True

    if changed:
        _save_meta(meta)

    return {"active": active}

@router.get("/list", response_class=JSONResponse)
def list_files():
    return {"files": _list_files()}

@router.get("/download")
def download(file: str = Query(...)):
    file = os.path.basename(file)
    path = CAP_DIR / file
    if not path.exists():
        return HTMLResponse("File inesistente", status_code=404)
    return FileResponse(path, filename=file, media_type="application/octet-stream")

@router.post("/delete")
def delete_file(request: Request, file: str = Form(...)):
    file = os.path.basename(file)
    path = CAP_DIR / file
    try:
        path.unlink()
    except Exception:
        pass
    meta = _load_meta()
    meta["captures"] = [c for c in meta.get("captures", []) if c.get("file") != file]
    _save_meta(meta)
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("pcap/delete", ok=True, actor=actor or "unknown", ip=ip,
              detail=f"file={file}", req_path=str(request.url))
    return RedirectResponse(url="/pcap", status_code=303)

@router.get("/summary", response_class=JSONResponse)
def summary(file: str = Query(...)):
    file = os.path.basename(file)
    path = CAP_DIR / file
    if not path.exists():
        return JSONResponse({"error":"missing"}, status_code=404)

    data={}
    data["overview"] = _capinfos_overview(path)
    data["phs"] = _tshark_table(
        ["/usr/bin/tshark","-r",str(path),"-q","-z","io,phs"], header_regex=r"Protocol")
    data["endpoints"] = _tshark_table(
        ["/usr/bin/tshark","-r",str(path),"-q","-z","endpoints,ip","-z","endpoints,ipv6","-z","endpoints,tcp","-z","endpoints,udp"],
        header_regex=r"Endpoint")
    data["conversations"] = _tshark_table(
        ["/usr/bin/tshark","-r",str(path),"-q","-z","conv,ip","-z","conv,ipv6","-z","conv,tcp","-z","conv,udp"],
        header_regex=r"<->|Conversations")
    data["dns"]  = _top_list(
        ["/usr/bin/tshark","-r",str(path),"-Y","dns.flags.response==0 && dns.qry.name","-T","fields","-e","dns.qry.name"],
        "dns.qry.name", 10)
    data["http"] = _top_list(
        ["/usr/bin/tshark","-r",str(path),"-Y","http.host","-T","fields","-e","http.host"],
        "http.host", 10)
    data["sni"]  = _top_list(
        ["/usr/bin/tshark","-r",str(path),"-Y","tls.handshake.extensions_server_name","-T","fields","-e","tls.handshake.extensions_server_name"],
        "tls.handshake.extensions_server_name", 10)
    data["ports"] = _top_ports(path, 10)
    return JSONResponse(data)   # <-- QUI

@router.get("/settings", response_class=HTMLResponse)
def pcap_settings():
    cfg = _load_cfg()
    html = _page_head("Impostazioni Packet Capture") + """
<style>
  .w400{max-width:400px}
</style>
<div class='grid'>
  <div class='card w400'>
    <h2>Impostazioni Sniffer</h2>
    <form method='post' action='/pcap/settings'>
      <label>Durata massima (s)</label>
      <input type='number' name='duration_max' min='1' max='86400' value='__DUR__' required/>

      <label>Quota storage (GB)</label>
      <input type='number' step='0.1' min='1' name='quota_gb' value='__QUOTA__' required/>

      <label>Policy quota</label>
      <select name='policy'>
        <option value='rotate' __SEL_ROT__>Ruota (elimina più vecchi)</option>
        <option value='block'  __SEL_BLK__>Blocca nuove catture</option>
      </select>

      <label>Refresh UI (ms)</label>
      <input type='number' name='poll_ms' min='250' max='10000' value='__POLL__' required/>

      <label class='row' style='align-items:center;gap:10px'>
        <input type='checkbox' name='allow_bpf' __BPF__/> Consenti filtri BPF personalizzati
      </label>

      <button class='btn' type='submit'>Salva</button>
      <a class='btn secondary' href='/pcap/'>Torna a PCAP</a>
    </form>
  </div>
</div>
</div></body></html>
"""
    html = html.replace("__DUR__",  str(int(cfg.get("duration_max", 3600))))
    html = html.replace("__QUOTA__", str(float(cfg.get("quota_gb", 5))))
    html = html.replace("__POLL__", str(int(cfg.get("poll_ms", 1000))))
    html = html.replace("__SEL_ROT__", "selected" if str(cfg.get("policy","rotate"))=="rotate" else "")
    html = html.replace("__SEL_BLK__", "selected" if str(cfg.get("policy","rotate"))=="block" else "")
    html = html.replace("__BPF__", "checked" if bool(cfg.get("allow_bpf", True)) else "")
    return HTMLResponse(html)

@router.post("/settings")
def pcap_settings_save(request: Request, duration_max: int = Form(...),
                       quota_gb: float = Form(...),
                       policy: str = Form(...),
                       poll_ms: int = Form(...),
                       allow_bpf: str = Form(None)):
    cfg = _load_cfg()
    cfg["duration_max"] = max(1, min(int(duration_max), 86400))
    try:
        cfg["quota_gb"] = max(1.0, float(quota_gb))
    except Exception:
        cfg["quota_gb"] = DEFAULT_CFG["quota_gb"]
    cfg["policy"] = "rotate" if policy == "rotate" else "block"
    cfg["poll_ms"] = max(250, min(int(poll_ms), 20000))
    cfg["allow_bpf"] = bool(allow_bpf)  # checkbox -> on/None
    _save_cfg(cfg)
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("pcap/settings", ok=True, actor=actor or "unknown", ip=ip, req_path=str(request.url),
              extra={"duration_max": cfg["duration_max"], "quota_gb": cfg["quota_gb"],
                     "policy": cfg["policy"], "poll_ms": cfg["poll_ms"], "allow_bpf": cfg["allow_bpf"]})
    return RedirectResponse(url="/pcap/settings", status_code=303)

    
