from fastapi import APIRouter, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from html import escape
from pathlib import Path
import os, json, time, subprocess, re, signal, shlex

router = APIRouter(prefix="/voip", tags=["voip"])

# --- paths ---
VOIP_DIR   = Path("/var/lib/netprobe/voip")
CAP_DIR    = VOIP_DIR / "captures"
META_FILE  = VOIP_DIR / "captures.json"   # {"captures":[{file,iface,start_ts,duration_s,pid,filter}]}
INDEX_FILE = VOIP_DIR / "index.json"      # {"calls":{callid:{...}}, "rtp_streams":[...], "built_ts":...}
CFG_PATH   = Path("/etc/netprobe/voip.json")

# --- default config ---
DEFAULT_CFG = {
    "sip_ports": [5060, 5061],
    "rtp_range": [10000, 20000],
    "duration_max": 3600,
    "quota_gb": 5,
    "policy": "rotate",              # rotate|block
    "allow_bpf": True,
    "privacy_mask_user": False,      # offusca user part (a***e@dom)
    "ui_poll_ms": 1000,
}

# --------------- utils base ---------------
def _run(cmd:list[str], timeout:int|None=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def _ensure_dirs():
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    VOIP_DIR.mkdir(parents=True, exist_ok=True)
    if not META_FILE.exists():
        META_FILE.write_text(json.dumps({"captures":[]}, indent=2), encoding="utf-8")
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text(json.dumps({"calls":{}, "rtp_streams":[], "built_ts":0}, indent=2), encoding="utf-8")
    _ensure_cfg()

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

def _load_index():
    _ensure_dirs()
    try:
        return json.loads(INDEX_FILE.read_text("utf-8"))
    except Exception:
        return {"calls":{}, "rtp_streams":[], "built_ts":0}

def _save_index(idx:dict):
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=2), encoding="utf-8")
    os.replace(tmp, INDEX_FILE)

def _alive(pid:int|None)->bool:
    if not pid: return False
    try:
        os.kill(pid, 0); return True
    except Exception:
        return False

def _list_ifaces():
    # dumpcap -D > nmcli/ip fallback
    rc, out, _ = _run(["/usr/bin/dumpcap","-D"])
    if rc==0 and out.strip():
        items=[]
        for line in out.splitlines():
            m=re.match(r"\s*\d+\.\s+([^\s]+)", line)
            if m: items.append(m.group(1))
        if items: return items
    rc, out, _ = _run(["/usr/sbin/ip","-o","link","show"])
    devs=[]
    if rc==0:
        for line in out.splitlines():
            try:
                name=line.split(":")[1].strip().split("@")[0]
                if name and name!="lo": devs.append(name)
            except Exception: pass
    outl=[]
    for d in devs:
        if d not in outl: outl.append(d)
    return outl

def _capdir_size() -> int:
    total=0
    for p in CAP_DIR.glob("*.pcapng"):
        try: total += p.stat().st_size
        except Exception: pass
    return total

def _apply_quota_rotation(quota_bytes:int) -> int:
    total=_capdir_size()
    if total <= quota_bytes: return 0
    files=sorted(CAP_DIR.glob("*.pcapng"), key=lambda p:p.stat().st_mtime)
    removed=0
    meta=_load_meta()
    for p in files:
        try:
            sz=p.stat().st_size
            p.unlink()
            removed+=1
            total-=sz
            meta["captures"]=[c for c in meta.get("captures",[]) if c.get("file")!=p.name]
            if total<=quota_bytes: break
        except Exception: pass
    _save_meta(meta)
    return removed

# --------------- settings ---------------
def _ensure_cfg():
    CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CFG_PATH.exists():
        CFG_PATH.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")

def _load_cfg():
    _ensure_cfg()
    try:
        data=json.loads(CFG_PATH.read_text("utf-8"))
    except Exception:
        data={}
    cfg={**DEFAULT_CFG, **(data or {})}
    # normalize
    try:
        cfg["sip_ports"]=[int(x) for x in cfg.get("sip_ports", [5060,5061])]
    except Exception:
        cfg["sip_ports"]=[5060,5061]
    try:
        rng=cfg.get("rtp_range",[10000,20000]); cfg["rtp_range"]=[int(rng[0]), int(rng[1])]
    except Exception:
        cfg["rtp_range"]=[10000,20000]
    return cfg

def _save_cfg(cfg:dict):
    tmp = CFG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, CFG_PATH)

def _default_bpf(cfg:dict)->str:
    sip_ports = " or ".join([f"port {p}" for p in cfg["sip_ports"]])
    r0, r1 = cfg["rtp_range"]
    return f"sip or udp portrange {r0}-{r1} or {sip_ports}"

# --------------- parsing ---------------
def _mask_user(s: str)->str:
    # "alice@dom" -> "a***e@dom"
    try:
        user, dom = s.split("@",1)
        if len(user)<=2: mu = user[:1] + "*"*max(0,len(user)-1)
        else: mu = user[0] + ("*"*(len(user)-2)) + user[-1]
        return mu + "@" + dom
    except Exception:
        return s

def _tshark_sip_rows(path:Path):
    # 11 campi
    fields = [
        "-e","frame.time_epoch",
        "-e","ip.src", "-e","ip.dst",
        "-e","sip.Call-ID",
        "-e","sip.CSeq.method",
        "-e","sip.Method",
        "-e","sip.Status-Code",
        "-e","sip.From.user",
        "-e","sip.To.user",
        "-e","sip.From", "-e","sip.To",
    ]
    cmd=["/usr/bin/tshark","-r",str(path),"-Y","sip","-T","fields","-E","separator=\\t"] + fields
    rc, out, err = _run(cmd, timeout=90)
    if rc!=0: return []
    rows=[]
    for line in out.splitlines():
        parts=line.split("\t")
        while len(parts) < 11: parts.append("")  # padding coerente
        rows.append(parts[:11])
    return rows

def _tshark_rtp_streams(path:Path):
    rc, out, err = _run(["/usr/bin/tshark","-r",str(path),"-q","-z","rtp,streams"], timeout=90)
    if rc!=0: return []
    lines=[l for l in out.splitlines() if l.strip()]
    rows=[]
    header_seen=False
    for l in lines:
        if not header_seen and re.search(r"SSRC", l) and re.search(r"Lost", l):
            header_seen=True
            continue
        if header_seen:
            if re.match(r"[-=]+", l): continue
            if re.match(r"\s*$", l): break
            cols=re.sub(r"\s{2,}","\t",l.strip()).split("\t")
            rows.append(cols)
    return rows

def _build_index_from_pcap(path:Path, privacy_mask=False)->dict:
    calls={}
    rows=_tshark_sip_rows(path)
    for r in rows:
        t, src, dst, callid, cseq_m, meth, status, from_user, to_user, from_full, to_full = (
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10]
        )
        if not callid: continue
        try: ts=float(t)
        except Exception: ts=None
        o=calls.get(callid) or {"callid":callid, "first_ts":ts, "last_ts":ts, "from":from_user, "to":to_user,
                                "from_full":from_full, "to_full":to_full, "msgs":[], "status":"in-progress",
                                "final_code":None, "method":None, "duration_s":None}
        o["last_ts"]=max(o["last_ts"] or ts, ts or o["last_ts"])
        if meth and not o.get("method"): o["method"]=meth
        # final response?
        if status and status.isdigit():
            code=int(status)
            if code>=200: o["final_code"]=code
        o["msgs"].append({
            "ts":ts,"src":src,"dst":dst,"method":meth or cseq_m or "",
            "code":int(status) if status and status.isdigit() else None
        })
        calls[callid]=o

    # compute state/duration
    for k,o in calls.items():
        codes=[m["code"] for m in o["msgs"] if m["code"]]
        final = max(codes) if codes else None
        if final is None: st="in-progress"
        elif 200 <= final < 300: st="ok"
        elif 300 <= final < 700: st="failed"
        else: st="in-progress"
        o["status"]=st
        # duration approx: INVITE .. BYE (se visto) altrimenti finestra osservata
        t_inv = next((m["ts"] for m in o["msgs"] if (m["method"]=="INVITE")), o["first_ts"])
        t_bye = next((m["ts"] for m in o["msgs"] if (m["method"]=="BYE")), None)
        if t_inv and t_bye: o["duration_s"]=max(0, (t_bye - t_inv))
        elif o["first_ts"] and o["last_ts"]: o["duration_s"]=max(0, (o["last_ts"] - o["first_ts"]))
        # privacy mask
        if privacy_mask:
            if o.get("from"): o["from"]=_mask_user(o["from"])
            if o.get("to"):   o["to"]=_mask_user(o["to"])
            if o.get("from_full"):
                o["from_full"]=re.sub(r'(?<=:)[^@>]+(?=@)', lambda m:_mask_user(m.group(0)).split("@")[0], o["from_full"])
            if o.get("to_full"):
                o["to_full"]=re.sub(r'(?<=:)[^@>]+(?=@)', lambda m:_mask_user(m.group(0)).split("@")[0], o["to_full"])

    rtp_rows = _tshark_rtp_streams(path)
    idx={"calls":calls, "rtp_streams":rtp_rows, "built_ts":int(time.time())}
    return idx

# --------------- HTML helpers ---------------
def _page_head(title:str)->str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'><div class='nav'><div class='brand'>"
        "<img src='/static/img/logo.svg' class='logo'/>"
        "<span>TestMachine</span></div><div class='links'><a class='btn small secondary' href='/'>Home</a></div></div>"
    )

# --------------- Pages ---------------
@router.get("/", response_class=HTMLResponse)
def voip_page():
    cfg=_load_cfg()
    ifaces=_list_ifaces()
    opt="".join(f"<option value='{escape(i)}'>{escape(i)}</option>" for i in ifaces)
    bpf_default=_default_bpf(cfg)

    # last index (for initial table render)
    idx=_load_index()
    calls=list(idx.get("calls", {}).values())
    calls.sort(key=lambda x: x.get("last_ts") or 0, reverse=True)

    rows=[]
    for o in calls[:20]:
        st=o.get("status","in-progress")
        color = "ok" if st=="ok" else ("bad" if st=="failed" else "warn")
        fromto = f"{escape(o.get('from') or '-')}&nbsp;→&nbsp;{escape(o.get('to') or '-')}"
        dur    = f"{(o.get('duration_s') or 0):.1f}s"
        cid    = escape(o.get("callid") or "")
        code   = int(o.get("final_code") or 0) or '-'
        rows.append(
            "<tr>"
            f"<td><span class='pill'><span class='dot {color}'></span>{st}</span></td>"
            f"<td class='mono'>{fromto}</td>"
            f"<td class='mono'>{dur}</td>"
            f"<td class='mono'>{code}</td>"
            f"<td>"
            f"  <a class='btn small' href='/voip/ladder?callid={cid}'>Ladder</a>"
            f"  <a class='btn small secondary' href='/voip/pcap?callid={cid}'>PCAP SIP</a>"
            f"</td>"
            "</tr>"
        )
    table = "".join(rows) or "<tr><td colspan='5' class='muted'>Nessun dialogo indicizzato.</td></tr>"

    html = _page_head("VoIP") + """
<style>
  .grid2{display:grid;gap:16px;grid-template-columns:1fr 1fr}
  @media (max-width:1000px){.grid2{grid-template-columns:1fr}}
  .kv{display:grid;grid-template-columns:160px 1fr;gap:6px}
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
  .pill{display:inline-flex;align-items:center;gap:8px;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.15)}
  .dot{width:9px;height:9px;border-radius:50%} .ok{background:#22c55e} .bad{background:#ef4444} .warn{background:#f59e0b}
  .table{overflow-x:auto} table{width:100%;border-collapse:collapse} th,td{padding:8px 10px;white-space:nowrap}
</style>

<div class='grid'>

  <div class='card'>
    <h2>VoIP – Cattura</h2>
    <form method='post' action='/voip/start' id='startForm'>
      <label>Interfaccia</label>
      <select name='iface'>__OPT__</select>

      <div class='row'>
        <div>
          <label>Durata (s)</label>
          <input name='duration' value='20' type='number' min='1' max='__MAX__' required/>
        </div>
        <div>
          <label>Filtro BPF</label>
          <input name='bpf' value='__BPF__' __BPF_DISABLED__/>
          <div class='muted tiny'>Default basato su porte SIP/RTP di <a href='/voip/settings'>Impostazioni VoIP</a>.</div>
        </div>
      </div>
      <button class='btn' type='submit'>Avvia</button>
      <button class='btn secondary' type='button' onclick='reindex()'>Indicizza ultima cattura</button>
    </form>

    <div id='activeBox' class='notice' style='margin-top:12px; display:none'>
      ⏱️ Cattura in corso… resta <b><span id='remain'>-</span>s</b> — file: <code id='actfile'>-</code> — <span id='actsize'>0 B</span>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
        <button class='btn danger' type='button' onclick='stopNow()'>Stop</button>
      </div>
      <form id="stopForm" method="post" action="/voip/stop" class="inline-form" style="display:none">
        <input type="hidden" name="file" id="stopFile" value="">
      </form>
    </div>
  </div>

  <div class='card'>
    <h2>KPI</h2>
    <div class='kv'>
      <div>Dialoghi indicizzati</div><div id='k_calls'>-</div>
      <div>% errori (≥400)</div><div id='k_err'>-</div>
      <div>RTP Streams</div><div id='k_rtp'>-</div>
      <div>Indice aggiornato</div><div id='k_built'>-</div>
    </div>
  </div>

  <div class='card' style='grid-column:1/-1'>
    <h2>Dialoghi (ultimi)</h2>
    <div class='table'>
      <table>
        <thead><tr><th>Stato</th><th>From → To</th><th>Durata</th><th>Final</th><th>Azioni</th></tr></thead>
        <tbody id='callsBody'>
          __TABLE__
        </tbody>
      </table>
    </div>
  </div>

</div>
</div>

<script>
function fmtBytes(b){ if(!b) return "0 B"; const u=["B","KB","MB","GB","TB"]; let i=0,v=Number(b); while(v>=1024&&i<u.length-1){v/=1024;i++;} return v.toFixed(1)+" "+u[i]; }
function tsHuman(s){ if(!s) return "-"; const d=new Date(s*1000); return d.toLocaleString(); }

async function stopNow(){
  const file = document.getElementById('stopFile').value;
  if(!file) return;
  try{ await fetch('/voip/stop', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'file='+encodeURIComponent(file)}); }catch(e){}
  setTimeout(()=>location.reload(), 600);
}

async function pollStatus(){
  try{
    const r = await fetch('/voip/status'); const js = await r.json();
    const box = document.getElementById('activeBox');
    if(js.active && js.active.length>0){
      const a = js.active[0];
      box.style.display='';
      document.getElementById('remain').textContent = Math.max(0, Math.floor(a.remaining_s));
      document.getElementById('actfile').textContent = a.file;
      document.getElementById('actsize').textContent = fmtBytes(a.size||0);
      document.getElementById('stopFile').value = a.file;
      if(a.remaining_s<=0) setTimeout(()=>location.reload(), 800);
    } else {
      box.style.display='none';
    }
  }catch(e){}
}

async function refreshIndex(){
  try{
    const r = await fetch('/voip/calls'); const js = await r.json();
    const calls = js.calls||[];
    const errors = calls.filter(c=> (c.final_code||0)>=400).length;
    const errpct = calls.length? Math.round(errors/calls.length*100):0;
    document.getElementById('k_calls').textContent = String(calls.length);
    document.getElementById('k_err').textContent   = errpct+'%';
    document.getElementById('k_rtp').textContent   = String(js.rtp_streams||0);
    document.getElementById('k_built').textContent = tsHuman(js.built_ts||0);

    const body = document.getElementById('callsBody');
    // render dinamico sempre, così aggiorniamo la tabella senza reload
    body.innerHTML = calls.slice(0,50).map(o=>{
      const st=o.status||'in-progress';
      const color= st==='ok'?'ok':(st==='failed'?'bad':'warn');
      const fromto=(o.from||'-')+' → '+(o.to||'-');
      const dur=((o.duration_s||0).toFixed(1))+'s';
      const cid=o.callid;
      const code=o.final_code||'-';
      return `<tr>
        <td><span class='pill'><span class='dot ${color}'></span>${st}</span></td>
        <td class='mono'>${fromto}</td>
        <td class='mono'>${dur}</td>
        <td class='mono'>${code}</td>
        <td>
          <a class='btn small' href='/voip/ladder?callid=${encodeURIComponent(cid)}'>Ladder</a>
          <a class='btn small secondary' href='/voip/pcap?callid=${encodeURIComponent(cid)}'>PCAP SIP</a>
        </td>
      </tr>`;
    }).join('');
  }catch(e){}
}

async function reindex(){
  await fetch('/voip/reindex', {method:'POST'});
  await refreshIndex();
}

setInterval(pollStatus, __POLL__);
setInterval(refreshIndex, __POLL__);
pollStatus();
refreshIndex();
</script>
</body></html>
"""
    html = html.replace("__OPT__", opt)
    html = html.replace("__MAX__", str(int(cfg.get("duration_max",3600))))
    html = html.replace("__BPF__", escape(bpf_default))
    html = html.replace("__BPF_DISABLED__", "" if cfg.get("allow_bpf", True) else "disabled")
    html = html.replace("__TABLE__", table)
    html = html.replace("__POLL__", str(int(cfg.get("ui_poll_ms", 1000))))
    return HTMLResponse(html)

# --------------- API azioni ---------------
def _has_active_capture(meta:dict|None=None)->bool:
    meta = meta or _load_meta()
    now = int(time.time())
    for c in meta.get("captures", []):
        pid=c.get("pid")
        dur=int(c.get("duration_s",0) or 0)
        start=int(c.get("start_ts",0) or 0)
        if pid and _alive(pid) and (now - start) < dur:
            return True
    return False

@router.post("/start")
def start_capture(iface: str = Form(...), duration: int = Form(...), bpf: str = Form("")):
    _ensure_dirs()
    cfg=_load_cfg()
    meta=_load_meta()
    if _has_active_capture(meta):
        return HTMLResponse("<script>alert('C’è già una cattura in corso. Ferma quella prima di avviarne un’altra.');window.location.href='/voip';</script>")

    # quota
    quota_bytes = int(float(cfg.get("quota_gb",5)) * (1024**3))
    if _capdir_size() >= quota_bytes:
        if cfg.get("policy","rotate") == "rotate":
            _apply_quota_rotation(quota_bytes)
        else:
            return HTMLResponse("<script>alert('Quota VoIP piena: cattura bloccata (policy=block).');window.location.href='/voip';</script>")

    if iface not in _list_ifaces():
        return HTMLResponse("<script>history.back();alert('Interfaccia non valida');</script>")

    duration = max(1, min(int(duration), int(cfg.get("duration_max",3600))))
    if not cfg.get("allow_bpf", True) or not bpf.strip():
        bpf = _default_bpf(cfg)

    ts=int(time.time())
    fname=f"{ts}_{iface}.pcapng"
    path=CAP_DIR / fname
    cmd=["/usr/bin/dumpcap","-i",iface,"-P","-w",str(path),"-a",f"duration:{duration}","-s","262144"]
    if bpf.strip():
        cmd+=["-f", bpf.strip()]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

    meta["captures"].append({
        "file": fname, "iface": iface, "start_ts": ts, "duration_s": duration,
        "pid": proc.pid, "filter": bpf.strip(),
    })
    _save_meta(meta)
    return RedirectResponse(url="/voip", status_code=303)

@router.post("/stop", response_class=JSONResponse)
def stop_capture(file: str = Form(None)):
    meta=_load_meta()
    stopped=0
    for c in meta.get("captures", []):
        if file and c.get("file")!=file: continue
        pid=c.get("pid")
        if pid and _alive(pid):
            try: os.killpg(pid, signal.SIGTERM)
            except Exception:
                try: os.kill(pid, signal.SIGTERM)
                except Exception: pass
            stopped+=1
    return {"stopped": stopped}

@router.get("/status", response_class=JSONResponse)
def status():
    now=int(time.time())
    meta=_load_meta()
    active=[]
    for c in meta.get("captures", []):
        pid=c.get("pid")
        dur=int(c.get("duration_s",0) or 0)
        start=int(c.get("start_ts",0) or 0)
        remaining=max(0, dur - (now - start))
        path = CAP_DIR / c["file"]
        size = path.stat().st_size if path.exists() else 0
        if pid and _alive(pid) and remaining>0:
            active.append({"file":c["file"],"iface":c["iface"],"remaining_s":remaining,"size":size})
    return {"active": active}

# --------------- indicizzazione & dati ---------------
def _latest_pcap()->Path|None:
    items=sorted(CAP_DIR.glob("*.pcapng"), key=lambda p:p.stat().st_mtime)
    return items[-1] if items else None

@router.post("/reindex", response_class=JSONResponse)
def reindex():
    cfg=_load_cfg()
    p=_latest_pcap()
    if not p or not p.exists():
        return {"ok": False, "error":"no_pcap"}
    idx=_build_index_from_pcap(p, privacy_mask=bool(cfg.get("privacy_mask_user", False)))
    _save_index(idx)
    return {"ok": True, "calls": len(idx.get("calls",{})), "rtp_streams": len(idx.get("rtp_streams",[]))}

@router.get("/calls", response_class=JSONResponse)
def calls(limit:int=Query(100, ge=1, le=1000)):
    idx=_load_index()
    calls=list(idx.get("calls",{}).values())
    calls.sort(key=lambda x: x.get("last_ts") or 0, reverse=True)
    out=calls[:limit]
    return {
        "calls": out,
        "rtp_streams": len(idx.get("rtp_streams",[])),
        "built_ts": idx.get("built_ts",0)
    }

@router.get("/call/{callid}", response_class=JSONResponse)
def call_detail(callid:str):
    idx=_load_index()
    o = idx.get("calls",{}).get(callid)
    if not o:
        return JSONResponse({"error":"not_found"}, status_code=404)
    return o

@router.get("/pcap")
def pcap_for_call(callid: str = Query(...)):
    # MVP: estrai SOLO SIP della call-id; step successivo: export con sngrep (SIP+RTP correlati)
    p=_latest_pcap()
    if not p or not p.exists():
        return HTMLResponse("Nessuna cattura trovata", status_code=404)
    safe_name = re.sub(r'[^A-Za-z0-9_.-]','_',callid)
    out_path = VOIP_DIR / f"sip_{safe_name}.pcapng"
    display_filter = f'sip.Call-ID == "{callid}"'
    cmd=["/usr/bin/tshark","-r",str(p),"-Y",display_filter,"-w",str(out_path)]
    rc, out, err = _run(cmd, timeout=120)
    if rc!=0 or not out_path.exists() or out_path.stat().st_size==0:
        return HTMLResponse("Export fallito o vuoto.", status_code=500)
    return FileResponse(out_path, filename=out_path.name, media_type="application/octet-stream")

# --------------- Ladder ---------------
@router.get("/ladder", response_class=HTMLResponse)
def ladder(callid:str = Query(...)):
    idx=_load_index()
    o=idx.get("calls",{}).get(callid)
    if not o:
        return HTMLResponse("<h3 style='margin:2rem'>Call-ID non trovata (ricostruisci indice?)</h3>", status_code=404)
    msgs=o.get("msgs",[])
    # euristica: 3 lifeline A/B/Proxy in base agli IP del primo messaggio
    if msgs:
        a_ip = msgs[0].get("src") or ""
        b_ip = msgs[0].get("dst") or ""
    else:
        a_ip, b_ip = "", ""
    def who(ip):
        if ip==a_ip: return "A"
        if ip==b_ip: return "B"
        return "P"
    rows=[]
    for m in msgs:
        frm=who(m.get("src",""))
        to =who(m.get("dst",""))
        label = m.get("method") or (f"{m['code']}" if m.get("code") else "?")
        rows.append(f"<tr><td class='who {frm}'>{frm}</td><td class='arrow'>→</td><td class='who {to}'>{to}</td><td class='lbl mono'>{escape(label)}</td></tr>")
    html = _page_head("VoIP Ladder") + f"""
<style>
  .ladder{{max-width:860px}}
  .who{{font-weight:700}}
  .A{{color:#60a5fa}} .B{{color:#22c55e}} .P{{color:#f59e0b}}
  .mono{{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}}
  table{{width:100%;border-collapse:collapse}} td{{padding:6px 10px}}
  .arrow{{opacity:.8}}
</style>
<div class='grid'><div class='card ladder'>
  <h2>Ladder – <span class='mono'>{escape(callid)}</span></h2>
  <div class='muted'>Semplificata (A/B/Proxy) – euristica basata sugli IP del primo messaggio.</div>
  <table>{"".join(rows) or "<tr><td class='muted'>Nessun messaggio.</td></tr>"}</table>
  <div style="margin-top:10px"><a class='btn secondary' href='/voip'>Torna</a></div>
</div></div></div></body></html>
"""
    return HTMLResponse(html)

# --------------- Settings page ---------------
@router.get("/settings", response_class=HTMLResponse)
def settings_page():
    cfg=_load_cfg()
    html=_page_head("Impostazioni VoIP") + f"""
<style>.w420{{max-width:420px}}</style>
<div class='grid'><div class='card w420'>
  <h2>Impostazioni VoIP</h2>
  <form method='post' action='/voip/settings'>
    <label>Porte SIP (comma)</label>
    <input name='sip_ports' value='{",".join(str(x) for x in cfg.get("sip_ports",[5060,5061]))}'/>

    <label>Range RTP (min-max)</label>
    <input name='rtp_range' value='{cfg.get("rtp_range",[10000,20000])[0]}-{cfg.get("rtp_range",[10000,20000])[1]}'/>

    <label>Durata massima (s)</label>
    <input type='number' name='duration_max' min='1' max='86400' value='{int(cfg.get("duration_max",3600))}' required/>

    <label>Quota storage (GB)</label>
    <input type='number' name='quota_gb' step='0.1' min='1' value='{float(cfg.get("quota_gb",5))}' required/>

    <label>Policy quota</label>
    <select name='policy'>
      <option value='rotate' {"selected" if cfg.get("policy","rotate")=="rotate" else ""}>Ruota (elimina più vecchi)</option>
      <option value='block' {"selected" if cfg.get("policy","rotate")=="block" else ""}>Blocca nuove catture</option>
    </select>

    <label class='row' style='align-items:center;gap:10px'>
      <input type='checkbox' name='allow_bpf' {"checked" if cfg.get("allow_bpf",True) else ""}/> Consenti BPF personalizzato
    </label>

    <label class='row' style='align-items:center;gap:10px'>
      <input type='checkbox' name='privacy_mask_user' {"checked" if cfg.get("privacy_mask_user",False) else ""}/> Offusca user part (privacy)
    </label>

    <label>UI refresh (ms)</label>
    <input type='number' name='ui_poll_ms' min='250' max='10000' value='{int(cfg.get("ui_poll_ms",1000))}' required/>

    <button class='btn' type='submit'>Salva</button>
    <a class='btn secondary' href='/voip'>Torna a VoIP</a>
  </form>
</div></div></div></body></html>
"""
    return HTMLResponse(html)

@router.post("/settings")
def settings_save(sip_ports: str = Form(...),
                  rtp_range: str = Form(...),
                  duration_max: int = Form(...),
                  quota_gb: float = Form(...),
                  policy: str = Form(...),
                  allow_bpf: str = Form(None),
                  privacy_mask_user: str = Form(None),
                  ui_poll_ms: int = Form(...)):
    cfg=_load_cfg()
    # sip ports
    try:
        ports=[int(x.strip()) for x in sip_ports.split(",") if x.strip()]
        cfg["sip_ports"]= [p for p in ports if 1<=p<=65535] or [5060,5061]
    except Exception:
        cfg["sip_ports"]=[5060,5061]
    # rtp range
    try:
        a,b = rtp_range.replace(" ","").split("-",1)
        a,b=int(a),int(b)
        if a>b: a,b=b,a
        a=max(1,a); b=min(65535,b)
        cfg["rtp_range"]=[a,b]
    except Exception:
        cfg["rtp_range"]=[10000,20000]

    cfg["duration_max"]=max(1, min(int(duration_max), 86400))
    try:
        cfg["quota_gb"]=max(1.0, float(quota_gb))
    except Exception:
        cfg["quota_gb"]=DEFAULT_CFG["quota_gb"]
    cfg["policy"]="rotate" if policy=="rotate" else "block"
    cfg["allow_bpf"]=bool(allow_bpf)
    cfg["privacy_mask_user"]=bool(privacy_mask_user)
    cfg["ui_poll_ms"]=max(250, min(int(ui_poll_ms), 20000))
    _save_cfg(cfg)
    return RedirectResponse(url="/voip/settings", status_code=303)
