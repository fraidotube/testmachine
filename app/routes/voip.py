from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse, PlainTextResponse
from html import escape
from pathlib import Path
import os, json, time, subprocess, re, signal, shlex, tempfile, shutil
from typing import List, Dict, Any, Tuple, Optional
from routes.auth import verify_session_cookie, _load_users
from statistics import mean

router = APIRouter(prefix="/voip", tags=["voip"])

# --- paths ---
VOIP_DIR   = Path("/var/lib/netprobe/voip")
CAP_DIR    = VOIP_DIR / "captures"
META_FILE  = VOIP_DIR / "captures.json"   # {"captures":[{file,iface,start_ts,duration_s,pid,filter}]}
INDEX_FILE = VOIP_DIR / "index.json"      # {"calls":{callid:{...}}, "rtp_streams":[], "built_ts":..., "built_src": "..."}
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
    "admin_required_actions": ["start", "stop", "delete"],  # azioni protette
    "default_codec": "PCMU",        # per MOS (fallback)
}

# --------------- utils base ---------------
def _run(cmd:List[str], timeout:Optional[int]=None) -> Tuple[int,str,str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def _ensure_dirs():
    VOIP_DIR.mkdir(parents=True, exist_ok=True)
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    if not META_FILE.exists():
        META_FILE.write_text(json.dumps({"captures":[]}, indent=2), encoding="utf-8")
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text(json.dumps({"calls":{}, "rtp_streams":[], "built_ts":0, "built_src": None}, indent=2), encoding="utf-8")
    _ensure_cfg()

def _load_meta() -> Dict[str,Any]:
    _ensure_dirs()
    try:
        return json.loads(META_FILE.read_text("utf-8"))
    except Exception:
        return {"captures":[]}

def _save_meta(meta:dict):
    tmp = META_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, META_FILE)

def _load_index() -> Dict[str,Any]:
    _ensure_dirs()
    try:
        return json.loads(INDEX_FILE.read_text("utf-8"))
    except Exception:
        return {"calls":{}, "rtp_streams":[], "built_ts":0, "built_src": None}

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

def _list_ifaces() -> List[str]:
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
            meta["captures"]= [c for c in meta.get("captures",[]) if c.get("file")!=p.name]
            if total<=quota_bytes: break
        except Exception: pass
    _save_meta(meta)
    return removed

# --------------- settings ---------------
def _ensure_cfg():
    CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CFG_PATH.exists():
        CFG_PATH.write_text(json.dumps(DEFAULT_CFG, indent=2), encoding="utf-8")

def _load_cfg() -> Dict[str,Any]:
    _ensure_cfg()
    try:
        data=json.loads(CFG_PATH.read_text("utf-8"))
    except Exception:
        data={}
    cfg={**DEFAULT_CFG, **(data or {})}
    try:
        cfg["sip_ports"]= [int(x) for x in cfg.get("sip_ports", [5060,5061])]
    except Exception:
        cfg["sip_ports"]= [5060,5061]
    try:
        rng=cfg.get("rtp_range",[10000,20000]); cfg["rtp_range"]= [int(rng[0]), int(rng[1])]
    except Exception:
        cfg["rtp_range"]= [10000,20000]
    return cfg

def _save_cfg(cfg:dict):
    tmp = CFG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, CFG_PATH)

def _validate_bpf(iface: str, bpf: str) -> tuple[bool, str]:
    rc, out, err = _run([
        "/usr/bin/dumpcap", "-i", iface, "-P",
        "-a", "duration:1", "-s", "1", "-f", bpf, "-w", "/dev/null"
    ], timeout=10)
    return (rc == 0), (err or out or "")

def _default_bpf(cfg:dict)->str:
    sip_parts = []
    for p in cfg["sip_ports"]:
        sip_parts.append(f"udp port {p}")
        sip_parts.append(f"tcp port {p}")
    sip_expr = " or ".join(sip_parts)
    r0, r1 = cfg["rtp_range"]
    rtp_expr = f"udp portrange {r0}-{r1}"
    return f"({sip_expr}) or ({rtp_expr})"

# ----- file helpers -----
def _pcap_path_from_param(file_param: Optional[str]) -> Optional[Path]:
    """Ritorna un Path sicuro dentro CAP_DIR per il nome file fornito (solo basename)."""
    if not file_param: return None
    fname = re.sub(r'[^A-Za-z0-9_.-]','_', Path(file_param).name)
    p = CAP_DIR / fname
    if p.exists() and p.is_file() and p.suffix.lower()==".pcapng":
        return p
    return None

# --------------- parsing ---------------
def _mask_user(s: str)->str:
    try:
        user, dom = s.split("@",1)
        if len(user)<=2: mu = user[:1] + "*"*max(0,len(user)-1)
        else: mu = user[0] + ("*"*(len(user)-2)) + user[-1]
        return mu + "@" + dom
    except Exception:
        return s

def _tshark_sip_rows(path:Path) -> List[List[str]]:
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
        while len(parts) < 11: parts.append("")
        rows.append(parts[:11])
    return rows

def _tshark_rtp_streams(path:Path) -> List[List[str]]:
    rc, out, err = _run(["/usr/bin/tshark","-r",str(path),"-q","-z","rtp,streams"], timeout=90)
    if rc!=0: return []
    lines=[l for l in out.splitlines() if l.strip()]
    rows=[]
    header_seen=False
    for l in lines:
        if not header_seen and re.search(r"SSRC", l) and re.search(r"Lost", l):
            header_seen=True; continue
        if header_seen:
            if re.match(r"[-=]+", l): continue
            if re.match(r"\s*$", l): break
            cols=re.sub(r"\s{2,}","\t",l.strip()).split("\t")
            rows.append(cols)
    return rows

def _extract_sdp_media_from_sip_pcap(sip_pcap:Path) -> List[Dict[str,Any]]:
    cmd=["/usr/bin/tshark","-r",str(sip_pcap),"-Y","sdp","-T","fields",
         "-e","sdp.media.port","-e","sdp.media.proto","-e","sdp.connection_info.address","-e","sdp.fmtp.payload_type","-e","sdp.media.attr"]
    rc, out, err = _run(cmd, timeout=60)
    medias=[]
    if rc!=0: return medias
    for line in out.splitlines():
        parts=line.split("\t")
        port = parts[0].split(",")[0] if parts and parts[0] else ""
        proto= parts[1] if len(parts)>1 else ""
        addr = parts[2] if len(parts)>2 else ""
        payload = parts[3] if len(parts)>3 else ""
        attr = parts[4] if len(parts)>4 else ""
        try:
            p=int(port)
            if 1<=p<=65535 and ("RTP" in proto.upper() or "UDP" in proto.upper()):
                medias.append({"ip":addr or None, "port":p, "proto":proto, "payload":payload, "attr":attr})
        except Exception:
            continue
    return medias

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
        if status and status.isdigit():
            code=int(status)
            if code>=200: o["final_code"]=code
        o["msgs"].append({
            "ts":ts,"src":src,"dst":dst,"method":meth or cseq_m or "",
            "code":int(status) if status and status.isdigit() else None
        })
        calls[callid]=o

    for k,o in calls.items():
        codes=[m["code"] for m in o["msgs"] if m["code"]]
        final = max(codes) if codes else None
        if final is None: st="in-progress"
        elif 200 <= final < 300: st="ok"
        elif 300 <= final < 700: st="failed"
        else: st="in-progress"
        o["status"]=st
        t_inv = next((m["ts"] for m in o["msgs"] if (m["method"]=="INVITE")), o["first_ts"])
        t_bye = next((m["ts"] for m in o["msgs"] if (m["method"]=="BYE")), None)
        if t_inv and t_bye: o["duration_s"]=max(0, (t_bye - t_inv))
        elif o["first_ts"] and o["last_ts"]: o["duration_s"]=max(0, (o["last_ts"] - o["first_ts"]))
        if privacy_mask:
            if o.get("from"): o["from"]=_mask_user(o["from"])  # type: ignore
            if o.get("to"):   o["to"]=_mask_user(o["to"])      # type: ignore
            if o.get("from_full"):
                o["from_full"]=re.sub(r'(?<=:)[^@>]+(?=@)', lambda m:_mask_user(m.group(0)).split("@")[0], o["from_full"])  # type: ignore
            if o.get("to_full"):
                o["to_full"]=re.sub(r'(?<=:)[^@>]+(?=@)', lambda m:_mask_user(m.group(0)).split("@")[0], o["to_full"])    # type: ignore

    rtp_rows = _tshark_rtp_streams(path)
    idx={"calls":calls, "rtp_streams":rtp_rows, "built_ts":int(time.time()), "built_src": path.name}
    return idx

# --------------- Auth / Permessi ---------------
from fastapi import Request
from fastapi.responses import JSONResponse

def _is_admin(req: Request) -> bool:
    if req.headers.get("X-Admin", "").lower() in ("1", "true", "yes"):
        return True
    user = verify_session_cookie(req)
    if not user:
        return False
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

def _require_admin(req: Request):
    if not _is_admin(req):
        return JSONResponse({"error": "forbidden", "detail": "Admin only"}, status_code=403)
    return None

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
            f"  <a class='btn small secondary' href='/voip/pcap?callid={cid}'>PCAP (SIP+RTP)</a>"
            f"  <a class='btn small secondary' href='/voip/rtp/stats?callid={cid}'>RTP Stats</a>"
            f"</td>"
            "</tr>"
        )
    table = "".join(rows) or "<tr><td colspan='5' class='muted'>Nessun dialogo indicizzato.</td></tr>"

    # archivio
    # archivio
    # archivio
    files = sorted(CAP_DIR.glob("*.pcapng"), key=lambda p: p.stat().st_mtime, reverse=True)
    f_rows = []
    for p in files[:100]:
      ts_epoch = int(p.stat().st_mtime)
      ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_epoch))
      size = p.stat().st_size
      fn = escape(p.name)
      f_rows.append(
        "<tr>"
        f"<td class='mono'>{fn}</td>"
        f"<td class='mono'>{size}</td>"
        f"<td class='mono' title='{ts_epoch}'>{escape(ts_human)}</td>"
        f"<td>"
        f"  <a class='btn small' href='/voip/download?file={fn}'>PCAP</a>"
        f"  <button class='btn small' onclick=\"reindexFile('{fn}')\">Indicizza</button>"
        f"  <button class='btn small secondary' onclick=\"kpiFile('{fn}')\">KPI</button>"
        f"  <button class='btn small danger' onclick=\"delFile('{fn}')\">Elimina</button>"
        f"</td>"
        "</tr>"
     )
    ftable = "".join(f_rows) or "<tr><td colspan='4' class='muted'>Nessuna cattura salvata.</td></tr>"


    built_src = escape(str(idx.get("built_src") or "-"))

    html = _page_head("VoIP") + """
<style>
  .grid2{display:grid;gap:16px;grid-template-columns:1fr 1fr}
  @media (max-width:1000px){.grid2{grid-template-columns:1fr}}
  .kv{display:grid;grid-template-columns:160px 1fr;gap:6px}
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
  .pill{display:inline-flex;align-items:center;gap:8px;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.15)}
  .dot{width:9px;height:9px;border-radius:50%} .ok{background:#22c55e} .bad{background:#ef4444} .warn{background:#f59e0b}
  .table{overflow-x:auto} table{width:100%;border-collapse:collapse} th,td{padding:8px 10px;white-space:nowrap}
  .tiny{font-size:.85em}
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
            <div class="row" style="align-items:center; gap:8px">
            <div class="muted tiny">Default basato su porte SIP/RTP.</div>
            <a class="btn small secondary" href="/voip/settings">Impostazioni VoIP</a>
          </div>
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
    <div class='kv' style='margin-top:10px'>
      <div>MOS medio</div><div id='k_mos'>-</div>
      <div>Jitter medio</div><div id='k_jit'>-</div>
      <div>Perdita media</div><div id='k_loss'>-</div>
      <div>Bitrate medio</div><div id='k_kbps'>-</div>
    </div>
    <div class='muted tiny' style='margin-top:6px'>Indice costruito da: <code id='k_src'>__SRC__</code></div>
    <div style='margin-top:8px'>
      <a class='btn small secondary' href='/voip/summary'>Riepilogo veloce</a>
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

  <div class='card' style='grid-column:1/-1'>
    <h2>Archivio catture</h2>
    <div class='table'>
      <table>
        <thead><tr><th>File</th><th>Size (B)</th><th>Ultima modifica</th><th>Azioni</th></tr></thead>
        <tbody id='filesBody'>
          __FTABLE__
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

async function refreshVoipKpi(file){
  try{
    const url = file ? ('/voip/kpi?file='+encodeURIComponent(file)) : '/voip/kpi';
    const r = await fetch(url); const js = await r.json();
    if(js && !js.error){
      document.getElementById('k_mos').textContent  = (js.mos_avg ?? '-');
      document.getElementById('k_jit').textContent  = (js.jitter_avg_ms!=null ? js.jitter_avg_ms.toFixed(1)+' ms' : '-');
      document.getElementById('k_loss').textContent = (js.loss_avg_pct!=null ? js.loss_avg_pct.toFixed(2)+'%' : '-');
      document.getElementById('k_kbps').textContent = (js.kbps_avg!=null ? js.kbps_avg.toFixed(1)+' kbps' : '-');
      if(js.src_file){ document.getElementById('k_src').textContent = js.src_file; }
    }
  }catch(e){}
}
setInterval(()=>refreshVoipKpi(), __POLL__);
refreshVoipKpi();

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
  }catch(e){}
}

async function reindex(){
  await fetch('/voip/reindex', {method:'POST'});
  await refreshIndex();
}

async function reindexFile(fn){
  await fetch('/voip/reindex?file='+encodeURIComponent(fn), {method:'POST'});
  await refreshIndex();
  await refreshVoipKpi(); // KPI now reflect new index src
}

async function kpiFile(fn){
  await refreshVoipKpi(fn);
}

async function delFile(fn){
  if(!confirm('Eliminare '+fn+'?')) return;
  await fetch('/voip/delete', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'file='+encodeURIComponent(fn)});
  location.reload();
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
    html = html.replace("__FTABLE__", ftable)
    html = html.replace("__POLL__", str(int(cfg.get("ui_poll_ms", 1000))))
    html = html.replace("__SRC__", built_src)
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
def start_capture(request: Request, iface: str = Form(...), duration: int = Form(...), bpf: str = Form("")):
    if _require_admin(request):
        return _require_admin(request)

    _ensure_dirs()
    cfg=_load_cfg()
    meta=_load_meta()
    if _has_active_capture(meta):
        return HTMLResponse("<script>alert('C’è già una cattura in corso. Ferma quella prima di avviarne un’altra.');window.location.href='/voip';</script>")

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

    ok, err = _validate_bpf(iface, bpf)
    if not ok:
        esc = escape((err or "").strip())[:400]
        return HTMLResponse(f"<script>alert('Filtro BPF non valido. Dumpcap ha risposto: {esc}');history.back();</script>",status_code=400)

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
def stop_capture(request: Request, file: str = Form(None)):
    if _require_admin(request):
        return _require_admin(request)
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

@router.get("/list", response_class=JSONResponse)
def list_pcaps():
    files=sorted(CAP_DIR.glob("*.pcapng"), key=lambda p:p.stat().st_mtime, reverse=True)
    return {"files":[
    {
        "file": p.name,
        "size": p.stat().st_size,
        "mtime": int(p.stat().st_mtime),
        "mtime_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
    } for p in files
]}

@router.get("/download")
def download(file: str = Query(...)):
    p = _pcap_path_from_param(file)
    if not p:
        return HTMLResponse("File non trovato", status_code=404)
    return FileResponse(p, filename=p.name, media_type="application/octet-stream")

@router.post("/delete", response_class=JSONResponse)
def delete_capture(request: Request, file: str = Form(...)):
    if _require_admin(request):
        return _require_admin(request)
    p = _pcap_path_from_param(file)
    if not p:
        return {"status":"error","detail":"file non trovato"}
    try:
        p.unlink()
        meta=_load_meta()
        meta["captures"] = [c for c in meta.get("captures",[]) if c.get("file")!=p.name]
        _save_meta(meta)
        # Se l'indice corrente era basato su questo file, resetta info sorgente
        idx=_load_index()
        if idx.get("built_src")==p.name:
            idx["built_src"]=None
            _save_index(idx)
        return {"status":"ok"}
    except Exception as e:
        return {"status":"error","detail":str(e)}

# --------------- indicizzazione & dati ---------------
def _latest_pcap()->Optional[Path]:
    items=sorted(CAP_DIR.glob("*.pcapng"), key=lambda p:p.stat().st_mtime)
    return items[-1] if items else None

@router.post("/reindex", response_class=JSONResponse)
def reindex(file: Optional[str] = Query(None)):
    cfg=_load_cfg()
    p = _pcap_path_from_param(file) if file else _latest_pcap()
    if not p or not p.exists():
        return {"ok": False, "error":"no_pcap"}
    idx=_build_index_from_pcap(p, privacy_mask=bool(cfg.get("privacy_mask_user", False)))
    _save_index(idx)
    return {"ok": True, "calls": len(idx.get("calls",{})), "rtp_streams": len(idx.get("rtp_streams",[])), "src_file": p.name}

@router.get("/calls", response_class=JSONResponse)
def calls(limit:int=Query(100, ge=1, le=1000)):
    idx=_load_index()
    calls=list(idx.get("calls",{}).values())
    calls.sort(key=lambda x: x.get("last_ts") or 0, reverse=True)
    out=calls[:limit]
    return {
        "calls": out,
        "rtp_streams": len(idx.get("rtp_streams",[])),
        "built_ts": idx.get("built_ts",0),
        "built_src": idx.get("built_src")
    }

@router.get("/call/{callid}", response_class=JSONResponse)
def call_detail(callid:str):
    idx=_load_index()
    o = idx.get("calls",{}).get(callid)
    if not o:
        return JSONResponse({"error":"not_found"}, status_code=404)
    return o

# --------------- Export PCAP per-call (SIP + RTP) ---------------
def _export_sip_for_call(src_pcap:Path, callid:str, out_sip:Path) -> bool:
    display_filter = f'sip.Call-ID == "{callid}"'
    cmd=["/usr/bin/tshark","-r",str(src_pcap),"-Y",display_filter,"-w",str(out_sip)]
    rc, _, _ = _run(cmd, timeout=180)
    return rc==0 and out_sip.exists() and out_sip.stat().st_size>0

def _merge_pcaps(out_path:Path, parts:List[Path]) -> bool:
    if shutil.which("/usr/bin/mergecap"):
        cmd=["/usr/bin/mergecap","-w",str(out_path)] + [str(p) for p in parts]
        rc,_,_=_run(cmd, timeout=120)
        return rc==0 and out_path.exists() and out_path.stat().st_size>0
    cmd=["/usr/bin/tshark","-w",str(out_path)]
    for p in parts: cmd += ["-r", str(p)]
    rc,_,_=_run(cmd, timeout=180)
    return rc==0 and out_path.exists() and out_path.stat().st_size>0

def _export_call_with_rtp(src_pcap:Path, callid:str, out_pcap:Path) -> bool:
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        sip_pcap = td/"sip.pcapng"
        if not _export_sip_for_call(src_pcap, callid, sip_pcap):
            return False
        medias = _extract_sdp_media_from_sip_pcap(sip_pcap)
        rtp_parts=[sip_pcap]
        for i,m in enumerate(medias):
            if not m.get("port"): continue
            port = int(m["port"])  # type: ignore
            ip   = m.get("ip")
            dfilter = f"udp && (udp.srcport=={port} || udp.dstport=={port})"
            if ip: dfilter = f"ip.addr=={ip} && ("+dfilter+")"
            outi = td/f"rtp_{i}.pcapng"
            rc,_,_=_run(["/usr/bin/tshark","-r",str(src_pcap),"-Y",dfilter,"-w",str(outi)], timeout=180)
            if rc==0 and outi.exists() and outi.stat().st_size>0:
                rtp_parts.append(outi)
        return _merge_pcaps(out_pcap, rtp_parts)

@router.get("/pcap")
def pcap_for_call(callid: str = Query(...), file: Optional[str] = Query(None)):
    p = _pcap_path_from_param(file) if file else _latest_pcap()
    if not p or not p.exists():
        return HTMLResponse("Nessuna cattura trovata", status_code=404)
    safe_name = re.sub(r'[^A-Za-z0-9_.-]','_',callid)
    out_path = VOIP_DIR / f"call_{safe_name}.pcapng"
    ok = _export_call_with_rtp(p, callid, out_path)
    if not ok:
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
    if msgs:
        a_ip = msgs[0].get("src") or ""
        b_ip = msgs[0].get("dst") or ""
    else:
        a_ip, b_ip = "", ""
    def who(ip:str):
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

# --------------- RTP Stats + MOS ---------------
def _estimate_mos(loss_pct:float, jitter_ms:float, codec:str="PCMU") -> float:
    codec=codec.upper()
    Ie = 0.0 if codec in ("PCMU","PCMA","G711","G.711") else 5.0
    Bpl = 10.0 if Ie==0 else 19.0
    Ppl = max(0.0, float(loss_pct))
    Ie_eff = Ie + (95.0 - Ie) * (Ppl) / (Ppl / Bpl + 95.0)
    J = max(0.0, float(jitter_ms))
    Id = min(20.0, J/10.0)
    R = 94.2 - Id - Ie_eff
    if R < 0: mos = 1.0
    elif R > 100: mos = 4.5
    else:
        mos = 1.0 + 0.035*R + R*(R-60.0)*(100.0-R)*7e-6
    return round(max(1.0, min(4.5, mos)), 2)

def _rtp_stats_from_pcap(path:Path) -> List[Dict[str,Any]]:
    rows=_tshark_rtp_streams(path)
    stats=[]
    for r in rows:
        line='\t'.join(r)
        def grab(pattern:str, default:Optional[float]=None) -> Optional[float]:
            m=re.search(pattern, line)
            try:
                return float(m.group(1)) if m else default
            except Exception:
                return default
        s={
            "ssrc": re.search(r"SSRC=([0-9a-fxA-F]+)", line).group(1) if re.search(r"SSRC=([0-9a-fxA-F]+)", line) else None,
            "ip_src": re.search(r"From (\S+):(\d+)", line).group(1) if re.search(r"From (\S+):(\d+)", line) else None,
            "port_src": int(re.search(r"From (\S+):(\d+)", line).group(2)) if re.search(r"From (\S+):(\d+)", line) else None,
            "ip_dst": re.search(r"To (\S+):(\d+)", line).group(1) if re.search(r"To (\S+):(\d+)", line) else None,
            "port_dst": int(re.search(r"To (\S+):(\d+)", line).group(2)) if re.search(r"To (\S+):(\d+)", line) else None,
            "pkt": grab(r"Packets:(\d+)", 0) or 0,
            "lost": grab(r"Lost:(\d+)", 0) or 0,
            "jitter_ms": grab(r"Jitter:\s*([0-9.]+)") or 0.0,
            "kbps": grab(r"Bandwidth:\s*([0-9.]+)\s*kbits/s") or None,
            "pt": re.search(r"PT=([0-9]+)", line).group(1) if re.search(r"PT=([0-9]+)", line) else None,
        }
        try:
            loss_pct = (float(s["lost"]) / max(1.0, float(s["pkt"])))*100.0
        except Exception:
            loss_pct = 0.0
        codec = _load_cfg().get("default_codec","PCMU")
        s["loss_pct"]= round(loss_pct, 2)
        s["mos"] = _estimate_mos(loss_pct, float(s["jitter_ms"] or 0.0), codec)
        stats.append(s)
    return stats

@router.get("/rtp/stats", response_class=JSONResponse)
def rtp_stats(callid:str = Query(...), file: Optional[str] = Query(None)):
    p = _pcap_path_from_param(file) if file else _latest_pcap()
    if not p or not p.exists():
        return JSONResponse({"error":"no_pcap"}, status_code=404)
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        out_path = td/"call.pcapng"
        if not _export_call_with_rtp(p, callid, out_path):
            return JSONResponse({"error":"export_failed"}, status_code=500)
        stats = _rtp_stats_from_pcap(out_path)
        return {"callid":callid, "src_file": p.name, "rtp_streams": stats}

# --------------- Riepiloghi rapidi (SIP/RTP/DNS in pcap) ---------------
@router.get("/summary", response_class=JSONResponse)
def quick_summary(limit:int=Query(200, ge=10, le=2000), file: Optional[str] = Query(None)):
    p = _pcap_path_from_param(file) if file else _latest_pcap()
    if not p or not p.exists():
        return JSONResponse({"error":"no_pcap"}, status_code=404)
    rc1, out1, _ = _run(["/usr/bin/tshark","-r",str(p),"-Y","sip.Method","-T","fields","-e","sip.Method"], timeout=90)
    rc2, out2, _ = _run(["/usr/bin/tshark","-r",str(p),"-Y","sip.Status-Code","-T","fields","-e","sip.Status-Code"], timeout=90)
    rc3, out3, _ = _run(["/usr/bin/tshark","-r",str(p),"-Y","dns.flags.response == 1 && (dns.naptr || dns.srv.name)","-T","fields","-e","dns.qry.name","-e","dns.srv.name","-e","dns.naptr.service"], timeout=90)
    from collections import Counter
    mcount = Counter(out1.split()) if rc1==0 else Counter()
    scount = Counter(out2.split()) if rc2==0 else Counter()
    dns_rows = [l.split("\t") for l in out3.splitlines()] if rc3==0 else []
    rc4, out4, _ = _run(["/usr/bin/tshark","-r",str(p),"-Y","sip","-T","fields","-e","ip.src","-e","ip.dst"], timeout=90)
    pairs = [tuple(x.split("\t")) for x in out4.splitlines() if "\t" in x] if rc4==0 else []
    ep = Counter([a for a,_ in pairs] + [b for _,b in pairs])
    return {
        "src_file": p.name,
        "methods": mcount.most_common(20),
        "status": scount.most_common(20),
        "dns": dns_rows[:limit],
        "top_endpoints": ep.most_common(20)
    }

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
    try:
        ports=[int(x.strip()) for x in sip_ports.split(",") if x.strip()]
        cfg["sip_ports"]= [p for p in ports if 1<=p<=65535] or [5060,5061]
    except Exception:
        cfg["sip_ports"]= [5060,5061]
    try:
        a,b = rtp_range.replace(" ","").split("-",1)
        a,b=int(a),int(b)
        if a>b: a,b=b,a
        a=max(1,a); b=min(65535,b)
        cfg["rtp_range"]= [a,b]
    except Exception:
        cfg["rtp_range"]= [10000,20000]

    cfg["duration_max"]=max(1, min(int(duration_max), 86400))
    try:
        cfg["quota_gb"]=max(1.0, float(quota_gb))
    except Exception:
        cfg["quota_gb"]=DEFAULT_CFG["quota_gb"]
    cfg["policy"]= "rotate" if policy=="rotate" else "block"
    cfg["allow_bpf"]= bool(allow_bpf)
    cfg["privacy_mask_user"]= bool(privacy_mask_user)
    cfg["ui_poll_ms"]= max(250, min(int(ui_poll_ms), 20000))
    _save_cfg(cfg)
    return RedirectResponse(url="/voip/settings", status_code=303)

@router.get("/kpi", response_class=JSONResponse)
def kpi_latest_capture(file: Optional[str] = Query(None)):
    p = _pcap_path_from_param(file) if file else _latest_pcap()
    if not p or not p.exists():
        return {"error": "no_pcap"}
    stats = _rtp_stats_from_pcap(p)
    if not stats:
        return {
            "src_file": p.name,
            "rtp_streams": 0,
            "mos_avg": None, "jitter_avg_ms": None, "loss_avg_pct": None, "kbps_avg": None,
            "streams": []
        }
    def vals(k): return [float(s[k]) for s in stats if s.get(k) is not None]
    out = {
        "src_file": p.name,
        "rtp_streams": len(stats),
        "mos_avg": round(mean(vals("mos")), 2) if vals("mos") else None,
        "jitter_avg_ms": round(mean(vals("jitter_ms")), 2) if vals("jitter_ms") else None,
        "loss_avg_pct": round(mean(vals("loss_pct")), 2) if vals("loss_pct") else None,
        "kbps_avg": round(mean(vals("kbps")), 2) if vals("kbps") else None,
        "streams": stats
    }
    return out
