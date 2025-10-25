from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from html import escape
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import subprocess, threading, time, json, re, ipaddress, shutil, os
from collections import Counter

from routes.auth import verify_session_cookie, _load_users
from util.audit import log_event

router = APIRouter(prefix="/netmap", tags=["netmap"])

# --- paths ---
BASE_DIR   = Path("/var/lib/netprobe/netmap")
SCANS_DIR  = BASE_DIR / "scans"
INDEX_FILE = BASE_DIR / "index.json"  # {"scans":[{id, started, target, iface, hosts_up, note}]}

# --- internal runtime state ---
_current_lock = threading.Lock()
_current: Dict[str,Any] = {}  # {"id":..., "phase": "...", "progress": 0..100, "started": ts}

# --- helpers base ------------------------------------------------------------
def _run(cmd: List[str], timeout: Optional[int]=None) -> Tuple[int,str,str]:
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

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
        for s in out.splitlines():
            try:
                name=s.split(":")[1].strip().split("@")[0]
                if name and name!="lo": devs.append(name)
            except Exception: pass
    outl=[]
    for d in devs:
        if d not in outl: outl.append(d)
    return outl

def _validate_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        return False

def _load_index() -> Dict[str,Any]:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text(json.dumps({"scans":[]}, indent=2), encoding="utf-8")
    try:
        return json.loads(INDEX_FILE.read_text("utf-8"))
    except Exception:
        return {"scans":[]}

def _save_index(idx: Dict[str,Any]):
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=2), encoding="utf-8")
    os.replace(tmp, INDEX_FILE)

def _scan_path(scan_id:str) -> Path:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    return SCANS_DIR / f"{scan_id}.json"

def _save_scan(scan: Dict[str,Any]):
    p = _scan_path(scan["id"])
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    os.replace(tmp, p)

def _mac_vendor_resolver() -> Dict[str,str]:
    db = {}
    for cand in ["/usr/share/ieee-data/oui.txt", "/usr/share/ieee-oui/oui.txt"]:
        if Path(cand).exists():
            try:
                txt = Path(cand).read_text(errors="ignore")
                for line in txt.splitlines():
                    # "FC-34-97   (hex)        Intel Corporate"
                    m=re.match(r"^([0-9A-F]{2})[-:]?([0-9A-F]{2})[-:]?([0-9A-F]{2}).*?\)\s+(.+)$", line.strip(), re.I)
                    if m:
                        key = f"{m.group(1)}:{m.group(2)}:{m.group(3)}".upper()
                        db[key] = m.group(4).strip()
            except Exception:
                pass
    return db

_VENDOR_CACHE = _mac_vendor_resolver()

def _vendor_from_mac(mac: Optional[str]) -> Optional[str]:
    if not mac: return None
    mac = mac.upper().replace("-",":")
    parts = mac.split(":")
    if len(parts) < 3: return None
    key = ":".join(parts[:3])
    return _VENDOR_CACHE.get(key)

# --- auth helpers ------------------------------------------------------------
def _is_admin(req: Request) -> bool:
    if req.headers.get("X-Admin", "").lower() in ("1","true","yes"):
        return True
    user = verify_session_cookie(req)
    if not user:
        return False
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

def _require_admin(req: Request):
    if not _is_admin(req):
        return JSONResponse({"error":"forbidden","detail":"Admin only"}, status_code=403)
    return None

# --- scanner core (thread) ---------------------------------------------------
def _parse_arp_scan(out: str) -> List[Dict[str,Any]]:
    hosts=[]
    for line in out.splitlines():
        m=re.match(r"^\s*([0-9.]+)\s+([0-9a-f:]{17})\s+(.+)$", line.strip(), re.I)
        if m:
            ip, mac, vend = m.group(1), m.group(2), m.group(3).strip()
            hosts.append({"ip":ip, "mac":mac.lower(), "vendor":vend})
    return hosts

def _parse_nmap_sn(out: str) -> List[str]:
    up=[]
    cur_ip=None
    for line in out.splitlines():
        m=re.match(r"^Nmap scan report for\s+(.+)$", line.strip())
        if m:
            token = m.group(1)
            m2=re.match(r".*\((\d+\.\d+\.\d+\.\d+)\)", token)
            ip = m2.group(1) if m2 else (token if re.match(r"\d+\.\d+\.\d+\.\d+$", token) else None)
            if ip:
                cur_ip=ip
                if ip not in up: up.append(ip)
    return up

def _parse_nmap_sv(out: str) -> Dict[str,Any]:
    hosts={}
    cur_ip=None
    for line in out.splitlines():
        m=re.match(r"^Nmap scan report for\s+(.+)$", line.strip())
        if m:
            token=m.group(1)
            m2=re.match(r".*\((\d+\.\d+\.\d+\.\d+)\)", token)
            ip = m2.group(1) if m2 else (token if re.match(r"\d+\.\d+\.\d+\.\d+$", token) else None)
            cur_ip=ip
            if cur_ip and cur_ip not in hosts:
                hosts[cur_ip]={"services":[]}
            continue
        m3=re.match(r"^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)(.*)$", line.strip())
        if cur_ip and m3:
            port=int(m3.group(1)); proto=m3.group(2); name=m3.group(3)
            rest=m3.group(4).strip()
            prod=None; ver=None
            if rest:
                prod=rest[:120]
            hosts[cur_ip]["services"].append({
                "port":port,"proto":proto,"name":name,"product":prod,"version":ver,"state":"open"
            })
    return hosts

def _human_ts(ts:int)->str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return "-"

def _scan_thread(scan_id:str, iface:str, cidr:str, speed:str, tcp_top:bool, os_detect:bool, note:str):
    with _current_lock:
        _current.update({"id":scan_id, "phase":"discovery", "progress":5, "started":int(time.time())})

    started=int(time.time())
    scan = {
        "id": scan_id,
        "iface": iface,
        "target": cidr,
        "started": started,
        "ended": None,
        "options": {"speed": speed, "tcp_top": tcp_top, "os": os_detect},
        "summary": {"hosts_up": 0, "open_ports": 0, "vendors": {}},
        "hosts": [],
        "note": note or None,
    }
    _save_scan(scan)

    # 1) discovery
    hosts: Dict[str,Dict[str,Any]] = {}
    rc, out, err = _run(["/usr/sbin/arp-scan","--interface",iface,"--localnet","--plain"])
    if rc==0 and out.strip():
        for h in _parse_arp_scan(out):
            ip=h["ip"]; mac=h.get("mac"); vend=h.get("vendor") or _vendor_from_mac(mac)
            hosts[ip]={"ip":ip,"mac":mac,"vendor":vend,"hostname":None,"services":[]}
    else:
        args=["/usr/bin/nmap","-sn","-PR","-PE","-T"+speed,"-n","-e",iface, cidr]
        rc2, out2, err2 = _run(args)
        up = _parse_nmap_sn(out2 if rc2==0 else "")
        for ip in up:
            hosts[ip]={"ip":ip,"mac":None,"vendor":None,"hostname":None,"services":[]}
        rc3, neigh, _ = _run(["/usr/sbin/ip","neigh","show"])
        for line in neigh.splitlines():
            m=re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+.*\s+lladdr\s+([0-9a-f:]{17})", line.strip(), re.I)
            if m and m.group(1) in hosts:
                mac=m.group(2).lower()
                hosts[m.group(1)]["mac"]=mac
                hosts[m.group(1)]["vendor"]=_vendor_from_mac(mac)

    with _current_lock:
        _current.update({"phase":"discovery", "progress":25})

    with _current_lock:
        _current.update({"phase":"services", "progress":30})

    # 2) services
    up_ips = list(hosts.keys())
    if tcp_top and up_ips:
        batched=[up_ips[i:i+64] for i in range(0,len(up_ips),64)]
        for i,b in enumerate(batched, start=1):
            args=["/usr/bin/nmap","-sS","-sV","--top-ports","200","-T"+speed,"-n","-e",iface] + b
            rc, out, err = _run(args, timeout=600)
            parsed = _parse_nmap_sv(out if rc==0 else "")
            for ip, data in parsed.items():
                if ip in hosts:
                    hosts[ip]["services"].extend(data.get("services",[]))
            with _current_lock:
                pct = 30 + int(i * 50 / max(1, len(batched)))  # 30→80
                _current.update({"phase":"services", "progress":pct})

    with _current_lock:
        _current.update({"phase":"services", "progress":80})

    # 3) OS detection (light)
    if os_detect and up_ips:
        with _current_lock:
            _current.update({"phase":"os-detect", "progress":85})
        try:
            args=["/usr/bin/nmap","-O","--osscan-guess","-T"+speed,"-n","-e",iface] + up_ips[:64]
            rc, out, err = _run(args, timeout=600)
            cur=None
            for line in out.splitlines():
                m=re.match(r"^Nmap scan report for\s+(.+)$", line.strip())
                if m:
                    token=m.group(1)
                    m2=re.match(r".*\((\d+\.\d+\.\d+\.\d+)\)", token)
                    cur = m2.group(1) if m2 else (token if re.match(r"\d+\.\d+\.\d+\.\d+$", token) else None)
                    continue
                if cur:
                    m2=re.match(r"^OS details:\s+(.+)$", line.strip())
                    if m2 and cur in hosts:
                        hosts[cur]["os"]={"name": m2.group(1)[:120], "accuracy": None}
        except Exception:
            pass
        with _current_lock:
            _current.update({"phase":"os-detect", "progress":92})

    # 4) finalize
    with _current_lock:
        _current.update({"phase":"finalize", "progress":98})

    ended=int(time.time())
    host_list=[]
    vend_count={}
    open_ports=0
    for ip,h in hosts.items():
        rdns=None
        try:
            rc, out, _ = _run(["/usr/bin/dig","+short","-x",ip])
            rdns = out.splitlines()[0].strip(".") if (rc==0 and out.strip()) else None
        except Exception:
            pass
        h["hostname"]=rdns
        if h.get("vendor"):
            vend_count[h["vendor"]]=vend_count.get(h["vendor"],0)+1
        open_ports += sum(1 for s in h.get("services",[]) if s.get("state")=="open")
        h["last_seen"]=ended
        host_list.append(h)

    scan.update({
        "ended": ended,
        "summary": {
            "hosts_up": len(host_list),
            "open_ports": open_ports,
            "vendors": vend_count
        },
        "hosts": sorted(host_list, key=lambda x: x["ip"])
    })
    _save_scan(scan)

    # index
    idx=_load_index()
    idx_scans=idx.get("scans",[])
    idx_scans=[s for s in idx_scans if s.get("id")!=scan_id]
    idx_scans.append({
        "id": scan_id,
        "started": started,
        "ended": ended,
        "target": cidr,
        "iface": iface,
        "hosts_up": len(host_list),
        "note": note or ""
    })
    idx["scans"]=sorted(idx_scans, key=lambda s: s["started"], reverse=True)
    _save_index(idx)

    with _current_lock:
        _current.update({"phase":"done", "progress":100})
    time.sleep(0.6)
    with _current_lock:
        _current.clear()

# --- UI ----------------------------------------------------------------------
def _page_head(title:str)->str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'><div class='nav'><div class='brand'>"
        "<img src='/static/img/logo.svg' class='logo'/>"
        "<span>TestMachine</span></div><div class='links'>"
        "<a class='btn small secondary' href='/'>Home</a></div></div>"
    )

@router.get("/", response_class=HTMLResponse)
def netmap_home():
    ifaces=_list_ifaces()
    opt="".join(f"<option value='{escape(i)}'>{escape(i)}</option>" for i in ifaces) or "<option>ens4</option>"

    # scans salvate
    idx=_load_index()
    rows=[]
    for s in idx.get("scans",[])[:50]:
        sid=escape(s["id"])
        note = s.get("note") or ""
        short = (note[:40] + "…") if len(note) > 40 else note
        rows.append(
            "<tr>"
            f"<td class='mono'>{sid}</td>"
            f"<td class='mono'>{escape(s.get('iface','-'))}</td>"
            f"<td class='mono'>{escape(s.get('target','-'))}</td>"
            f"<td class='mono'>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(s.get('started',0) or 0)))}</td>"
            f"<td class='mono'>{int(s.get('hosts_up',0) or 0)}</td>"
            f"<td class='muted' title='{escape(note)}'>{escape(short) or '-'}</td>"
            f"<td>"
            f"  <a class='btn small' href='/netmap/view?id={sid}'>Apri</a>"
            f"  <a class='btn small secondary' href='/netmap/export?id={sid}&fmt=json'>JSON</a>"
            f"  <a class='btn small secondary' href='/netmap/export?id={sid}&fmt=csv'>CSV</a>"
            f"  <button class='btn small secondary' onclick=\"editNote('{sid}')\">Nota</button>"
            f"  <button class='btn small danger' onclick=\"delScan('{sid}')\">Elimina</button>"
            f"</td>"
            "</tr>"
        )
    table = "".join(rows) or "<tr><td colspan='7' class='muted'>Nessuna scansione.</td></tr>"

    html=_page_head("Net Mapper") + """
<style>
  .grid2{display:grid;gap:16px;grid-template-columns:1fr;} /* card storico in basso */
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
  .table{overflow-x:auto}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px 10px;white-space:nowrap}
  .tiny{font-size:.85em}

  .progress{position:relative;height:10px;background:rgba(255,255,255,.12);border-radius:999px;overflow:hidden;margin-top:6px}
  .progress .bar{position:absolute;inset:0 100% 0 0;background:linear-gradient(90deg,#60a5fa,#22c55e);transition:inset .25s ease}
  .muted-row{opacity:.8}
</style>

<div class='grid2'>
  <div class='card'>
    <h2>Nuova scansione</h2>
    <form method='post' action='/netmap/start' id='startForm'>
      <div class='row'>
        <div>
          <label>Interfaccia</label>
          <select name='iface'>__OPT__</select>
        </div>
        <div>
          <label>Rete (CIDR)</label>
          <input name='cidr' value='192.168.1.0/24' required/>
        </div>
      </div>
      <div class='row'>
        <div>
          <label>Velocità</label>
          <select name='speed'>
            <option value='T2'>T2 (moderata)</option>
            <option value='T3' selected>T3 (bilanciata)</option>
            <option value='T4'>T4 (aggressiva)</option>
          </select>
        </div>
        <div>
          <label>Opzioni</label>
          <label class='row' style='gap:8px;align-items:center'><input type='checkbox' name='tcp_top' checked/> TCP top-ports</label>
          <label class='row' style='gap:8px;align-items:center'><input type='checkbox' name='os_detect'/> OS fingerprint</label>
        </div>
      </div>
      <label>Nota (facoltativa)</label>
      <input name='note' placeholder='es. ufficio 2° piano'/>
      <div class='row' style='gap:8px;flex-wrap:wrap;margin-top:8px'>
        <button class='btn' type='submit'>Avvia</button>
        <button class='btn secondary' type='button' onclick='pollStatus(true)'>Aggiorna stato</button>
      </div>
    </form>
    <div id='statusBox' class='tiny muted-row' style='margin-top:8px'>
      <div>Stato: <b id='st_phase'>-</b> — <span id='st_prog'>0%</span></div>
      <div class='progress'><div id='st_bar' class='bar'></div></div>
    </div>
  </div>

  <div class='card'>
    <h2>Storico scansioni</h2>
    <div class='table'>
      <table>
        <thead><tr><th>ID</th><th>If</th><th>Target</th><th>Inizio</th><th>Hosts</th><th>Nota</th><th>Azioni</th></tr></thead>
        <tbody>
          __TABLE__
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
async function pollStatus(forceOnce){
  try{
    const r = await fetch('/netmap/status'); const js = await r.json();
    const bar = document.getElementById('st_bar');
    const lbl = document.getElementById('st_prog');
    const phase = document.getElementById('st_phase');
    const form = document.getElementById('startForm');
    const inputs = form.querySelectorAll('input, select, button[type=submit]');

    if(js.active){
      const p = Math.max(0, Math.min(100, Number(js.progress||0)));
      phase.textContent = js.phase || '-';
      lbl.textContent = p + '%';
      bar.style.inset = `0 ${100-p}% 0 0`;
      inputs.forEach(el => el.disabled = (el.type === 'button') ? false : true);
      setTimeout(()=>pollStatus(), 1000);
    }else{
      phase.textContent = '-';
      lbl.textContent = '0%';
      bar.style.inset = '0 100% 0 0';
      inputs.forEach(el => el.disabled = false);
      if(forceOnce!==true){ /* noop */ }
    }
  }catch(e){
    const form = document.getElementById('startForm');
    form.querySelectorAll('input, select, button[type=submit]').forEach(el => el.disabled = false);
  }
}
pollStatus(true);

setInterval(async () => {
  try{
    const r = await fetch('/netmap/status'); const js = await r.json();
    const rows = document.querySelectorAll('tbody tr');
    rows.forEach(tr => tr.classList.remove('muted-row'));
    if(js.active){
      const first = document.querySelector('tbody tr');
      if(first) first.classList.add('muted-row');
    }
  }catch(e){}
}, 3000);

async function delScan(id){
  if(!confirm('Eliminare '+id+'?')) return;
  await fetch('/netmap/delete', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'id='+encodeURIComponent(id)});
  location.reload();
}

async function editNote(id){
  const v = prompt('Inserisci/aggiorna nota per '+id+':');
  if (v===null) return;
  await fetch('/netmap/note', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'id='+encodeURIComponent(id)+'&note='+encodeURIComponent(v)});
  location.reload();
}
</script>
<script src="/static/bg.js"></script>
</body></html>
"""
    html = html.replace("__OPT__", opt)
    html = html.replace("__TABLE__", table)
    return HTMLResponse(html)

@router.get("/view", response_class=HTMLResponse)
def netmap_view(id: str = Query(...)):
    p=_scan_path(id)
    if not p.exists():
        return HTMLResponse("<h3 style='margin:2rem'>Scan non trovato</h3>", status_code=404)
    js = json.loads(p.read_text("utf-8"))
    hosts = js.get("hosts", []) or []

    # ---- riassunti ---------------------------------------------------------
    vend_counter = Counter((h.get("vendor") or "(Unknown)") for h in hosts)
    vend_top = vend_counter.most_common(6)
    vend_html = "".join(
        f"<div class='bar'><span class='lbl'>{escape(v)}</span><span class='val'>{n}</span></div>"
        for v, n in vend_top
    ) or "<div class='muted'>N/A</div>"

    svc_list = []
    for h in hosts:
        for s in h.get("services", []) or []:
            name = s.get("name") or f"{s.get('proto','?')}/{s.get('port','?')}"
            svc_list.append(name)
    svc_counter = Counter(svc_list)
    svc_top = svc_counter.most_common(6)
    svc_html = "".join(
        f"<div class='bar'><span class='lbl'>{escape(s)}</span><span class='val'>{n}</span></div>"
        for s, n in svc_top
    ) or "<div class='muted'>N/A</div>"

    os_counter = Counter(((h.get("os") or {}).get("name") or "(sconosciuto)") for h in hosts if h.get("os"))
    os_top = os_counter.most_common(6)
    os_html = "".join(
        f"<div class='bar'><span class='lbl'>{escape(o)}</span><span class='val'>{n}</span></div>"
        for o, n in os_top
    ) or "<div class='muted'>N/A</div>"

    # ---- tabella host ------------------------------------------------------
    rows=[]
    for h in hosts:
        ports = [f"{s.get('proto')}/{s.get('port')} {escape(s.get('name') or '')}" for s in (h.get("services") or [])]
        ip = escape(h.get('ip','-'))
        rows.append(
            "<tr data-ip='{ip}'>"
            f"<td class='mono'>{ip}</td>"
            f"<td class='mono'>{escape(h.get('hostname') or '-')}</td>"
            f"<td class='mono'>{escape(h.get('mac') or '-')}</td>"
            f"<td class='mono'>{escape(h.get('vendor') or '-')}</td>"
            f"<td class='mono'>{escape((h.get('os') or {}).get('name') or '-')}</td>"
            f"<td>{escape(', '.join(ports) or '-')}</td>"
            f"<td><button class='btn small' onclick=\"showHost('{ip}')\">Dettagli</button></td>"
            "</tr>"
        )
    table_html = "".join(rows) or "<tr><td colspan='7' class='muted'>Nessun host rilevato.</td></tr>"

    # Nota / KPI
    note = js.get("note")
    note_html = f"<div class='muted tiny'>Nota: <span class='mono'>{escape(note)}</span></div>" if note else ""
    hosts_up   = js.get("summary", {}).get("hosts_up", len(hosts))
    open_ports = js.get("summary", {}).get("open_ports", 0)
    vendors_num= len(vend_counter)
    os_known   = sum(1 for h in hosts if h.get("os"))

    # JSON al client (escape </)
    data_json = json.dumps(js).replace("</", "<\\/")

    html = _page_head("Net Mapper – Risultati") + """
<style>
  .grid{display:grid;gap:16px}
  .full{grid-column:1 / -1}
  .row3{grid-column:1 / -1; display:grid; gap:16px; grid-template-columns:repeat(3, minmax(0,1fr)); width:100%;}
  @media (max-width:1100px){ .row3{ grid-template-columns:1fr } }
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
  .table{overflow-x:auto}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px 10px;white-space:nowrap}
  .tiny{font-size:.85em}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid rgba(255,255,255,.18);border-radius:999px;margin-right:6px}
  .bar{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border:1px solid rgba(255,255,255,.12);border-radius:10px;margin-bottom:6px}
  .lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:75%}
  .val{font-weight:700;opacity:.9}
  .searchbox{margin:8px 0 12px; display:flex; gap:10px; align-items:center}
  .modal{position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; align-items:center; justify-content:center; z-index:50}
  .modal .panel{background:rgba(17,24,39,.98); border:1px solid rgba(255,255,255,.12); border-radius:16px; padding:16px; width:min(860px, 94vw)}
  .badges>span{display:inline-block; margin:3px 6px 0 0; padding:3px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.12)}
</style>

<div class='grid'>

  <div class='card full'>
    <h2>Risultati: <span class='mono'>__ID__</span></h2>
    <div class='tiny muted'>
      Interfaccia <b>__IFACE__</b> — Target <b>__TARGET__</b>
      — Avvio <b>__START__</b> — Fine <b>__END__</b> — Durata <b>__DUR__s</b>
    </div>
    __NOTE__
    <div style="margin-top:10px">
      <span class='pill'>🧩 Hosts <b>__HOSTS__</b></span>
      <span class='pill'>🔓 Porte aperte <b>__OPEN__</b></span>
      <span class='pill'>🏷️ Vendors <b>__VNUM__</b></span>
      <span class='pill'>🧪 OS noti <b>__OSKNOWN__</b></span>
    </div>
  </div>

  <div class='row3 full'>
    <div class='card'>
      <h3>Distribuzione Vendor (top)</h3>
      __VEND__
    </div>
    <div class='card'>
      <h3>Porte/Servizi più comuni (top)</h3>
      __SVC__
    </div>
    <div class='card'>
      <h3>Sistemi Operativi (best-effort)</h3>
      __OS__
    </div>
  </div>

  <div class='card full'>
    <h3>Elenco Host</h3>
    <div class='searchbox'>
      <input id='q' placeholder='Cerca IP/hostname/MAC/vendor/porta…' style='flex:1'/>
      <button class='btn small secondary' onclick='doFilter()'>Filtra</button>
      <button class='btn small' onclick='resetFilter()'>Reset</button>
    </div>
    <div class='table' style='margin-top:8px'>
      <table id='hostsTable'>
        <thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>OS</th><th>Servizi</th><th></th></tr></thead>
        <tbody>__TABLE__</tbody>
      </table>
    </div>
    <div class='row' style='gap:8px;margin-top:10px'>
      <a class='btn secondary' href='/netmap/export?id=__ID__&fmt=json'>Export JSON</a>
      <a class='btn secondary' href='/netmap/export?id=__ID__&fmt=csv'>Export CSV</a>
      <a class='btn' href='/netmap'>Torna</a>
    </div>
  </div>

</div>

<div id='modal' class='modal' onclick="if(event.target.id==='modal') this.style.display='none'">
  <div class='panel'>
    <div class='row' style='justify-content:space-between; align-items:center'>
      <h3 id='m_title'>Host</h3>
      <button class='btn small danger' onclick="document.getElementById('modal').style.display='none'">Chiudi</button>
    </div>
    <div id='m_body' style='margin-top:8px'></div>
  </div>
</div>

<script>
const DATA = __DATA__;

function doFilter(){
  const q = (document.getElementById('q').value||'').toLowerCase().trim();
  const rows = document.querySelectorAll('#hostsTable tbody tr');
  rows.forEach(r=>{
    const txt = r.innerText.toLowerCase();
    r.style.display = (!q || txt.indexOf(q)>=0) ? '' : 'none';
  });
}
function resetFilter(){
  document.getElementById('q').value='';
  doFilter();
}
function showHost(ip){
  const h = (DATA.hosts||[]).find(x=>x.ip===ip);
  if(!h) return;
  const body = document.getElementById('m_body');
  const title = document.getElementById('m_title');
  title.textContent = 'Host '+(h.ip||'-');

  const badges = (h.services||[]).map(s=>{
    const nm = s.name || '';
    const pp = (s.proto||'?') + '/' + (s.port||'?');
    return `<span>${pp} ${escapeHtml(nm)}</span>`;
  }).join('');

  body.innerHTML = `
    <div class='row' style='gap:14px; flex-wrap:wrap'>
      <div><div class='tiny muted'>IP</div><div class='mono'>${escapeHtml(h.ip||'-')}</div></div>
      <div><div class='tiny muted'>Hostname</div><div class='mono'>${escapeHtml(h.hostname||'-')}</div></div>
      <div><div class='tiny muted'>MAC</div><div class='mono'>${escapeHtml(h.mac||'-')}</div></div>
      <div><div class='tiny muted'>Vendor</div><div class='mono'>${escapeHtml(h.vendor||'-')}</div></div>
      <div><div class='tiny muted'>OS</div><div class='mono'>${escapeHtml((h.os||{}).name||'-')}</div></div>
    </div>
    <div style='margin-top:12px'>
      <div class='tiny muted' style='margin-bottom:6px'>Servizi</div>
      <div class='badges'>${badges || '<span class="muted tiny">Nessun servizio rilevato</span>'}</div>
    </div>
    <div class='row' style='gap:8px;margin-top:12px'>
      <button class='btn small secondary' onclick="copyText(h.ip||'')">Copia IP</button>
      ${h.mac ? `<button class='btn small secondary' onclick="copyText(h.mac)">Copia MAC</button>` : ''}
    </div>`;
  document.getElementById('modal').style.display='flex';
}
function copyText(t){ navigator.clipboard.writeText(t||''); }
function escapeHtml(s){
  if(!s) return '';
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
}
</script>
</body></html>
"""
    html = (html
        .replace("__ID__", escape(id))
        .replace("__IFACE__", escape(js.get("iface","-") or "-"))
        .replace("__TARGET__", escape(js.get("target","-") or "-"))
        .replace("__START__", escape(_human_ts(js.get("started") or 0)))
        .replace("__END__",   escape(_human_ts(js.get("ended") or 0)))
        .replace("__DUR__",   str(max(0, (js.get("ended") or 0) - (js.get("started") or 0))))
        .replace("__NOTE__",  note_html)
        .replace("__HOSTS__", str(hosts_up))
        .replace("__OPEN__",  str(open_ports))
        .replace("__VNUM__",  str(vendors_num))
        .replace("__OSKNOWN__", str(os_known))
        .replace("__VEND__", vend_html)
        .replace("__SVC__",  svc_html)
        .replace("__OS__",   os_html)
        .replace("__TABLE__", table_html)
        .replace("__DATA__", data_json)
    )
    return HTMLResponse(html)

# --- API ---------------------------------------------------------------------

@router.post("/start")
def start(request: Request,
          iface: str = Form(...),
          cidr: str  = Form(...),
          speed: str = Form("T3"),
          tcp_top: Optional[str] = Form(None),
          os_detect: Optional[str] = Form(None),
          note: str = Form("")):
    if _require_admin(request): return _require_admin(request)
    if iface not in _list_ifaces():
        return HTMLResponse("<script>alert('Interfaccia non valida');history.back();</script>", status_code=400)
    if not _validate_cidr(cidr):
        return HTMLResponse("<script>alert('CIDR non valida');history.back();</script>", status_code=400)
    with _current_lock:
        if _current:
            return HTMLResponse("<script>alert('Scansione già in corso. Attendere la fine.');history.back();</script>", status_code=409)
    scan_id = f"scan-{int(time.time())}"
    t = threading.Thread(target=_scan_thread, kwargs=dict(
        scan_id=scan_id, iface=iface, cidr=cidr, speed=speed,
        tcp_top=bool(tcp_top), os_detect=bool(os_detect), note=note.strip()
    ), daemon=True)
    t.start()
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("netmap/start", ok=True, actor=actor, ip=ip, req_path=str(request.url),
              detail=f"id={scan_id}", extra={"iface": iface, "cidr": cidr, "speed": speed,
                                             "tcp_top": bool(tcp_top), "os_detect": bool(os_detect)})
    return RedirectResponse(url="/netmap", status_code=303)

@router.get("/status", response_class=JSONResponse)
def status():
    with _current_lock:
        if not _current:
            return {"active": False}
        return {"active": True, **_current}

@router.get("/list", response_class=JSONResponse)
def list_scans():
    idx=_load_index()
    return idx

@router.get("/result", response_class=JSONResponse)
def result(id: str = Query(...)):
    p=_scan_path(id)
    if not p.exists():
        return JSONResponse({"error":"not_found"}, status_code=404)
    return json.loads(p.read_text("utf-8"))

@router.get("/export")
def export(id: str = Query(...), fmt: str = Query("json")):
    p=_scan_path(id)
    if not p.exists():
        return HTMLResponse("Scan non trovato", status_code=404)
    if fmt=="json":
        return FileResponse(p, filename=f"{id}.json", media_type="application/json")
    elif fmt=="csv":
        js=json.loads(p.read_text("utf-8"))
        note = (js.get("note") or "").replace("\n"," ").strip()
        rows=["ip,hostname,mac,vendor,os,ports,note"]
        for h in js.get("hosts", []):
            ports = ";".join([f"{s.get('proto')}/{s.get('port')} {s.get('name')}" for s in h.get("services",[])])
            row = [
                h.get("ip",""), h.get("hostname") or "", h.get("mac") or "",
                h.get("vendor") or "", (h.get("os") or {}).get("name") or "", ports,
                note
            ]
            rows.append(",".join([('"'+x.replace('"','""')+'"') for x in row]))
        data="\n".join(rows).encode("utf-8")
        tmp = p.with_suffix(".csv")
        tmp.write_bytes(data)
        return FileResponse(tmp, filename=f"{id}.csv", media_type="text/csv")
    else:
        return HTMLResponse("Formato non supportato", status_code=400)

@router.post("/note", response_class=JSONResponse)
def update_note(request: Request, id: str = Form(...), note: str = Form("")):
    if _require_admin(request): return _require_admin(request)
    p=_scan_path(id)
    if not p.exists():
        return JSONResponse({"status":"error","detail":"not_found"}, status_code=404)
    js=json.loads(p.read_text("utf-8"))
    js["note"]=note.strip() or None
    _save_scan(js)
    idx=_load_index()
    for s in idx.get("scans",[]):
        if s.get("id")==id:
            s["note"]=note.strip() or ""
            break
    _save_index(idx)
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("netmap/note", ok=True, actor=actor, ip=ip, req_path=str(request.url),
              detail=f"id={id}", extra={"note_len": len(note or "")})
    return {"status":"ok"}

@router.post("/delete", response_class=JSONResponse)
def delete(request: Request, id: str = Form(...)):
    if _require_admin(request): return _require_admin(request)
    p=_scan_path(id)
    if not p.exists():
        return {"status":"error","detail":"not_found"}
    try:
        p.unlink()
    except Exception as e:
        return {"status":"error","detail":str(e)}
    idx=_load_index()
    idx["scans"]=[s for s in idx.get("scans",[]) if s.get("id")!=id]
    _save_index(idx)
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("netmap/delete", ok=True, actor=actor, ip=ip, req_path=str(request.url), detail=f"id={id}")
    return {"status":"ok"}
