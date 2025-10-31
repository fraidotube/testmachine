# /opt/netprobe/app/jobs/alertd.py
from __future__ import annotations
import os, re, json, time, shutil, subprocess, urllib.request, urllib.parse
from pathlib import Path
import sys

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

CFG        = Path("/etc/netprobe/alerts.json")
STATE      = Path("/var/lib/netprobe/tmp/alertd.state.json")
AUDIT      = Path("/var/lib/netprobe/logs/audit.jsonl")
SPEED_HIST = Path("/var/lib/netprobe/speedtest/history.jsonl")
SP_DB      = Path("/etc/smokeping/config.d/Database")
DBG        = Path("/var/lib/netprobe/tmp/alertd.debug")  # debug leggero

def _d(msg:str):
    try:
        DBG.parent.mkdir(parents=True, exist_ok=True)
        DBG.open("a", encoding="utf-8").write(f"[{int(time.time())}] {msg}\n")
    except Exception:
        pass

def _load(path:Path, default):
    try: return json.loads(path.read_text("utf-8"))
    except Exception: return default

def _save(path:Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)

def _http_ok(url:str, timeout:int=5)->bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 400
    except Exception:
        return False

def _is_active(unit:str)->bool:
    p = subprocess.run(["/bin/systemctl","is-active","--quiet",unit],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0

def _apache_port()->int:
    try:
        txt = Path("/etc/apache2/sites-available/testmachine.conf").read_text("utf-8",errors="ignore")
        m = re.search(r"<VirtualHost\s+\*:(\d+)>", txt)
        return int(m.group(1)) if m else 8080
    except Exception:
        return 8080

def _smokeping_datadir()->Path|None:
    try:
        txt = SP_DB.read_text("utf-8",errors="ignore")
        m = re.search(r"(?m)^\s*datadir\s*=\s*(\S+)", txt)
        if m: return Path(m.group(1))
    except Exception:
        pass
    return None

# ===== Checks esistenti =====
def check_disk(cfg)->list[tuple[str,str]]:
    alerts=[]
    for pth in cfg.get("paths", []):
        try:
            u = shutil.disk_usage(pth)
            pct = int(round((u.used/u.total)*100))
            if pct >= int(cfg.get("warn_pct", 90)):
                alerts.append((f"disk:{pth}", f"Disk {pth} {pct}% (>{cfg.get('warn_pct',90)}%)"))
        except Exception:
            pass
    return alerts

def check_services(cfg)->list[tuple[str,str]]:
    alerts=[]
    for svc in cfg.get("list", []):
        if not _is_active(svc):
            alerts.append((f"svc:{svc}", f"Service DOWN: {svc}"))
    return alerts

def _latest_file_mtime(dir:Path)->float:
    latest=0.0
    for root,_,files in os.walk(dir):
        for f in files:
            try:
                t = (Path(root)/f).stat().st_mtime
                if t>latest: latest=t
            except Exception:
                pass
    return latest

def check_flow(cfg)->list[tuple[str,str]]:
    try:
        p=Path(cfg.get("dir","/var/lib/netprobe/flows"))
        if not p.exists(): return [("flow:dir", f"Flow dir not found: {p}")]
        latest = _latest_file_mtime(p)
        if latest==0: return [("flow:none","Nessun file flusso trovato")]
        if time.time() - latest > int(cfg.get("stale_min",10))*60:
            age=int((time.time()-latest)//60)
            return [("flow:stale", f"Flussi bloccati: ultimo flusso {age} min fa (>= {cfg.get('stale_min',10)}m)")]
    except Exception:
        pass
    return []

def check_cacti(cfg)->list[tuple[str,str]]:
    alerts=[]
    url = cfg.get("url") or f"http://127.0.0.1:{_apache_port()}/cacti/"
    if not _http_ok(url):
        alerts.append(("cacti:http","Cacti HTTP check failed"))
    d = Path(cfg.get("log_dir") or "/usr/share/cacti/site/log")
    try:
        mt = max((f.stat().st_mtime for f in d.glob("*.log")), default=0)
        if mt and (time.time()-mt) > int(cfg.get("log_stale_min",15))*60:
            alerts.append(("cacti:log","Cacti log bloccati (nessun aggiornamento recente)"))
    except Exception:
        pass
    return alerts

def check_smokeping(cfg)->list[tuple[str,str]]:
    alerts=[]
    if not _is_active("smokeping"):
        alerts.append(("smoke:svc","Smokeping service DOWN"))
    dd = _smokeping_datadir() or Path("/var/lib/smokeping")
    try:
        latest = _latest_file_mtime(dd)
        if latest==0:
            return alerts+[("smoke:rrd","Nessun RRD trovato")]
        if time.time()-latest > int(cfg.get("rrd_fresh_min",10))*60:
            alerts.append(("smoke:stale", f"Smokeping RRD bloccati (> {cfg.get('rrd_fresh_min',10)} min senza aggiornamenti)"))
    except Exception:
        pass
    return alerts

def check_speedtest(cfg)->list[tuple[str,str]]:
    try:
        with open(SPEED_HIST,"r",encoding="utf-8") as f:
            last=None
            for ln in f:
                try: last=json.loads(ln)
                except Exception: pass
        if not last: return []
        dl = (last.get("down_bps") or 0)/1e6
        ul = (last.get("up_bps") or 0)/1e6
        pg = last.get("ping_ms") or 0
        out=[]
        if dl < float(cfg.get("down_min_mbps", 0)): out.append(("speed:down", f"Download {dl:.1f} Mb/s < {cfg.get('down_min_mbps',0)}"))
        if ul < float(cfg.get("up_min_mbps",   0)): out.append(("speed:up",   f"Upload {ul:.1f} Mb/s < {cfg.get('up_min_mbps',0)}"))
        if pg > float(cfg.get("ping_max_ms",  9999)): out.append(("speed:ping", f"Ping {pg:.1f} ms > {cfg.get('ping_max_ms',9999)}"))
        return out
    except Exception:
        return []

def check_auth(cfg, last_ts:int)->tuple[list[tuple[str,str]], int]:
    fails=[]
    newest=last_ts
    try:
        with open(AUDIT,"r",encoding="utf-8") as f:
            for ln in f:
                try:
                    ev=json.loads(ln)
                except Exception:
                    continue
                ts=int(ev.get("ts",0)); newest=max(newest, ts)
                if ts < time.time()-int(cfg.get("window_min",5))*60:
                    continue
                act = ev.get("action","")
                is_fail = (act == "auth/login" and not ev.get("ok",False)) or act in ("auth/login_failed","auth/fail")
                if is_fail:
                    fails.append(ev.get("ip") or "unknown")
    except Exception:
        pass
    if len(fails)>=int(cfg.get("fail_threshold",3)):
        ipset=", ".join(sorted(set(fails)))
        return [("auth:fail", f"Tentativi login falliti: {len(fails)} negli ultimi {cfg.get('window_min',5)} min (IP: {ipset})")], newest
    return [], newest

# ===== Nuovo: LAN Watch DHCP =====
def _tail_jsonl(path:Path, max_bytes:int=200_000)->list[dict]:
    if not path.exists(): return []
    size = path.stat().st_size
    with open(path, "rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
            f.readline()
        data = f.read().decode("utf-8", "ignore")
    out=[]
    for ln in data.splitlines():
        ln=ln.strip()
        if not ln: continue
        try: out.append(json.loads(ln))
        except Exception: pass
    return out

def check_lanwatch_dhcp(checks)->list[tuple[str,str]]:
    lw = checks.get("lanwatch",{}) if isinstance(checks.get("lanwatch"), dict) else {}
    if not lw.get("enabled", True) or not lw.get("dhcp_enabled", False):
        return []
    logf = Path(lw.get("dhcp_log") or "/var/lib/netprobe/lanwatch/dhcp.jsonl")
    win  = int(lw.get("window_min", 10))
    now  = int(time.time())
    recent = _tail_jsonl(logf)
    alerts=[]
    for ev in recent:
        try:
            if ev.get("type") == "dhcp_offer" and not ev.get("allowed", True):
                ts = int(ev.get("ts", 0))
                if ts and (now - ts) <= win*60:
                    sip = ev.get("server_ip","?")
                    iface = ev.get("iface","?")
                    alerts.append(("lanwatch:rogue_dhcp", f"Rogue DHCP su {iface}: server {sip} (non in allow/gateway)"))
                    break
        except Exception:
            pass
    return alerts

# ===== Notifica =====
def _send_telegram(cfg:dict, text:str):
    chan = cfg.get("channels",{}).get("telegram",{})
    if not (isinstance(chan, dict) and chan.get("enabled")):
        return
    token = (chan.get("token") or "").strip()
    chat_id = str(chan.get("chat_id") or "").strip()
    if not token or not chat_id:
        return
    try:
        from util.notify import send_telegram
        send_telegram(token, chat_id, text)
        return
    except Exception:
        pass
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            _ = r.status
    except Exception:
        pass

def main():
    _d("start sweep")
    cfg = _load(CFG, {})
    if not cfg:
        _d("cfg vuota -> esco")
        return
    if int(time.time()) < int(cfg.get("silence_until",0)):
        _d("silenced -> esco")
        return

    st  = _load(STATE, {"sent":{}, "last_audit_ts":0})
    sent = st.get("sent",{}) if isinstance(st.get("sent"), dict) else {}
    alerts=[]

    checks = cfg.get("checks", {})
    # checks (tolleranti)
    if isinstance(checks.get("disk"), dict) and checks["disk"].get("enabled"):
        alerts += check_disk(checks["disk"])
    if isinstance(checks.get("services"), dict) and checks["services"].get("enabled"):
        alerts += check_services(checks["services"])
    if isinstance(checks.get("flow"), dict) and checks["flow"].get("enabled"):
        alerts += check_flow(checks["flow"])
    if isinstance(checks.get("cacti"), dict) and checks["cacti"].get("enabled"):
        alerts += check_cacti(checks["cacti"])
    if isinstance(checks.get("smokeping"), dict) and checks["smokeping"].get("enabled"):
        alerts += check_smokeping(checks["smokeping"])
    if isinstance(checks.get("speedtest"), dict) and checks["speedtest"].get("enabled"):
        alerts += check_speedtest(checks["speedtest"])
    if isinstance(checks.get("auth"), dict) and checks["auth"].get("enabled"):
        extra, newest = check_auth(checks["auth"], int(st.get("last_audit_ts",0)))
        alerts += extra
        st["last_audit_ts"] = newest

    # nuovo: LAN Watch DHCP
    try:
        alerts += check_lanwatch_dhcp(checks)
    except Exception as e:
        _d(f"lanwatch error: {e!r}")

    _d(f"alerts found: {alerts}")

    thr_min = int(cfg.get("throttle_min", 30))
    THROTTLE = max(0, thr_min) * 60
    now=int(time.time())
    to_send=[]
    for key,msg in alerts:
        last=int(sent.get(key,0))
        if (now-last)>=THROTTLE:
            to_send.append((key,msg))
            sent[key]=now
    st["sent"]=sent

    if to_send:
        text = "⚠️ TestMachine Alerts:\n" + "\n".join(f"- {m}" for _,m in to_send)
        _d(f"sending: {to_send}")
        _send_telegram(cfg, text)
    else:
        _d("nessun alert da inviare")

    _save(STATE, st)

if __name__=="__main__":
    main()
