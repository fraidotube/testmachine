# /opt/netprobe/app/jobs/alertd.py
from __future__ import annotations
import os, re, json, time, shutil, subprocess, urllib.request, urllib.parse
from pathlib import Path
import sys

# Rende importabile util.* quando lanciato come script di systemd
APP_ROOT = Path(__file__).resolve().parents[1]  # /opt/netprobe/app
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

CFG        = Path("/etc/netprobe/alerts.json")
STATE      = Path("/var/lib/netprobe/tmp/alertd.state.json")
AUDIT      = Path("/var/lib/netprobe/logs/audit.jsonl")
SPEED_HIST = Path("/var/lib/netprobe/speedtest/history.jsonl")
SP_DB      = Path("/etc/smokeping/config.d/Database")

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
    p = subprocess.run(
        ["/bin/systemctl","is-active","--quiet",unit],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
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

def check_disk(cfg)->list[tuple[str,str]]:
    alerts=[]
    for pth in cfg["paths"]:
        try:
            u = shutil.disk_usage(pth)
            pct = int(round((u.used/u.total)*100))
            if pct >= int(cfg["warn_pct"]):
                alerts.append((f"disk:{pth}", f"Disk {pth} {pct}% (>{cfg['warn_pct']}%)"))
        except Exception:
            pass
    return alerts

def check_services(cfg)->list[tuple[str,str]]:
    alerts=[]
    for svc in cfg["list"]:
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
        p=Path(cfg["dir"])
        if not p.exists(): return [(f"flow:dir", f"Flow dir not found: {p}")]
        latest = _latest_file_mtime(p)
        if latest==0: return [(f"flow:none","Nessun file flusso trovato")]
        if time.time() - latest > cfg["stale_min"]*60:
            age=int((time.time()-latest)//60)
            return [(f"flow:stale", f"Flussi bloccati: ultimo flusso {age} min fa (>= {cfg['stale_min']}m)")]
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
        if mt and (time.time()-mt) > cfg["log_stale_min"]*60:
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
        if time.time()-latest > cfg["rrd_fresh_min"]*60:
            alerts.append(("smoke:stale", f"Smokeping RRD bloccati (> {cfg['rrd_fresh_min']} min senza aggiornamenti)"))
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
        if dl < cfg["down_min_mbps"]: out.append(("speed:down", f"Download {dl:.1f} Mb/s < {cfg['down_min_mbps']}"))
        if ul < cfg["up_min_mbps"]:   out.append(("speed:up",   f"Upload {ul:.1f} Mb/s < {cfg['up_min_mbps']}"))
        if pg > cfg["ping_max_ms"]:   out.append(("speed:ping", f"Ping {pg:.1f} ms > {cfg['ping_max_ms']}"))
        return out
    except Exception:
        return []

def check_auth(cfg, last_ts:int)->tuple[list[tuple[str,str]], int]:
    # aggrega failure negli ultimi window_min minuti
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
                if ts < time.time()-cfg.get("window_min",5)*60: 
                    continue
                act = ev.get("action","")
                # supporta più etichette di fallimento
                is_fail = (act == "auth/login" and not ev.get("ok",False)) or act in ("auth/login_failed","auth/fail")
                if is_fail:
                    fails.append(ev.get("ip") or "unknown")
    except Exception:
        pass
    if len(fails)>=int(cfg.get("fail_threshold",3)):
        ipset=", ".join(sorted(set(fails)))
        return [("auth:fail", f"Tentativi login falliti: {len(fails)} negli ultimi {cfg.get('window_min',5)} min (IP: {ipset})")], newest
    return [], newest

def _send_telegram(cfg:dict, text:str):
    chan = cfg.get("channels",{}).get("telegram",{})
    if not chan or not chan.get("enabled"):
        return
    token = (chan.get("token") or "").strip()
    chat_id = str(chan.get("chat_id") or "").strip()
    if not token or not chat_id:
        return
    try:
        from util.notify import send_telegram  # usa helper dell'app
        send_telegram(token, chat_id, text)
        return
    except Exception:
        pass
    # fallback minimale via urllib
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            _ = r.status  # ignoro dettagli
    except Exception:
        pass

def main():
    cfg = _load(CFG, {})
    if not cfg:
        return
    # silenzia
    if int(time.time()) < int(cfg.get("silence_until",0)):
        return
    st  = _load(STATE, {"sent":{}, "last_audit_ts":0})
    sent = st.get("sent",{})
    alerts=[]
    # checks
    if cfg["checks"]["disk"]["enabled"]:      alerts += check_disk(cfg["checks"]["disk"])
    if cfg["checks"]["services"]["enabled"]:  alerts += check_services(cfg["checks"]["services"])
    if cfg["checks"]["flow"]["enabled"]:      alerts += check_flow(cfg["checks"]["flow"])
    if cfg["checks"]["cacti"]["enabled"]:     alerts += check_cacti(cfg["checks"]["cacti"])
    if cfg["checks"]["smokeping"]["enabled"]: alerts += check_smokeping(cfg["checks"]["smokeping"])
    if cfg["checks"]["speedtest"]["enabled"]: alerts += check_speedtest(cfg["checks"]["speedtest"])
    if cfg["checks"]["auth"]["enabled"]:
        extra, newest = check_auth(cfg["checks"]["auth"], int(st.get("last_audit_ts",0)))
        alerts += extra
        st["last_audit_ts"] = newest

    # dedupe/throttle configurabile
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
        _send_telegram(cfg, text)

    _save(STATE, st)

if __name__=="__main__":
    main()
