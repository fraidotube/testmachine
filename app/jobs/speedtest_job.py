# /opt/netprobe/app/jobs/speedtest_job.py
from __future__ import annotations
from pathlib import Path
import json, os, time, subprocess, shutil

SPEED_DIR = Path("/var/lib/netprobe/speedtest")
STATE_FILE= SPEED_DIR / "state.json"
HIST_FILE = SPEED_DIR / "history.jsonl"
CFG_FILE  = Path("/etc/netprobe/speedtest.json")

DEFAULT_CFG = {"interval_min": 120, "retention_days": 90}

def _load_cfg():
    try: return json.loads(CFG_FILE.read_text("utf-8"))
    except Exception: return DEFAULT_CFG

def _ensure():
    SPEED_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps({"pid": None, "started": None, "result": None, "tool": None}, indent=2))

def _alive(pid:int|None)->bool:
    if not pid: return False
    try: os.kill(pid,0); return True
    except Exception: return False

def _pick_cmd():
    if shutil.which("speedtest"):
        return (["/usr/bin/speedtest","-f","json","-p","no","--accept-license","--accept-gdpr"], "ookla")
    py = shutil.which("python3") or "python3"
    code = ("import json,sys; import speedtest as s; st=s.Speedtest(); st.get_servers(); st.get_best_server(); "
            "d=st.download(); u=st.upload(pre_allocate=False); p=st.results.ping; sv=st.results.server or {}; "
            "print(json.dumps({'ping':p,'download':d,'upload':u,'server':sv}))")
    return ([py,"-c", code], "pycli")

def _last_hist_ts()->int:
    ts=0
    try:
        with open(HIST_FILE,"r",encoding="utf-8") as f:
            for ln in f:
                try: ts=int(json.loads(ln).get("ts",0))
                except Exception: pass
    except Exception: pass
    return ts

def main():
    _ensure()
    cfg = _load_cfg()
    st  = json.loads(STATE_FILE.read_text("utf-8"))
    if _alive(st.get("pid")):
        return  # test manuale in corso
    last_ts = _last_hist_ts()
    if last_ts and time.time()-last_ts < cfg.get("interval_min",120)*60:
        return  # non ancora tempo
    # esegui test (riuso wrapper di speedtest.py in modo minimale)
    cmd, tool = _pick_cmd()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        out = p.stdout or ""; err = p.stderr or ""
    except Exception as e:
        out, err = "", str(e)
    try:
        res = json.loads((out or "").strip() or "{}")
    except Exception:
        res = {}
    now=int(time.time())
    # compattazione entry (compatibile con UI)
    def _bits(val):
        if isinstance(val,dict) and "bandwidth" in val: return (val.get("bandwidth") or 0)*8
        return val if isinstance(val,(int,float)) else None
    if isinstance(res.get("ping"),dict):
        ping=res["ping"].get("latency"); jit=res["ping"].get("jitter")
    else:
        ping=res.get("ping"); jit=None
    server=res.get("server") or {}
    iface =res.get("interface") or {}
    rid=(res.get("result") or {}).get("id")
    entry={
        "ts": now, "tool": tool, "ok": bool(res),
        "ping_ms": ping, "jitter_ms": jit, "loss_pct": res.get("packetLoss"),
        "down_bps": _bits(res.get("download")), "up_bps": _bits(res.get("upload")),
        "server_name": server.get("name"), "server_loc": server.get("location"), "server_id": server.get("id"),
        "isp": res.get("isp"), "internalIp": iface.get("internalIp"), "externalIp": iface.get("externalIp"),
        "uuid": rid
    }
    with open(HIST_FILE,"a",encoding="utf-8") as f:
        f.write(json.dumps(entry,separators=(",",":"))+"\n")

if __name__=="__main__":
    main()
