#!/usr/bin/env python3
import os, json, time, subprocess, pathlib, shutil, signal

DIR   = pathlib.Path("/var/lib/netprobe/speedtest")
STATE = DIR / "state.json"
HIST  = DIR / "history.jsonl"
LAST  = DIR / "last.json"
LOG   = DIR / "last.log"
CFG   = pathlib.Path("/etc/netprobe/speedtest.json")

def cfg():
    try:
        c = json.loads(CFG.read_text("utf-8"))
    except Exception:
        c = {}
    c.setdefault("enabled", True)
    c.setdefault("interval_min", 120)
    c.setdefault("retention_max", 10000)
    c.setdefault("prefer", "auto")
    c.setdefault("server_id", "")
    c.setdefault("tag", "")
    return c

def alive(pid):
    if not pid: return False
    try: os.kill(pid, 0); return True
    except Exception: return False

def state_load():
    try: return json.loads(STATE.read_text("utf-8"))
    except Exception: return {"pid": None, "started": None, "result": None, "tool": None}

def state_save(st):
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    os.replace(tmp, STATE)

def last_ts():
    try:
        j = json.loads(LAST.read_text("utf-8"))
        return int(j.get("ts", 0) or 0)
    except Exception:
        pass
    # fallback: ultima riga di history
    try:
        ts = 0
        with open(HIST, "rb") as f:
            for ln in f:
                pass
        if ln:
            ts = int(json.loads(ln.decode("utf-8")).get("ts", 0) or 0)
        return ts
    except Exception:
        return 0

def pick_cmd(c):
    prefer = (c.get("prefer") or "auto").lower()
    sid = str(c.get("server_id") or "").strip()
    if prefer in ("auto","ookla") and shutil.which("speedtest"):
        cmd = ["/usr/bin/speedtest", "-f","json","-p","no","--accept-license","--accept-gdpr"]
        if sid: cmd += ["--server-id", sid]
        return cmd, "ookla"
    py = shutil.which("python3") or "python3"
    code = (
        "import json,sys; import speedtest as s; st=s.Speedtest(); "
        "sid=sys.argv[1] if len(sys.argv)>1 else ''; "
        "st.get_servers(([int(sid)] if (sid and sid.isdigit()) else None)); "
        "st.get_best_server(); d=st.download(); u=st.upload(pre_allocate=False); "
        "p=st.results.ping; sv=st.results.server or {}; "
        "print(json.dumps({'ping':p,'download':d,'upload':u,'server':sv}))"
    )
    return [py,"-c",code,sid], "pycli"

def start_now():
    c = cfg()
    cmd, tool = pick_cmd(c)

    # genera lo stesso wrapper usato dalla route /speedtest/start
    DIR.mkdir(parents=True, exist_ok=True)
    wrapper = DIR / "run_speedtest.py"
    wrapper.write_text(f"""
import json, subprocess, pathlib, sys, os, time
STATE = pathlib.Path({json.dumps(str(STATE))})
LOG   = pathlib.Path({json.dumps(str(LOG))})
HIST  = pathlib.Path({json.dumps(str(HIST))})
LAST  = pathlib.Path({json.dumps(str(LAST))})
CMD   = {json.dumps(cmd)}
CFG   = pathlib.Path('/etc/netprobe/speedtest.json')
TAG   = {json.dumps(c.get("tag") or "")}
def _cfg_retention():
    try: return int(json.loads(CFG.read_text('utf-8')).get('retention_max',10000)) or 0
    except Exception: return 0
try:
    p = subprocess.run(CMD, capture_output=True, text=True, timeout=900)
    OUT,ERR = (p.stdout or ""), (p.stderr or "")
except Exception as e:
    OUT,ERR = "", str(e)
try: LOG.write_text(OUT + ("\\n" if OUT else "") + ERR)
except Exception: pass
try: result = json.loads(OUT.strip() or "{{}}")
except Exception: result = {{}}
try: st = json.loads(STATE.read_text())
except Exception: st = {{"pid": None, "started": None, "result": None, "tool": None}}
st["result"]=result; st["pid"]=None; STATE.write_text(json.dumps(st, indent=2))
now=int(time.time())
ping_ms=jitter_ms=None
if isinstance(result.get("ping"), dict):
    ping_ms=result["ping"].get("latency"); jitter_ms=result["ping"].get("jitter")
elif isinstance(result.get("ping"), (int,float)): ping_ms=result["ping"]
down_bps=None
if isinstance(result.get("download"), dict) and "bandwidth" in result["download"]:
    down_bps=(result["download"]["bandwidth"] or 0)*8
elif isinstance(result.get("download"), (int,float)): down_bps=result["download"]
up_bps=None
if isinstance(result.get("upload"), dict) and "bandwidth" in result["upload"]:
    up_bps=(result["upload"]["bandwidth"] or 0)*8
elif isinstance(result.get("upload"), (int,float)): up_bps=result["upload"]
server=result.get("server") or {{}}
iface=result.get("interface") or {{}}
rid=(result.get("result") or {{}}).get("id")
entry={{"ts":now,"tool":{json.dumps(tool)},"ok":bool(result),"tag":TAG,"ping_ms":ping_ms,"jitter_ms":jitter_ms,
       "loss_pct":result.get("packetLoss"),"down_bps":down_bps,"up_bps":up_bps,
       "server_name":server.get("name"),"server_loc":server.get("location"),"server_id":server.get("id"),
       "isp":result.get("isp"),"internalIp":iface.get("internalIp"),"externalIp":iface.get("externalIp"),"uuid":rid}}
try:
    with open(HIST,"a",encoding="utf-8") as f: f.write(json.dumps(entry,separators=(",",":"))+"\\n")
except Exception: pass
try:
    with open(LAST,"w",encoding="utf-8") as f: json.dump(entry,f,indent=2)
except Exception: pass
try:
    N=_cfg_retention()
    if N>0:
        with open(HIST,"r",encoding="utf-8") as f: lines=f.readlines()
        if len(lines)>N:
            with open(HIST,"w",encoding="utf-8") as f: f.writelines(lines[-N:])
except Exception: pass
""", encoding="utf-8")

    st = state_load()
    proc = subprocess.Popen(
        ["/usr/bin/env","python3",str(wrapper)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    st["pid"] = proc.pid
    st["started"] = int(time.time())
    st["tool"] = tool
    state_save(st)

def main():
    c = cfg()
    if not c.get("enabled", True):
        print("[speedtestd] disabled"); return
    DIR.mkdir(parents=True, exist_ok=True)
    st = state_load()
    if alive(st.get("pid")):
        print("[speedtestd] already running"); return
    last = last_ts()
    wait_s = int(c.get("interval_min", 120)) * 60
    if last and (time.time() - last) < (wait_s - 1):
        print("[speedtestd] interval not reached"); return
    print("[speedtestd] starting test…")
    start_now()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[speedtestd] ERROR:", e)
