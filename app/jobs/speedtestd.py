#!/usr/bin/env python3
import os, json, time, subprocess, pathlib, shutil, sys

DIR   = pathlib.Path("/var/lib/netprobe/speedtest")
STATE = DIR / "state.json"
HIST  = DIR / "history.jsonl"
LAST  = DIR / "last.json"
LOG   = DIR / "last.log"
CFG   = pathlib.Path("/etc/netprobe/speedtest.json")

# ---------------- config & utils ----------------
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

def _file_mtime(p: pathlib.Path) -> int:
    try:
        return int(p.stat().st_mtime)
    except Exception:
        return 0

def last_ts() -> int:
    """Ultimo timestamp completato (robusto: last.json, history.jsonl, mtimes)."""
    candidates = []
    # last.json
    try:
        j = json.loads(LAST.read_text("utf-8"))
        if isinstance(j, dict) and "ts" in j:
            candidates.append(int(j["ts"]))
    except Exception:
        pass
    # ultima riga history.jsonl
    try:
        if HIST.exists():
            with open(HIST, "rb") as f:
                last_line = None
                for ln in f:
                    last_line = ln
            if last_line:
                obj = json.loads(last_line.decode("utf-8"))
                if isinstance(obj, dict) and "ts" in obj:
                    candidates.append(int(obj["ts"]))
    except Exception:
        pass
    # fallback mtimes
    candidates.append(_file_mtime(LAST))
    candidates.append(_file_mtime(HIST))
    return int(max(candidates) if candidates else 0)

def pick_cmd(c):
    prefer = (c.get("prefer") or "auto").lower()
    sid = str(c.get("server_id") or "").strip()
    # Ookla CLI se presente
    if prefer in ("auto","ookla") and shutil.which("speedtest"):
        cmd = ["/usr/bin/speedtest", "-f","json","-p","no","--accept-license","--accept-gdpr"]
        if sid: cmd += ["--server-id", sid]
        return cmd, "ookla"
    # Fallback Python speedtest-cli (pip)
    py = shutil.which("python3") or "python3"
    code = (
        "import json,sys; import speedtest as s; st=s.Speedtest(); "
        "sid=sys.argv[1] if len(sys.argv)>1 else ''; "
        "st.get_servers(([int(sid)] if (sid and sid.isdigit()) else None)); "
        "st.get_best_server(); d=st.download(); u=st.upload(pre_allocate=False); "
        "p=st.results.ping; sv=st.results.server or {}; "
        "iface=getattr(st.results,'client',{}) or {}; "
        "print(json.dumps({'ping':p,'download':d,'upload':u,'server':sv,'interface':{'internalIp':iface.get('ip',None)}}))"
    )
    return [py,"-c",code,sid], "pycli"

def write_atom(path: pathlib.Path, data: str | bytes):
    tmp = path.with_suffix(".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8")
    else:
        tmp.write_bytes(data)
    os.replace(tmp, path)

# --------------- core: run now (sync) ---------------
def run_now_sync():
    c = cfg()
    cmd, tool = pick_cmd(c)
    tag = c.get("tag") or ""

    DIR.mkdir(parents=True, exist_ok=True)

    # esegui test (max 15 min)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        OUT, ERR = (p.stdout or ""), (p.stderr or "")
    except Exception as e:
        OUT, ERR = "", str(e)

    # log raw
    try:
        write_atom(LOG, (OUT + ("\n" if OUT else "") + (ERR or "")))
    except Exception:
        pass

    # parse risultato
    try:
        result = json.loads(OUT.strip() or "{}")
    except Exception:
        result = {}

    # estrazioni compatibili con UI
    # ping/jitter
    ping_ms = jitter_ms = None
    if isinstance(result.get("ping"), dict):
        ping_ms  = result["ping"].get("latency")
        jitter_ms = result["ping"].get("jitter")
    elif isinstance(result.get("ping"), (int,float)):
        ping_ms = result["ping"]

    # download/upload in bps (Ookla fornisce bandwidth in Byte/s)
    down_bps = up_bps = None
    if isinstance(result.get("download"), dict) and "bandwidth" in result["download"]:
        down_bps = (result["download"]["bandwidth"] or 0) * 8
    elif isinstance(result.get("download"), (int,float)):
        down_bps = result["download"]
    if isinstance(result.get("upload"), dict) and "bandwidth" in result["upload"]:
        up_bps = (result["upload"]["bandwidth"] or 0) * 8
    elif isinstance(result.get("upload"), (int,float)):
        up_bps = result["upload"]

    server = result.get("server") or {}
    iface  = result.get("interface") or {}
    rid    = (result.get("result") or {}).get("id")

    entry = {
        "ts": int(time.time()),
        "tool": tool,
        "ok": bool(result),
        "tag": tag,
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
        "uuid": rid,
    }

    # append history + update last
    try:
        with open(HIST, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",",":")) + "\n")
    except Exception:
        pass
    try:
        write_atom(LAST, json.dumps(entry, indent=2))
    except Exception:
        pass

    # retention
    try:
        N = int(c.get("retention_max", 10000)) or 0
        if N > 0 and HIST.exists():
            with open(HIST, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > N:
                with open(HIST, "w", encoding="utf-8") as f:
                    f.writelines(lines[-N:])
    except Exception:
        pass

    # aggiorna state (facoltativo)
    try:
        st = {"pid": None, "started": None, "result": result, "tool": tool}
        write_atom(STATE, json.dumps(st, indent=2))
    except Exception:
        pass

    # riga di riepilogo in journal
    mbps = lambda b: round((b or 0) / 1_000_000, 2)
    print(f"[speedtestd] done: ping={ping_ms}ms jitter={jitter_ms}ms "
          f"down={mbps(down_bps)}Mbps up={mbps(up_bps)}Mbps ok={bool(result)}")

# --------------- scheduler entrypoint ---------------
def main():
    c = cfg()
    if not c.get("enabled", True):
        print("[speedtestd] disabled"); return

    DIR.mkdir(parents=True, exist_ok=True)

    last = last_ts()
    now  = int(time.time())
    wait_s = int(c.get("interval_min", 120)) * 60
    delta = now - (last or 0)

    print(f"[speedtestd] now={now} last={last} delta={delta}s interval={wait_s}s")
    if last:
        print(f"[speedtestd] last sources mtime: last.json={_file_mtime(LAST)} history.jsonl={_file_mtime(HIST)}")

    # anti-rimbalzo <60s
    if delta < 60:
        print("[speedtestd] bounce guard (<60s): skip")
        return
    if last and delta < (wait_s - 1):
        print("[speedtestd] interval not reached: skip")
        return

    print("[speedtestd] starting test…")
    run_now_sync()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[speedtestd] ERROR:", e)
        sys.exit(0)
