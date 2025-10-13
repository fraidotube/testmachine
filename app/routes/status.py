# /opt/netprobe/app/routes/status.py
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import subprocess, shutil, socket, json, time, os, re
from pathlib import Path

router = APIRouter(prefix="/status", tags=["status"])

def _run(cmd:list[str], timeout:int|None=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except Exception as e:
        return 1, "", str(e)

def _uptime_seconds()->float|None:
    try:
        with open("/proc/uptime","r") as f:
            return float(f.read().split()[0])
    except Exception:
        return None

def _disk_usage(path:str="/"):
    try:
        total, used, free = shutil.disk_usage(path)
        return {"total": total, "used": used, "free": free}
    except Exception:
        return {"total": None, "used": None, "free": None}

def _ip_addresses():
    # IPv4
    rc4, out4, _ = _run(["/usr/sbin/ip","-o","-4","addr","show","up"])
    # IPv6
    rc6, out6, _ = _run(["/usr/sbin/ip","-o","-6","addr","show","up"])

    data: dict[str, dict] = {}
    if rc4 == 0:
        for line in out4.splitlines():
            # 2: eth0    inet 192.168.1.10/24 brd ... scope global ...
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                addr  = parts[3]  # ip/mask
                if iface not in data:
                    data[iface] = {"ipv4": [], "ipv6": []}
                data[iface]["ipv4"].append(addr)
    #if rc6 == 0:
     #   for line in out6.splitlines():
      #      parts = line.split()
       #     if len(parts) >= 4:
        #        iface = parts[1]
         #       addr  = parts[3]
          #      if iface not in data:
           #         data[iface] = {"ipv4": [], "ipv6": []}
            #    data[iface]["ipv6"].append(addr)
    return data

def _service_status(names:list[str]):
    res = {}
    for name in names:
        rc, out, _ = _run(["/bin/systemctl","is-active", name])
        state = (out.strip() if rc == 0 else "inactive")
        # normalizza alcuni stati
        if state not in ("active","inactive","failed","activating","deactivating","reloading"):
            state = "inactive"
        res[name] = state
    return res

def _dumpcap_caps():
    rc, out, err = _run(["/sbin/getcap","/usr/bin/dumpcap"])
    if rc == 0 and out.strip():
        return out.strip()
    # fallback: se getcap non disponibile/errore
    return None

@router.get("/summary", response_class=JSONResponse)
def summary():
    hostname = socket.gethostname()
    uptime_s = _uptime_seconds()
    disk = _disk_usage("/")
    addrs = _ip_addresses()
    services = _service_status(["netprobe-api","apache2","smokeping","systemd-timesyncd"])
    dumpcap = _dumpcap_caps()

    return {
        "time": int(time.time()),
        "hostname": hostname,
        "uptime_s": uptime_s,
        "disk": disk,
        "interfaces": addrs,
        "services": services,
        "dumpcap_caps": dumpcap,
    }
