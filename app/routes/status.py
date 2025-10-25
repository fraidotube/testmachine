# /opt/netprobe/app/routes/status.py
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import subprocess, shutil, socket, time

router = APIRouter(prefix="/status", tags=["status"])

# --------------------------- helpers ---------------------------------
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
    # IPv4 (coerente con la tua versione: IPv6 lasciato off per non cambiare comportamento)
    rc4, out4, _ = _run(["/usr/sbin/ip","-o","-4","addr","show","up"])

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

    # # IPv6 (se un domani vuoi attivarlo)
    # rc6, out6, _ = _run(["/usr/sbin/ip","-o","-6","addr","show","up"])
    # if rc6 == 0:
    #     for line in out6.splitlines():
    #         parts = line.split()
    #         if len(parts) >= 4:
    #             iface = parts[1]
    #             addr  = parts[3]
    #             if iface not in data:
    #                 data[iface] = {"ipv4": [], "ipv6": []}
    #             data[iface]["ipv6"].append(addr)

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
    rc, out, _ = _run(["/sbin/getcap","/usr/bin/dumpcap"])
    if rc == 0 and out.strip():
        return out.strip()
    # fallback: se getcap non disponibile/errore
    return None

# --------------------------- extra: nuovi servizi ---------------------
def _php_fpm_unit()->str:
    rc, out, _ = _run(["/usr/bin/php","-r","echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"])
    ver = (out or "").strip()
    return f"php{ver}-fpm" if ver else "php-fpm"

def _exporter_instances():
    # elenca eventuali istanze netprobe-flow-exporter@*.service attive/failed
    rc, out, _ = _run([
        "/bin/systemctl","list-units","netprobe-flow-exporter@*.service",
        "--state=active,running,failed","--no-legend","--no-pager"
    ])
    units=[]
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                units.append(parts[0])  # es. netprobe-flow-exporter@enp2s0.service
    return units

# --------------------------- route -----------------------------------
@router.get("/summary", response_class=JSONResponse)
def summary():
    hostname = socket.gethostname()
    uptime_s = _uptime_seconds()
    disk = _disk_usage("/")
    addrs = _ip_addresses()

    # Base + nuovi servizi/timer + php-fpm dinamico
    services_to_check = [
        "netprobe-api",              # API (service, anche se socket-activated)
        #"netprobe-api.socket",       # API (socket)
        "apache2",
        "smokeping",
        "systemd-timesyncd",
        "cron",
        "mariadb",
        "netprobe-flow-collector",
        "softflowd",
        "netprobe-alertd.timer",
        "netprobe-speedtestd.timer",
        _php_fpm_unit(),
    ]
    services = _service_status(services_to_check)

    # istanze exporter@ se presenti
    for u in _exporter_instances():
        services.update(_service_status([u]))

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
