# /opt/netprobe/app/routes/snmp.py
from __future__ import annotations
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from html import escape
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import os, json, time, re, subprocess, shlex, tarfile, io, threading, random

from util.audit import log_event

router = APIRouter(prefix="/snmp", tags=["snmp"])

# ---- Percorsi & costanti ----
CONF_PATH   = Path("/etc/netprobe/snmp.json")           # {defaults:{...}, devices:[{ip,...}]}
DATA_ROOT   = Path("/var/lib/netprobe/snmp")            # /<ip>/<ifIndex>.rrd + ifcache.json
GROUP_NAME  = "netprobe"

# RRD: nomi DS
DS = [
    ("in_bytes",  "COUNTER"),
    ("out_bytes", "COUNTER"),
    ("in_err",    "COUNTER"),
    ("out_err",   "COUNTER"),
    ("in_dis",    "COUNTER"),
    ("out_dis",   "COUNTER"),
]
RRD_STEP = 15             # secondi
RRD_HEARTBEAT = 60

# OID (numeric) per performance e compatibilità
OID = {
    "sysName":       "1.3.6.1.2.1.1.5.0",
    "sysUpTime":     "1.3.6.1.2.1.1.3.0",
    # IF-MIB
    "ifName":        "1.3.6.1.2.1.31.1.1.1.1",      # Preferito, fallback a ifDescr
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2",
    "ifAlias":       "1.3.6.1.2.1.31.1.1.1.18",
    "ifSpeed":       "1.3.6.1.2.1.2.2.1.5",         # bps (32-bit)
    "ifHighSpeed":   "1.3.6.1.2.1.31.1.1.1.15",     # Mbps (32-bit)
    "ifHCInOctets":  "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16",
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
    "ifInDiscards":  "1.3.6.1.2.1.2.2.1.13",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
}

# -------------- Helpers generali --------------

def _ensure_dirs():
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_ROOT, 0o2770)
        import grp
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(DATA_ROOT, 0, gid)
    except Exception:
        pass


def _load_conf() -> Dict[str, Any]:
    """Carica/crea config con defaults sensati."""
    if not CONF_PATH.exists():
        defaults = {
            "version": "2c",
            "port": 161,
            "community": "public",
            "timeout_ms": 1500,
            "retries": 1,
            "poll_interval_s": 15,
            "bulk": True,
            "if_include_regex": ".*",
            "if_exclude_regex": "(^lo$|^docker.*)",
        }
        payload = {"defaults": defaults, "devices": []}
        CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CONF_PATH.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, CONF_PATH)
        try:
            os.chmod(CONF_PATH, 0o600)
            import grp
            gid = grp.getgrnam(GROUP_NAME).gr_gid
            os.chown(CONF_PATH, 0, gid)
        except Exception:
            pass
        return payload
    try:
        return json.loads(CONF_PATH.read_text("utf-8"))
    except Exception:
        return {"defaults": {}, "devices": []}


def _save_conf(conf: Dict[str, Any]):
    CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONF_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, CONF_PATH)
    try:
        os.chmod(CONF_PATH, 0o600)
        import grp
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(CONF_PATH, 0, gid)
    except Exception:
        pass


def _ip_s(ip: str) -> str:
    ip = (ip or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F:\.\-]+", ip):
        raise ValueError("IP non valido")
    return ip


# -------------- SNMP via net-snmp --------------

def _run(cmd: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return p.returncode, p.stdout.decode(errors="ignore"), p.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def _snmp_get(ip: str, community: str, oid_list: List[str], port: int, timeout_ms: int, retries: int) -> Dict[str, str]:
    cmd = [
        "snmpget", "-v2c", "-c", community,
        "-t", str(max(1, timeout_ms//1000)), "-r", str(retries), "-Onq", f"{ip}:{port}",
    ] + oid_list
    rc, out, err = _run(cmd, timeout=max(2, timeout_ms//1000 + 2))
    res: Dict[str, str] = {}
    if rc == 0:
        for line in out.splitlines():
            # .1.3.6... = value
            try:
                k, v = line.split(" ", 1)
                res[k.strip()] = v.strip()
            except ValueError:
                continue
    return res


def _snmp_walk(ip: str, community: str, base_oid: str, port: int, timeout_ms: int, retries: int) -> Dict[int, str]:
    # Prefer bulkwalk ma fallback su walk
    base = ["snmpbulkwalk", "-v2c", "-c", community, "-Cr10"]
    if os.system("command -v snmpbulkwalk >/dev/null 2>&1") != 0:
        base = ["snmpwalk", "-v2c", "-c", community]
    cmd = base + [
        "-t", str(max(1, timeout_ms//1000)), "-r", str(retries), "-Onq", f"{ip}:{port}", base_oid
    ]
    rc, out, err = _run(cmd, timeout=max(4, timeout_ms//1000 + 5))
    res: Dict[int, str] = {}
    if rc == 0:
        for line in out.splitlines():
            # .1.3.6...<.idx> = value
            try:
                k, v = line.split(" ", 1)
                # idx = ultima parte dopo il punto
                m = re.search(r"\.(\d+)$", k)
                if not m:
                    continue
                idx = int(m.group(1))
                res[idx] = v.strip()
            except ValueError:
                continue
    return res


# -------------- RRD helpers --------------

def _rrd_path(ip: str, ifidx: int) -> Path:
    return DATA_ROOT / ip / f"{ifidx}.rrd"


def _ensure_rrd(ip: str, ifidx: int):
    d = DATA_ROOT / ip
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o2770)
        import grp
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(d, 0, gid)
    except Exception:
        pass
    rrd = _rrd_path(ip, ifidx)
    if rrd.exists():
        return
    ds_parts = [f"DS:{name}:{typ}:{RRD_HEARTBEAT}:0:U" for name, typ in DS]
    rra = [
        # AVERAGE
        f"RRA:AVERAGE:0.5:1:{(4*60*60)//RRD_STEP}",     # 4h a step base
        f"RRA:AVERAGE:0.5:{60//RRD_STEP}:{48*60}",      # 1min x 48h
        f"RRA:AVERAGE:0.5:{(5*60)//RRD_STEP}:{(14*24*60)//5}", # 5min x 14d
        f"RRA:AVERAGE:0.5:{(30*60)//RRD_STEP}:{(90*24*60)//30}",# 30min x 90d
        # MAX
        f"RRA:MAX:0.5:{60//RRD_STEP}:{48*60}",
    ]
    cmd = ["rrdtool", "create", str(rrd), f"--step", str(RRD_STEP), *ds_parts, *rra]
    _run(cmd, timeout=5)


def _rrd_update(ip: str, ifidx: int, vals: Dict[str, int]):
    _ensure_rrd(ip, ifidx)
    rrd = _rrd_path(ip, ifidx)
    tpl = ":".join([n for n, _ in DS])
    vlist = [str(vals.get(n, "U")) for n, _ in DS]
    cmd = ["rrdtool", "update", str(rrd), f"--template", tpl, f"N:{':'.join(vlist)}"]
    _run(cmd, timeout=4)


def _rrd_fetch_series(ip: str, ifidx: int, cf: str = "AVERAGE", range_s: int = 900) -> Dict[str, Any]:
    rrd = _rrd_path(ip, ifidx)
    if not rrd.exists():
        return {"points": [], "step": RRD_STEP}
    end = int(time.time())
    start = end - range_s
    cmd = ["rrdtool", "fetch", str(rrd), cf, "-s", str(start), "-e", str(end)]
    rc, out, err = _run(cmd, timeout=6)
    if rc != 0:
        return {"points": [], "step": RRD_STEP}
    lines = out.splitlines()
    # header like:                     in_bytes out_bytes in_err ...
    if not lines:
        return {"points": [], "step": RRD_STEP}
    header = lines[0]
    fields = [f for f in header.strip().split()]
    pts = []
    for ln in lines[1:]:
        ln = ln.strip()
        if not ln or not ln[0].isdigit():
            continue
        try:
            ts_s, rest = ln.split(":", 1)
            ts = int(ts_s)
            vals = rest.strip().split()
            row = {fields[i]: (None if vals[i] == 'nan' else float(vals[i])) for i in range(min(len(fields), len(vals)))}
            pts.append([ts, row])
        except Exception:
            continue
    return {"points": pts, "step": RRD_STEP, "fields": fields}


# -------------- Polling --------------

class _Poller:
    def __init__(self):
        self._lock = threading.Lock()
        self._last_poll: Dict[str, float] = {}    # ip -> ts
        self._stop = threading.Event()
        self._thr = threading.Thread(target=self._loop, name="snmp-poller", daemon=True)

    def start(self):
        if not self._thr.is_alive():
            self._thr.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        # jitter iniziale per evitare burst all'avvio
        time.sleep(random.uniform(0.5, 1.5))
        while not self._stop.is_set():
            try:
                conf = _load_conf()
                defaults = conf.get("defaults", {})
                devices = conf.get("devices", [])
                now = time.time()
                for dev in devices:
                    if not dev.get("enabled", True):
                        continue
                    ip = dev.get("ip")
                    if not ip:
                        continue
                    ival = int(dev.get("poll_interval_s", defaults.get("poll_interval_s", 15)) or 15)
                    last = self._last_poll.get(ip, 0)
                    if now - last >= ival:
                        # Esegui poll (protetto da lock blando)
                        try:
                            self.poll_device(dev, defaults)
                        except Exception:
                            pass
                        self._last_poll[ip] = now
                # sleep breve
                self._stop.wait(2.0)
            except Exception:
                self._stop.wait(2.0)

    def poll_device(self, dev: Dict[str, Any], defaults: Dict[str, Any]) -> bool:
        ip = dev.get("ip")
        community = dev.get("community") or defaults.get("community", "public")
        port = int(dev.get("port", defaults.get("port", 161)) or 161)
        timeout_ms = int(dev.get("timeout_ms", defaults.get("timeout_ms", 1500)) or 1500)
        retries = int(dev.get("retries", defaults.get("retries", 1)) or 1)
        include_re = re.compile(dev.get("if_include_regex", defaults.get("if_include_regex", ".*")))
        exclude_re = re.compile(dev.get("if_exclude_regex", defaults.get("if_exclude_regex", "(^lo$|^docker.*)")))

        # Device info
        g = _snmp_get(ip, community, [OID["sysName"], OID["sysUpTime"]], port, timeout_ms, retries)
        sysname = g.get(OID["sysName"], "-")
        # Tabelle interfacce (name/descr/alias/speed + counters)
        name_map = _snmp_walk(ip, community, OID["ifName"], port, timeout_ms, retries)
        if not name_map:
            name_map = _snmp_walk(ip, community, OID["ifDescr"], port, timeout_ms, retries)
        alias_map = _snmp_walk(ip, community, OID["ifAlias"], port, timeout_ms, retries)
        speed_map = _snmp_walk(ip, community, OID["ifSpeed"], port, timeout_ms, retries)
        hs_map    = _snmp_walk(ip, community, OID["ifHighSpeed"], port, timeout_ms, retries)

        def _speed_bps(idx: int) -> Optional[int]:
            # ifHighSpeed è in Mbps
            if idx in hs_map:
                try:
                    return int(float(hs_map[idx].split(":",1)[-1].strip())) * 1_000_000
                except Exception:
                    pass
            if idx in speed_map:
                try:
                    return int(float(speed_map[idx].split(":",1)[-1].strip()))
                except Exception:
                    pass
            return None

        # Counters (prefer 64-bit)
        in_oct  = _snmp_walk(ip, community, OID["ifHCInOctets"],  port, timeout_ms, retries) or _snmp_walk(ip, community, OID["ifInOctets"],  port, timeout_ms, retries)
        out_oct = _snmp_walk(ip, community, OID["ifHCOutOctets"], port, timeout_ms, retries) or _snmp_walk(ip, community, OID["ifOutOctets"], port, timeout_ms, retries)
        in_err  = _snmp_walk(ip, community, OID["ifInErrors"],    port, timeout_ms, retries)
        out_err = _snmp_walk(ip, community, OID["ifOutErrors"],   port, timeout_ms, retries)
        in_dis  = _snmp_walk(ip, community, OID["ifInDiscards"],  port, timeout_ms, retries)
        out_dis = _snmp_walk(ip, community, OID["ifOutDiscards"], port, timeout_ms, retries)

        # Cache meta
        cache = {"sysName": sysname, "if": {}}
        for idx, nm in name_map.items():
            try:
                # value format example: "STRING: eth0" or "=?" ? prendiamo dopo ":"
                name = nm.split(":",1)[-1].strip()
            except Exception:
                name = str(nm)
            if not include_re.search(name) or exclude_re.search(name):
                continue
            alias = alias_map.get(idx, "").split(":",1)[-1].strip() if idx in alias_map else ""
            sp = _speed_bps(idx)
            cache["if"][str(idx)] = {"name": name, "alias": alias, "speed": sp}

        # Scrivi cache
        ip_dir = DATA_ROOT / ip
        ip_dir.mkdir(parents=True, exist_ok=True)
        tmp = ip_dir / "ifcache.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, ip_dir / "ifcache.json")

        # Aggiorna RRD
        for idx_s, meta in cache["if"].items():
            idx = int(idx_s)
            vals = {
                "in_bytes":  _to_int_safe(in_oct.get(idx)),
                "out_bytes": _to_int_safe(out_oct.get(idx)),
                "in_err":    _to_int_safe(in_err.get(idx)),
                "out_err":   _to_int_safe(out_err.get(idx)),
                "in_dis":    _to_int_safe(in_dis.get(idx)),
                "out_dis":   _to_int_safe(out_dis.get(idx)),
            }
            _rrd_update(ip, idx, vals)

        return True


def _to_int_safe(snmp_val: Optional[str]) -> Optional[int]:
    if snmp_val is None:
        return None
    # valori tipici: "Counter64: 12345" oppure "STRING: xxx"
    try:
        if ":" in snmp_val:
            snmp_val = snmp_val.split(":",1)[-1]
        snmp_val = snmp_val.strip()
        # elimina unità tipo " Timeticks: (123)" -> "(123)"
        m = re.search(r"(-?\d+)", snmp_val)
        if m:
            return int(m.group(1))
    except Exception:
        return None
    return None


_poller = _Poller()
_ensure_dirs()
_poller.start()


# -------------- UI helpers --------------

def _head(title: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'>"
        "<div class='nav'>"
          "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
          "<div class='title-center'>TestMachine</div>"
          "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
        "</div>"
    )


# -------------- Pagine --------------

@router.get("/", response_class=HTMLResponse)
def snmp_home(request: Request):
    conf = _load_conf()
    defaults = conf.get("defaults", {})
    devices = conf.get("devices", [])

    # tabella device
    rows = []
    for d in devices:
        ip = escape(d.get("ip","-"))
        name = escape(d.get("name") or "-")
        en = d.get("enabled", True)
        badge = "<span class='chip ok'>enabled</span>" if en else "<span class='chip'>disabled</span>"
        rows.append(
            f"<tr><td><a href='/snmp/device/{ip}'>{ip}</a></td><td>{name}</td><td>{badge}</td>"
            f"<td><a class='btn secondary' href='/snmp/poll?ip={ip}'>Poll now</a></td>"
            f"<td><a class='btn danger' href='/snmp/manage/delete?ip={ip}' onclick=\"return confirm('Rimuovere {ip}?');\">Elimina</a></td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5' class='muted'>Nessun dispositivo configurato.</td></tr>")

    html = _head("SNMP") + f"""
    <style>
      .full{{ grid-column:1 / -1; }}
    </style>
    <div class='grid'>
      <div class='card full'>
        <h2>SNMP Mini-Monitor</h2>
        <p class='muted'>Collezione SNMP v2c con storage RRD; polling in background.</p>
        <div class='table' style='overflow:auto'>
          <table>
            <thead><tr><th>IP</th><th>Nome</th><th>Stato</th><th>Azioni</th><th></th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
      </div>

      <div class='card full'>
        <h3>Aggiungi dispositivo</h3>
        <form method='post' action='/snmp/manage/add' class='row' style='gap:10px; flex-wrap:wrap'>
          <div style='min-width:220px'><label>IP / Host</label><input name='ip' required placeholder='192.168.1.10'/></div>
          <div style='min-width:220px'><label>Nome</label><input name='name' placeholder='switch-core'/></div>
          <div style='min-width:220px'><label>Community</label><input name='community' placeholder='public'/></div>
          <div><label>Porta</label><input type='number' name='port' value='161' min='1' max='65535'/></div>
          <div><label>Timeout ms</label><input type='number' name='timeout_ms' value='1500' min='200' max='10000'/></div>
          <div><label>Retries</label><input type='number' name='retries' value='1' min='0' max='5'/></div>
          <div><label>Poll (s)</label><input type='number' name='poll_interval_s' value='15' min='5' max='3600'/></div>
          <div style='min-width:260px'><label>Include if (regex)</label><input name='if_include_regex' value='.*'/></div>
          <div style='min-width:260px'><label>Escludi if (regex)</label><input name='if_exclude_regex' value='(^lo$|^docker.*)'/></div>
          <div style='align-self:flex-end'><button class='btn' type='submit'>Aggiungi</button></div>
        </form>
      </div>

     <div class='card full'>
        <h3>Defaults</h3>
        <form method='post' action='/snmp/manage/defaults' class='row' style='gap:10px; flex-wrap:wrap'>
          <div><label>Community</label><input name='community' value='{escape(str(defaults.get('community','public')))}'/></div>
          <div><label>Porta</label><input type='number' name='port' value='{int(defaults.get('port',161))}'/></div>
          <div><label>Timeout ms</label><input type='number' name='timeout_ms' value='{int(defaults.get('timeout_ms',1500))}'/></div>
          <div><label>Retries</label><input type='number' name='retries' value='{int(defaults.get('retries',1))}'/></div>
          <div><label>Poll (s)</label><input type='number' name='poll_interval_s' value='{int(defaults.get('poll_interval_s',15))}'/></div>
          <div style='min-width:260px'><label>Include if (regex)</label><input name='if_include_regex' value='{escape(defaults.get('if_include_regex','.*'))}'/></div>
          <div style='min-width:260px'><label>Escludi if (regex)</label><input name='if_exclude_regex' value='{escape(defaults.get('if_exclude_regex','(^lo$|^docker.*)'))}'/></div>
          <div style='align-self:flex-end'><button class='btn' type='submit'>Salva defaults</button></div>
        </form>
      </div>
    </div>
    </div></body></html>
    """
    return HTMLResponse(html)


@router.get("/device/{ip}", response_class=HTMLResponse)
def device_page(ip: str):
    ip = _ip_s(ip)
    ip_js = json.dumps(ip)
    cache = DATA_ROOT / ip / "ifcache.json"
    if not cache.exists():
        body = _head("SNMP device") + f"<div class='card'><h3>Device {escape(ip)}</h3><p class='muted'>Nessun dato. Esegui un <a href='/snmp/poll?ip={escape(ip)}'>Poll now</a>.</p></div></div></body></html>"
        return HTMLResponse(body)
    meta = json.loads(cache.read_text("utf-8"))
    rows = []
    for idx, info in sorted(((int(k), v) for k, v in (meta.get("if") or {}).items()), key=lambda x:x[0]):
        name = escape(info.get("name") or "-")
        alias = escape(info.get("alias") or "")
        sp = info.get("speed") or 0
        rows.append(
            f"<tr><td>{idx}</td><td class='mono'>{name}</td><td class='mono'>{alias}</td><td class='mono'>{sp or '-'}</td>"
            f"<td><a class='btn secondary' href='/snmp/api/series?ip={escape(ip)}&if={idx}&range=15m'>Series JSON</a></td>"
            f"<td><a class='btn secondary' href='/snmp/export/series?ip={escape(ip)}&if={idx}&range=60m&format=csv'>Export CSV</a></td>"
            f"</tr>"
        )

    # Opzioni select interfacce per il grafico
    if_opts = []
    for idx, info in sorted(((int(k), v) for k, v in (meta.get("if") or {}).items()), key=lambda x:x[0]):
        name = info.get("name") or f"if{idx}"
        if_opts.append(f"<option value='{idx}'>[{idx}] {escape(name)}</option>")

    html = _head("SNMP device") + f"""
    <style>
      .full{{ grid-column:1 / -1; }}
    </style>
    <div class='grid'>
      <div class='card full'>
        <h2>Device {escape(ip)}</h2>
        <div class='table' style='overflow:auto'>
          <table>
            <thead><tr><th>Idx</th><th>ifName/ifDescr</th><th>Alias</th><th>Speed (bps)</th><th>Series</th><th>Export</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
        <div class='row' style='gap:8px;margin-top:12px'>
          <a class='btn' href='/snmp/poll?ip={escape(ip)}'>Poll now</a>
          <a class='btn secondary' href='/snmp/export/rrd?ip={escape(ip)}'>Download RRD (.tgz)</a>
          <a class='btn secondary' href='/snmp/export/snapshot?ip={escape(ip)}&format=csv'>Snapshot CSV</a>
        </div>
      </div>

      <div class='card full'>
        <h3>Grafico traffico</h3>
        <form id="gform" class="row" style="gap:10px; flex-wrap:wrap; align-items:flex-end">
          <div style="min-width:260px">
            <label>Interfaccia</label>
            <select id="ifsel" name="if">
              {''.join(if_opts)}
            </select>
          </div>
          <div>
            <label>Range</label>
            <select id="rangesel" name="range">
              <option value="15m">15 minuti</option>
              <option value="60m" selected>60 minuti</option>
              <option value="24h">24 ore</option>
            </select>
          </div>
          <button class="btn" type="submit">Aggiorna</button>
        </form>
        <div style="margin-top:12px">
          <canvas id="chart" height="140"></canvas>
        </div>
        <p class="muted">Valori in <b>Mbps</b> (byte/s * 8 / 1e6). Gli errori/discards sono disponibili in export CSV/JSONL.</p>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <script>
    const ip = {ip_js};
    const ctx = document.getElementById('chart').getContext('2d');
    let chart;

    function fmtTime(ts) {{
      const d = new Date(ts*1000);
      return d.toLocaleTimeString('it-IT', {{hour:'2-digit', minute:'2-digit', second:'2-digit'}});
    }}

    async function loadSeries() {{
      const ifidx = document.getElementById('ifsel').value;
      const range = document.getElementById('rangesel').value;
      const url = `/snmp/api/series?ip=${{encodeURIComponent(ip)}}&if=${{encodeURIComponent(ifidx)}}&range=${{encodeURIComponent(range)}}`;
      const r = await fetch(url);
      const js = await r.json();
      const pts = js.points || [];
      const labels = pts.map(p => fmtTime(p[0]));
      // rrdtool AVERAGE su DS COUNTER ? rate in byte/s, convertiamo in Mbps
      const in_mbps  = pts.map(p => (p[1] && p[1].in_bytes  != null) ? (p[1].in_bytes  * 8 / 1e6) : null);
      const out_mbps = pts.map(p => (p[1] && p[1].out_bytes != null) ? (p[1].out_bytes * 8 / 1e6) : null);

      const ds = [
        {{ label: 'In (Mbps)',  data: in_mbps,  borderWidth: 1, tension: 0.2, spanGaps: true }},
        {{ label: 'Out (Mbps)', data: out_mbps, borderWidth: 1, tension: 0.2, spanGaps: true }}
      ];

      if (chart) {{
        chart.data.labels = labels;
        chart.data.datasets[0].data = in_mbps;
        chart.data.datasets[1].data = out_mbps;
        chart.update();
      }} else {{
        chart = new Chart(ctx, {{
          type: 'line',
          data: {{ labels, datasets: ds }},
          options: {{
            maintainAspectRatio: false,
            scales: {{
              y: {{ beginAtZero: true }}
            }},
            plugins: {{
              legend: {{ position: 'bottom' }}
            }}
          }}
        }});
      }}
    }}

    document.getElementById('gform').addEventListener('submit', (e)=>{{ e.preventDefault(); loadSeries(); }});
    // aggiorna anche al cambio selettori
    document.getElementById('ifsel').addEventListener('change', loadSeries);
    document.getElementById('rangesel').addEventListener('change', loadSeries);
    // primo render
    loadSeries();
    </script>
    </div></body></html>
    """
    return HTMLResponse(html)


# -------------- API: device mgmt --------------

@router.get("/devices", response_class=JSONResponse)
def list_devices():
    conf = _load_conf()
    return {"devices": conf.get("devices", []), "defaults": conf.get("defaults", {})}


@router.post("/manage/add")
def device_add(request: Request,
               ip: str = Form(...), name: str = Form(""), community: str = Form(""),
               port: int = Form(161), timeout_ms: int = Form(1500), retries: int = Form(1),
               poll_interval_s: int = Form(15), if_include_regex: str = Form(".*"), if_exclude_regex: str = Form("(^lo$|^docker.*)")):
    actor = getattr(request.state, 'user', None) or 'unknown'
    ip = _ip_s(ip)
    conf = _load_conf()
    devs = conf.setdefault("devices", [])
    if any(d.get("ip") == ip for d in devs):
        return HTMLResponse("<script>alert('Device già presente');history.back()</script>")
    devs.append({
        "ip": ip, "name": name.strip(), "community": community.strip(), "port": int(port),
        "timeout_ms": int(timeout_ms), "retries": int(retries), "poll_interval_s": int(poll_interval_s),
        "if_include_regex": if_include_regex.strip() or ".*", "if_exclude_regex": if_exclude_regex.strip(),
        "enabled": True,
    })
    try:
        _save_conf(conf)
    except PermissionError:
        log_event("snmp/device/add", ok=False, actor=actor, detail=f"ip:{ip}")
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    log_event("snmp/device/add", ok=True, actor=actor, detail=f"ip:{ip}")
    return RedirectResponse(url="/snmp", status_code=303)


@router.get("/manage/delete")
def device_delete(request: Request, ip: str = Query(...)):
    actor = getattr(request.state, 'user', None) or 'unknown'
    ip = _ip_s(ip)
    conf = _load_conf()
    devs = conf.get("devices", [])
    ndevs = [d for d in devs if d.get("ip") != ip]
    if len(ndevs) == len(devs):
        return HTMLResponse("<script>alert('Device non trovato');history.back()</script>")
    conf["devices"] = ndevs
    try:
        _save_conf(conf)
    except PermissionError:
        log_event("snmp/device/delete", ok=False, actor=actor, detail=f"ip:{ip}")
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    # opzionale: lasciare i dati su disco per storico
    log_event("snmp/device/delete", ok=True, actor=actor, detail=f"ip:{ip}")
    return RedirectResponse(url="/snmp", status_code=303)


@router.post("/manage/defaults")
def update_defaults(request: Request,
                    community: str = Form("public"), port: int = Form(161), timeout_ms: int = Form(1500), retries: int = Form(1),
                    poll_interval_s: int = Form(15), if_include_regex: str = Form(".*"), if_exclude_regex: str = Form("(^lo$|^docker.*)")):
    actor = getattr(request.state, 'user', None) or 'unknown'
    conf = _load_conf()
    conf.setdefault("defaults", {})
    conf["defaults"].update({
        "community": community.strip(), "port": int(port), "timeout_ms": int(timeout_ms),
        "retries": int(retries), "poll_interval_s": int(poll_interval_s),
        "if_include_regex": if_include_regex.strip() or ".*", "if_exclude_regex": if_exclude_regex.strip(),
    })
    try:
        _save_conf(conf)
    except PermissionError:
        log_event("snmp/defaults/update", ok=False, actor=actor)
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    log_event("snmp/defaults/update", ok=True, actor=actor)
    return RedirectResponse(url="/snmp", status_code=303)


# -------------- API: poll & series --------------

@router.get("/poll")
def poll_now(request: Request, ip: str = Query(...)):
    actor = getattr(request.state, 'user', None) or 'unknown'
    ip = _ip_s(ip)
    conf = _load_conf()
    dev = next((d for d in conf.get("devices", []) if d.get("ip") == ip), None)
    if not dev:
        return HTMLResponse("<script>alert('Device non trovato');history.back()</script>")
    try:
        ok = _poller.poll_device(dev, conf.get("defaults", {}))
    except Exception:
        ok = False
    log_event("snmp/poll", ok=bool(ok), actor=actor, detail=f"ip:{ip}")
    return RedirectResponse(url=f"/snmp/device/{ip}", status_code=303)


@router.get("/api/series", response_class=JSONResponse)
def api_series(ip: str = Query(...), if_: int = Query(alias="if"), range: str = Query("15m")):
    ip = _ip_s(ip)
    rng = str(range).strip().lower()
    m = re.match(r"^(\d+)([smhd])$", rng)
    if not m:
        rng_s = 900
    else:
        fac = {"s":1,"m":60,"h":3600,"d":86400}[m.group(2)]
        rng_s = int(m.group(1)) * fac
    data = _rrd_fetch_series(ip, int(if_), "AVERAGE", rng_s)
    return data


# -------------- Export --------------

@router.get("/export/series")
def export_series(ip: str = Query(...), if_: str = Query(alias="if", default="all"), range: str = Query("60m"), format: str = Query("csv")):
    ip = _ip_s(ip)
    # range
    m = re.match(r"^(\d+)([smhd])$", range.lower())
    fac = {"s":1,"m":60,"h":3600,"d":86400}
    rng_s = int(m.group(1)) * fac[m.group(2)] if m else 3600

    targets: List[int] = []
    if if_ == "all":
        cache = DATA_ROOT / ip / "ifcache.json"
        if cache.exists():
            meta = json.loads(cache.read_text("utf-8"))
            targets = [int(k) for k in (meta.get("if") or {}).keys()]
    else:
        try:
            targets = [int(if_)]
        except Exception:
            targets = []
    if not targets:
        return HTMLResponse("Nessuna interfaccia", status_code=404)

    if format == "jsonl":
        def gen():
            for idx in targets:
                series = _rrd_fetch_series(ip, idx, "AVERAGE", rng_s)
                for ts, row in series.get("points", []):
                    payload = {"ip": ip, "ifIndex": idx, **row, "ts": ts}
                    yield json.dumps(payload, ensure_ascii=False) + "\n"
        fname = f"snmp_{ip.replace(':','_')}_series.jsonl"
        return StreamingResponse(gen(), media_type="application/x-ndjson",
                                 headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    # CSV
    header = "ts,ip,ifIndex,in_bps,out_bps,in_err_ps,out_err_ps,in_dis_ps,out_dis_ps\n"
    def esc(v: Any) -> str:
        s = "" if v is None else str(v)
        return '"' + s.replace('"','""') + '"'

    def gen_csv():
        yield header
        for idx in targets:
            series = _rrd_fetch_series(ip, idx, "AVERAGE", rng_s)
            for ts, row in series.get("points", []):
                r = [ts, ip, idx,
                     row.get("in_bytes"), row.get("out_bytes"),
                     row.get("in_err"), row.get("out_err"), row.get("in_dis"), row.get("out_dis")]
                yield ",".join(esc(x) for x in r) + "\n"
    fname = f"snmp_{ip.replace(':','_')}_series.csv"
    return StreamingResponse(gen_csv(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/export/snapshot")
def export_snapshot(ip: str = Query(...), format: str = Query("csv")):
    ip = _ip_s(ip)
    cache = DATA_ROOT / ip / "ifcache.json"
    if not cache.exists():
        return HTMLResponse("Nessun dato", status_code=404)
    meta = json.loads(cache.read_text("utf-8"))

    # Per snapshot, prendiamo l'ultimo punto disponibile per ogni RRD
    records: List[Dict[str, Any]] = []
    for idx_s in (meta.get("if") or {}).keys():
        idx = int(idx_s)
        series = _rrd_fetch_series(ip, idx, "AVERAGE", 15*60)
        pts = series.get("points", [])
        last = pts[-1][1] if pts else {}
        info = meta["if"][idx_s]
        rec = {
            "ip": ip, "ifIndex": idx,
            "name": info.get("name"), "alias": info.get("alias"), "speed": info.get("speed"),
            "in_bps": last.get("in_bytes"), "out_bps": last.get("out_bytes"),
            "in_err_ps": last.get("in_err"), "out_err_ps": last.get("out_err"),
            "in_dis_ps": last.get("in_dis"), "out_dis_ps": last.get("out_dis"),
        }
        records.append(rec)

    if format == "json":
        buf = json.dumps({"items": records}, ensure_ascii=False)
        return StreamingResponse(io.BytesIO(buf.encode("utf-8")), media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="snmp_{ip}_snapshot.json"'})

    # CSV
    header = "ip,ifIndex,name,alias,speed,in_bps,out_bps,in_err_ps,out_err_ps,in_dis_ps,out_dis_ps\n"
    def esc(v: Any) -> str:
        s = "" if v is None else str(v)
        return '"' + s.replace('"','""') + '"'
    def gen_csv():
        yield header
        for r in records:
            row = [r.get("ip"), r.get("ifIndex"), r.get("name"), r.get("alias"), r.get("speed"),
                   r.get("in_bps"), r.get("out_bps"), r.get("in_err_ps"), r.get("out_err_ps"), r.get("in_dis_ps"), r.get("out_dis_ps")]
            yield ",".join(esc(x) for x in row) + "\n"
    return StreamingResponse(gen_csv(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="snmp_{ip}_snapshot.csv"'})


@router.get("/export/rrd")
def export_rrd(ip: str = Query(...)):
    ip = _ip_s(ip)
    base = DATA_ROOT / ip
    if not base.exists():
        return HTMLResponse("Nessun dato", status_code=404)
    mem = io.BytesIO()
    with tarfile.open(fileobj=mem, mode="w:gz") as tar:
        for p in base.glob("*.rrd"):
            tar.add(p, arcname=p.name)
        ic = base / "ifcache.json"
        if ic.exists():
            tar.add(ic, arcname=ic.name)
    mem.seek(0)
    return StreamingResponse(mem, media_type="application/gzip",
                             headers={"Content-Disposition": f'attachment; filename="snmp_{ip}.tgz"'})
