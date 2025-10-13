import os, re
from fastapi import APIRouter, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse
from util.shell import run

router = APIRouter()

def head(title:str)->str:
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

# ------------------- Utility esistenti (porta) -------------------
def _self_ip() -> str:
    rc, out, _ = run(["/usr/sbin/ip","route","get","1.1.1.1"])
    if rc == 0:
        m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m: return m.group(1)
    rc, out, _ = run(["/usr/sbin/ip","-4","-o","addr","show","scope","global","up"])
    if rc == 0:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
        if m: return m.group(1)
    return "127.0.0.1"

def _current_port() -> int:
    try:
        with open("/etc/apache2/sites-available/testmachine.conf","r") as f:
            m = re.search(r"<VirtualHost\s+\*:(\d+)>", f.read())
            if m: return int(m.group(1))
    except Exception:
        pass
    return 8080

# ------------------- Nuove utility (clock/NTP) -------------------
def _time_status():
    """Ritorna dict con local_time, timezone e ntp_service."""
    d = {"local_time":"n/d", "timezone":"Etc/UTC", "ntp_service":"timesyncd"}
    rc, out, _ = run(["/usr/bin/timedatectl"])
    if rc == 0:
        m = re.search(r"Local time:\s+(.*)", out)
        if m: d["local_time"] = m.group(1).strip()
        m = re.search(r"Time zone:\s+([^\s]+)", out)
        if m: d["timezone"]   = m.group(1).strip()
    return d

def _tz_options(current: str) -> str:
    zones = []
    try:
        with open("/usr/share/zoneinfo/zone1970.tab","r") as f:
            for line in f:
                if not line or line.startswith("#"): continue
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    tz = parts[2]
                    if "/" in tz:
                        zones.append(tz)
    except Exception:
        pass
    zones = sorted(set(zones))
    return "".join(
        f"<option value='{z}' {'selected' if z==current else ''}>{z}</option>"
        for z in zones
    )

def _read_ntp_servers() -> str:
    path = "/etc/systemd/timesyncd.conf"
    if os.path.exists(path):
        try:
            txt = open(path,"r").read()
            m = re.search(r"(?m)^\s*NTP\s*=\s*(.+)$", txt)
            if m: return m.group(1).strip()
        except Exception:
            pass
    return ""

# ------------------- Pagina Impostazioni -------------------
@router.get("/", response_class=HTMLResponse)
def settings_home(request: Request):
    # card porta (invariata)
    cur = _current_port()
    port_card = f"""
    <div class='card'>
      <h2>Porta Web (Apache)</h2>
      <form method='post' action='/settings/port'>
        <label>Porta</label>
        <input name='port' value='{cur}' pattern='[0-9]{{2,5}}' required />
        <button class='btn' type='submit'>Applica</button>
      </form>
      <p class='notice'>Dopo il cambio porta verrai reindirizzato automaticamente.</p>
    </div>"""

    # card orario & NTP (nuova)
    st = _time_status()
    tz_current = st["timezone"]
    tz_opts = _tz_options(tz_current)
    ntp_servers = _read_ntp_servers()
    clock_card = f"""
    <div class='card'>
      <h2>Orario & NTP</h2>
      <p>Ora server: <b>{st['local_time']}</b> — Fuso attuale: <b>{tz_current}</b></p>
      <p>Servizio NTP: timesyncd — Server configurati: <b>{ntp_servers or 'n/d'}</b></p>

      <h3>Cambia fuso orario</h3>
      <form method='post' action='/settings/timezone'>
        <label>Timezone</label>
        <select name='tz'>{tz_opts}</select>
        <button class='btn' type='submit'>Imposta Timezone</button>
      </form>

      <h3>Server NTP</h3>
      <form method='post' action='/settings/ntp'>
        <label>Elenco server (separa con spazio)</label>
        <input name='servers' value='{ntp_servers or "0.pool.ntp.org 1.pool.ntp.org"}'/>
        <button class='btn' type='submit'>Applica NTP</button>
      </form>
      <p class='muted'>Supportato <code>systemd-timesyncd</code>.</p>
    </div>"""

    html = head("Impostazioni") + f"""
    <div class='grid'>
      {port_card}
      {clock_card}
    </div></div></body></html>"""
    return HTMLResponse(html)

# ------------------- Azioni porta (INVARIATE) -------------------
def _apply_port_change(tmp_ports, tmp_vhost, bak_ports, bak_vhost):
    import time
    time.sleep(0.7)
    r1 = run(["sudo","-n","/usr/bin/install","-m","644", tmp_ports, "/etc/apache2/ports.conf"])
    r2 = run(["sudo","-n","/usr/bin/install","-m","644", tmp_vhost, "/etc/apache2/sites-available/testmachine.conf"])
    run(["sudo","-n","/usr/sbin/a2ensite","testmachine"])
    r3 = run(["sudo","-n","/bin/systemctl","restart","apache2"])
    if r1[0]!=0 or r2[0]!=0 or r3[0]!=0:
        if os.path.exists(bak_ports):
            run(["sudo","-n","/usr/bin/install","-m","644", bak_ports, "/etc/apache2/ports.conf"])
        if os.path.exists(bak_vhost):
            run(["sudo","-n","/usr/bin/install","-m","644", bak_vhost, "/etc/apache2/sites-available/testmachine.conf"])
        run(["sudo","-n","/bin/systemctl","restart","apache2"])

@router.post("/port")
def set_port(background_tasks: BackgroundTasks, port: int = Form(...)):
    tmpdir = "/var/lib/netprobe/tmp"
    os.makedirs(tmpdir, exist_ok=True)
    tag = str(os.getpid())
    tmp_ports = os.path.join(tmpdir, f"ports.conf.{tag}")
    tmp_vhost = os.path.join(tmpdir, f"testmachine.conf.{tag}")
    bak_ports = os.path.join(tmpdir, f"ports.conf.bak.{tag}")
    bak_vhost = os.path.join(tmpdir, f"testmachine.conf.bak.{tag}")

    ports_txt = f"""Listen 80
<IfModule ssl_module>
    Listen 443
</IfModule>
<IfModule mod_gnutls.c>
    Listen 443
</IfModule>
Listen {port}
"""
    vhost_txt = f"""<VirtualHost *:{port}>
    ServerName testmachine.local
    ProxyPreserveHost On
    ProxyPass        /api/ws ws://127.0.0.1:9000/api/ws
    ProxyPassReverse /api/ws ws://127.0.0.1:9000/api/ws
    ProxyPass /smokeping/ !
    ProxyPass /cgi-bin/ !
    ProxyPass        / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
    ErrorLog /var/log/apache2/testmachine-error.log
    CustomLog /var/log/apache2/testmachine-access.log combined
</VirtualHost>
"""
    if os.path.exists("/etc/apache2/ports.conf"):
        run(["/usr/bin/install","-m","644","/etc/apache2/ports.conf", bak_ports])
    if os.path.exists("/etc/apache2/sites-available/testmachine.conf"):
        run(["/usr/bin/install","-m","644","/etc/apache2/sites-available/testmachine.conf", bak_vhost])
    with open(tmp_ports,"w") as f: f.write(ports_txt)
    with open(tmp_vhost,"w") as f: f.write(vhost_txt)
    background_tasks.add_task(_apply_port_change, tmp_ports, tmp_vhost, bak_ports, bak_vhost)
    ip = _self_ip()
    target = f"http://{ip}:{port}/settings/"
    html = head("Impostazioni") + f"""
    <div class='grid'><div class='card'>
      <h2 class='ok'>Porta impostata a {port}</h2>
      <p>Riavvio di Apache in corso. Verrai reindirizzato automaticamente.</p>
      <p>Se non succede, clicca: <a class='btn' href="{target}">{target}</a></p></div></div></div>
    <meta http-equiv="refresh" content="3; url={target}">
    <script>setTimeout(function(){{ location.replace("{target}"); }}, 3000);</script>
    </body></html>"""
    return HTMLResponse(html)

# ------------------- Azioni nuove: timezone & NTP -------------------
@router.post("/timezone", response_class=HTMLResponse)
def set_timezone(tz: str = Form(...)):
    if not tz or "/" not in tz or ".." in tz or "\\" in tz:
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Timezone non valida</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    if not os.path.exists(f"/usr/share/zoneinfo/{tz}"):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Timezone inesistente</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    run(["sudo","-n","/usr/bin/timedatectl","set-timezone", tz])
    return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='ok'>Timezone aggiornata</h2><a class='btn' href='/settings/'>Torna alle Impostazioni</a></div></div></div></body></html>")

@router.post("/ntp", response_class=HTMLResponse)
def set_ntp(servers: str = Form(...)):
    sv = [s.strip() for s in re.split(r"[,\s]+", servers or "") if s.strip()]
    if not sv:
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Inserisci almeno un server</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    os.makedirs("/var/lib/netprobe/tmp", exist_ok=True)
    tag = str(os.getpid())
    tmp = f"/var/lib/netprobe/tmp/timesyncd.conf.{tag}"
    txt = "[Time]\nNTP=" + " ".join(sv) + "\n"
    with open(tmp,"w") as f: f.write(txt)
    r1 = run(["sudo","-n","/usr/bin/install","-m","644", tmp, "/etc/systemd/timesyncd.conf"])
    r2 = run(["sudo","-n","/bin/systemctl","restart","systemd-timesyncd"])
    if r1[0]!=0 or r2[0]!=0:
        return HTMLResponse(head("Impostazioni") + f"<div class='grid'><div class='card'><h2 class='err'>Errore nel configurare NTP</h2><pre>{r1}\n{r2}</pre><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='ok'>Server NTP aggiornati</h2><a class='btn' href='/settings/'>Torna alle Impostazioni</a></div></div></div></body></html>")
