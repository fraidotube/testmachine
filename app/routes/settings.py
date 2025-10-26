# /opt/netprobe/app/routes/settings.py

import os, re, time
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from util.shell import run
from util.audit import log_event
from routes.auth import verify_session_cookie, _load_users

router = APIRouter()

REPO_DIR = "/opt/netprobe"
CACTI_DEBIAN_PHP = "/etc/cacti/debian.php"  # path file Cacti
INSTALLER_CANDIDATES = (
    "/opt/netprobe/install-testmachine.sh",
    "/opt/netprobe/install/install-testmachine.sh",
)
LOG_DIR = "/var/lib/netprobe/tmp"

# ------------------- helpers comuni -------------------
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

def _require_admin(request: Request) -> bool:
    user = verify_session_cookie(request)
    if not user:
        return False
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

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
        f"<option value='{escape(z)}' {'selected' if z==current else ''}>{escape(z)}</option>"
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

# ------------------- Git utils -------------------
def _git_short_status():
    s = []
    rc, out, _ = run(["/usr/bin/git","-C",REPO_DIR,"rev-parse","--abbrev-ref","HEAD"])
    if rc == 0: s.append(f"branch: {out.strip()}")
    rc, out, _ = run(["/usr/bin/git","-C",REPO_DIR,"rev-parse","--short","HEAD"])
    if rc == 0: s.append(f"commit: {out.strip()}")
    rc, out, _ = run(["/usr/bin/git","-C",REPO_DIR,"status","-sb"])
    if rc == 0: s.append(out.strip())
    return "\n".join(s) if s else "n/d"

def _find_installer() -> str | None:
    for p in INSTALLER_CANDIDATES:
        if os.path.exists(p):
            return p
    return None

# ---- systemd helpers
def _systemd_run(args: list[str]):
    for sd in ("/bin/systemd-run", "/usr/bin/systemd-run"):
        if os.path.exists(sd):
            return run(["sudo","-n", sd] + args)
    return (1, "", "systemd-run non trovato")

def _schedule_reboot(delay_s: int, reason: str = ""):
    rc, out, err = _systemd_run(["--unit", "testmachine-reboot",
                                 "--on-active", str(max(1, delay_s)),
                                 "/sbin/reboot"])
    if rc == 0:
        return rc, out, err
    # Fallback a shutdown:
    msg = f"TestMachine: {reason}".strip() or "TestMachine: reboot"
    if delay_s <= 60:
        return run(["sudo","-n","/usr/sbin/shutdown","-r","now", msg])
    else:
        minutes = max(1, delay_s // 60)
        return run(["sudo","-n","/usr/sbin/shutdown","-r", f"+{minutes}", msg])

def _unit_active(name: str) -> bool:
    rc, _, _ = run(["/bin/systemctl","is-active",name])
    return rc == 0

# ------------------- Pagina Impostazioni -------------------
@router.get("/", response_class=HTMLResponse)
def settings_home(request: Request):
    is_admin = _require_admin(request)

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

    st = _time_status()
    tz_current = st["timezone"]
    tz_opts = _tz_options(tz_current)
    ntp_servers = _read_ntp_servers()
    clock_card = f"""
    <div class='card'>
      <h2>Orario & NTP</h2>
      <p>Ora server: <b>{escape(st['local_time'])}</b> — Fuso attuale: <b>{escape(tz_current)}</b></p>
      <p>Servizio NTP: timesyncd — Server configurati: <b>{escape(ntp_servers or 'n/d')}</b></p>

      <h3>Cambia fuso orario</h3>
      <form method='post' action='/settings/timezone'>
        <label>Timezone</label>
        <select name='tz'>{tz_opts}</select>
        <button class='btn' type='submit'>Imposta Timezone</button>
      </form>

      <h3>Server NTP</h3>
      <form method='post' action='/settings/ntp'>
        <label>Elenco server (separa con spazio)</label>
        <input name='servers' value='{escape(ntp_servers or "0.pool.ntp.org 1.pool.ntp.org")}'/>
        <button class='btn' type='submit'>Applica NTP</button>
      </form>
      <p class='muted'>Supportato <code>systemd-timesyncd</code>.</p>
    </div>"""

    host = os.uname().nodename
    git_info = _git_short_status() if is_admin else "—"
    maint_card = f"""
    <div class='card'>
      <h2>Manutenzione & Aggiornamenti</h2>
      {"<p class='muted'>Area riservata agli amministratori.</p>" if not is_admin else ""}

      <h3>Hostname</h3>
      <form method='post' action='/settings/hostname'>
        <label>Hostname attuale</label>
        <input value='{escape(host)}' readonly />
        <label>Nuovo hostname</label>
        <input name='hostname' placeholder='es. testmachine-01' pattern='[a-zA-Z0-9][a-zA-Z0-9-\\.]{0,251}[a-zA-Z0-9]' />
        <button class='btn' type='submit' {"disabled" if not is_admin else ""}>Cambia hostname</button>
      </form>

      <h3>Riavvio sistema</h3>
      <form method='post' action='/settings/reboot' onsubmit="return confirm('Riavviare ora la macchina?');">
        <button class='btn danger' type='submit' {"disabled" if not is_admin else ""}>Riavvia</button>
      </form>

      <h3>Aggiornamento da GitHub</h3>
      <p class='mono small'>Repo: {escape(REPO_DIR)}<br/>{escape(git_info)}</p>
      <form method='post' action='/settings/update' onsubmit="return confirm('Aggiornare e riavviare al termine?');">
        <label>Branch remoto</label>
        <input name='branch' value='main' />
        <button class='btn' type='submit' {"disabled" if not is_admin else ""}>Aggiorna &amp; mostra log</button>
      </form>
      <p class='muted'>Fa: <code>git fetch --all --prune</code>, <code>git reset --hard origin/&lt;branch&gt;</code>, esegue <code>install-testmachine.sh --update</code> e <b>programma il reboot</b> a fine run.</p>
    </div>"""

    # Card Cacti (stringa normale)
    cacti_card = """
    <div class='card' style='grid-column:1 / -1'>
      <h2>Cacti (DB password)</h2>
      <p class='muted'>Legge la password dell'utente DB <b>cacti</b> da <code>/etc/cacti/debian.php</code>.</p>
      <div class='row' style='gap:8px; align-items:flex-end; flex-wrap:wrap'>
        <input id='cactiPw' class='mono' type='password' style='min-width:320px' placeholder='••••••••' readonly/>
        <button class='btn' type='button' onclick='showCactiPw()'>Mostra</button>
        <button class='btn secondary' type='button' onclick='copyCactiPw()'>Copia</button>
      </div>
      <p id='cactiPwMsg' class='muted' style='margin-top:6px'></p>
    </div>
    <script>
    async function showCactiPw(){
      const msg = document.getElementById('cactiPwMsg');
      msg.textContent = '';
      try{
        const r = await fetch('/settings/cacti/dbpass');
        const t = await r.text();
        let js;
        try{ js = JSON.parse(t); }catch(_e){ js = {ok:false, error:t}; }
        if(js.ok){
          const el = document.getElementById('cactiPw');
          el.type = 'text';
          el.value = js.password || '';
          msg.textContent = 'Letta correttamente.';
        }else{
          alert('Errore: '+(js.error||'operazione non riuscita'));
        }
      }catch(e){
        alert('Errore: '+e);
      }
    }
    function copyCactiPw(){
      const el = document.getElementById('cactiPw');
      if(!el.value) return;
      navigator.clipboard.writeText(el.value).then(()=>{
        const msg = document.getElementById('cactiPwMsg');
        msg.textContent = 'Copiata negli appunti.';
      });
    }
    </script>
    """

    html = head("Impostazioni") + f"""
    <div class='grid'>
      {port_card}
      {clock_card}
      {maint_card}
      {cacti_card}
    </div></div>
    <script src="/static/bg.js"></script>
    </body></html>"""
    return HTMLResponse(html)

# ------------------- Azioni porta (INVARIATE) -------------------
def _apply_port_change(tmp_ports, tmp_vhost, bak_ports, bak_vhost):
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
def set_port(request: Request, port: int = Form(...)):
    tmpdir = LOG_DIR
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
    ProxyRequests Off
    RequestHeader set X-Forwarded-Proto "http"

    # Esclusioni prima
    ProxyPass /smokeping/ !
    ProxyPass /cgi-bin/   !
    ProxyPass /cacti/     !
    
    ProxyPass        /api/ws   ws://127.0.0.1:9000/api/ws
    ProxyPassReverse /api/ws   ws://127.0.0.1:9000/api/ws
    ProxyPass        /shell/ws ws://127.0.0.1:9000/shell/ws
    ProxyPassReverse /shell/ws ws://127.0.0.1:9000/shell/ws

    # Graylog sotto /graylog (rewrite cookie SOLO qui)
    <Location "/graylog/">
      ProxyPassReverseCookiePath / /graylog/
    </Location>
    ProxyPass        /graylog/          http://127.0.0.1:9001/
    ProxyPassReverse /graylog/          http://127.0.0.1:9001/
    ProxyPass        /graylog/api/ws    ws://127.0.0.1:9001/api/ws
    ProxyPassReverse /graylog/api/ws    ws://127.0.0.1:9001/api/ws
    ProxyPass        /graylog/shell/ws  ws://127.0.0.1:9001/shell/ws
    ProxyPassReverse /graylog/shell/ws  ws://127.0.0.1:9001/shell/ws

    # App FastAPI (root)
    ProxyPass        /  http://127.0.0.1:9000/
    ProxyPassReverse /  http://127.0.0.1:9000/

    ErrorLog  /var/log/apache2/testmachine-error.log
    CustomLog /var/log/apache2/testmachine-access.log combined
</VirtualHost>
"""
    if os.path.exists("/etc/apache2/ports.conf"):
        run(["/usr/bin/install","-m","644","/etc/apache2/ports.conf", bak_ports])
    if os.path.exists("/etc/apache2/sites-available/testmachine.conf"):
        run(["/usr/bin/install","-m","644","/etc/apache2/sites-available/testmachine.conf", bak_vhost])
    open(tmp_ports,"w").write(ports_txt)
    open(tmp_vhost,"w").write(vhost_txt)

    # Applico in background 
    def _apply():
        _apply_port_change(tmp_ports, tmp_vhost, bak_ports, bak_vhost)
    try:
        import threading
        threading.Thread(target=_apply, daemon=True).start()
    except Exception:
        _apply()

    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("settings/port", ok=True, actor=actor, ip=ip, detail=f"port={port}", req_path=str(request.url))
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
def set_timezone(request: Request, tz: str = Form(...)):
    if not tz or "/" not in tz or ".." in tz or "\\" in tz:
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Timezone non valida</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    if not os.path.exists(f"/usr/share/zoneinfo/{tz}"):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Timezone inesistente</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    rc, out, err = run(["sudo","-n","/usr/bin/timedatectl","set-timezone", tz])
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("settings/timezone", ok=(rc==0), actor=actor, ip=ip, detail=f"tz={tz}", req_path=str(request.url),
              extra={"rc": rc, "stderr": err[:200] if err else ""})
    return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='ok'>Timezone aggiornata</h2><a class='btn' href='/settings/'>Torna alle Impostazioni</a></div></div></div></body></html>")

@router.post("/ntp", response_class=HTMLResponse)
def set_ntp(request: Request, servers: str = Form(...)):
    sv = [s.strip() for s in re.split(r"[,\s]+", servers or "") if s.strip()]
    if not sv:
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Inserisci almeno un server</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    os.makedirs(LOG_DIR, exist_ok=True)
    tag = str(os.getpid())
    tmp = f"{LOG_DIR}/timesyncd.conf.{tag}"
    txt = "[Time]\nNTP=" + " ".join(sv) + "\n"
    open(tmp,"w").write(txt)
    r1 = run(["sudo","-n","/usr/bin/install","-m","644", tmp, "/etc/systemd/timesyncd.conf"])
    r2 = run(["sudo","-n","/bin/systemctl","restart","systemd-timesyncd"])
    if r1[0]!=0 or r2[0]!=0:
        actor = verify_session_cookie(request) or "unknown"
        ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
        log_event("settings/ntp", ok=False, actor=actor, ip=ip, detail="apply_failed",
                  req_path=str(request.url), extra={"rc_install": r1[0], "rc_restart": r2[0]})
        return HTMLResponse(head("Impostazioni") + f"<div class='grid'><div class='card'><h2 class='err'>Errore nel configurare NTP</h2><pre>{escape(str(r1))}\n{escape(str(r2))}</pre><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("settings/ntp", ok=True, actor=actor, ip=ip, detail="updated", req_path=str(request.url), extra={"servers": sv})
    return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='ok'>Server NTP aggiornati</h2><a class='btn' href='/settings/'>Torna alle Impostazioni</a></div></div></div></body></html>")

# ------------------- Hostname / Reboot -------------------
_HOST_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

def _patch_etc_hosts(new_host: str):
    try:
        txt = open("/etc/hosts","r").read()
    except Exception:
        txt = ""
    lines = []
    replaced = False
    for ln in txt.splitlines():
        if ln.strip().startswith("127.0.1.1"):
            lines.append(f"127.0.1.1\t{new_host}")
            replaced = True
        else:
            lines.append(ln)
    if not replaced:
        lines.append(f"127.0.1.1\t{new_host}")
    tmp = f"{LOG_DIR}/hosts.{os.getpid()}"
    os.makedirs(LOG_DIR, exist_ok=True)
    open(tmp,"w").write("\n".join(lines) + "\n")
    run(["sudo","-n","/usr/bin/install","-m","644", tmp, "/etc/hosts"])

@router.post("/hostname", response_class=HTMLResponse)
def set_hostname(request: Request, hostname: str = Form(...)):
    if not _require_admin(request):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Operazione non permessa</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")

    hn = (hostname or "").strip()
    if not hn or len(hn) > 253 or not _HOST_RE.fullmatch(hn):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Hostname non valido</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")

    rc, out, err = run(["sudo","-n","/usr/bin/hostnamectl","set-hostname", hn])
    _patch_etc_hosts(hn)
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("settings/hostname", ok=(rc==0), actor=actor, ip=ip,
              detail=f"hostname={hn}", req_path=str(request.url), extra={"rc": rc, "stderr": err[:200] if err else ""})

    return HTMLResponse(head("Impostazioni") + f"<div class='grid'><div class='card'><h2 class='ok'>Hostname impostato a <code>{escape(hn)}</code></h2><a class='btn' href='/settings/'>Torna</a></div></div></div></body></html>")

@router.post("/reboot", response_class=HTMLResponse)
def reboot_machine(request: Request):
    if not _require_admin(request):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Operazione non permessa</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    rc, out, err = _schedule_reboot(5, reason=f"riavvio richiesto da {actor} via UI")
    log_event("settings/reboot", ok=(rc==0), actor=actor, ip=ip,
              detail="scheduled", extra={"rc": rc, "stderr": (err or "")[:200]})
    return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='ok'>Riavvio programmato in pochi secondi…</h2><p>La pagina diventerà irraggiungibile per ~1–2 minuti.</p></div></div></div></body></html>")

# ------------------- UPDATE: unit transiente + polling log + reboot integrato -------------------
def _safe_log_from_id(log_id: str) -> str | None:
    if not re.fullmatch(r"\d{9,12}", log_id):  # timestamp-like
        return None
    path = f"{LOG_DIR}/update.{log_id}.log"
    # harden: ensure path stays within LOG_DIR
    if os.path.commonpath([os.path.abspath(path), os.path.abspath(LOG_DIR)]) != os.path.abspath(LOG_DIR):
        return None
    return path

def _start_update_unit(branch: str, unit: str, log_path: str) -> tuple[int, str]:
    """
    Unit transiente (root) che:
      - ferma servizi APT automatici (soft)
      - attende i lock APT/dpkg
      - prova la riparazione dpkg interrotto
      - git fetch/reset (utente 'netprobe')
      - esegue installer (root)
      - se RC==0, programma reboot in 10s
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    open(log_path, "a").close()
    inst = _find_installer()
    if not inst:
        script = f'echo "[ERRORE] installer non trovato" >> {log_path} 2>&1; exit 1'
    else:
        script = (
            f'LOG="{log_path}"; '
            f'echo "[UPDATE] start $(date -Ins)" >> "$LOG" 2>&1; '
            f'echo "[WHOAMI] uid=$(id -u) user=$(whoami)" >> "$LOG" 2>&1; '

            # stop soft di servizi/timer che possono tenere lock
            'systemctl try-stop --no-block apt-daily.service apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true; '
            'systemctl try-stop --no-block apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true; '

            # attesa lock (max ~10 min)
            'for i in $(seq 1 300); do '
            '  if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 '
            '     && ! fuser /var/lib/dpkg/lock >/dev/null 2>&1 '
            '     && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then '
            '       break; '
            '  fi; '
            '  echo "[WAIT] dpkg/apt lock in use, retry..." >> "$LOG" 2>&1; '
            '  sleep 2; '
            'done; '

            # preflight riparazione dpkg interrotto
            'export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none; '
            'echo "[PRE] dpkg --configure -a" >> "$LOG" 2>&1; '
            'dpkg --configure -a >> "$LOG" 2>&1 || true; '
            'echo "[PRE] apt-get -f install" >> "$LOG" 2>&1; '
            'apt-get -o Dpkg::Lock::Timeout=600 -y -f install >> "$LOG" 2>&1 || true; '

            # sync codice come netprobe
            f'sudo -u netprobe -H git -C {REPO_DIR} fetch --all --prune >> "$LOG" 2>&1; '
            f'sudo -u netprobe -H git -C {REPO_DIR} reset --hard origin/{branch} >> "$LOG" 2>&1; '

            # installer (root)
            f'DEBIAN_FRONTEND=noninteractive /bin/bash {inst} --update >> "$LOG" 2>&1; '
            'RC=$?; echo "[UPDATE] done rc=$RC $(date -Ins)" >> "$LOG" 2>&1; '

            # reboot solo se OK
            'if [ "$RC" -eq 0 ]; then '
            '  echo "[REBOOT] scheduling in 10s" >> "$LOG" 2>&1; '
            '  /bin/systemd-run --unit testmachine-reboot --on-active=10 /sbin/reboot >> "$LOG" 2>&1; '
            'else '
            '  echo "[REBOOT] skipped due to rc=$RC" >> "$LOG" 2>&1; '
            'fi; '
            'exit $RC'
        )
    rc, out, err = _systemd_run(["--unit", unit, "--collect", "--uid", "root", "/bin/bash", "-lc", script])
    return rc, (err or "")


@router.post("/update", response_class=HTMLResponse)
def update_from_git(request: Request, branch: str = Form("main")):
    if not _require_admin(request):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Operazione non permessa</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")

    b = (branch or "main").strip()
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", b):
        return HTMLResponse(head("Impostazioni") + "<div class='grid'><div class='card'><h2 class='err'>Branch non valido</h2><a class='btn' href='/settings/'>Indietro</a></div></div></div></body></html>")

    log_id = str(int(time.time()))
    log_path = _safe_log_from_id(log_id)
    unit = f"testmachine-update-{log_id}"

    rc_unit, err = _start_update_unit(b, unit, log_path)
    actor = verify_session_cookie(request) or "unknown"
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("settings/update", ok=(rc_unit==0), actor=actor, ip=ip, detail=f"branch={b}", req_path=str(request.url),
              extra={"unit": unit, "log": log_path})

    html = head("Aggiornamento in corso") + f"""
<div class='grid'><div class='card' style='grid-column:1 / -1'>
  <h2>Update &amp; Install</h2>
  <p class='mono small'>Unit: {escape(unit)} — Log ID: <code>{escape(log_id)}</code></p>
  {"<p class='err'>Avvio unit fallito: "+escape(err)+"</p>" if rc_unit!=0 else ""}
  <pre id='out' style='height:65vh;overflow:auto;white-space:pre-wrap'></pre>
  <p class='muted'>Il sistema si riavvierà automaticamente ~10s dopo la fine dell'installer.</p>
</div></div>
<script>
const pre = document.getElementById('out');
function append(t){{ pre.textContent += t; pre.scrollTop = pre.scrollHeight; }}
let pos = 0;
let done = false;
async function poll(){{
  try{{
    const r = await fetch('/settings/update/tail?id={escape(log_id)}&unit={escape(unit)}&pos='+pos);
    const js = await r.json();
    if(js.chunk) append(js.chunk);
    if(typeof js.pos === 'number') pos = js.pos;
    if(js.done) {{
      done = true;
      append("\\n[UI] Fine aggiornamento. Se non riparte, riavvia manualmente.\\n");
      return;
    }}
  }}catch(e){{ append("\\n[UI] "+String(e)+"\\n"); }}
  if(!done) setTimeout(poll, 400);
}}
poll();
</script>
</body></html>"""
    return HTMLResponse(html)

@router.get("/update/tail", response_class=JSONResponse)
def update_tail(request: Request, id: str, unit: str, pos: int = 0):
    if not _require_admin(request):
        return JSONResponse({"error":"forbidden"}, status_code=403)
    log_path = _safe_log_from_id(id)
    if not log_path:
        return JSONResponse({"error":"bad id"}, status_code=400)
    # clamp pos
    if pos < 0: pos = 0
    max_chunk = 32768
    chunk = ""
    try:
        size = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        if pos > size: pos = 0
        if size > pos:
            with open(log_path,"r", encoding="utf-8", errors="ignore") as f:
                f.seek(pos)
                chunk = f.read(min(max_chunk, size - pos))
                pos = f.tell()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    # done quando la unit non è più attiva e non ci sono bytes nuovi
    done = (not _unit_active(unit)) and (chunk == "")
    return JSONResponse({"ok": True, "pos": pos, "chunk": chunk, "done": done})

# ------------------- API: lettura password DB di Cacti -------------------
_pw_re = re.compile(r"""(?m)^\s*\$database_password\s*=\s*(['"])(.*?)\1\s*;""")

@router.get("/cacti/dbpass", response_class=JSONResponse)
def cacti_db_password(request: Request):
    if not _require_admin(request):
        return JSONResponse({"ok": False, "error": "Operazione non permessa"}, status_code=403)

    txt = None
    try:
        with open(CACTI_DEBIAN_PHP, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        open_err = f"{e.__class__.__name__}: {e}"
    else:
        open_err = None

    if txt is None:
        rc, out, err = run(["/usr/bin/grep", r"^\$database_password", CACTI_DEBIAN_PHP])
        if rc == 0:
            txt = out
        else:
            log_event("settings/cacti/dbpass", ok=False, actor=verify_session_cookie(request) or "unknown",
                      detail="read_failed", extra={"open_err": open_err or "", "rc_grep": rc, "stderr_grep": (err or "")[:160]})
            return JSONResponse({"ok": False, "error": f"Impossibile leggere {CACTI_DEBIAN_PHP} (rc={rc})"}, status_code=500)

    m = _pw_re.search(txt or "")
    if not m:
        log_event("settings/cacti/dbpass", ok=False, actor=verify_session_cookie(request) or "unknown",
                  detail="regex_no_match")
        return JSONResponse({"ok": False, "error": "Campo $database_password non trovato"}, status_code=404)

    pw = m.group(2)
    log_event("settings/cacti/dbpass", ok=True, actor=verify_session_cookie(request) or "unknown")
    return JSONResponse({"ok": True, "password": pw})
