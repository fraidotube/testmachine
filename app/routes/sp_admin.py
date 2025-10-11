from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, FileResponse
import os, re, tempfile, shutil, subprocess, tarfile, time
from pathlib import Path
from html import escape

router = APIRouter(prefix="/sp-admin", tags=["sp-admin"])

# --- Paths & constants -------------------------------------------------------
TARGETS   = Path("/etc/smokeping/config.d/Targets")
GENERAL   = Path("/etc/smokeping/config.d/General")
DB_FILE   = Path("/etc/smokeping/config.d/Database")
BEGIN     = "# BEGIN_TM_MANAGED"
END       = "# END_TM_MANAGED"
GROUP_HEADER = "+ TestMachine\nmenu = TestMachine\ntitle = Hosts gestiti da TestMachine\n\n"

RRD_DIR   = Path("/var/lib/smokeping/TestMachine")
LOCAL_DIR = Path("/var/lib/smokeping/Local")  # alcuni setup creano LocalMachine.rrd qui
TMP_DIR   = Path("/opt/netprobe/tmp")
TMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Helpers comuni ----------------------------------------------------------
def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)

def sp_check():
    p = run(["/usr/sbin/smokeping", "--check"])
    return p.returncode, p.stdout, p.stderr

def sp_reload():
    run(["sudo","-n","/bin/systemctl","reload","smokeping"])

def svc_state():
    p = run(["/bin/systemctl","is-active","smokeping"])
    st = (p.stdout or "").strip()
    return st if st else "unknown"

# ---- Database helpers (step/pings) ------------------------------------------
def db_get_vals():
    txt = DB_FILE.read_text(encoding="utf-8")
    m1 = re.search(r"(?m)^\s*step\s*=\s*(\d+)\s*$",  txt);  step  = int(m1.group(1)) if m1 else 300
    m2 = re.search(r"(?m)^\s*pings\s*=\s*(\d+)\s*$", txt);  pings = int(m2.group(1)) if m2 else 20
    return step, pings, txt

def db_write_safely(step:int, pings:int, original_txt:str):
    # sostituisco SOLO le righe step/pings
    new_txt = re.sub(r"(?m)^\s*step\s*=\s*\d+\s*$",  f"step     = {step}",  original_txt)
    new_txt = re.sub(r"(?m)^\s*pings\s*=\s*\d+\s*$", f"pings    = {pings}", new_txt)

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = TMP_DIR / f"Database.{int(time.time())}"
    tmp.write_text(new_txt, encoding="utf-8")

    # install + check
    run(["sudo","-n","/usr/bin/install","-m","644", str(tmp), str(DB_FILE)])
    rc, so, se = sp_check()
    if rc != 0:
        # rollback
        rb = TMP_DIR / f"Database.rollback.{int(time.time())}"
        rb.write_text(original_txt, encoding="utf-8")
        run(["sudo","-n","/usr/bin/install","-m","644", str(rb), str(DB_FILE)])
        return False, (so + se)
    sp_reload()
    return True, ""

# ---- RRD safety check -------------------------------------------------------
def rrd_existing():
    """Conta RRD esistenti per evitare mismatch quando cambia lo STEP."""
    paths = []
    for d in (RRD_DIR, LOCAL_DIR):
        if d.exists():
            paths += [str(p) for p in d.glob("*.rrd")]
    return len(paths), paths

# ---- Targets helpers --------------------------------------------------------
def read_targets() -> str:
    return TARGETS.read_text(encoding="utf-8")

def ensure_block(txt: str) -> str:
    if BEGIN in txt and END in txt:
        return txt
    addition = f"\n{BEGIN}\n{GROUP_HEADER}{END}\n"
    if not txt.endswith("\n"):
        txt += "\n"
    return txt + addition

def get_indices(txt: str):
    i1 = txt.find(BEGIN)
    i2 = txt.find(END, i1 + 1)
    return i1, i2

def parse_hosts(block: str):
    hosts = []
    for part in re.split(r"(?m)^\+\+\s*", block):
        part = part.strip("\n")
        if not part:
            continue
        lines = part.splitlines()
        if not lines:
            continue
        name = lines[0].strip()
        addr = None
        for ln in lines:
            s = ln.strip()
            if s.lower().startswith("host"):
                kv = s.split("=", 1)
                if len(kv) == 2:
                    addr = kv[1].strip()
        if addr:
            hosts.append({"name": name, "address": addr})
    return hosts

def current_hosts(txt: str):
    i1, i2 = get_indices(txt)
    inner = txt[i1 + len(BEGIN):i2] if (i1 >= 0 and i2 >= 0) else ""
    return parse_hosts(inner)

def build_block(hosts):
    body = f"{BEGIN}\n{GROUP_HEADER}"
    for h in hosts:
        name = h["name"]; addr = h["address"]
        body += f"++ {name}\nmenu = {name}\ntitle = {name}\nhost = {addr}\n\n"
    body += f"{END}"
    return body

def save_targets(original_txt: str, hosts):
    i1, i2 = get_indices(original_txt)
    new_block = build_block(hosts)
    if i1 >= 0 and i2 >= 0:
        endpos = i2 + len(END)
        new_txt = original_txt[:i1] + new_block + original_txt[endpos:]
    else:
        new_txt = ensure_block(original_txt)
        i1, i2 = get_indices(new_txt)
        endpos = i2 + len(END)
        new_txt = new_txt[:i1] + new_block + new_txt[endpos:]
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write(new_txt)
        tmp = f.name
    if TARGETS.exists():
        shutil.copymode(TARGETS, tmp)
    os.replace(tmp, TARGETS)
    return new_txt

# --- UI fragments ------------------------------------------------------------
NAV = (
    "<div class='nav'>"
    "  <div class='brand'><img src='/static/img/logo.svg' class='logo' alt='Logo'><span>TestMachine</span></div>"
    "  <div class='links'><a href='/'>Home</a></div>"
    "</div>"
)

# --- Home --------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def admin_home():
    html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>SmokePing Admin</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='grid'>
  <div class='card'>
    <h2>SmokePing Admin</h2>
    <p>Sezione amministrativa minima. Qui gestisci target e servizio.</p>
    <div class='row' style='gap:12px;flex-wrap:wrap'>
      <a class='btn' href='/smokeping/'>Apri interfaccia SmokePing</a>
      <a class='btn' href='/sp-admin/targets'>Vedi/gestisci Targets</a>
      <a class='btn' href='/sp-admin/tuning'>Tuning sonda SmokePing</a>
      <a class='btn danger' href='/sp-admin/restart'>Riavvia servizio</a>
    </div>
  </div>
</div>
</div></body></html>"""
    return HTMLResponse(html)

# --- Targets UI --------------------------------------------------------------
@router.get("/targets", response_class=HTMLResponse)
def targets_page():
    txt = ensure_block(read_targets())
    hosts = current_hosts(txt)

    def row_html(h):
        n = escape(h["name"]); a = escape(h["address"])
        return (
            "<div class='row' style='justify-content:space-between;align-items:center;margin:6px 0'>"
            "<div><b>"+n+"</b> <span class='muted'>"+a+"</span></div>"
            "<button class='btn danger' onclick=\"delHost('"+n+"')\">Elimina</button>"
            "</div>"
        )

    initial = "".join(row_html(h) for h in hosts) or "<div class='muted'>Nessun host gestito.</div>"

    html = (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<title>Targets</title>"
        "<link rel='stylesheet' href='/static/styles.css'/></head>"
        "<body><div class='container'>"
        + NAV +
        "<div class='card'>"
        "  <h2>Gestione Targets</h2>"
        "  <div class='row'>"
        "    <div style='flex:1'>"
        "      <h3>Host gestiti</h3>"
        "      <div id='hostList' class='card muted' style='padding:8px'>"+initial+"</div>"
        "    </div>"
        "    <div style='flex:1'>"
        "      <h3>Aggiungi host</h3>"
        "      <label>Nome</label><input id='name' value='host1'/>"
        "      <label>Indirizzo/IP</label><input id='addr' value='8.8.8.8'/>"
        "      <button class='btn' onclick='add()'>Aggiungi</button>"
        "      <p class='muted'>Gli host vengono inseriti sotto il gruppo <b>TestMachine</b>.</p>"
        "      <div class='row'>"
        "        <a class='btn' href='/sp-admin/targets/raw'>Vedi file Targets (raw)</a>"
        "        <a class='btn' href='/sp-admin/export/rrd'>Esporta RRD (tar.gz)</a>"
        "      </div>"
        "    </div>"
        "  </div>"
        "</div>"
        "<script>"
        "async function load(){"
        "  try {"
        "    const r = await fetch('/sp-admin/hosts/list', {cache:'no-cache'});"
        "    const data = await r.json();"
        "    const el = document.getElementById('hostList');"
        "    el.innerHTML='';"
        "    if(!data.length){ el.innerHTML = \"<div class='muted'>Nessun host gestito.</div>\"; return; }"
        "    for (const h of data){"
        "      const row = document.createElement('div');"
        "      row.className='row';"
        "      row.style.justifyContent='space-between';"
        "      row.style.alignItems='center';"
        "      row.style.margin='6px 0';"
        "      row.innerHTML="
        "        \"<div><b>\"+h.name+\"</b> <span class='muted'>\"+h.address+\"</span></div>\" +"
        "        \"<button class=\\\"btn danger\\\" onclick=\\\"delHost('\"+h.name.replace(/'/g,'&#39;')+\"')\\\">Elimina</button>\";"
        "      el.appendChild(row);"
        "    }"
        "  } catch(e){ console.error('load() error', e); }"
        "}"
        "async function add(){"
        "  const n=document.getElementById('name').value.trim();"
        "  const a=document.getElementById('addr').value.trim();"
        "  if(!n||!a){ alert('Nome e indirizzo sono obbligatori'); return; }"
        "  const r=await fetch('/sp-admin/hosts/add?name='+encodeURIComponent(n)+'&address='+encodeURIComponent(a));"
        "  const j=await r.json().catch(()=>({status:'error',detail:'risposta non json'}));"
        "  if(j.status!=='ok') alert(j.detail||'Errore');"
        "  await load();"
        "}"
        "async function delHost(n){"
        "  if(!confirm('Eliminare '+n+'?')) return;"
        "  const r=await fetch('/sp-admin/hosts/delete?name='+encodeURIComponent(n));"
        "  const j=await r.json().catch(()=>({status:'error',detail:'risposta non json'}));"
        "  if(j.status!=='ok') alert(j.detail||'Errore');"
        "  await load();"
        "}"
        "document.addEventListener('DOMContentLoaded', load);"
        "</script>"
        "</div></body></html>"
    )
    return HTMLResponse(html)

# --- Raw view ---------------------------------------------------------------
@router.get("/targets/raw", response_class=PlainTextResponse)
def targets_raw():
    return TARGETS.read_text(encoding="utf-8")

# --- JSON APIs (targets) ----------------------------------------------------
@router.get("/hosts/list", response_class=JSONResponse)
def hosts_list():
    txt = ensure_block(read_targets())
    return current_hosts(txt)

_name_re = re.compile(r"^[A-Za-z0-9_.-]+$")

@router.get("/hosts/add", response_class=JSONResponse)
def hosts_add(name: str, address: str):
    if not name or not address:
        return {"status":"error","detail":"name e address sono obbligatori"}
    if not _name_re.match(name):
        return {"status":"error","detail":"Nome non valido"}
    original = ensure_block(read_targets())
    hosts = current_hosts(original)
    if any(h["name"]==name for h in hosts):
        return {"status":"ok","detail":"Già presente"}
    hosts.append({"name":name, "address":address})
    save_targets(original, hosts)
    rc, so, se = sp_check()
    if rc != 0:
        with open(TARGETS,"w",encoding="utf-8") as f: f.write(original)
        return {"status":"error","detail":"Config non valida","check_out":so,"check_err":se}
    sp_reload()
    return {"status":"ok"}

@router.get("/hosts/delete", response_class=JSONResponse)
def hosts_delete(name: str):
    original = ensure_block(read_targets())
    hosts = current_hosts(original)
    new_hosts = [h for h in hosts if h["name"] != name]
    if len(new_hosts)==len(hosts):
        return {"status":"error","detail":"Host non trovato"}
    save_targets(original, new_hosts)
    rc, so, se = sp_check()
    if rc != 0:
        with open(TARGETS,"w",encoding="utf-8") as f: f.write(original)
        return {"status":"error","detail":"Config non valida","check_out":so,"check_err":se}
    sp_reload()
    return {"status":"ok"}

# --- Tuning UI --------------------------------------------------------------
@router.get("/tuning", response_class=HTMLResponse)
def tuning_page():
    step, pings, _ = db_get_vals()
    rrd_n, _ = rrd_existing()

    warn_html = ""
    if rrd_n > 0:
        warn_html = (
          "<div class='card' style='margin-top:10px;background:rgba(255,200,0,.08);"
          "border:1px solid rgba(255,200,0,.35)'>"
          "<b>Attenzione</b>: risultano <b>"+str(rrd_n)+"</b> file RRD di host già presenti. "
          "Cambiare lo <b>step</b> con RRD esistenti causa errore di mismatch. "
          "Prima elimina tutti i target dalla pagina <a class='btn' href='/sp-admin/targets'>Vedi/gestisci Targets</a> "
          "e verifica che la cartella RRD sia vuota.</div>"
        )

    html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Tuning sonda SmokePing</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='card'>
  <h2>Tuning sonda SmokePing</h2>
  <form method='post' action='/sp-admin/tuning/save'>
    <label>Intervallo (step)</label>
    <input name='step' value='{step}' pattern='[0-9]{{1,5}}' required />
    <label>Pings per round</label>
    <input name='pings' value='{pings}' pattern='[0-9]{{1,5}}' required />
    <button class='btn' type='submit'>Salva</button>
  </form>
  <p class='muted'>I parametri vengono scritti in <code>/etc/smokeping/config.d/Database</code>,
  validati con <code>smokeping --check</code> e poi applicati con reload.</p>
  {warn_html}
</div>
</div></body></html>"""
    return HTMLResponse(html)

# --- Tuning APIs ------------------------------------------------------------
@router.get("/tuning/info", response_class=JSONResponse)
def tuning_info():
    step, pings, _ = db_get_vals()
    return {"state": svc_state(), "step": step, "pings": pings}

@router.get("/tuning/save", response_class=JSONResponse)
def tuning_save_api(step: int, pings: int):
    if not (10 <= step <= 3600 and 1 <= pings <= 1000):
        return {"status":"error","detail":"Valori non validi (step 10..3600, pings 1..1000)"}
    cur_step, cur_pings, original = db_get_vals()
    if step != cur_step:
        rrd_n, _ = rrd_existing()
        if rrd_n > 0:
            return {"status":"error",
                    "detail": f"Sono presenti {rrd_n} RRD. Elimina i target prima di cambiare lo step."}
    ok, detail = db_write_safely(step, pings, original)
    if not ok:
        return {"status":"error","detail":"Config non valida","check_out":detail}
    return {"status":"ok"}

@router.post("/tuning/save", response_class=HTMLResponse)
def tuning_save(step: int = Form(...), pings: int = Form(...)):
    # Validazioni "safe"
    if not (10 <= step <= 3600):
        msg = f"Valore step non valido: {step}. Range consigliato 10..3600."
        html = f"<!doctype html><html><head><meta charset='utf-8'/>" \
               f"<meta name='viewport' content='width=device-width,initial-scale=1'/>" \
               f"<title>Errore</title><link rel='stylesheet' href='/static/styles.css'/></head>" \
               f"<body><div class='container'>{NAV}" \
               f"<div class='card'><h2 class='err'>{escape(msg)}</h2>" \
               f"<a class='btn' href='/sp-admin/tuning'>Torna</a></div></div></body></html>"
        return HTMLResponse(html, status_code=400)

    if not (1 <= pings <= 1000):
        msg = f"Valore pings non valido: {pings}. Range consigliato 1..1000."
        html = f"<!doctype html><html><head><meta charset='utf-8'/>" \
               f"<meta name='viewport' content='width=device-width,initial-scale=1'/>" \
               f"<title>Errore</title><link rel='stylesheet' href='/static/styles.css'/></head>" \
               f"<body><div class='container'>{NAV}" \
               f"<div class='card'><h2 class='err'>{escape(msg)}</h2>" \
               f"<a class='btn' href='/sp-admin/tuning'>Torna</a></div></div></body></html>"
        return HTMLResponse(html, status_code=400)

    # Se sto cambiando lo step e ci sono RRD nel gruppo TestMachine -> blocca
    cur_step, cur_pings, original = db_get_vals()
    rrd_files = sorted(p.name for p in RRD_DIR.glob("*.rrd"))
    if step != cur_step and rrd_files:
        files_html = "".join(f"<li><code>{escape(n)}</code></li>" for n in rrd_files)
        html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Impossibile applicare</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='card warn'>
  <h2>Impossibile applicare</h2>
  <p>Hai richiesto di cambiare lo <b>step</b> da <code>{cur_step}</code> a <code>{step}</code>, 
     ma risultano <b>{len(rrd_files)}</b> file RRD già presenti nel gruppo <code>TestMachine</code>.
     SmokePing richiede che gli RRD siano creati con lo stesso step del file di configurazione.</p>
  <p><b>Cosa fare:</b></p>
  <ol>
    <li>Elimina tutti i target dalla pagina <a class='btn' href='/sp-admin/targets'>Vedi/gestisci Targets</a>.</li>
    <li>Verifica che la cartella <code>{RRD_DIR}</code> sia vuota.</li>
    <li>Riprova a salvare i nuovi parametri.</li>
  </ol>
  <details style="margin-top:10px">
    <summary class='muted'>Elenco RRD presenti</summary>
    <ul style="margin-top:8px">{files_html}</ul>
  </details>
  <div class='row' style='gap:12px;flex-wrap:wrap;margin-top:14px'>
    <a class='btn' href='/sp-admin/targets'>Vedi/gestisci Targets</a>
    <a class='btn' href='/sp-admin/tuning'>Torna</a>
  </div>
</div>
</div></body></html>"""
        return HTMLResponse(html, status_code=400)

    # Scrivi, verifica con smokeping --check, reload; rollback automatico in caso di errore
    ok, detail = db_write_safely(step, pings, original)
    if not ok:
        det = escape(detail) if detail else "Config non valida"
        html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Errore configurazione</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='card'>
  <h2 class='err'>Errore: configurazione non valida</h2>
  <pre class='muted' style="white-space:pre-wrap">{det}</pre>
  <a class='btn' href='/sp-admin/tuning'>Torna</a>
</div>
</div></body></html>"""
        return HTMLResponse(html, status_code=500)

    # Successo
    html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Parametri aggiornati</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='card'>
  <h2 class='ok'>Parametri aggiornati</h2>
  <p>Step: <code>{step}</code> — Pings per round: <code>{pings}</code>.<br/>
     Il servizio SmokePing è stato ricaricato.</p>
  <div class='row' style='gap:12px;flex-wrap:wrap;margin-top:6px'>
    <a class='btn' href='/sp-admin/'>Torna all'admin</a>
    <a class='btn' href='/sp-admin/tuning'>Modifica ancora</a>
    <a class='btn' href='/smokeping/'>Apri SmokePing</a>
  </div>
</div>
</div></body></html>"""
    return HTMLResponse(html)




# --- Actions ----------------------------------------------------------------
@router.get("/restart", response_class=JSONResponse)
def restart():
    p = run(["sudo","-n","/bin/systemctl","restart","smokeping"])
    if p.returncode != 0:
        return {"status":"error","out":p.stdout,"err":p.stderr}
    return {"status":"ok"}

@router.get("/export/rrd")
def export_rrd():
    if not RRD_DIR.exists():
        return PlainTextResponse("RRD dir non trovata", status_code=404)
    out = TMP_DIR / f"rrd-{int(time.time())}.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        for p in RRD_DIR.glob("*.rrd"):
            tar.add(str(p), arcname=p.name)
    return FileResponse(str(out), media_type="application/gzip", filename=out.name)

