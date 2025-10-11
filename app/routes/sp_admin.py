from fastapi import APIRouter
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, FileResponse
import os, re, tempfile, shutil, subprocess, tarfile, time
from pathlib import Path
from html import escape


router = APIRouter(prefix="/sp-admin", tags=["sp-admin"])

# --- Paths & constants -------------------------------------------------------
TARGETS = Path("/etc/smokeping/config.d/Targets")
BEGIN = "# BEGIN_TM_MANAGED"
END   = "# END_TM_MANAGED"
GROUP_HEADER = "+ TestMachine\nmenu = TestMachine\ntitle = Hosts gestiti da TestMachine\n\n"

RRD_DIR = Path("/var/lib/smokeping/TestMachine")
TMP_DIR = Path("/opt/netprobe/tmp")
TMP_DIR.mkdir(parents=True, exist_ok=True)

# --- Helpers -----------------------------------------------------------------
def read_targets() -> str:
    return TARGETS.read_text(encoding="utf-8")

def ensure_block(txt: str) -> str:
    """Garantisce la presenza del blocco BEGIN..END (vuoto) in coda al file."""
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
    """Sostituisce l’intero blocco gestito con gli host passati."""
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

def sp_check():
    p = subprocess.run(["/usr/sbin/smokeping","--check"], text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def sp_reload():
    subprocess.run(["sudo","-n","/bin/systemctl","reload","smokeping"], text=True, capture_output=True)

# --- UI fragments ------------------------------------------------------------
NAV = """
<div class='nav'>
  <div class='brand'><img src='/static/img/logo.svg' class='logo' alt='Logo'><span>TestMachine</span></div>
  <div class='links'><a href='/'>Home</a></div>
</div>
"""

# --- Pages -------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def admin_home():
    html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>SmokePing Admin</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='grid'><div class='card'>
  <h2>SmokePing Admin</h2>
  <p>Sezione amministrativa minima. Qui gestisci target e servizio.</p>
  <div class='row'>
    <a class='btn' href='/smokeping/'>Apri interfaccia SmokePing</a>
    <a class='btn' href='/sp-admin/targets'>Vedi/gestisci Targets</a>
  </div>
  <a class='btn danger' href='/sp-admin/restart'>Riavvia servizio</a>
</div></div>
</div></body></html>"""
    return HTMLResponse(html)


@router.get("/targets", response_class=HTMLResponse)
def targets_page():
    # Pre-render server-side della lista host
    txt = ensure_block(read_targets())
    hosts = current_hosts(txt)

    def row_html(h):
        n = escape(h["name"])
        a = escape(h["address"])
        # bottone elimina chiama delHost('<name>')
        return (
            "<div class='row' style='justify-content:space-between;align-items:center;margin:6px 0'>"
            f"<div><b>{n}</b> <span class='muted'>{a}</span></div>"
            f"<button class='btn danger' onclick=\"delHost('{n}')\">Elimina</button>"
            "</div>"
        )

    initial = "".join(row_html(h) for h in hosts) or "<div class='muted'>Nessun host gestito.</div>"

    html = f"""<!doctype html><html><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Targets</title>
<link rel='stylesheet' href='/static/styles.css'/></head>
<body><div class='container'>
{NAV}
<div class='card'>
  <h2>Gestione Targets</h2>
  <div class='row'>
    <div style='flex:1'>
      <h3>Host gestiti</h3>
      <div id='hostList' class='card muted' style='padding:8px'>{initial}</div>
    </div>
    <div style='flex:1'>
      <h3>Aggiungi host</h3>
      <label>Nome</label><input id='name' value='host1'/>
      <label>Indirizzo/IP</label><input id='addr' value='8.8.8.8'/>
      <button class='btn' onclick='add()'>Aggiungi</button>
      <p class='muted'>Gli host vengono inseriti sotto il gruppo <b>TestMachine</b>.</p>
      <div class='row'>
        <a class='btn' href='/sp-admin/targets/raw'>Vedi file Targets (raw)</a>
        <a class='btn' href='/sp-admin/export/rrd'>Esporta RRD (tar.gz)</a>
      </div>
    </div>
  </div>
</div>
<script>
async function load(){{
  try {{
    const r = await fetch('/sp-admin/hosts/list', {{cache:'no-cache'}});
    const data = await r.json();
    const el = document.getElementById('hostList');
    el.innerHTML = '';
    if(!data.length){{ el.innerHTML = "<div class='muted'>Nessun host gestito.</div>"; return; }}
    for (const h of data){{
      const row = document.createElement('div');
      row.className = 'row';
      row.style.justifyContent='space-between';
      row.style.alignItems='center';
      row.style.margin='6px 0';
      row.innerHTML =
        "<div><b>"+h.name+"</b> <span class='muted'>"+h.address+"</span></div>" +
        "<button class='btn danger' onclick=\\"delHost('"+h.name.replace(/'/g,"&#39;")+"')\\">Elimina</button>";
      el.appendChild(row);
    }}
  }} catch(e) {{
    console.error('load() error', e);
  }}
}}
async function add(){{
  const n = document.getElementById('name').value.trim();
  const a = document.getElementById('addr').value.trim();
  if(!n || !a){{ alert('Nome e indirizzo sono obbligatori'); return; }}
  const r = await fetch('/sp-admin/hosts/add?name='+encodeURIComponent(n)+'&address='+encodeURIComponent(a));
  const j = await r.json().catch(()=>({{status:'error',detail:'risposta non json'}}));
  if(j.status!=='ok') alert(j.detail||'Errore');
  await load();
}}
async function delHost(n){{
  if(!confirm('Eliminare '+n+'?')) return;
  const r = await fetch('/sp-admin/hosts/delete?name='+encodeURIComponent(n));
  const j = await r.json().catch(()=>({{status:'error',detail:'risposta non json'}}));
  if(j.status!=='ok') alert(j.detail||'Errore');
  await load();
}}
// aggiorna via JS appena la pagina è pronta
document.addEventListener('DOMContentLoaded', load);
</script>
</div></body></html>"""
    return HTMLResponse(html)




# --- Raw view ---------------------------------------------------------------
@router.get("/targets/raw", response_class=PlainTextResponse)
def targets_raw():
    return TARGETS.read_text(encoding="utf-8")

# --- JSON APIs --------------------------------------------------------------
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

# --- Actions ----------------------------------------------------------------
@router.get("/restart", response_class=JSONResponse)
def restart():
    p = subprocess.run(["sudo","-n","/bin/systemctl","restart","smokeping"], text=True, capture_output=True)
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



