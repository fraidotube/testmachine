# /opt/netprobe/app/routes/browser.py
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from html import escape

from routes.auth import verify_session_cookie, _load_users

router = APIRouter(tags=["browser"])

def _require_admin(request: Request) -> bool:
    user = verify_session_cookie(request)
    if not user:
        return False
    roles = (_load_users().get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

def _head(title: str) -> str:
    return ("<!doctype html><html><head><meta charset='utf-8'/>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            f"<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
            "<div class='container'><div class='nav'>"
            "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
            "<div class='title-center'>TestMachine</div>"
            "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
            "</div>")

@router.get("/browser-ui", response_class=HTMLResponse)
def browser_ui(request: Request):
    if not _require_admin(request):
        return HTMLResponse(
            _head("Embedded Browser")
            + "<div class='card'><h2 class='err'>Operazione non permessa</h2></div></div></body></html>",
            status_code=403,
        )

    html = _head("Embedded Browser") + """
<div class='grid' style='grid-template-columns:1fr;gap:18px'>

  <!-- Card: Basic Auth -->
  <div class='card'>
    <h2>Basic Auth</h2>
    <p class='muted'>Protegge <code>/browser/</code> con credenziali Apache.</p>

    <form id='authForm' onsubmit='return false' class='row' style='gap:12px;flex-wrap:wrap'>

      <!-- Toggle Enable/Disable -->
      <div style="display:flex;gap:8px;align-items:center">
        <input type="hidden" id="authEnableVal" value="true"/>
        <button type="button" id="enableOn"  class="btn sm"        title="Abilita protezione">Enable</button>
        <button type="button" id="enableOff" class="btn sm danger" title="Disabilita protezione">Disable</button>
      </div>

      <label>Username
        <input name='username' value='admin' style='min-width:180px'/>
      </label>

      <label>Password
        <input type='password' name='password' placeholder='••••••••' style='min-width:200px'/>
      </label>

      <label>Conferma password
        <input type='password' name='password2' placeholder='ripeti password' style='min-width:200px'/>
      </label>

      <div style="display:flex;gap:10px;align-items:center">
        <button class='btn sm' onclick='saveAuth()'>Salva</button>
        <button class='btn sm secondary' type='button' onclick='forceLogout()' title='Cambia realm Basic Auth per forzare il re-login'>Forza logout</button>
      </div>
    </form>
    <div id='authMsg' class='muted' style='margin-top:8px'></div>
  </div>

  <!-- Card: HTTPS / Porta -->
  <div class='card'>
    <h2>HTTPS / Porta</h2>
    <p class='muted'>Vhost Apache in TLS con WebSocket verso <code>127.0.0.1:6902</code>. L'URL usa automaticamente l'IP WAN della macchina.</p>

    <form id='portForm' onsubmit='return false' class='row' style='gap:12px;flex-wrap:wrap'>
      <label>HTTPS Port
        <input name='port' id='port' value='8446' type='number' min='1024' max='65535' style='width:120px'/>
      </label>
      <label>Cert file
        <input name='cert' id='cert' value='/etc/ssl/certs/ssl-cert-snakeoil.pem' style='min-width:320px'/>
      </label>
      <label>Key file
        <input name='key' id='key' value='/etc/ssl/private/ssl-cert-snakeoil.key' style='min-width:320px'/>
      </label>

      <div style="display:flex;gap:10px;align-items:center">
        <button class='btn sm' onclick='savePort()'>Salva & Ricarica Apache</button>
        <button class='btn sm secondary' type='button' onclick='openBrowser()'>Apri /browser/</button>
      </div>
    </form>
    <div id='portMsg' class='muted' style='margin-top:8px'></div>
  </div>

</div>

<script>
// ---- helpers UI ----
function banner(el, text, cls){
  el.className = 'muted ' + (cls||''); el.textContent = text;
}
async function api(path, form){
  const body = form instanceof HTMLFormElement ? new FormData(form) : form;
  const r = await fetch(path, { method: 'POST', body, credentials: 'include' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

// ---- toggle enable/disable ----
(function(){
  const on  = document.getElementById('enableOn');
  const off = document.getElementById('enableOff');
  const val = document.getElementById('authEnableVal');

  function setEnable(v){
    val.value = v ? 'true' : 'false';
    // stile attivo leggero (senza toccare CSS globale)
    on.style.filter  = v ? 'brightness(1.05)' : '';
    off.style.filter = v ? '' : 'brightness(1.05)';
    on.style.opacity  = v ? '1' : '.85';
    off.style.opacity = v ? '.85' : '1';
  }
  on.addEventListener('click',  ()=> setEnable(true));
  off.addEventListener('click', ()=> setEnable(false));
  setEnable(true); // default
})();

// ---- AUTH ----
async function saveAuth(){
  const f = document.getElementById('authForm');
  const msg = document.getElementById('authMsg');
  msg.textContent = "";

  const enabled = document.getElementById('authEnableVal').value === 'true';
  const fd = new FormData();
  fd.set('enable', enabled ? 'true' : 'false');

  if (enabled) {
    const u  = (f.username.value || '').trim();
    const p1 = (f.password.value || '');
    const p2 = (f.password2.value || '');
    if (!u || !p1){ msg.textContent = 'Inserisci username e password.'; return; }
    if (p1 !== p2){ msg.textContent = 'Le password non coincidono.'; return; }
    fd.set('username', u);
    fd.set('password', p1);
  }

  try{
    const j = await api('/api/browser/auth', fd);
    msg.textContent = j.ok ? 'Salvato.' : ('Errore: ' + (j.err||''));
  }catch(e){
    msg.textContent = 'Errore: ' + e.message;
  }
}

async function forceLogout(){
  const msg = document.getElementById('authMsg');
  msg.textContent = "";
  try{
    const j = await api('/api/browser/force-relogin', new FormData());
    msg.textContent = j.ok
      ? ('Realm aggiornato: ' + j.realm + ' — chiudi la scheda /browser/ e riaprila per vedere l’effetto')
      : ('Errore: ' + (j.err||''));
  }catch(e){
    msg.textContent = 'Errore: ' + e.message;
  }
}

// ---- PORT/VHOST ----
async function savePort(){
  const el = document.getElementById('portMsg');
  try{
    const f = document.getElementById('portForm');
    const fd = new FormData();
    fd.set('port',      f.port.value);
    fd.set('cert_file', f.cert.value);
    fd.set('cert_key',  f.key.value);
    banner(el, 'Scrivo vhost & ricarico Apache...', '');
    const j = await api('/api/browser/port', fd);
    if (j.ok){
      banner(el, 'Attivo su: ' + j.url, 'ok');
    }else{
      banner(el, 'Errore: ' + (j.err||''), 'err');
    }
  }catch(e){
    banner(el, 'Errore: ' + e.message, 'err');
  }
}

async function openBrowser(){
  try{
    const r = await fetch('/api/browser/status', { credentials: 'include' });
    const s = await r.json();
    const port = (s && s.port) ? s.port : (document.getElementById('port').value || '8446');
    const host = (s && s.servername) ? s.servername : location.hostname;
    window.open('https://' + host + ':' + port + '/browser/', '_blank');
  }catch(e){
    const port = document.getElementById('port').value || '8446';
    window.open('https://' + location.hostname + ':' + port + '/browser/', '_blank');
  }
}

// Prefill stato corrente
(async ()=>{
  try{
    const r = await fetch('/api/browser/status', { credentials: 'include' });
    const s = await r.json();
    if (s && s.ok && s.port) document.getElementById('port').value = s.port;
  }catch(e){}
})();
</script>
<script src="/static/bg.js"></script>
</body></html>
"""
    return HTMLResponse(html)
