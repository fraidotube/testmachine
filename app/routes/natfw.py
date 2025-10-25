# routes/natfw.py
from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from util.shell import run
import json, re, ipaddress, time

router = APIRouter(prefix="/nat", tags=["nat"])

# ---------- UI ----------
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

# ---------- Helpers ----------
def _ip_route_get()->dict:
    rc, out, _ = run(["/usr/sbin/ip","-j","route","get","1.1.1.1"])
    if rc==0 and out.strip():
        try:
            js = json.loads(out)
            return js[0] if isinstance(js, list) and js else {}
        except Exception:
            pass
    return {}

def _public_ip()->str:
    rc, out, _ = run(["/usr/bin/dig","+short","myip.opendns.com","@resolver1.opendns.com"])
    ip = (out or "").strip().splitlines()[-1] if out else ""
    try:
        if ip: ipaddress.ip_address(ip); return ip
    except Exception:
        ip = ""
    rc, out, _ = run(["/usr/bin/curl","-fsSL","https://1.1.1.1/cdn-cgi/trace"])
    if rc==0 and out:
        m = re.search(r"ip=([0-9a-fA-F\.:]+)", out)
        if m:
            ip = m.group(1)
            try:
                ipaddress.ip_address(ip); return ip
            except Exception:
                pass
    return ""

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_CGN = ipaddress.ip_network("100.64.0.0/10")

def _classify(ip:str)->str:
    try:
        a = ipaddress.ip_address(ip)
        if any(a in n for n in _RFC1918): return "RFC1918"
        if a in _CGN: return "CGNAT"
        return "PUBLIC"
    except Exception:
        return "UNKNOWN"

# ========================================================================
#                                   UI
# ========================================================================
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    return HTMLResponse(
        head("NAT & Firewall") +
        """
<div class='grid'>
  <div class='card'>
    <h2>NAT &amp; Firewall Visibility</h2>
    <p class='muted'>Rileva IP WAN vs IP pubblico (CGNAT), prova apertura porta via UPnP e reachability locale.</p>

    <div class='row'>
      <div>
        <b>Verifica NAT</b>
        <p class='muted-small'>Confronta l'indirizzo di uscita WAN con l'IP pubblico visto da Internet.</p>
        <a class='btn' href='#' onclick='runCheck();return false;'>Esegui verifica</a>
      </div>
      <div>
        <b>UPnP: apri porta</b>
        <div class='row'>
          <div><label>Porta</label><input id='upnp_port' placeholder='50000'/></div>
          <div>
            <label>Protocollo</label>
            <select id='upnp_proto'>
              <option>TCP</option>
              <option>UDP</option>
            </select>
          </div>
        </div>
        <a class='btn' href='#' onclick='runUPnP();return false;'>Apri via UPnP</a>
        <div class='muted tiny'>Richiede un router con UPnP abilitato sul percorso WAN.</div>
      </div>
    </div>

    <hr class='hr-thin'>

    <div>
      <b>Listener locale (finestra temporale)</b>
      <div class='row'>
        <div><label>Porta (>=1024)</label><input id='ls_port' placeholder='55000'/></div>
        <div><label>Durata (s)</label><input id='ls_sec' placeholder='10' value='10'/></div>
      </div>
      <a class='btn' href='#' onclick='runListen();return false;'>Apri finestra di test</a>
      <div class='muted tiny'>Durante la finestra, prova a collegarti dall’esterno all’IP pubblico:porta per verificare il port-forward/firewall.</div>
    </div>
  </div>

  <div class='card'>
    <h2>Risultati</h2>
    <div id='out' class='table mono' style='font-size:.95rem'></div>
  </div>
</div>

<script>
function pill(txt, cls){
  return "<span class='pill'><span class='dot "+cls+"'></span>"+txt+"</span>";
}
function fmtKV(obj){
  if(!obj) return "";
  const esc = (s)=> String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  return "<table><tbody>" + Object.entries(obj).map(([k,v])=>{
    if(v && typeof v==='object') v = JSON.stringify(v);
    return "<tr><th style='text-align:left;opacity:.85;padding-right:10px'>"+esc(k)+"</th><td>"+esc(v??'')+"</td></tr>";
  }).join("") + "</tbody></table>";
}

async function runCheck(){
  const out = document.getElementById('out');
  out.innerHTML = "Esecuzione...";
  try{
    const r = await fetch('/nat/check');
    const js = await r.json();
    if(!js.ok){ out.textContent = 'Errore: risposta non ok'; return; }
    const nat  = js.nat || {};
    const wan  = js.wan || {};
    const pub  = js.public || {};
    const badge =
      (nat.behind_cgnat ? pill("CGNAT", "bad") :
       nat.behind_nat   ? pill("NAT", "warn") :
                          pill("Pubblico", "ok"));

    out.innerHTML =
      "<div style='display:flex;gap:10px;align-items:center;margin-bottom:8px'><b>Classificazione</b>"+badge+"</div>" +
      "<h3>WAN (locale)</h3>"+ fmtKV(wan) +
      "<h3>Pubblico (esterno)</h3>"+ fmtKV(pub) +
      "<h3>Dettagli</h3>"+ fmtKV(nat);
  }catch(e){
    out.textContent = "Errore: "+e;
  }
}

async function runUPnP(){
  const out = document.getElementById('out');
  const p   = Number(document.getElementById('upnp_port').value || 0);
  const pr  = document.getElementById('upnp_proto').value || 'TCP';
  if(!p || p<1 || p>65535){ alert('Porta non valida'); return; }
  out.innerHTML = "UPnP in corso...";
  try{
    const r = await fetch('/nat/upnp/open?port='+encodeURIComponent(p)+'&proto='+encodeURIComponent(pr), {method:'POST'});
    const js = await r.json();
    out.innerHTML = "<h3>UPnP</h3>"+fmtKV(js);
  }catch(e){
    out.textContent = "Errore: "+e;
  }
}

async function runListen(){
  const out = document.getElementById('out');
  const p   = Number(document.getElementById('ls_port').value || 0);
  const s   = Number(document.getElementById('ls_sec').value || 10);
  if(!p || p<1024 || p>65535){ alert('Scegli una porta >=1024'); return; }
  if(!s || s<2 || s>120){ alert('Durata 2..120 secondi'); return; }
  out.innerHTML = "Apro listener...";
  try{
    const r = await fetch('/nat/listen?port='+encodeURIComponent(p)+'&seconds='+encodeURIComponent(s));
    const js = await r.json();
    out.innerHTML = "<h3>Listener</h3>"+fmtKV(js);
  }catch(e){
    out.textContent = "Errore: "+e;
  }
}

// Prefill porte con la porta della UI (se presente)
document.addEventListener('DOMContentLoaded', ()=>{
  const uiPort = (window.location.port && Number(window.location.port)) || 8080;
  const up = document.getElementById('upnp_port');
  const lp = document.getElementById('ls_port');
  if(up && !up.value) up.value = uiPort;
  if(lp && !lp.value) lp.value = uiPort;
});
</script>

</div>
<script src="/static/bg.js"></script>
</body></html>
        """
    )

# ========================================================================
#                                   API
# ========================================================================
@router.get("/check")
def nat_check():
    rget = _ip_route_get()
    ifname = rget.get("dev")
    src_ip = rget.get("prefsrc")
    pub_ip = _public_ip()

    wan_class = _classify(src_ip or "")
    pub_class = _classify(pub_ip or "")

    behind_nat   = (wan_class in ("RFC1918","CGNAT")) and (pub_class == "PUBLIC")
    behind_cgnat = (wan_class == "CGNAT") and (pub_class == "PUBLIC")

    return {
        "ok": True,
        "wan": {"iface": ifname, "addr": src_ip, "class": wan_class},
        "public": {"addr": pub_ip, "class": pub_class},
        "nat": {"behind_nat": behind_nat, "behind_cgnat": behind_cgnat}
    }

@router.post("/upnp/open")
def upnp_open(port: int = Query(..., ge=1, le=65535), proto: str = Query("TCP")):
    proto = (proto or "TCP").upper()
    if proto not in ("TCP","UDP"):
        return JSONResponse({"ok": False, "error": "Protocollo non valido"}, status_code=400)
    rc, out, err = run(["/usr/bin/upnpc","-e","TestMachine","-a","0.0.0.0",str(port),str(port),proto])
    ok = (rc == 0) and (("is redirected" in (out or "")) or ("successfully" in (out or "").lower()))
    return {"ok": bool(ok), "rc": rc, "raw": (out or err or "").strip()}

@router.get("/listen")
def listen_tmp(port: int = Query(..., ge=1024, le=65535), seconds: int = Query(10, ge=2, le=120)):
    """
    Apre un listener TCP locale per 'seconds' secondi senza bloccare la richiesta.
    Implementazione: timeout + socat in background (detached).
    """
    # Comando che si autoconsuma: timeout <s> socat TCP-LISTEN:port,fork,reuseaddr SYSTEM:'echo -ne ...'
    socat_cmd = (
        f"/usr/bin/timeout {int(seconds)}s "
        f"/usr/bin/socat TCP-LISTEN:{int(port)},fork,reuseaddr "
        r"""SYSTEM:'echo -ne TestMachine\ reachability\ ok'"""
    )
    # Esecuzione totalmente dettached
    # nohup bash -lc '<cmd>' >/dev/null 2>&1 &
    rc, out, err = run([
        "/usr/bin/nohup", "/bin/bash", "-lc",
        socat_cmd + " >/dev/null 2>&1 &"
    ])
    # Il nohup ritorna subito; anche se rc!=0, proviamo a dire cosa è successo.
    until_ts = int(time.time()) + int(seconds)
    return {
        "ok": True if rc==0 else False,
        "rc": rc,
        "port": int(port),
        "proto": "TCP",
        "window_s": int(seconds),
        "until_epoch": until_ts,
        "exec": socat_cmd,
        "note": "Il listener si chiude automaticamente allo scadere della finestra."
    }
