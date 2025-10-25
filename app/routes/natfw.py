# routes/natfw.py (updated)
from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from util.shell import run
import json, re, ipaddress, shutil

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

# --------- MTU/MSS Pathfinder helpers ---------
def _nm_get_mtu(profile:"str"="wan0"):
    rc, out, _ = run(["sudo","nmcli","-t","-f","connection.id,ipv4.mtu","connection","show",profile])
    if rc==0 and out:
        parts = out.strip().split(":")
        if len(parts)==2 and parts[1].strip().isdigit():
            return int(parts[1].strip())
    return None

def _nm_set_mtu(profile:"str", mtu:int)->bool:
    rc, _, _ = run(["sudo","nmcli","connection","modify",profile,"ipv4.mtu",str(int(mtu))])
    if rc!=0: return False
    rc, _, _ = run(["sudo","nmcli","connection","up",profile])
    return rc==0

TRACEPATH = shutil.which("tracepath")
PING = shutil.which("ping") or "/bin/ping"

def _tracepath_pmtu(target:str)->int|None:
    if not TRACEPATH:
        return None
    rc, out, _ = run([TRACEPATH,"-n","-m","30",target])
    if rc==0 and out:
        for line in out.splitlines():
            m = re.search(r"pmtu\s+(\d+)", line)
            if m:
                try:
                    return int(m.group(1))
                except:
                    pass
    return None

# Binary search using ping DF: payload + 28 = MTU
def _ping_df_ok(host:str, payload:int)->bool:
    rc, out, _ = run([PING,"-c","1","-W","1","-M","do","-s",str(int(payload)),host])
    if rc!=0: return False
    if "0 received" in (out or "") or "100% packet loss" in (out or ""): return False
    if "Frag needed" in (out or "") or "Message too long" in (out or ""): return False
    return True

def _mtu_search_ping(host:str, lo:int=1200, hi:int=1500)->int|None:
    best = None
    L = max(576, lo)
    H = min(hi, 2000)
    while L <= H:
        mid = (L + H)//2
        payload = mid - 28
        ok = _ping_df_ok(host, payload)
        if ok:
            best = mid
            L = mid + 1
        else:
            H = mid - 1
    return best

def _suggestions(mtu:int|None)->dict:
    sugg = {}
    if mtu:
        ladder = [1460, 1440, 1432, 1400]
        mss = max(536, mtu-40)
        sugg = {"mss": mss, "ladder": ladder, "note": "MSS stimata IPv4 = MTU-40"}
    return sugg

# ========================================================================
#                                   UI
# ========================================================================
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    return HTMLResponse(
        head("NAT & Firewall") +
        """
<div class='grid' style="grid-template-columns: repeat(2, minmax(340px, 1fr)); gap: 24px;">
  <div class='card'>
    <h2>NAT &amp; Firewall Visibility</h2>
    <p class='muted'>Rileva IP WAN vs IP pubblico (CGNAT) e prova apertura porta via UPnP.</p>

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
  </div>

  <div class='card'>
    <h2>Path MTU / MSS</h2>
    <div class='row'>
      <div><label>Target 1</label><input id='mtu_t1' value='1.1.1.1'/></div>
      <div><label>Target 2</label><input id='mtu_t2' value='8.8.8.8'/></div>
    </div>
    <a class='btn' href='#' onclick='runMtuTest();return false;'>Esegui test</a>
    <div id='mtu_out' class='mono' style='margin-top:8px'></div>
    <div class='row' style='margin-top:8px'>
      <div><label>Applica MTU</label><input id='mtu_apply_val' placeholder='es. 1492'/></div>
      <div>
        <label>Opzioni</label>
        <label class='checkbox'><input type='checkbox' id='mss_clamp'/> MSS clamp (TCPMSS)</label>
      </div>
    </div>
    <a class='btn secondary' href='#' onclick='applyMtu();return false;'>Applica</a>
  </div>

  <!-- Traceroute full width -->
  <div class='card' style='grid-column: 1 / -1;'>
    <h2>Traceroute Visualizer</h2>
    <div class='row'>
      <div><label>Destinazione</label><input id='trg' placeholder='8.8.8.8 or example.com'/></div>
      <div>
        <label>Protocollo</label>
        <select id='proto'>
          <option>ICMP</option>
          <option>UDP</option>
          <option>TCP:80</option>
          <option>TCP:443</option>
        </select>
      </div>
      <div><label>Sonde</label><input id='count' value='10'/></div>
    </div>
    <a class='btn' href='#' onclick='runTrace();return false;'>Esegui</a>
    <div id='trace_out' class='table mono' style='font-size:.95rem;margin-top:8px'></div>
  </div>

  <div class='card' style='grid-column: 1 / -1;'>
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
  const esc = (s)=> String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));
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
  }catch(e){ out.textContent = "Errore: "+e; }
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
  }catch(e){ out.textContent = "Errore: "+e; }
}

async function runMtuTest(){
  const box = document.getElementById('mtu_out');
  box.innerHTML = 'Test MTU in corso...';
  try{
    const t1 = (document.getElementById('mtu_t1').value||'').trim();
    const t2 = (document.getElementById('mtu_t2').value||'').trim();
    const body = { targets: [t1||'1.1.1.1', t2||'8.8.8.8'] };
    const r = await fetch('/nat/mtu/test', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const js = await r.json();
    if(!js.ok){ box.textContent = 'Errore: '+(js.error||''); return; }
    let html = '';
    html += '<div><b>MTU attuale</b>: '+(js.mtu_current ?? 'n/d')+'</div>';
    html += '<div><b>MTU consigliata</b>: '+(js.mtu_best ?? 'n/d')+' <span class="muted-small">('+js.method+')</span></div>';
    if(js.suggest && js.suggest.mss){ html += '<div><b>MSS stimata</b>: '+js.suggest.mss+'</div>'; }
    if(js.results){
      html += '<h3>Dettagli per target</h3><table><thead><tr><th>Target</th><th>Metodo</th><th>MTU OK</th><th>Note</th></tr></thead><tbody>'+
        js.results.map(r=>'<tr><td>'+r.target+'</td><td>'+r.method+'</td><td>'+(r.mtu_ok??'')+'</td><td>'+(r.warnings?.join('; ')||'')+'</td></tr>').join('')+
        '</tbody></table>';
    }
    if(js.warnings && js.warnings.length){ html += '<div class="muted">⚠ '+js.warnings.join(' | ')+'</div>'; }
    box.innerHTML = html;
    const ap = document.getElementById('mtu_apply_val');
    if(ap && js.mtu_best) ap.value = js.mtu_best;
  }catch(e){ box.textContent = 'Errore: '+e; }
}

async function applyMtu(){
  const ap = document.getElementById('mtu_apply_val');
  const clamp = document.getElementById('mss_clamp').checked;
  const val = Number(ap.value||0);
  if(!val || val<576 || val>2000){ alert('MTU non valida (576..2000)'); return; }
  const box = document.getElementById('mtu_out');
  box.innerHTML = 'Applicazione in corso...';
  try{
    const r = await fetch('/nat/mtu/apply?mtu='+encodeURIComponent(val)+'&mss_clamp='+(clamp?'true':'false'));
    const js = await r.json();
    box.innerHTML = '<h3>Applicazione</h3>'+fmtKV(js);
  }catch(e){ box.textContent = 'Errore: '+e; }
}

async function runTrace(){
  const dest = (document.getElementById('trg').value||'8.8.8.8').trim();
  const protoSel = document.getElementById('proto').value;
  const count = Number(document.getElementById('count').value||10);
  const out = document.getElementById('trace_out');
  out.innerHTML = 'Esecuzione traceroute...';
  try{
    const r = await fetch('/nat/trace', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({dest, proto: protoSel, count})});
    const js = await r.json();
    if(!js.ok){ out.textContent = 'Errore: '+(js.error||''); return; }
    const hops = Array.isArray(js.hops) ? js.hops : [];
    if (!hops.length) {
      let raw = js.raw ? `<pre style="white-space:pre-wrap">${js.raw}</pre>` : '';
      out.innerHTML = `<div class="muted">Nessun dato dal traceroute (possibile filtro ICMP o parse vuoto).</div>${raw}`;
      return;
    }
    let rows = hops.map(h=>`<tr><td>${h.hop}</td><td>${h.ip||''}</td><td>${h.loss}%</td><td>${h.snt}</td><td>${h.last}</td><td>${h.avg}</td><td>${h.best}</td><td>${h.wrst}</td><td>${h.stdev}</td></tr>`).join('');
    out.innerHTML = `<table><thead><tr><th>#</th><th>IP</th><th>Loss</th><th>Snt</th><th>Last</th><th>Avg</th><th>Best</th><th>Wrst</th><th>σ</th></tr></thead><tbody>${rows}</tbody></table>`;
  }catch(e){ out.textContent = 'Errore: '+e; }
}

// Prefill porta UPnP con la porta della UI
document.addEventListener('DOMContentLoaded', ()=>{
  const uiPort = (window.location.port && Number(window.location.port)) || 8080;
  const up = document.getElementById('upnp_port');
  if(up && !up.value) up.value = uiPort;
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

# -------- MTU endpoints --------
@router.post("/mtu/test")
def mtu_test(payload: dict):
    targets = [t for t in (payload or {}).get('targets', []) if t]
    if not targets:
        targets = ["1.1.1.1","8.8.8.8"]
    results = []
    warnings = []

    mtu_cur = _nm_get_mtu("wan0")

    bests = []
    method = "tracepath+ping"
    for t in targets:
        mtu_tp = _tracepath_pmtu(t)
        if mtu_tp:
            results.append({"target": t, "method": "tracepath", "mtu_ok": mtu_tp, "success": True, "warnings": []})
            bests.append(mtu_tp)
        else:
            mtu_pg = _mtu_search_ping(t)
            if mtu_pg:
                results.append({"target": t, "method": "ping DF", "mtu_ok": mtu_pg, "success": True, "warnings": []})
                bests.append(mtu_pg)
            else:
                results.append({"target": t, "method": "tracepath/ping", "mtu_ok": None, "success": False, "warnings": ["Target non raggiungibile o ICMP filtrato"]})
                warnings.append(f"Nessun responso affidabile da {t}")

    mtu_best = min(bests) if bests else None
    suggest = _suggestions(mtu_best)

    return {
        "ok": True,
        "mtu_current": mtu_cur,
        "mtu_best": mtu_best,
        "method": method,
        "results": results,
        "suggest": suggest,
        "warnings": warnings,
    }

@router.get("/mtu/apply")
def mtu_apply(mtu: int = Query(..., ge=576, le=2000), mss_clamp: bool = Query(False)):
    rget = _ip_route_get()
    ifname = rget.get("dev") or "wan0"

    prev = _nm_get_mtu("wan0")
    ok = _nm_set_mtu("wan0", mtu)
    if not ok:
        return {"ok": False, "error": "Impossibile applicare MTU via nmcli"}

    rc, _, _ = run(["/bin/ping","-c","1","-W","1","1.1.1.1"])
    if rc != 0:
        if prev is not None:
            _nm_set_mtu("wan0", prev)
        return {"ok": False, "error": "Sanity check fallito; rollback MTU", "restored": prev}

    res = {"ok": True, "applied_mtu": mtu}

    if mss_clamp:
        comment = "TM_MSS_CLAMP"
        rc, out, _ = run(["sudo","iptables","-t","mangle","-S"])
        exists = (rc==0 and comment in (out or ""))
        if not exists:
            rc, _, err = run(["sudo","iptables","-t","mangle","-A","FORWARD","-o",ifname,
                              "-p","tcp","--tcp-flags","SYN,RST","SYN","-j","TCPMSS","--clamp-mss-to-pmtu","-m","comment","--comment",comment])
            res["mss_clamp"] = (rc==0)
            if rc!=0:
                res["mss_error"] = err or "iptables non disponibile o permessi insufficienti"
        else:
            res["mss_clamp"] = True
            res["mss_note"] = "Regola già presente"
    return res

# -------- Traceroute Visualizer --------
@router.post("/trace")
def trace(payload: dict):
    dest = (payload or {}).get('dest')
    proto = (payload or {}).get('proto','ICMP')
    count = int((payload or {}).get('count',10))
    if not dest:
        return {"ok": False, "error": "Destinazione mancante"}

    proto = str(proto).upper()
    if proto.startswith('TCP:'):
        port = proto.split(':',1)[1]
        base = ["/usr/bin/mtr","-n","-r","-c",str(count),"-T","-P",str(port)]
    elif proto == 'UDP':
        base = ["/usr/bin/mtr","-n","-r","-c",str(count),"-u"]
    else:
        base = ["/usr/bin/mtr","-n","-r","-c",str(count)]

    rc, out, err = run(base + [dest])
    if rc != 0:
        return {"ok": False, "error": (err or out or "mtr errore")}

    # Parse classic mtr report
    hops = []
    # Regex 1: formato con "|--" (il tuo caso)
    re_pipe = re.compile(
        r"^\s*(\d+)\.\s*\|\-\-\s*(\S+)\s+(\d+(?:\.\d+)?)%\s+(\d+)\s+"
        r"([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)"
    )
    # Regex 2: fallback senza "|--"
    re_plain = re.compile(
        r"^\s*(\d+)\.\s+(\S+)\s+(\d+(?:\.\d+)?)%\s+(\d+)\s+"
        r"([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)"
    )

    for line in (out or "").splitlines():
        s = line.strip()
        if not s or s.startswith(("Start:", "HOST:", "PACKETS", "Loss%")):
            continue
        m = re_pipe.match(s) or re_plain.match(s)
        if m:
            hops.append({
                "hop":  int(m.group(1)),
                "ip":   m.group(2),
                "loss": float(m.group(3)),
                "snt":  int(m.group(4)),
                "last": float(m.group(5)),
                "avg":  float(m.group(6)),
                "best": float(m.group(7)),
                "wrst": float(m.group(8)),
                "stdev":float(m.group(9)),
            })

    # Se vuoto, ritorna anche l'output raw per debug UI
    if not hops:
        return {"ok": True, "hops": [], "raw": out}
    return {"ok": True, "hops": hops}