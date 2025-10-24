# /opt/netprobe/app/routes/speedtest.py
from fastapi import APIRouter, Form, Body, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from pathlib import Path
from html import escape
import subprocess, os, json, time, signal, shutil, pathlib

router = APIRouter(prefix="/speedtest", tags=["speedtest"])

SPEED_DIR   = Path("/var/lib/netprobe/speedtest")
STATE_FILE  = SPEED_DIR / "state.json"     # {"pid":int|null, "started":ts, "result":{...}|null, "tool":"ookla|pycli"}
LOG_FILE    = SPEED_DIR / "last.log"
HIST_FILE   = SPEED_DIR / "history.jsonl"  # 1 riga JSON per test (append-only)
LAST_FILE   = SPEED_DIR / "last.json"      # snapshot ultimo test (compat per alerting)

SPEEDTEST_CFG = Path("/etc/netprobe/speedtest.json")

_DEFAULT_CFG = {
    "enabled": True,           # scheduler abilitato
    "interval_min": 120,       # ogni N minuti
    "retention_max": 10000,    # massimo record da conservare
    "prefer": "auto",          # auto | ookla | pycli
    "server_id": "",           # opzionale
    "tag": ""                  # tag libero
}

def _cfg_load():
    try:
        cfg = json.loads(SPEEDTEST_CFG.read_text("utf-8"))
        for k,v in _DEFAULT_CFG.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        return dict(_DEFAULT_CFG)

def _cfg_save(c:dict):
    tmp=SPEEDTEST_CFG.with_suffix(".tmp")
    tmp.write_text(json.dumps(c,indent=2),encoding="utf-8"); os.replace(tmp,SPEEDTEST_CFG)

# ----------------- helpers -----------------
def _ensure_dir():
    SPEED_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps({"pid": None, "started": None, "result": None, "tool": None}, indent=2), encoding="utf-8")
    if not HIST_FILE.exists():
        HIST_FILE.write_text("", encoding="utf-8")
    if not LAST_FILE.exists():
        LAST_FILE.write_text("{}", encoding="utf-8")

def _load_state():
    _ensure_dir()
    try:
        return json.loads(STATE_FILE.read_text("utf-8"))
    except Exception:
        return {"pid": None, "started": None, "result": None, "tool": None}

def _save_state(st: dict):
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_FILE)

def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def _read_history(limit: int = 100) -> list[dict]:
    _ensure_dir()
    if not HIST_FILE.exists():
        return []
    rows = []
    try:
        with open(HIST_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    pass
    except Exception:
        return []
    rows.reverse()
    return rows[: max(1, min(1000, int(limit)))]

# ----------------- UI -----------------
def _page_head(title: str) -> str:
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

def _pick_cmd(cfg: dict) -> tuple[list[str], str]:
    prefer = (cfg.get("prefer") or "auto").lower()
    server_id = str(cfg.get("server_id") or "").strip()

    if prefer in ("auto", "ookla") and shutil.which("speedtest"):
        cmd = ["/usr/bin/speedtest", "-f", "json", "-p", "no", "--accept-license", "--accept-gdpr"]
        if server_id:
            cmd += ["--server-id", server_id]
        return (cmd, "ookla")

    py = shutil.which("python3") or "python3"
    code = (
        "import json,sys; import speedtest as s; st=s.Speedtest(); "
        "sid=sys.argv[1] if len(sys.argv)>1 else ''; "
        "st.get_servers(([int(sid)] if (sid and sid.isdigit()) else None)); "
        "st.get_best_server(); "
        "d=st.download(); u=st.upload(pre_allocate=False); "
        "p=st.results.ping; sv=st.results.server or {}; "
        "print(json.dumps({'ping':p,'download':d,'upload':u,'server':sv}))"
    )
    cmd = [py, "-c", code, server_id]
    return (cmd, "pycli")

# ====== CARD GRAFICI (HTML+JS) =================================================
charts_card = """
<div class='card'>
  <div style='display:flex; align-items:center; gap:10px; justify-content:space-between; flex-wrap:wrap'>
    <h2 style='margin:0'>Grafici speedtest</h2>
    <div style='display:flex; gap:8px; align-items:center'>
      <button class='btn secondary' id='btnRange24h'>24h</button>
      <button class='btn secondary' id='btnRange7d'>7g</button>
      <button class='btn secondary' id='btnRange30d'>30g</button>
      <button class='btn secondary' id='btnRangeAll'>Tutto</button>
      <label class='muted' style='margin-left:10px'>
        <input type='checkbox' id='maToggle'/> Media
      </label>
      <button class='btn' id='btnChartReload'>Aggiorna</button>
    </div>
  </div>

  <div style='margin-top:10px'>
    <h3 style='margin:8px 0 4px 0'>Download / Upload (Mbps)</h3>
    <canvas id='chartDu' width='1200' height='220' style='width:100%; max-width:100%'></canvas>
  </div>
  <div style='margin-top:14px'>
    <h3 style='margin:8px 0 4px 0'>Ping / Jitter (ms)</h3>
    <canvas id='chartPj' width='1200' height='220' style='width:100%; max-width:100%'></canvas>
  </div>

  <p class='muted small' id='chartInfo' style='margin-top:8px'></p>
</div>

<script>
(function(){
  const qs = s=>document.querySelector(s);
  const du = qs('#chartDu'), pj = qs('#chartPj');
  const info = qs('#chartInfo');
  let rangeSec = 24*3600;  // default 24h

  function avg(arr, w){
    const out=[]; let s=0, q=[];
    for(const v of arr){
      q.push(v); s += v;
      if(q.length>w){ s -= q.shift(); }
      out.push( q.length ? s/q.length : v );
    }
    return out;
  }

  function draw(canvas, xs, series, yLabel){
    const W = canvas.width, H = canvas.height;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0,0,W,H);

    const padL=48, padR=12, padT=10, padB=22;
    const w = W - padL - padR, h = H - padT - padB;
    if(xs.length===0){ ctx.fillStyle='#bbb'; ctx.fillText('Nessun dato', padL+10, padT+20); return; }

    let yMin=+Infinity, yMax=-Infinity;
    for(const s of series){
      for(const v of s.values){ if(v==null) continue; if(v<yMin) yMin=v; if(v>yMax) yMax=v; }
    }
    if(!isFinite(yMin)||!isFinite(yMax)){ yMin=0; yMax=1; }
    if(yMax===yMin){ yMax=yMin+1; }

    function y2p(v){ return padT + h - ( (v - yMin) / (yMax - yMin) ) * h; }
    function x2p(i){ return padL + (i/(xs.length-1)) * w; }

    // griglia
    const grid='rgba(255,255,255,0.08)';
    const text='rgba(255,255,255,0.75)';
    ctx.strokeStyle=grid; ctx.lineWidth=1; ctx.beginPath();
    for(let i=0;i<=5;i++){
      const yy = padT + (i/5)*h; ctx.moveTo(padL, yy); ctx.lineTo(W-padR, yy);
    }
    ctx.stroke();

    // assi/etichette
    ctx.fillStyle=text; ctx.font='12px system-ui, sans-serif';
    ctx.textAlign='right'; ctx.textBaseline='middle';
    for(let i=0;i<=5;i++){
      const vv = yMin + (i/5)*(yMax-yMin);
      const yy = padT + (1-i/5)*h;
      ctx.fillText(vv.toFixed( (yMax-yMin)<10 ? 1 : 0 ), padL-6, yy);
    }
    ctx.save(); ctx.translate(10, padT + h/2); ctx.rotate(-Math.PI/2); ctx.fillText(yLabel, 0, 0); ctx.restore();

    const colors = ['#58a6ff','#8b949e','#2ea043','#db61a2'];
    series.forEach((s,si)=>{
      ctx.strokeStyle = colors[si % colors.length];
      ctx.lineWidth = 2; ctx.beginPath();
      s.values.forEach((v,i)=>{ if(v==null) return; const X=x2p(i), Y=y2p(v); if(i===0) ctx.moveTo(X,Y); else ctx.lineTo(X,Y); });
      ctx.stroke();
      // legenda
      ctx.fillStyle=colors[si%colors.length]; ctx.fillRect(W-100, padT+6+si*16, 10,10);
      ctx.fillStyle=text; ctx.textAlign='left'; ctx.textBaseline='top'; ctx.fillText(s.label, W-86, padT+4+si*16);
    });
  }

  function fetchSeries(){
    const now = Math.floor(Date.now()/1000);
    const url = rangeSec>0 ? `/speedtest/history/series?frm=${now-rangeSec}&to=${now}&limit=2000`
                           : `/speedtest/history/series?limit=2000`;
    fetch(url).then(r=>r.json()).then(js=>{
      const pts = (js && js.points)||[];
      info.textContent = `Punti: ${pts.length}` + (rangeSec?` • finestra: ${Math.round(rangeSec/3600)}h`:'');
      const xs = pts.map(p=>p.ts);
      const ma = qs('#maToggle')?.checked;
      const w  = 5;

      const mbps = v => v==null ? null : Math.round(v*100)/100;

      // down/up
      let down = pts.map(p=>mbps(p.down_mbps)), up = pts.map(p=>mbps(p.up_mbps));
      if(ma){ down = avg(down,w); up = avg(up,w); }
      draw(du, xs, [
        {label:'Download', values:down},
        {label:'Upload',   values:up}
      ], 'Mbps');

      // ping/jitter
      let p = pts.map(x=>x.ping_ms), j = pts.map(x=>x.jitter_ms);
      if(ma){ p = avg(p,w); j = avg(j,w); }
      draw(pj, xs, [
        {label:'Ping',   values:p},
        {label:'Jitter', values:j}
      ], 'ms');
    }).catch(()=>{ info.textContent='Errore caricamento serie'; });
  }

  document.getElementById('btnChartReload').addEventListener('click', fetchSeries);
  document.getElementById('maToggle').addEventListener('change', fetchSeries);
  document.getElementById('btnRange24h').addEventListener('click', ()=>{rangeSec=24*3600; fetchSeries();});
  document.getElementById('btnRange7d').addEventListener('click', ()=>{rangeSec=7*24*3600; fetchSeries();});
  document.getElementById('btnRange30d').addEventListener('click', ()=>{rangeSec=30*24*3600; fetchSeries();});
  document.getElementById('btnRangeAll').addEventListener('click', ()=>{rangeSec=0; fetchSeries();});
  setTimeout(fetchSeries, 10);
})();
</script>
"""

@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    head = _page_head("Speedtest")
    body = """
<style>
  :root{ --st-a:#10b981; --st-b:#059669; }
  .card--st{ background:linear-gradient(160deg, rgba(16,185,129,.22), rgba(5,150,105,.10)); border:1px solid rgba(16,185,129,.30); }
  .hero{display:flex;gap:14px;align-items:center;justify-content:space-between}
  .pill{padding:4px 10px;border-radius:999px;background:rgba(255,255,255,.08);font-size:.9rem;border:1px solid rgba(255,255,255,.1)}
  .kv{display:grid;grid-template-columns:120px 1fr;gap:6px;margin-top:10px}
  .big{font-size:1.8rem;font-weight:700}
  .meter{height:10px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;position:relative}
  .meter .bar{position:absolute;left:0;top:0;height:100%;width:28%;background:linear-gradient(90deg,var(--st-a),var(--st-b));filter:saturate(120%);animation:pulse 1.1s ease-in-out infinite}
  @keyframes pulse {0%{transform:translateX(-40%)}50%{transform:translateX(120%)}100%{transform:translateX(-40%)}}
  .phase{display:inline-flex;gap:6px;align-items:center;margin-top:6px}
  .dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.25)} .on{background:var(--st-a)}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .small{font-size:.92em;opacity:.95}
  /* --- Speedtest card: layout 2 colonne + stat tiles --- */
.st-grid{
  display:grid;
  grid-template-columns: 1fr 1fr;
  gap:16px;
  margin-top:12px;
}
@media (max-width: 980px){
  .st-grid{ grid-template-columns: 1fr; }
}

.details .kv{ grid-template-columns: 110px 1fr; } /* già presente, solo rifinitura */

.stats{
  display:grid;
  grid-template-columns: repeat(3, minmax(160px, 1fr));
  gap:12px;
}
@media (max-width: 640px){
  .stats{ grid-template-columns: 1fr; }
}

.stat{
  padding:12px 14px;
  border-radius:12px;
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.10);
}
.stat .label{
  font-size:.88rem;
  opacity:.85;
  margin-bottom:6px;
}
.stat .value{
  font-weight:600;        /* meno “pesante” del 700 */
  font-size:1.5rem;       /* meno enorme: era 1.8rem */
  letter-spacing:.2px;
}
.stat .unit{
  opacity:.8;
  font-size:.95rem;
  margin-left:4px;
}

.stat-meta{
  margin-top:8px;
  font-size:.95rem;
  opacity:.9;
}
.stat-meta .kvline{
  display:flex; gap:12px; flex-wrap:wrap;
}
.stat-meta .kvline span{ opacity:.85; }


  /* —— layout verticale: 3 card impilate, mai fuori pagina —— */
  .container{ max-width: 1200px; }          /* contenitore più compatto */
  .grid--stack{ grid-template-columns: 1fr; gap: 14px; }
  .card{ min-width: 0; }                    /* abilita shrink */
  .table{ overflow-x:auto; }
  #histTbl{ width:100%; border-collapse:collapse; table-layout:auto; }  /* <— auto, non fixed */
  #histTbl th, #histTbl td{
  padding:6px 8px;
  white-space:nowrap;         /* niente a capo (niente …) */
  }

  /* Larghezze minime e allineamenti */
  #histTbl th:first-child, #histTbl td:first-child{  /* selezione */
  width: 36px; min-width:36px; text-align:center;
   }
   #histTbl th:nth-child(2), #histTbl td:nth-child(2){ /* Quando */
   width: 200px; min-width:200px;
   }
  #histTbl th:nth-child(3), #histTbl td:nth-child(3),  /* Ping */
  #histTbl th:nth-child(4), #histTbl td:nth-child(4),  /* Jitter */
    #histTbl th:nth-child(5), #histTbl td:nth-child(5){  /* Loss */
    width: 80px; min-width:80px; text-align:right;
    }
    #histTbl th:nth-child(6), #histTbl td:nth-child(6),  /* Download */
    #histTbl th:nth-child(7), #histTbl td:nth-child(7){  /* Upload   */
    width: 130px; min-width:130px; text-align:right;
    }
    #histTbl th:nth-child(8), #histTbl td:nth-child(8){  /* Server */
    min-width: 240px;
    }
    #histTbl th:nth-child(9), #histTbl td:nth-child(9){  /* ISP */
    min-width: 160px;
    }
    #histTbl th:nth-child(10), #histTbl td:nth-child(10){/* IP */
    min-width: 240px;
    }  

/* checkbox ben visibile e non schiacciata */
#histTbl td:first-child input{ transform:scale(1.05); cursor:pointer; }
  .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace; 
       font-variant-numeric: tabular-nums; }

</style>

<div class='grid grid--stack'>
  <div class='card card--st'>
    <div class='hero'>
      <h2>Speedtest</h2>
      <div class='row'>
        <a class='btn secondary small' href='/speedtest/settings'>Impostazioni scheduler</a>
        <div id="state-pill" class="pill">Pronto</div>
      </div>
    </div>
    <p class='muted'>Misura ping, download e upload.</p>

    <div id="pre-box">
  <button class='btn' onclick='startTest()'>Avvia test</button>
</div>

<div id="run-box" style="display:none">
  <div class="meter" style="margin:10px 0 6px"><div class="bar"></div></div>
  <div class="phase"><span id="ph1" class="dot"></span><span>Ping</span></div>
  <div class="phase"><span id="ph2" class="dot"></span><span>Download</span></div>
  <div class="phase"><span id="ph3" class="dot"></span><span>Upload</span></div>
  <button class='btn secondary' style="margin-top:10px" onclick='cancelTest()'>Annulla</button>
</div>

<div id="res-box" style="display:none;margin-top:4px">
  <div class="st-grid">
    <!-- Colonna sinistra: dettagli -->
    <div class="details">
      <div class="kv"><div>Server</div><div id="sv"></div></div>
      <div class="kv"><div>ISP</div><div id="isp"></div></div>
      <div class="kv"><div>IP</div><div id="ips"></div></div>
      
    </div>

    <!-- Colonna destra: tiles -->
    <div>
      <div class="stats">
        <div class="stat">
          <div class="label">Ping</div>
          <div class="value"><span id="pg">-</span></div>
        </div>
        <div class="stat">
          <div class="label">Download</div>
          <div class="value"><span id="dl">-</span> <span class="unit"></span></div>
        </div>
        <div class="stat">
          <div class="label">Upload</div>
          <div class="value"><span id="ul">-</span> <span class="unit"></span></div>
        </div>
      </div>

      <div class="stat-meta">
        <div class="kvline">
          <span><b>Jitter:</b> <span id="jit">-</span></span>
          <span><b>Loss:</b> <span id="pl">-</span></span>
        </div>
      </div>
    </div>
  </div>
</div>

<div class='muted' id='tool-note' style="margin-top:10px"></div>


    <div class='muted' id='tool-note' style="margin-top:10px"></div>
  </div>

  <div class='card'>
    <div class='row' style='justify-content:space-between'>
      <h3 style='margin:0'>Storico test</h3>
      <div class='row'>
        <button class='btn small' onclick='histRefresh()'>Aggiorna</button>
        <a class='btn small' href='/speedtest/history/export.csv'>Esporta CSV</a>
        <a class='btn small secondary' href='/speedtest/history/export.jsonl'>JSONL</a>
        <button class='btn small danger' onclick='histDeleteSel()'>Elimina selezionati</button>
        <button class='btn small danger' onclick='histClear()'>Svuota</button>
      </div>
    </div>
    <div class='table' style='margin-top:8px'>
      <table id="histTbl">
        <thead>
          <tr>
            <th></th><th>Quando</th><th>Ping</th><th>Jitter</th><th>Loss</th>
            <th>Download</th><th>Upload</th><th>Server</th><th>ISP</th><th>IP</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class='small muted' id='histNote' style='margin-top:6px'></div>
  </div>

""" + charts_card + """
</div>

</div>
<script>
let timer=null, phase=0, histOnce=true;

function humanBitsps(bps){ if(!bps) return "-"; const u=["bps","Kbps","Mbps","Gbps","Tbps"]; let i=0,v=Number(bps); while(v>=1000 && i<u.length-1){ v/=1000; i++; } return v.toFixed(2)+" "+u[i]; }
function setPhase(p){ phase=p; for(let i=1;i<=3;i++){ document.getElementById('ph'+i).classList.toggle('on', i<=p); }}

async function status(){
  const r = await fetch('/speedtest/status');
  if(!r.ok) return;
  const js = await r.json();
  const running = !!js.running;
  document.getElementById('tool-note').textContent = js.tool ? ("Tool: "+js.tool) : "";
  document.getElementById('state-pill').textContent = running ? "In esecuzione" : "Pronto";
  document.getElementById('state-pill').style.background = running ? "rgba(16,185,129,.2)" : "rgba(255,255,255,.08)";
  document.getElementById('pre-box').style.display = running ? "none":""; 
  document.getElementById('run-box').style.display = running ? "":"none";

  if(running){
    const t = Date.now() % 9000;
    if(t<1000) setPhase(1);
    else if(t<5000) setPhase(2);
    else setPhase(3);
  }

  if(js.result){
    setPhase(3);
    const res = js.result;
    if(res.server){
      const s = res.server;
      document.getElementById('sv').textContent = [s.name, s.location].filter(Boolean).join(" · ");
    }
    document.getElementById('isp').textContent = res.isp || "-";
    const iface = res.interface || {};
    const iptxt = [iface.internalIp, iface.externalIp].filter(Boolean).join(" → ");
    document.getElementById('ips').textContent = iptxt || "-";

    const pingMs = (res.ping?.latency ?? res.ping ?? res.ping_ms ?? null);
    document.getElementById('pg').textContent = pingMs!=null ? (+pingMs).toFixed(2)+" ms" : "-";
    document.getElementById('jit').textContent = res.ping?.jitter!=null ? (+res.ping.jitter).toFixed(2)+" ms" : "-";
    document.getElementById('pl').textContent  = (res.packetLoss!=null) ? (res.packetLoss+" %") : "-";

    let d = res.download?.bandwidth!=null ? res.download.bandwidth*8 : (res.download ?? null);
    let u = res.upload?.bandwidth!=null   ? res.upload.bandwidth*8   : (res.upload   ?? null);
    document.getElementById('dl').textContent = humanBitsps(d);
    document.getElementById('ul').textContent = humanBitsps(u);

    document.getElementById('res-box').style.display = "";
    if(!histOnce){ histOnce=true; histRefresh(); }
  } else {
    document.getElementById('res-box').style.display = "none";
  }
}

function histRow(tr, it){
  const iptxt = [it.internalIp, it.externalIp].filter(Boolean).join(" → ");
  const sv = [it.server_name, it.server_loc].filter(Boolean).join(" · ");
  tr.innerHTML = `
    <td><input type="checkbox" data-ts="${it.ts}"></td>
    <td class="mono trunc">${new Date(it.ts*1000).toLocaleString('it-IT', { hour12:false })}</td>
    <td class="mono" style="text-align:right">${it.ping_ms!=null ? (+it.ping_ms).toFixed(2)+' ms' : '-'}</td>
    <td class="mono" style="text-align:right">${it.jitter_ms!=null ? (+it.jitter_ms).toFixed(2)+' ms' : '-'}</td>
    <td class="mono" style="text-align:right">${it.loss_pct!=null ? it.loss_pct+' %' : '-'}</td>
    <td class="mono" style="text-align:right">${humanBitsps(it.down_bps)}</td>
    <td class="mono" style="text-align:right">${humanBitsps(it.up_bps)}</td>
    <td class="mono trunc">${sv || '-'}</td>
    <td class="mono trunc">${it.isp || '-'}</td>
    <td class="mono trunc">${iptxt || '-'}</td>
  `;
}

async function histRefresh(){
  try{
    const r = await fetch('/speedtest/history?limit=50'); if(!r.ok) return;
    const js = await r.json();
    const tb = document.querySelector('#histTbl tbody'); tb.innerHTML='';
    js.items.forEach(it=>{
      const tr = document.createElement('tr'); histRow(tr, it); tb.appendChild(tr);
    });
    document.getElementById('histNote').textContent = 'Totale: '+js.total+' (mostrati: '+js.items.length+')';
  }catch(e){}
}

async function histClear(){
  if(!confirm('Svuotare tutto lo storico?')) return;
  await fetch('/speedtest/history/clear', {method:'POST'});
  histRefresh();
}

async function histDeleteSel(){
  const cbs = Array.from(document.querySelectorAll('#histTbl input[type=checkbox]:checked'));
  if(!cbs.length){ alert('Seleziona almeno un elemento'); return; }
  if(!confirm('Eliminare '+cbs.length+' elementi selezionati?')) return;
  const ids = cbs.map(cb=>Number(cb.dataset.ts));
  await fetch('/speedtest/history/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ts: ids})});
  histRefresh();
}

async function startTest(){ await fetch('/speedtest/start',{method:'POST'}); setPhase(1); histOnce=false; if(!timer){ timer=setInterval(status, 1000); } status(); }
async function cancelTest(){ await fetch('/speedtest/cancel',{method:'POST'}); setPhase(0); status(); }

(function(){
  const p = new URLSearchParams(location.search);
  if(p.get('start')==='1'){ startTest(); }
})();

timer=setInterval(status, 1000);
status(); histRefresh();
</script>
</body></html>
"""
    return HTMLResponse(head + body)

# ----------------- API di stato -----------------
@router.get("/status", response_class=JSONResponse)
def st_status():
    st = _load_state()
    running = _alive(st.get("pid"))
    if not running and st.get("pid"):
        st["pid"] = None
        _save_state(st)
    return {"running": running, "result": st.get("result"), "tool": st.get("tool")}

# ----------------- start/cancel -----------------
@router.post("/start", response_class=JSONResponse)
def start():
    _ensure_dir()
    st = _load_state()
    if _alive(st.get("pid")):
        return {"ok": True, "running": True}

    st["result"] = None
    st["started"] = int(time.time())
    _save_state(st)

    cfg = _cfg_load()
    cmd, tool = _pick_cmd(cfg)
    st["tool"] = tool
    _save_state(st)

    wrapper = SPEED_DIR / "run_speedtest.py"
    wrapper_code = f"""
import json, subprocess, pathlib, sys, os, time
STATE = pathlib.Path({json.dumps(str(STATE_FILE))})
LOG   = pathlib.Path({json.dumps(str(LOG_FILE))})
HIST  = pathlib.Path({json.dumps(str(HIST_FILE))})
LAST  = pathlib.Path({json.dumps(str(LAST_FILE))})
CMD   = {json.dumps(cmd)}
CFG   = pathlib.Path('/etc/netprobe/speedtest.json')  # FIX: per retention
TAG   = {json.dumps(_cfg_load().get("tag") or "")}

def _cfg_retention():
    try:
        import json
        c = json.loads(CFG.read_text('utf-8'))
        return int(c.get('retention_max', 10000)) or 0
    except Exception:
        return 0

try:
    p = subprocess.run(CMD, capture_output=True, text=True, timeout=900)
    OUT = (p.stdout or "")
    ERR = (p.stderr or "")
except Exception as e:
    OUT, ERR = "", str(e)

try:
    LOG.write_text(OUT + ("\\n" if OUT else "") + ERR)
except Exception:
    pass

try:
    result = json.loads(OUT.strip() or "{{}}")
except Exception:
    result = {{}}

try:
    st = json.loads(STATE.read_text())
except Exception:
    st = {{"pid": None, "started": None, "result": None, "tool": None}}
st["result"] = result
st["pid"] = None
STATE.write_text(json.dumps(st, indent=2))

now = int(time.time())
ping_ms = None
jitter_ms = None
if isinstance(result.get("ping"), dict):
    ping_ms = result.get("ping",{{}}).get("latency")
    jitter_ms = result.get("ping",{{}}).get("jitter")
elif isinstance(result.get("ping"), (int,float)):
    ping_ms = result.get("ping")
elif "ping_ms" in result:
    ping_ms = result.get("ping_ms")

down_bps = None
if isinstance(result.get("download"), dict) and "bandwidth" in result.get("download"):
    down_bps = (result["download"]["bandwidth"] or 0) * 8
elif isinstance(result.get("download"), (int,float)):
    down_bps = result.get("download")

up_bps = None
if isinstance(result.get("upload"), dict) and "bandwidth" in result.get("upload"):
    up_bps = (result["upload"]["bandwidth"] or 0) * 8
elif isinstance(result.get("upload"), (int,float)):
    up_bps = result.get("upload")

server = result.get("server") or {{}}
iface  = result.get("interface") or {{}}
rid    = (result.get("result") or {{}}).get("id")

entry = {{
    "ts": now,
    "tool": {json.dumps(st.get("tool"))},
    "ok": bool(result),
    "tag": TAG,
    "ping_ms": ping_ms,
    "jitter_ms": jitter_ms,
    "loss_pct": result.get("packetLoss"),
    "down_bps": down_bps,
    "up_bps": up_bps,
    "server_name": server.get("name"),
    "server_loc": server.get("location"),
    "server_id": server.get("id"),
    "isp": result.get("isp"),
    "internalIp": iface.get("internalIp"),
    "externalIp": iface.get("externalIp"),
    "uuid": rid
}}

try:
    with open(HIST, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\\n")
except Exception:
    pass

try:
    with open(LAST, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)
except Exception:
    pass

# FIX: trim retention
try:
    N = _cfg_retention()
    if N > 0:
        with open(HIST, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > N:
            with open(HIST, "w", encoding="utf-8") as f:
                f.writelines(lines[-N:])
except Exception:
    pass
"""
    wrapper.write_text(wrapper_code, encoding="utf-8")

    proc = subprocess.Popen(
        ["/usr/bin/env", "python3", str(wrapper)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    st["pid"] = proc.pid
    _save_state(st)
    return {"ok": True, "running": True, "pid": proc.pid, "tool": tool}

@router.post("/cancel", response_class=JSONResponse)
def cancel():
    st = _load_state()
    pid = st.get("pid")
    if _alive(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try: os.kill(pid, signal.SIGTERM)
            except Exception: pass
    st["pid"] = None
    _save_state(st)
    return {"ok": True}

# ----------------- API storico -----------------
@router.get("/history", response_class=JSONResponse)
def history(limit: int = 100):
    items = _read_history(limit=limit)
    try:
        total = sum(1 for _ in open(HIST_FILE, "r", encoding="utf-8"))
    except Exception:
        total = len(items)
    return {"items": items, "total": total}

@router.post("/history/clear", response_class=JSONResponse)
def history_clear():
    _ensure_dir()
    try:
        HIST_FILE.write_text("", encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@router.post("/history/delete", response_class=JSONResponse)
def history_delete(ts: dict = Body(default={"ts": []})):
    _ensure_dir()
    ids = set(int(x) for x in (ts or {}).get("ts", []) if isinstance(x, (int, float, str)))
    if not ids:
        return {"ok": True, "deleted": 0}
    try:
        lines = []
        with open(HIST_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                try:
                    obj = json.loads(ln)
                    if int(obj.get("ts", -1)) in ids:
                        continue
                except Exception:
                    pass
                lines.append(ln)
        tmp = HIST_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines)
        os.replace(tmp, HIST_FILE)
        return {"ok": True, "deleted": len(ids)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@router.get("/history/export.jsonl")
def history_export_jsonl():
    _ensure_dir()
    if not HIST_FILE.exists():
        HIST_FILE.write_text("", encoding="utf-8")
    return FileResponse(str(HIST_FILE), media_type="application/json", filename="speedtest-history.jsonl")

@router.get("/history/export.csv")
def history_export_csv():
    items = _read_history(limit=1000000)
    head = ["timestamp","iso","tool","ok","tag","ping_ms","jitter_ms","loss_pct","down_bps","up_bps","server_name","server_loc","server_id","isp","internalIp","externalIp","uuid"]
    rows = [",".join(head)]
    from datetime import datetime
    for it in reversed(items):
        ts = int(it.get("ts",0))
        iso = datetime.utcfromtimestamp(ts).isoformat()+"Z" if ts else ""
        vals = [
            str(ts), iso, it.get("tool",""), str(bool(it.get("ok"))).lower(),
            it.get("tag",""),
            str(it.get("ping_ms") if it.get("ping_ms") is not None else ""),
            str(it.get("jitter_ms") if it.get("jitter_ms") is not None else ""),
            str(it.get("loss_pct") if it.get("loss_pct") is not None else ""),
            str(it.get("down_bps") if it.get("down_bps") is not None else ""),
            str(it.get("up_bps") if it.get("up_bps") is not None else ""),
            (it.get("server_name") or ""), (it.get("server_loc") or ""), str(it.get("server_id") or ""),
            (it.get("isp") or ""), (it.get("internalIp") or ""), (it.get("externalIp") or ""), (it.get("uuid") or "")
        ]
        vals = [('"'+v.replace('"','""')+'"') if ("," in v or '"' in v or " " in v) else v for v in vals]
        rows.append(",".join(vals))
    csv = "\n".join(rows) + "\n"
    return Response(content=csv, media_type="text/csv", headers={"Content-Disposition":"attachment; filename=speedtest-history.csv"})


# ----------------- Settings UI -----------------
@router.get("/settings", response_class=HTMLResponse)
def st_settings():
    c = _cfg_load()
    checked = "checked" if c.get("enabled", True) else ""
    prefer = (c.get("prefer") or "auto").lower()

    head = _page_head("Speedtest • Impostazioni")

    form = f"""
<div class='grid'>
  <div class='card'>
    <h2>Schedulazione</h2>
    <form method='post' action='/speedtest/settings'>
      <label><input type='checkbox' name='enabled' value='1' {checked}/> Abilita scheduler</label>

      <label style='margin-top:8px'>Intervallo (minuti)</label>
      <input name='interval_min' type='number' min='5' step='5' value='{int(c.get("interval_min",120))}'/>

      <label style='margin-top:8px'>Conserva al massimo N record</label>
      <input name='retention_max' type='number' min='10' step='10' value='{int(c.get("retention_max",10000))}'/>

      <label style='margin-top:8px'>Preferisci tool</label>
      <select name='prefer'>
        <option value='auto'  {"selected" if prefer=="auto" else ""}>Auto (Ookla se presente, altrimenti Python)</option>
        <option value='ookla' {"selected" if prefer=="ookla" else ""}>Ookla CLI</option>
        <option value='pycli' {"selected" if prefer=="pycli" else ""}>Python speedtest-cli</option>
      </select>

      <label style='margin-top:8px'>Server ID (opzionale)</label>
      <input name='server_id' value='{escape(str(c.get("server_id") or ""))}' placeholder='es. 12345' />

      <label style='margin-top:8px'>Tag (es. "sede1/FTTH TIM")</label>
      <input name='tag' value='{escape(c.get("tag") or "")}' />

      <div class='row' style='gap:8px;margin-top:12px'>
        <button class='btn' type='submit'>Salva</button>
        <a class='btn secondary' href='/speedtest/'>Torna</a>
        <button class='btn' type='button' onclick='runNow()'>Esegui ora</button>
      </div>
      <p class='muted' style='margin-top:6px'>
        Il job schedulato gira ogni minuto ma esegue il test solo se è passato almeno l'intervallo impostato.
        Se disabilitato, non esegue nulla.
      </p>
    </form>
  </div>
</div>
"""
    script = """
<script>
async function runNow(){
  try { await fetch('/speedtest/start', {method:'POST'}); } catch(e) {}
  location.href='/speedtest/?start=1';
}
</script>
</div></body></html>
"""
    return HTMLResponse(head + form + script)


@router.post("/settings", response_class=HTMLResponse)
def st_settings_save(
    enabled: str | None = Form(None),
    interval_min: int = Form(120),
    retention_max: int = Form(10000),
    prefer: str = Form("auto"),
    server_id: str = Form(""),
    tag: str = Form("")
):
    c = _cfg_load()
    c["enabled"]       = bool(enabled)
    c["interval_min"]  = max(5, int(interval_min))
    c["retention_max"] = max(10, int(retention_max))
    c["prefer"]        = prefer if prefer in ("auto","ookla","pycli") else "auto"
    c["server_id"]     = (server_id or "").strip()
    c["tag"]           = (tag or "").strip()
    _cfg_save(c)
    # torniamo alla pagina settings per vedere i valori aggiornati
    return HTMLResponse("<script>location.replace('/speedtest/settings');</script>")



# ----------------- Serie per grafici -----------------
_SPEED_DIR = pathlib.Path("/var/lib/netprobe/speedtest")
_SPEED_HIST = _SPEED_DIR / "history.jsonl"

def _tail_history(max_lines: int = 2000):
    """Legge velocemente le ultime N righe dello storico (se esiste)."""
    if not _SPEED_HIST.exists():
        return []
    lines = []
    with open(_SPEED_HIST, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        while pos > 0 and len(lines) < max_lines:
            step = min(8192, pos)
            pos -= step
            f.seek(pos)
            chunk = f.read(step)
            buf = chunk + buf
            *rest, buf = buf.split(b"\n")
            for ln in reversed(rest):
                if ln.strip():
                    try:
                        lines.append(json.loads(ln.decode("utf-8")))
                    except Exception:
                        pass
            f.seek(pos)
        if buf.strip() and len(lines) < max_lines:
            try:
                lines.append(json.loads(buf.decode("utf-8")))
            except Exception:
                pass
    return list(reversed(lines))  # ordine cronologico crescente

@router.get("/history/series")
def speedtest_series(request: Request,
                     frm: int | None = None,  # epoch sec "from"
                     to:  int | None = None,  # epoch sec "to"
                     limit: int = 1000):
    """
    Restituisce punti storici per i grafici.
    Output: {"points":[{ts, down_mbps, up_mbps, ping_ms, jitter_ms, loss_pct}]}
    """
    now = int(time.time())
    t0  = int(frm or 0)
    t1  = int(to or now)

    rows = _tail_history(max_lines=max(200, min(50000, limit*5 or 1000)))
    pts  = []
    for r in rows:
        ts = int(r.get("ts") or 0)
        if ts < t0 or ts > t1:
            continue
        def mbps(bps):
            try:
                return round((float(bps) or 0.0)/1_000_000.0, 2)
            except Exception:
                return 0.0
        pts.append({
            "ts": ts,
            "down_mbps": mbps(r.get("down_bps")),
            "up_mbps":   mbps(r.get("up_bps")),
            "ping_ms":   float(r.get("ping_ms") or 0.0),
            "jitter_ms": float(r.get("jitter_ms") or 0.0),
            "loss_pct":  float(r.get("loss_pct") or 0.0),
        })

    if limit and len(pts) > limit:
        pts = pts[-limit:]

    return JSONResponse({"ok": True, "points": pts})
