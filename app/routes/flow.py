# -*- coding: utf-8 -*-
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from html import escape
import subprocess, time, re, datetime, os, json

from routes.auth import verify_session_cookie, _load_users

router = APIRouter(prefix="/flow", tags=["flow"])

# Symlink che punta al profilo live nfsen-ng
FLOWS_DIR = "/var/lib/netprobe/flows"

# ----------------- helpers shell -----------------
def _runp(args: list[str], timeout: int = 25):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def _svc(action: str, unit: str) -> tuple[bool, str]:
    rc = subprocess.call(["sudo", "systemctl", action, unit])
    return (rc == 0, f"systemctl {action} {unit} -> rc={rc}")

def _is_active(unit: str) -> bool:
    return subprocess.call(["systemctl", "is-active", "--quiet", unit]) == 0

def _ifaces() -> list[str]:
    # prova dumpcap -D, fallback a ip link
    rc, out, _ = _runp(["/usr/bin/dumpcap", "-D"], timeout=8)
    if rc == 0 and out.strip():
        items = []
        for line in out.splitlines():
            m = re.match(r"\s*\d+\.\s+([^\s]+)", line)
            if m:
                name = m.group(1)
                if name != "lo" and name not in items:
                    items.append(name)
        if items:
            return items
    rc, out, _ = _runp(["/usr/sbin/ip", "-o", "link", "show"], timeout=8)
    items = []
    if rc == 0:
        for line in out.splitlines():
            try:
                name = line.split(":")[1].strip().split("@")[0]
                if name != "lo" and name not in items:
                    items.append(name)
            except Exception:
                pass
    return items

def _require_admin(request: Request) -> bool:
    user = verify_session_cookie(request)
    if not user:
        return False
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    return "admin" in roles

# ----------------- nfdump CSV -> aggregati -----------------
def _window_to_seconds(w: str) -> int:
    w = (w or "15m").lower().strip()
    if w.endswith("m"):
        return max(1, int(re.sub(r"[^0-9]", "", w))) * 60
    if w.endswith("h"):
        return max(1, int(re.sub(r"[^0-9]", "", w))) * 3600
    if w.endswith("d"):
        return max(1, int(re.sub(r"[^0-9]", "", w))) * 86400
    return 15 * 60

def _time_range_str(window: str) -> tuple[str, str, int, int]:
    sec = _window_to_seconds(window)
    t_end = int(time.time())
    t_start = t_end - sec
    fmt = "%Y/%m/%d.%H:%M:%S"  # formato per nfdump
    ts = time.strftime(fmt, time.localtime(t_start))
    te = time.strftime(fmt, time.localtime(t_end))
    return ts, te, t_start, t_end

def _nfdump_csv_rows(window: str = "15m", limit: int = 200000):
    ts, te, _, _ = _time_range_str(window)
    args = ["nfdump", "-R", FLOWS_DIR, "-t", f"{ts}-{te}", "-o", "csv", "-c", str(limit)]
    rc, out, err = _runp(args, timeout=30)
    if rc != 0 or not out:
        return []

    rows = []
    header = None
    for raw in out.splitlines():
        ln = raw.strip()
        if not ln:
            continue
        if ln.lower().startswith("ts,"):
            header = [h.strip() for h in ln.split(",")]
            continue
        if ln.startswith("Summary"):
            break
        if ln.lower().startswith("flows,bytes"):
            break
        if header is None:
            continue
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) != len(header):
            continue
        rows.append(dict(zip(header, parts)))
    return rows

def _to_int(x, default=0):
    try:
        return int(float(x))
    except Exception:
        return default

def _aggregate(rows: list[dict], n: int = 10):
    agg_srcip, agg_dstip, agg_dstport, agg_proto = {}, {}, {}, {}
    total_bytes = 0
    total_pkts = 0
    flows = len(rows)
    for r in rows:
        sa = r.get("sa") or r.get("srcip") or r.get("sa:ip")
        da = r.get("da") or r.get("dstip") or r.get("da:ip")
        dp = r.get("dp") or r.get("dstport")
        pr = r.get("pr") or r.get("proto")
        ib = _to_int(r.get("ibyt") or r.get("bytes") or r.get("byt") or "0")
        ip = _to_int(r.get("ipkt") or r.get("pkts") or "0")
        total_bytes += ib
        total_pkts += ip
        if sa: agg_srcip[sa] = agg_srcip.get(sa, 0) + ib
        if da: agg_dstip[da] = agg_dstip.get(da, 0) + ib
        if dp: agg_dstport[dp] = agg_dstport.get(dp, 0) + ib
        if pr: agg_proto[pr] = agg_proto.get(pr, 0) + ib

    def topn(d: dict):
        return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]

    return {
        "totals": {"flows": flows, "bytes": total_bytes, "packets": total_pkts},
        "srcip": topn(agg_srcip),
        "dstip": topn(agg_dstip),
        "dstport": topn(agg_dstport),
        "proto": topn(agg_proto),
    }

def _timeseries(rows: list[dict], t_start: int, t_end: int, step: int = 60):
    bins = []
    t = (t_start // step) * step
    while t <= t_end:
        bins.append(t)
        t += step
    byts = [0] * len(bins)
    for r in rows:
        te = r.get("te") or r.get("end") or ""
        try:
            dt = datetime.datetime.strptime(te.split(".")[0], "%Y-%m-%d %H:%M:%S")
            ts_end = int(dt.timestamp())
        except Exception:
            continue
        ib = _to_int(r.get("ibyt") or r.get("bytes") or "0")
        idx = (ts_end - bins[0]) // step
        if 0 <= idx < len(byts):
            byts[idx] += ib
    labels = [time.strftime("%H:%M:%S", time.localtime(x)) for x in bins]
    return {"labels": labels, "bytes": byts}

# ----------------- helpers gestione dati -----------------
def _parse_age(s: str) -> int:
    s = (s or "24h").strip().lower()
    num = int(re.sub(r"[^0-9]", "", s) or "24")
    if s.endswith("m"): return num * 60
    if s.endswith("h"): return num * 3600
    if s.endswith("d"): return num * 86400
    return num * 3600  # default ore

def _cleanup_flows_older_than(seconds: int) -> dict:
    cutoff = int(time.time()) - max(0, seconds)
    removed = 0
    try:
        for root, _, files in os.walk(FLOWS_DIR):
            for fn in files:
                if not fn.startswith("nfcapd."):
                    continue
                fp = os.path.join(root, fn)
                try:
                    st = os.stat(fp)
                    if int(st.st_mtime) < cutoff:
                        os.unlink(fp)
                        removed += 1
                except Exception:
                    continue
        return {"ok": True, "removed": removed}
    except Exception as e:
        return {"ok": False, "error": str(e), "removed": removed}

# ----------------- API JSON -----------------
@router.get("/api/status", response_class=JSONResponse)
def api_status():
    rc, out, _ = _runp(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "netprobe-flow-exporter@*"]
    )
    exporters = [ln.split()[0] for ln in out.splitlines() if "netprobe-flow-exporter@" in ln] if rc == 0 else []
    return {
        "collector": "active" if _is_active("netprobe-flow-collector") else "inactive",
        "exporters": exporters,
    }

@router.get("/api/summary", response_class=JSONResponse)
def api_summary(window: str = Query("15m"), n: int = Query(10)):
    rows = _nfdump_csv_rows(window=window)
    agg = _aggregate(rows, n=n)
    ts, te, t_start, t_end = _time_range_str(window)
    return {"window": window, "t_start": t_start, "t_end": t_end, "top": agg}

@router.get("/api/timeseries", response_class=JSONResponse)
def api_timeseries(window: str = Query("60m"), step: int = Query(60)):
    ts, te, t_start, t_end = _time_range_str(window)
    rows = _nfdump_csv_rows(window=window)
    serie = _timeseries(rows, t_start, t_end, step=max(10, step))
    return {"window": window, "step": step, "series": serie}

@router.get("/api/export")
def api_export(window: str = Query("15m")):
    ts, te, _, _ = _time_range_str(window)
    rc, out, err = _runp(["nfdump", "-R", FLOWS_DIR, "-t", f"{ts}-{te}", "-o", "csv"], timeout=40)
    if rc != 0:
        out = f"# nfdump rc={rc}\n{err}"
    fname = f"flows_{window}.csv"
    return StreamingResponse(
        iter([out]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )

# ----------------- actions (solo admin) -----------------
@router.post("/exporter/start", response_class=JSONResponse)
def exporter_start(request: Request, iface: str = Form(...)):
    if not _require_admin(request):
        return {"ok": False, "error": "forbidden"}
    _svc("start", "netprobe-flow-collector")
    ok, msg = _svc("restart", f"netprobe-flow-exporter@{iface}")
    return {"ok": ok, "detail": msg}

@router.post("/exporter/stop", response_class=JSONResponse)
def exporter_stop(request: Request):
    if not _require_admin(request):
        return {"ok": False, "error": "forbidden"}
    rc, out, _ = _runp(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "netprobe-flow-exporter@*"]
    )
    lines = [ln.split()[0] for ln in out.splitlines() if "netprobe-flow-exporter@" in ln] if rc == 0 else []
    stopped = []
    for unit in lines:
        ok, _ = _svc("stop", unit)
        if ok:
            stopped.append(unit)
    return {"stopped": stopped, "ok": True}

@router.post("/admin/cleanup", response_class=JSONResponse)
def admin_cleanup(request: Request, older: str = Form("24h")):
    if not _require_admin(request):
        return {"ok": False, "error": "forbidden"}
    secs = _parse_age(older)
    res = _cleanup_flows_older_than(secs)
    return res

# ----------------- UI -----------------
def _page_head(title: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{escape(title)}</title>"
        "<link rel='stylesheet' href='/static/styles.css'/>"
        "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>"
        "<style>"
        ".mono{font-family:ui-monospace,Menlo,Consolas,monospace}"
        ".grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}"
        ".full{grid-column:1 / -1}"
        "@media(max-width:1100px){.grid{grid-template-columns:1fr}}"
        ".pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid rgba(255,255,255,.18);border-radius:999px;margin-right:6px}"
        ".table{overflow-x:auto} table{width:100%;border-collapse:collapse} th,td{padding:6px 8px;white-space:nowrap}"
        ".small{font-size:.92em;opacity:.95}"
        ".row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}"
        ".chart-wrap{position:relative;width:100%;height:340px;max-height:60vh;min-height:220px}"
        ".chart-pie{position:relative;width:100%;height:240px}"
        "canvas{display:block;width:100% !important;height:100% !important}"
        "</style></head><body>"
        "<div class='container'><div class='nav'><div class='brand'>"
        "<img src='/static/img/logo.svg' class='logo'/>"
        "<span>TestMachine</span></div><div class='links'>"
        "<a class='btn small secondary' href='/'>&larr; Home</a></div></div>"
    )

@router.get("/", response_class=HTMLResponse)
def flow_dashboard(request: Request, window: str = Query("15m"), n: int = Query(10)):
    ifaces = _ifaces()
    iface_options = (
        "".join(f"<option value='{escape(i)}'>{escape(i)}</option>" for i in ifaces) if ifaces else "<option>ens4</option>"
    )

    html = _page_head("Flow Monitor") + """
<div class='grid'>

  <div class='card'>
    <h2>Flow Monitor</h2>
    <div id="st" class="small" style="margin-bottom:8px"></div>

    <!-- form senza action: lo gestiamo via JS -->
    <form id='expForm' class='row'>
      <div>
        <label>Interfaccia</label>
        <select name='iface'>__IFACE_OPTIONS__</select>
      </div>
      <button class='btn' type='submit' data-action='/flow/exporter/start'>Start exporter</button>
      <button class='btn danger' type='submit' data-action='/flow/exporter/stop'>Stop tutti</button>
    </form>
    <div id="flash" class="small mono" style="margin-top:6px;"></div>

    <div class='row' style='margin-top:10px'>
      <label>Finestra</label>
      <a class='btn small' href='/flow?window=15m&n=__N__'>15m</a>
      <a class='btn small' href='/flow?window=1h&n=__N__'>1h</a>
      <a class='btn small' href='/flow?window=6h&n=__N__'>6h</a>
      <a class='btn small' href='/flow?window=24h&n=__N__'>24h</a>
    </div>
  </div>

  <div class='card'>
    <h2>Gestione dati</h2>
    <form id="cleanForm" class="row">
      <div>
        <label>Mantieni ultimi</label>
        <input name="older" value="24h" class="mono" style="width:90px" />
      </div>
      <button class="btn danger" type="submit">Pulisci vecchi</button>
    </form>
    <div id="flash2" class="small mono" style="margin-top:6px;"></div>

    <div class="row" style="margin-top:10px">
      <label>Export CSV</label>
      <a class="btn small" href="/flow/api/export?window=15m" target="_blank">15m</a>
      <a class="btn small" href="/flow/api/export?window=1h"  target="_blank">1h</a>
      <a class="btn small" href="/flow/api/export?window=6h"  target="_blank">6h</a>
      <a class="btn small" href="/flow/api/export?window=24h" target="_blank">24h</a>
    </div>
  </div>

  <div class='card full'>
    <h3>Traffico nel tempo</h3>
    <div class="chart-wrap"><canvas id="chartLine"></canvas></div>
  </div>

  <div class='card'>
    <h3>Protocolli</h3>
    <div class="chart-pie"><canvas id="chartProto"></canvas></div>
  </div>

  <div class='card'>
    <h3>Top sorgenti</h3>
    <div class='table'><table id="tblSrc"><thead><tr><th>IP sorgente</th><th>Bytes</th></tr></thead><tbody></tbody></table></div>
  </div>

  <div class='card'>
    <h3>Top destinazioni</h3>
    <div class='table'><table id="tblDst"><thead><tr><th>IP destinazione</th><th>Bytes</th></tr></thead><tbody></tbody></table></div>
  </div>

  <div class='card'>
    <h3>Top porte dst</h3>
    <div class='table'><table id="tblPort"><thead><tr><th>Porta</th><th>Bytes</th></tr></thead><tbody></tbody></table></div>
  </div>

</div>

<script>
const WIN = {window: "__WINDOW__", n: __N__};

function humanBytes(b){
  if(b === undefined || b === null) return "-";
  const u=["B","KB","MB","GB","TB"]; let i=0; let v=Number(b);
  while(v>=1024 && i<u.length-1){v/=1024;i++}
  return v.toFixed(1)+" "+u[i];
}

async function fetchStatus(){
  try{
    const r = await fetch("/flow/api/status"); const js = await r.json();
    const st = document.getElementById("st");
    const pills = [];
    pills.push("<span class='pill'>Collector: <b>"+(js.collector||"-")+"</b></span>");
    pills.push("<span class='pill'>Exporters: <b>"+((js.exporters||[]).length)+"</b></span>");
    st.innerHTML = pills.join(" ");
  }catch(e){}
}

let lineChart=null, protoChart=null;

function updTable(id, arr){
  const tb = document.querySelector(id+" tbody"); tb.innerHTML="";
  (arr||[]).forEach(function(pair){
    const k = pair[0]; const v = pair[1];
    const tr = document.createElement("tr");
    tr.innerHTML = "<td class='mono'>"+k+"</td><td class='mono' style='text-align:right'>"+humanBytes(v)+"</td>";
    tb.appendChild(tr);
  });
}

async function refreshAll(){
  try{
    const s = await (await fetch("/flow/api/summary?window="+WIN.window+"&n="+WIN.n)).json();
    const t = await (await fetch("/flow/api/timeseries?window="+WIN.window+"&step=60")).json();

    const ctx1 = document.getElementById("chartLine").getContext("2d");
    if(lineChart) lineChart.destroy();
    lineChart = new Chart(ctx1, {
      type: 'line',
      data: { labels: t.series.labels, datasets: [{ label: 'Bytes', data: t.series.bytes }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        resizeDelay: 150,
        animation: { duration: 300 },
        plugins: { legend: { display:false } },
        interaction: { mode: 'index', intersect: false },
        scales: { y: { beginAtZero: true } }
      }
    });

    const proto = (s.top.proto||[]).map(function(x){ return {k:x[0], v:x[1]}; });
    const ctx2 = document.getElementById("chartProto").getContext("2d");
    if(protoChart) protoChart.destroy();
    protoChart = new Chart(ctx2, {
      type: 'doughnut',
      data: { labels: proto.map(function(x){return x.k;}), datasets: [{ data: proto.map(function(x){return x.v;}) }] },
      options: { responsive:true, maintainAspectRatio:false, animation:{duration:300}, plugins:{ legend:{ position:'bottom' } } }
    });

    updTable("#tblSrc", s.top.srcip);
    updTable("#tblDst", s.top.dstip);
    updTable("#tblPort", s.top.dstport);
  }catch(e){}
}

// Gestione AJAX dei pulsanti Start/Stop
(function(){
  const form = document.getElementById("expForm");
  const flash = document.getElementById("flash");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const action = ev.submitter && ev.submitter.dataset.action ? ev.submitter.dataset.action : "/flow/exporter/start";
    const body = new FormData(form);
    try{
      const r = await fetch(action, { method:"POST", body });
      let ok=false, msg="";
      try { const j = await r.json(); ok = !!j.ok; msg = j.detail || j.error || ""; } catch(_){}
      flash.textContent = ok ? "OK" + (msg ? " - " + msg : "") : "Errore" + (msg ? " - " + msg : "");
      fetchStatus();
      refreshAll();
    }catch(e){
      flash.textContent = "Errore di rete";
    }
    setTimeout(()=>{ flash.textContent=""; }, 2500);
  });
})();

// Cleanup vecchi file (solo admin)
(function(){
  const form = document.getElementById("cleanForm");
  const flash = document.getElementById("flash2");
  form.addEventListener("submit", async (ev)=>{
    ev.preventDefault();
    try{
      const r = await fetch("/flow/admin/cleanup", { method:"POST", body: new FormData(form) });
      let txt=""; let ok=false;
      try{ const j=await r.json(); ok=!!j.ok; txt = ok ? ("Rimossi: "+(j.removed||0)) : (j.error||"Errore"); }catch(_){}
      flash.textContent = ok ? ("OK - "+txt) : ("Errore - "+txt);
      refreshAll();
    }catch(_){
      flash.textContent = "Errore di rete";
    }
    setTimeout(()=>{ flash.textContent=""; }, 3000);
  });
})();

fetchStatus();
refreshAll();
setInterval(function(){ fetchStatus(); refreshAll(); }, 10000);
</script>

</body></html>
"""
    html = html.replace("__IFACE_OPTIONS__", iface_options)
    html = html.replace("__WINDOW__", escape(window))
    html = html.replace("__N__", str(n))
    return HTMLResponse(html)
