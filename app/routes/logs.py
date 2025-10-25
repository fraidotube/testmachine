# /opt/netprobe/app/routes/logs.py
from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from html import escape
from pathlib import Path
import os, json, time, re, gzip
from typing import List, Dict, Any, Iterable, Optional

router = APIRouter(prefix="/logs", tags=["logs"])

# Percorsi log (audit JSONL); puoi aggiungere altri file se vuoi
LOG_DIR = Path("/var/lib/netprobe/logs")
LOG_FILES_ORDER = [
    LOG_DIR / "audit.jsonl",           # corrente
    LOG_DIR / "audit.jsonl.1",         # ruotato plain (opz.)
    LOG_DIR / "audit.jsonl.1.gz",      # ruotato gz (opz.)
]

# ---- Helpers UI ----
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

# ---- Parse/filters ----
def _parse_timespec(s: str) -> Optional[int]:
    """
    Converte '15m', '2h', '7d' in timestamp (>=) oppure None se vuoto/non valido.
    """
    if not s: return None
    s = s.strip().lower()
    m = re.match(r"^(\d+)\s*([smhd])$", s)
    if not m: return None
    val = int(m.group(1))
    unit = m.group(2)
    mult = {"s":1, "m":60, "h":3600, "d":86400}[unit]
    return int(time.time()) - val * mult

def _open_log_file(p: Path) -> Optional[Iterable[str]]:
    try:
        if p.suffix == ".gz":
            return (line.decode("utf-8", "ignore") for line in gzip.open(p, "rb"))
        return (l for l in p.read_text("utf-8", errors="ignore").splitlines())
    except Exception:
        return None

def _iter_entries(files: List[Path]) -> Iterable[Dict[str, Any]]:
    """
    Itera le entry JSONL dai file presenti (dall'ultimo al primo per avere i più recenti in testa).
    """
    for p in files:
        if not p.exists(): 
            continue
        src = _open_log_file(p)
        if not src:
            continue
        # leggiamo dalla fine: per i file non compressi proviamo un tail veloce,
        # altrimenti leggiamo e rovesciamo (ok, i file sono piccoli)
        if p.suffix != ".gz":
            try:
                with open(p, "rb") as f:
                    # tail semplice: ultimi ~2MB
                    max_back = 2 * 1024 * 1024
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - max_back))
                    chunk = f.read().decode("utf-8", "ignore")
                    lines = chunk.splitlines()
                    for ln in reversed(lines):
                        try:
                            yield json.loads(ln)
                        except Exception:
                            continue
                continue
            except Exception:
                pass
        # fallback generico (anche .gz)
        buf = list(src)
        for ln in reversed(buf):
            try:
                yield json.loads(ln)
            except Exception:
                continue

def _norm_event(e: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizza campi comuni se presenti; non fallisce se mancano.
    """
    ts = e.get("ts")
    if ts is None:
        # prova con 'time' iso o epoch string
        t = e.get("time") or e.get("@timestamp")
        if isinstance(t, (int, float)):
            ts = int(t)
        elif isinstance(t, str):
            # best-effort: timestamp int come stringa
            if re.fullmatch(r"\d{10}", t):
                ts = int(t)
    evt = e.get("evt") or e.get("event") or e.get("category") or e.get("type") or "-"
    actor = e.get("actor") or e.get("user") or e.get("username") or "-"
    ip = e.get("ip") or e.get("remote") or "-"
    ok = e.get("ok")
    path = e.get("req_path") or e.get("path") or "-"
    detail = e.get("detail") or e.get("message") or e.get("msg") or ""
    return {"ts": ts, "evt": evt, "actor": actor, "ip": ip, "ok": ok, "path": path, "detail": detail, "_raw": e}

def _filter_entries(
    q: str = "", 
    since_ts: Optional[int] = None, 
    limit: int = 500
) -> List[Dict[str, Any]]:
    q = (q or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for raw in _iter_entries(LOG_FILES_ORDER):
        e = _norm_event(raw)
        if since_ts and e["ts"] and int(e["ts"]) < since_ts:
            # visto che stiamo scorrendo dal più recente al più vecchio, possiamo
            # continuare comunque: i file ruotati possono mischiare un po’ le date
            pass
        # full-text filter
        if q:
            hay = json.dumps(e["_raw"], ensure_ascii=False).lower()
            if q not in hay:
                continue
        out.append(e)
        if len(out) >= limit:
            break
    # Ordina DESC per ts se presente
    out.sort(key=lambda x: (x["ts"] or 0), reverse=True)
    return out

# ---- Pagine ----
@router.get("/", response_class=HTMLResponse)
def logs_page():
    if not LOG_DIR.exists():
        msg = "<div class='card'><h2>Log</h2><p class='danger'>Directory log assente: {}</p></div>".format(escape(str(LOG_DIR)))
        return HTMLResponse(_head("Log") + "<div class='grid'>" + msg + "</div></div></body></html>")

    html = _head("Log") + """
<style>
  /* Card full width nel grid principale */
  .full{ grid-column:1 / -1 }

  /* Layout verticale: controlli sopra, tabella sotto */
  .vstack{ display:flex; flex-direction:column; gap:14px }

  /* Form/toolbar compatta che va a capo bene */
  .controls.row{ gap:10px; flex-wrap:wrap; align-items:flex-end }

  /* Tabella: larga e scorrevole, header sticky */
  .table{ overflow:auto; max-height:70vh; }
  .table table{ width:100%; border-collapse:collapse; table-layout:auto; }
  .table th, .table td{ white-space:nowrap; padding:8px 10px; }
  .sticky thead th{ position:sticky; top:0; z-index:1; background:rgba(255,255,255,.08); }
</style>


<div class='grid'>

  <div class='card full'>
  <h2>Audit Log</h2>

  <div class="vstack">
    <!-- Toolbar / filtri -->
    <form id="f" class="controls row">
      <div>
        <label>Periodo</label>
        <select name="since">
          <option value="">Tutto</option>
          <option value="15m">Ultimi 15m</option>
          <option value="1h" selected>Ultima 1h</option>
          <option value="6h">Ultime 6h</option>
          <option value="24h">Ultime 24h</option>
          <option value="7d">Ultimi 7 giorni</option>
        </select>
      </div>
      <div>
        <label>Limite</label>
        <input name="limit" type="number" value="500" min="10" max="5000"/>
      </div>
      <div style="flex:1; min-width:260px">
        <label>Ricerca full-text</label>
        <input name="q" placeholder="es. auth/login, username, IP, path…"/>
      </div>
      <div class="row" style="gap:8px; align-items:flex-end">
        <button class="btn" type="submit">Aggiorna</button>
        <a id="expCsv" class="btn secondary" href="#">Export CSV</a>
        <a id="expJsonl" class="btn secondary" href="#">Export JSONL</a>
      </div>
    </form>

    <!-- Tabella -->
    <div class="table sticky">
      <table id="tbl">
        <thead>
          <tr>
            <th>Ora</th><th>Evento</th><th>Utente</th><th>IP</th>
            <th>OK</th><th>Path</th><th>Dettagli</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</div>


</div>

<script>
function fmtTs(ts){
  if(!ts) return '-';
  const d = new Date(ts*1000);
  return new Intl.DateTimeFormat('it-IT', {
    year:'numeric', month:'2-digit', day:'2-digit',
    hour:'2-digit', minute:'2-digit', second:'2-digit',
    hour12:false
  }).format(d);
}
function row(e){
  const ok = (e.ok===true || e.ok==='true' || e.ok===1) ? 'true' : (e.ok===false ? 'false' : '');
  return "<tr>"
    +"<td class='mono'>"+fmtTs(e.ts)+"</td>"
    +"<td class='mono'>"+(e.evt||'-')+"</td>"
    +"<td class='mono'>"+(e.actor||'-')+"</td>"
    +"<td class='mono'>"+(e.ip||'-')+"</td>"
    +"<td>"+(ok===''?'-':("<span class='chip "+(ok==='true'?"ok":"err")+"'>"+ok+"</span>"))+"</td>"
    +"<td class='mono'>"+(e.path||'-')+"</td>"
    +"<td>"+(e.detail?String(e.detail).replace(/[<>]/g, s=>({'<':'&lt;','>':'&gt;'}[s])):'')+"</td>"
    +"</tr>";
}
async function load(){
  const f = document.getElementById('f');
  const q = f.q.value.trim();
  const since = f.since.value;
  const limit = f.limit.value || 500;

  const url = new URL('/logs/api/list', location.origin);
  if(q) url.searchParams.set('q', q);
  if(since) url.searchParams.set('since', since);
  url.searchParams.set('limit', limit);

  const r = await fetch(url); const js = await r.json();
  const tb = document.querySelector('#tbl tbody'); tb.innerHTML = '';
  (js.items||[]).forEach(e => tb.insertAdjacentHTML('beforeend', row(e)));

  const makeExp = (fmt)=> {
    const u = new URL('/logs/export', location.origin);
    if(q) u.searchParams.set('q', q);
    if(since) u.searchParams.set('since', since);
    u.searchParams.set('limit', limit);
    u.searchParams.set('fmt', fmt);
    return u.toString();
  };
  document.getElementById('expCsv').href = makeExp('csv');
  document.getElementById('expJsonl').href = makeExp('jsonl');
}
document.getElementById('f').addEventListener('submit', (ev)=>{ev.preventDefault(); load();});
load();
</script>
<script src="/static/bg.js"></script>
</body></html>
"""
    return HTMLResponse(html)


# ---- API: list ----
@router.get("/api/list", response_class=JSONResponse)
def api_list(
    q: str = Query(""),
    since: str = Query("1h"),
    limit: int = Query(500, ge=10, le=5000),
):
    since_ts = _parse_timespec(since) if since else None
    items = _filter_entries(q=q, since_ts=since_ts, limit=limit)
    return {"items": items, "count": len(items)}

# ---- Export ----
@router.get("/export")
def export(
    q: str = Query(""),
    since: str = Query(""),
    limit: int = Query(2000, ge=10, le=50000),
    fmt: str = Query("jsonl")
):
    since_ts = _parse_timespec(since) if since else None
    items = _filter_entries(q=q, since_ts=since_ts, limit=limit)

    if fmt == "jsonl":
        def gen():
            for e in items:
                yield json.dumps(e["_raw"], ensure_ascii=False) + "\n"
        fname = f"audit_export_{int(time.time())}.jsonl"
        return StreamingResponse(gen(), media_type="application/x-ndjson",
                                 headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    if fmt == "csv":
        # CSV leggero su campi principali
        def esc(v: Any) -> str:
            s = "" if v is None else str(v)
            return '"' + s.replace('"','""') + '"'
        header = "ts,evt,actor,ip,ok,path,detail\n"
        def gen():
            yield header
            for e in items:
                row = [e.get("ts"), e.get("evt"), e.get("actor"), e.get("ip"), e.get("ok"), e.get("path"), e.get("detail")]
                yield ",".join(esc(x) for x in row) + "\n"
        fname = f"audit_export_{int(time.time())}.csv"
        return StreamingResponse(gen(), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    return HTMLResponse("Formato non supportato", status_code=400)
