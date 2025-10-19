# /opt/netprobe/app/routes/console.py
import os, pty, fcntl, termios, struct, signal, asyncio, re
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from html import escape
from routes.auth import verify_session_cookie, _load_users  # già esistenti
from routes.settings import head  # per riusare l’header UI
from util.audit import log_event

router = APIRouter()

# ----- helpers -----
def _require_admin_ws(ws: WebSocket) -> str | None:
    # ricrea una Request finta per riusare verify_session_cookie()
    # (serve solo il cookie)
    scope = {"type": "http", "headers": [(b"cookie", (ws.headers.get("cookie","")).encode())]}
    req = Request(scope)
    user = verify_session_cookie(req)
    if not user: return None
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    return user if "admin" in roles else None

def _set_winsize(fd: int, cols: int, rows: int):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass

# ----- pagina HTML con xterm.js -----
@router.get("/console", response_class=HTMLResponse)
def console_page(request: Request):
    user = verify_session_cookie(request)
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    if not user or "admin" not in roles:
        return HTMLResponse(head("Console") + "<div class='grid'><div class='card'><h2 class='err'>Operazione non permessa</h2><a class='btn' href='/'>Home</a></div></div></div></body></html>", status_code=403)

    html = head("Console root") + """
    <div class='grid'><div class='card' style='grid-column:1 / -1'>
      <h2>Console root</h2>
      <p class='muted'>Sessione con privilegi <b>root</b> dentro un PTY. Le azioni sono tracciate a log. Timeout inattività: 15 minuti.</p>
      <div id="term" style="width:100%; height:520px; background:#111; border-radius:12px;"></div>
      <div style="margin-top:8px">
        <button class='btn' onclick='fitTerm()'>Fit</button>
        <button class='btn danger' onclick='killTerm()'>Chiudi</button>
        <span id="stat" class="muted" style="margin-left:10px"></span>
      </div>
    </div></div></div>
    <script src="https://unpkg.com/xterm/lib/xterm.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/xterm/css/xterm.css"/>
    <script>
    const term = new Terminal({cursorBlink:true, fontFamily:'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize:13});
    term.open(document.getElementById('term'));
    let ws;
    function connect(){
      const proto = (location.protocol === 'https:') ? 'wss' : 'ws';
      ws = new WebSocket(proto + '://' + location.host + '/api/console/ws');
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        document.getElementById('stat').textContent = 'connesso';
        fitTerm();
      };
      ws.onclose = () => document.getElementById('stat').textContent = 'chiuso';
      ws.onerror = () => document.getElementById('stat').textContent = 'errore';
      ws.onmessage = ev => {
        if (ev.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(ev.data));
        } else {
          // messaggi di controllo testuali (pochi)
          try {
            const js = JSON.parse(ev.data);
            if (js.msg) document.getElementById('stat').textContent = js.msg;
          } catch { /* ignore */ }
        }
      };
      term.onData(d => {
        if (ws && ws.readyState === 1) ws.send(d);
      });
      window.addEventListener('resize', fitTerm);
    }
    function fitTerm(){
      const cols = Math.max(80, Math.floor(term._core._renderService.dimensions.css.canvasWidth / term._core._renderService.dimensions.css.cellWidth));
      const rows = Math.max(24, Math.floor(520 / term._core._renderService.dimensions.css.cellHeight));
      ws && ws.readyState === 1 && ws.send(JSON.stringify({resize:[cols,rows]}));
    }
    function killTerm(){ ws && ws.close(); }
    connect();
    </script>
    </body></html>
    """
    return HTMLResponse(html)

# ----- WebSocket PTY -----
@router.websocket("/api/console/ws")
async def console_ws(ws: WebSocket):
    await ws.accept()
    user = _require_admin_ws(ws)
    if not user:
        await ws.send_text('{"msg":"forbidden"}'); await ws.close(code=4403); return

    # Crea un PTY e lancia la root shell tramite wrapper (vedi sudoers)
    master_fd, slave_fd = pty.openpty()
    _set_winsize(master_fd, 120, 34)
    env = os.environ.copy()
    env.update({"TERM":"xterm-256color", "LANG":"C.UTF-8"})

    # esegui wrapper con sudo (registrazione transcript)
    cmd = ["sudo","-n","/usr/local/sbin/netprobe-root-shell"]

    pid = os.fork()
    if pid == 0:
        # child: collega slave al stdio e exec
        os.setsid()
        os.close(master_fd)
        os.dup2(slave_fd, 0); os.dup2(slave_fd, 1); os.dup2(slave_fd, 2)
        if slave_fd > 2: os.close(slave_fd)
        os.execvpe(cmd[0], cmd, env)
        os._exit(1)

    os.close(slave_fd)
    log_event("console/ws", ok=True, actor=user, detail="open")

    async def reader():
        try:
            loop = asyncio.get_running_loop()
            while True:
                data = await asyncio.to_thread(os.read, master_fd, 4096)
                if not data: break
                await ws.send_bytes(data)
        except Exception:
            pass

    reader_task = asyncio.create_task(reader())

    try:
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=900)  # 15 min idle timeout
            except asyncio.TimeoutError:
                await ws.send_text('{"msg":"timeout 15m"}')
                break

            if msg["type"] == "websocket.disconnect":
                break
            if "text" in msg and isinstance(msg["text"], str):
                t = msg["text"]
                # resize payload {"resize":[cols,rows]}
                if t.startswith("{"):
                    try:
                        js = __import__("json").loads(t)
                        if "resize" in js and isinstance(js["resize"], list) and len(js["resize"])==2:
                            cols, rows = int(js["resize"][0]), int(js["resize"][1])
                            _set_winsize(master_fd, cols, rows)
                            os.kill(pid, signal.SIGWINCH)
                            continue
                    except Exception:
                        pass
                os.write(master_fd, t.encode())
            elif "bytes" in msg and msg["bytes"] is not None:
                os.write(master_fd, msg["bytes"])
    except WebSocketDisconnect:
        pass
    finally:
        try:
            os.kill(pid, signal.SIGHUP)
        except Exception:
            pass
        try:
            reader_task.cancel()
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass
        log_event("console/ws", ok=True, actor=user, detail="close")
