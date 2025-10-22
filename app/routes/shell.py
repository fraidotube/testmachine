# app/routes/shell.py
# -*- coding: utf-8 -*-
"""
WebShell
========
- GET  /shell     -> pagina HTML (xterm.js) che apre un WebSocket
- WS   /shell/ws  -> ponte PTY <-> WebSocket

Apre un PTY e lancia una login shell chiedendo la password (default: 'su -l').
Puoi cambiare il comando di login con l'env SHELL_CMD (es. "sudo -s" oppure "/bin/bash -l").
Se esiste routes.auth.require_admin lo usa come guard di accesso pagina.
"""

from __future__ import annotations

import asyncio
import json
import os
import pty
import signal
import fcntl
import termios
import struct
from pathlib import Path

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# -------------------------
# Auth opzionale
# -------------------------
def _noauth_stub():
    return None

try:
    from routes.auth import require_admin  # type: ignore
except Exception:
    require_admin = _noauth_stub  # type: ignore

# -------------------------
# Templates (percorso assoluto)
# -------------------------
BASE_DIR = Path(__file__).resolve().parents[1]   # -> /opt/netprobe/app
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["Shell"])


@router.get("/shell", response_class=HTMLResponse)
async def shell_page(request: Request, _user=Depends(require_admin)):
    """Render della pagina terminale (fallback se il template manca)."""
    tpl = TEMPLATES_DIR / "shell.html"
    if not tpl.exists():
        return HTMLResponse(
            "<h1>Shell</h1><p>Template <code>app/templates/shell.html</code> non trovato.</p>",
            status_code=200,
        )
    return templates.TemplateResponse("shell.html", {"request": request})


def set_winsize(fd: int, cols: int, rows: int) -> None:
    """Imposta dimensioni del PTY."""
    if cols > 0 and rows > 0:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


async def _forward_ws_to_pty(ws: WebSocket, master_fd: int) -> None:
    """
    WS -> PTY
    - bytes: scrive direttamente
    - text: se JSON {"resize":[c,r]} fa resize, altrimenti invia come input
    """
    while True:
        msg = await ws.receive()
        t = msg.get("type")

        if t == "websocket.disconnect":
            break

        data_b = msg.get("bytes")
        if data_b is not None:
            try:
                os.write(master_fd, data_b)
            except OSError:
                break
            continue

        data_t = msg.get("text")
        if data_t is not None:
            # tentativo resize JSON
            try:
                obj = json.loads(data_t)
                if isinstance(obj, dict) and "resize" in obj:
                    cols, rows = obj["resize"]
                    set_winsize(master_fd, int(cols), int(rows))
                    continue
            except Exception:
                pass
            try:
                os.write(master_fd, data_t.encode("utf-8", errors="ignore"))
            except OSError:
                break


async def _forward_pty_to_ws(ws: WebSocket, master_fd: int) -> None:
    """PTY -> WS (sempre come bytes)."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            chunk = await loop.run_in_executor(None, os.read, master_fd, 4096)
        except Exception:
            break
        if not chunk:
            break
        try:
            await ws.send_bytes(chunk)
        except (WebSocketDisconnect, RuntimeError):
            break


@router.websocket("/shell/ws")
async def shell_ws(ws: WebSocket) -> None:
    """WebSocket: crea PTY, esegue 'su -l' (o $SHELL_CMD) e fa da proxy."""
    await ws.accept()

    # Comando di login (default: su -l)
    login_cmd = os.environ.get("SHELL_CMD", "su -l")
    argv = login_cmd.split()

    # Crea il PTY e fork
    pid, master_fd = pty.fork()
    if pid == 0:
        # Child: nuova login shell sullo slave del PTY
        try:
            os.environ.setdefault("TERM", "xterm-256color")
            os.environ.setdefault("LANG", "C.UTF-8")
            os.execvp(argv[0], argv)  # es. ['su', '-l']
        except Exception:
            # fallback: bash login shell
            os.execvp("/bin/bash", ["bash", "-l"])
        finally:
            os._exit(1)

    # Parent: inoltra dati
    try:
        set_winsize(master_fd, 120, 32)
    except Exception:
        pass

    to_pty = asyncio.create_task(_forward_ws_to_pty(ws, master_fd))
    to_ws = asyncio.create_task(_forward_pty_to_ws(ws, master_fd))

    try:
        await asyncio.wait({to_pty, to_ws}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (to_pty, to_ws):
            try:
                t.cancel()
            except Exception:
                pass
        try:
            os.close(master_fd)
        except Exception:
            pass
        # prova a chiudere gentilmente la sessione di login
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        # aspetta il child per evitare zombie
        try:
            await asyncio.get_running_loop().run_in_executor(None, os.waitpid, pid, 0)
        except Exception:
            pass
        # chiudi il WS lato server se ancora aperto
        try:
            await ws.close()
        except Exception:
            pass
