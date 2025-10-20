# app/routes/shell.py
# -*- coding: utf-8 -*-
"""
WebShell: /shell (HTML) + /shell/ws (WebSocket).
Opens a local PTY and execs 'su -l' (login shell). The browser must type the
root password at the prompt. Page access should be protected by require_admin
if available in your project; otherwise it is a no-op.
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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Optional auth: try to import require_admin; fallback to no-op.
def _noauth_stub():
    return None

try:
    from routes.auth import require_admin  # type: ignore
except Exception:
    require_admin = _noauth_stub  # type: ignore

templates = Jinja2Templates(directory="app/templates")
router = APIRouter(tags=["Shell"])


@router.get("/shell", response_class=HTMLResponse)
async def shell_page(request: Request, _user=Depends(require_admin)):
    """Render the terminal page (protected by require_admin if present)."""
    return templates.TemplateResponse("shell.html", {"request": request})


def set_winsize(fd: int, cols: int, rows: int) -> None:
    """Set PTY window size."""
    if cols <= 0 or rows <= 0:
        return
    winsz = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)


async def _forward_ws_to_pty(ws: WebSocket, master_fd: int):
    """
    Receive messages from WebSocket and write to PTY.
    Supports {"resize": [cols, rows]} JSON messages for terminal resize.
    """
    while True:
        msg = await ws.receive()
        if msg.get("type") == "websocket.disconnect":
            break

        if msg.get("bytes") is not None:
            os.write(master_fd, msg["bytes"])
            continue

        if msg.get("text") is not None:
            text = msg["text"]
            # try resize
            try:
                data = json.loads(text)
                if isinstance(data, dict) and "resize" in data:
                    cols, rows = data["resize"]
                    set_winsize(master_fd, int(cols), int(rows))
                    continue
            except Exception:
                pass
            os.write(master_fd, text.encode(errors="ignore"))


async def _forward_pty_to_ws(ws: WebSocket, master_fd: int):
    """Read from PTY and send bytes to WebSocket."""
    loop = asyncio.get_running_loop()
    while True:
        data = await loop.run_in_executor(None, os.read, master_fd, 4096)
        if not data:
            break
        await ws.send_bytes(data)


@router.websocket("/shell/ws")
async def shell_ws(ws: WebSocket):
    """
    WebSocket endpoint: create PTY, exec 'su -l' in child, and proxy bytes.
    Do not construct a Request(scope) here; scope type is 'websocket'.
    """
    await ws.accept()

    pid, master_fd = pty.fork()
    if pid == 0:
        # Child: exec login shell
        try:
            os.environ.setdefault("TERM", "xterm-256color")
            os.environ.setdefault("LANG", "C.UTF-8")
            os.execvp("su", ["su", "-l"])
        except Exception:
            os.execvp("/bin/bash", ["bash", "-l"])
        finally:
            os._exit(1)

    # Parent: proxy
    try:
        set_winsize(master_fd, 120, 32)
    except Exception:
        pass

    to_pty = asyncio.create_task(_forward_ws_to_pty(ws, master_fd))
    to_ws = asyncio.create_task(_forward_pty_to_ws(ws, master_fd))

    try:
        await asyncio.wait({to_pty, to_ws}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        # cleanup
        for t in (to_pty, to_ws):
            try:
                t.cancel()
            except Exception:
                pass
        try:
            os.close(master_fd)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        try:
            await asyncio.get_running_loop().run_in_executor(None, os.waitpid, pid, 0)
        except Exception:
            pass
