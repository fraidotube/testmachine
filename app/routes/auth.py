from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pathlib import Path
from html import escape
import json, os, time, hmac, hashlib, base64, secrets, re

router = APIRouter(prefix="/auth", tags=["auth"])

USERS_FILE   = Path("/etc/netprobe/users.json")
KEY_FILE     = Path("/etc/netprobe/session.key")
COOKIE_NAME  = "np_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 giorni

# Ruoli disponibili (minimo utile)
ROLES = ["admin", "operator", "viewer"]

_username_re = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")

# ---------- utils: file utente/chiave ----------
def _ensure_dirs():
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(USERS_FILE.parent, 0o770)
        import grp
        gid = grp.getgrnam("netprobe").gr_gid
        os.chown(USERS_FILE.parent, 0, gid)
    except Exception:
        pass

def _pbkdf2(password: str, salt_hex: str, rounds: int = 260000) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return dk.hex()

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    rounds = 260000
    return f"pbkdf2_sha256${rounds}${salt}${_pbkdf2(password, salt, rounds)}"

def _verify_password(stored: str, password: str) -> bool:
    try:
        algo, rounds_s, salt, digest = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        calc = _pbkdf2(password, salt, int(rounds_s))
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False

def _load_users():
    """Dict canonicale: {username: {pw:..., roles:[...]}, ...}"""
    _ensure_dirs()
    if not USERS_FILE.exists():
        USERS_FILE.write_text(json.dumps({
            "users": {"admin": {"pw": _hash_password("admin"), "roles": ["admin"]}}
        }, indent=2), encoding="utf-8")
        os.chmod(USERS_FILE, 0o660)

    data = json.loads(USERS_FILE.read_text(encoding="utf-8") or "{}")
    users = data.get("users", {})

    # retro-compat
    if isinstance(users, list):
        norm = {}
        for u in users:
            name  = u.get("username") or u.get("user") or u.get("name")
            hashed = u.get("pw") or u.get("hash") or u.get("password")
            roles = u.get("roles", [])
            if name and hashed:
                norm[name] = {"pw": hashed, "roles": roles}
        users = norm
    elif isinstance(users, dict):
        for k, v in list(users.items()):
            if isinstance(v, dict) and ("pw" not in v):
                hv = v.get("hash") or v.get("password")
                if hv:
                    v["pw"] = hv
            if "roles" not in v or v["roles"] is None:
                v["roles"] = []
    else:
        users = {}

    return users

def _save_users(users: dict):
    """Scrittura atomica con fsync + replace, permessi best-effort."""
    _ensure_dirs()
    payload = {"users": users}

    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, USERS_FILE)
    try:
        os.chmod(USERS_FILE, 0o660)
        import grp
        gid = grp.getgrnam("netprobe").gr_gid
        os.chown(USERS_FILE, 0, gid)
    except Exception:
        pass

def _get_secret() -> bytes:
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(secrets.token_bytes(32))
        os.chmod(KEY_FILE, 0o600)
    return KEY_FILE.read_bytes()

# ---------- utils: session cookie ----------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _sign(data: bytes) -> str:
    key = _get_secret()
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return _b64e(mac)

def _make_session(username: str) -> str:
    payload = json.dumps({"u": username, "iat": int(time.time())}, separators=(",", ":")).encode()
    return _b64e(payload) + "." + _sign(payload)

def _verify_session(token: str):
    try:
        payload_b64, sig = token.split(".", 1)
        payload = _b64d(payload_b64)
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        data = json.loads(payload.decode())
        if int(time.time()) - int(data.get("iat", 0)) > SESSION_MAX_AGE:
            return None
        return data.get("u")
    except Exception:
        return None

def verify_session_cookie(request: Request):
    c = request.cookies.get(COOKIE_NAME)
    if not c:
        return None
    return _verify_session(c)

def _current_user(request: Request):
    u = verify_session_cookie(request)
    if not u:
        return None, []
    users = _load_users()
    roles = users.get(u, {}).get("roles", []) or []
    return u, roles

def _nav():
    return (
        "<div class='nav'>"
        "  <div class='brand'><img src='/static/img/logo.svg' class='logo' alt='Logo'><span>TestMachine</span></div>"
        "  <div class='links'><a href='/'>Home</a> <a href='/auth/logout?next=/'>Logout</a></div>"
        "</div>"
    )

# ---------- Routes tecniche ----------
@router.get("/users/list", response_class=JSONResponse)
def users_list_json():
    users = _load_users()
    return {"users": [{"username": u, "roles": info.get("roles", [])} for u, info in users.items()]}

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    html = (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<title>Login</title>"
        "<link rel='stylesheet' href='/static/styles.css'/></head>"
        "<body><div class='container'>"
        + _nav() +
        "<div class='card' style='max-width:520px;margin:28px auto;'>"
        "  <h2>Accesso</h2>"
        "  <form method='post' action='/auth/login'>"
        "    <input type='hidden' name='next' value='" + escape(next) + "'/>"
        "    <label>Utente</label><input name='username' autocomplete='username' required/>"
        "    <label>Password</label><input name='password' type='password' autocomplete='current-password' required/>"
        "    <button class='btn' type='submit'>Entra</button>"
        "  </form>"
        "  <p class='muted'>Default: <code>admin</code> / <code>admin</code>.</p>"
        "</div>"
        "</div></body></html>"
    )
    return HTMLResponse(content=html)

@router.post("/login")
def login_submit(response: Response, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    users = _load_users()
    info = users.get(username)
    if not info or not _verify_password(info.get("pw", ""), password):
        return HTMLResponse("<script>history.back();alert('Credenziali non valide');</script>")
    token = _make_session(username)
    r = RedirectResponse(url=next if next else "/", status_code=303)
    r.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", secure=False, path="/", max_age=SESSION_MAX_AGE)
    return r

@router.get("/logout")
def logout(next: str = "/"):
    r = RedirectResponse(url=next if next else "/", status_code=303)
    r.delete_cookie(COOKIE_NAME, path="/")
    return r

# ---------- Pagina GESTIONE UTENTI ----------
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user, roles = _current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login?next=/auth/users", status_code=303)
    if "admin" not in roles:
        return HTMLResponse("<h3 style='margin:2rem'>Accesso negato</h3>", status_code=403)

    users = _load_users()
    rows = []
    for u, info in users.items():
        ro = ", ".join(info.get("roles", []) or []) or "-"
        rows.append(
            "<div class='row' style='grid-template-columns: 1fr 1fr auto; align-items:center;'>"
            "  <div><b>" + escape(u) + "</b></div>"
            "  <div class='muted'>" + escape(ro) + "</div>"
            "  <form method='post' action='/auth/users/delete' onsubmit=\"return confirm('Eliminare " + escape(u) + "?');\">"
            "    <input type='hidden' name='username' value='" + escape(u) + "'/>"
            "    <button class='btn danger' type='submit'>Elimina</button>"
            "  </form>"
            "</div>"
        )
    list_html = "".join(rows) or "<div class='muted'>Nessun utente.</div>"

    # select ruoli
    options = "".join(f"<option value='{escape(r)}'>{escape(r)}</option>" for r in ROLES)

    page = (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<title>Gestione utenti</title>"
        "<link rel='stylesheet' href='/static/styles.css'/></head>"
        "<body><div class='container'>"
        + _nav() +
        "<div class='grid'>"
        "  <div class='card'>"
        "    <h2>Utenti & accesso</h2>"
        "    <p class='muted'>Gestisci utenti, ruoli e password. Sei autenticato come <b>" + escape(user) + "</b>.</p>"
        "    <div class='card' style='padding:12px'>" + list_html + "</div>"
        "  </div>"
        "  <div class='card'>"
        "    <h3>Aggiungi utente</h3>"
        "    <form method='post' action='/auth/users/add'>"
        "      <label>Username</label><input name='username' required placeholder='es. admin2'/>"
        "      <label>Password</label><input name='password1' type='password' required/>"
        "      <label>Ripeti password</label><input name='password2' type='password' required/>"
        "      <label>Ruolo</label><select name='role'>" + options + "</select>"
        "      <button class='btn' type='submit'>Crea</button>"
        "    </form>"
        "    <p class='muted'>Ammessi caratteri: lettere, numeri, . _ - (max 32).</p>"
        "  </div>"
        "  <div class='card'>"
        "    <h3>Cambia password</h3>"
        "    <form method='post' action='/auth/users/pass'>"
        "      <label>Username (vuoto = te stesso)</label><input name='username' placeholder='" + escape(user) + "'/>"
        "      <label>Password attuale</label><input name='oldpass' type='password'/>"
        "      <label>Nuova password</label><input name='newpass1' type='password' required/>"
        "      <label>Ripeti nuova password</label><input name='newpass2' type='password' required/>"
        "      <button class='btn' type='submit'>Aggiorna</button>"
        "    </form>"
        "    <p class='muted'>Se cambi la tua password è obbligatoria la password attuale.</p>"
        "  </div>"
        "</div>"
        "</div></body></html>"
    )
    return HTMLResponse(page)

# ---------- Azioni (POST) ----------
@router.post("/users/add")
def user_add(
    request: Request,
    username: str = Form(...),
    password1: str = Form(...),
    password2: str = Form(...),
    role: str = Form("admin"),
):
    me, myroles = _current_user(request)
    if not me:
        return RedirectResponse(url="/auth/login?next=/auth/users", status_code=303)
    if "admin" not in myroles:
        return HTMLResponse("Accesso negato", status_code=403)

    username = username.strip()
    if not _username_re.match(username):
        return HTMLResponse("<script>history.back();alert('Username non valido');</script>")
    if role not in ROLES:
        return HTMLResponse("<script>history.back();alert('Ruolo non valido');</script>")
    if password1 != password2:
        return HTMLResponse("<script>history.back();alert('Le password non coincidono');</script>")
    if len(password1) < 4:
        return HTMLResponse("<script>history.back();alert('Password troppo corta');</script>")

    users = _load_users()
    if username in users:
        return HTMLResponse("<script>history.back();alert('Utente già esistente');</script>")

    users[username] = {"pw": _hash_password(password1), "roles": [role]}
    try:
        _save_users(users)
    except PermissionError:
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    return RedirectResponse(url="/auth/users", status_code=303)

@router.post("/users/pass")
def user_pass(
    request: Request,
    username: str = Form(""),
    oldpass: str = Form(""),
    newpass1: str = Form(...),
    newpass2: str = Form(...),
):
    me, myroles = _current_user(request)
    if not me:
        return RedirectResponse(url="/auth/login?next=/auth/users", status_code=303)

    users = _load_users()
    target = (username or me).strip()

    is_admin = "admin" in myroles
    if not is_admin and target != me:
        return HTMLResponse("Accesso negato", status_code=403)

    if target not in users:
        return HTMLResponse("<script>history.back();alert('Utente inesistente');</script>")
    if newpass1 != newpass2:
        return HTMLResponse("<script>history.back();alert('Le nuove password non coincidono');</script>")
    if len(newpass1) < 4:
        return HTMLResponse("<script>history.back();alert('Password troppo corta');</script>")

    # Se stai cambiando la *tua* password (o non sei admin), verifica oldpass
    need_old = (target == me) or (not is_admin)
    if need_old:
        if not oldpass or not _verify_password(users[target].get("pw", ""), oldpass):
            return HTMLResponse("<script>history.back();alert('Password attuale errata');</script>")

    users[target]["pw"] = _hash_password(newpass1)
    try:
        _save_users(users)
    except PermissionError:
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    return RedirectResponse(url="/auth/users", status_code=303)

@router.post("/users/delete")
def user_delete(request: Request, username: str = Form(...)):
    me, myroles = _current_user(request)
    if not me:
        return RedirectResponse(url="/auth/login?next=/auth/users", status_code=303)
    if "admin" not in myroles:
        return HTMLResponse("Accesso negato", status_code=403)

    users = _load_users()
    if username not in users:
        return HTMLResponse("<script>history.back();alert('Utente inesistente');</script>")

    admins = [u for u, info in users.items() if "admin" in (info.get("roles") or [])]
    if username == me:
        return HTMLResponse("<script>history.back();alert('Non puoi eliminare te stesso');</script>")
    if username in admins and len(admins) <= 1:
        return HTMLResponse("<script>history.back();alert('Non puoi eliminare l\\'ultimo admin');</script>")

    users.pop(username, None)
    try:
        _save_users(users)
    except PermissionError:
        return HTMLResponse("<script>alert('Permesso negato su /etc/netprobe');history.back()</script>")
    return RedirectResponse(url="/auth/users", status_code=303)
