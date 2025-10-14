# /opt/netprobe/app/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Routers principali
from routes.wan import router as wan_router
from routes.lan import router as lan_router
from routes.settings import router as settings_router
from routes.pcap import router as pcap_router
from routes.status import router as status_router  # <-- NEW
from routes.speedtest import router as speedtest_router
from routes.voip import router as voip_router


# Auth
from routes.auth import router as auth_router, verify_session_cookie, _load_users  # _load_users per leggere i ruoli

app = FastAPI()

# Static e templates
app.mount("/static", StaticFiles(directory="/opt/netprobe/app/static"), name="static")
templates = Jinja2Templates(directory="/opt/netprobe/app/templates")

# --------- RBAC: prefisso -> ruoli ammessi ----------
PATH_ROLES = {
    "/sp-admin": ["admin"],                        # pannello SmokePing admin
    "/settings": ["admin"],                        # impostazioni aggiuntive
    "/wan":      ["admin", "operator"],            # config rete WAN
    "/lan":      ["admin", "operator"],            # config rete LAN
    "/smokeping":["admin", "operator", "viewer"],  # fruizione grafici
    "/auth":     ["admin"],                        # gestione utenti/ruoli 
    "/pcap":     ["admin", "operator"],            # cattura pacchetti
    "/speedtest":["admin", "operator", "viewer"],  # speedtest
    # "/status" NON è mappato -> libero (solo lettura per homepage)
}

# Percorsi sempre liberi
ALLOW_PREFIXES = ("/static", "/auth/login", "/auth/logout", "/favicon.ico")

@app.middleware("http")
async def auth_gatekeeper(request: Request, call_next):
    path = request.url.path or "/"

    # homepage sempre libera
    if path == "/":
        return await call_next(request)

    # liberi
    if any(path.startswith(p) for p in ALLOW_PREFIXES):
        return await call_next(request)

    # trova eventuale prefisso protetto
    protected = None
    for prefix in PATH_ROLES:
        if path.startswith(prefix):
            protected = prefix
            break

    if not protected:
        # non mappato: lascia passare (es. /status/summary)
        return await call_next(request)

    # richiede login
    user = verify_session_cookie(request)
    if not user:
        return RedirectResponse(url=f"/auth/login?next={path}", status_code=307)

    # verifica ruolo
    users = _load_users()
    roles = (users.get(user, {}) or {}).get("roles", []) or []
    allowed = PATH_ROLES.get(protected, [])
    if not any(r in allowed for r in roles):
        return HTMLResponse("<h3 style='margin:2rem'>Accesso negato</h3>", status_code=403)

    request.state.user = user
    return await call_next(request)

# --------- routes base ---------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    from routes.auth import verify_session_cookie
    user = verify_session_cookie(request)  # mostra link Logout se c’è sessione valida
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

# Registra i router
app.include_router(wan_router, prefix="/wan")
app.include_router(lan_router, prefix="/lan")
app.include_router(settings_router, prefix="/settings")
app.include_router(auth_router)
app.include_router(pcap_router)          # ha già prefix="/pcap"
app.include_router(status_router)        # NEW: espone /status/summary
app.include_router(speedtest_router)
app.include_router(voip_router)  # ha già prefix="/voip"


# (Opzionale) pannello admin Smokeping
try:
    from routes.sp_admin import router as sp_admin_router  # type: ignore
    app.include_router(sp_admin_router)
except Exception:
    pass
