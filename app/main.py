# /opt/netprobe/app/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
from routes.netmap import router as netmap_router
from routes.flow import router as flow_router
from routes.logs import router as logs_router
from routes.shell import router as shell_router
from routes.alerts import router as alerts_router
from routes import bg
from routes.natfw import router as natfw_router
from routes import dhcpsentinel
from routes.browser_settings import router as browser_api_router
from routes.browser import router as browser_ui_router



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
    "/voip/start": ["admin"],
    "/voip/stop":  ["admin"],
    "/voip":       ["admin", "operator", "viewer"],  # per la sola pagina/GET
    # "/status" NON è mappato -> libero (solo lettura per homepage)
    "/flow/exporter/start": ["admin"],
    "/flow/exporter/stop":  ["admin"],
    "/flow":                ["admin", "operator", "viewer"],  # sola pagina/GET
    "/logs": ["admin", "operator", "viewer"],
    "/cacti-dbpass": ["admin"],                   # <-- NUOVO: lettura password DB Cacti (solo admin)
    "/cacti": ["admin", "operator", "viewer"],
    "/shell": ["admin"],
    "/alerts": ["admin"],
    "/api/browser": ["admin"],
    "/browser":     ["admin"],   # la pagina /browser (UI)


}

# Percorsi sempre liberi
ALLOW_PREFIXES = ("/static", "/auth/login", "/auth/logout", "/favicon.ico", "/cacti")

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
app.include_router(pcap_router)          
app.include_router(status_router)        
app.include_router(speedtest_router)
app.include_router(voip_router)  
app.include_router(netmap_router)
app.include_router(flow_router)
app.include_router(logs_router)
app.include_router(shell_router) 
app.include_router(alerts_router)
app.include_router(bg.router)
app.include_router(natfw_router)
app.include_router(dhcpsentinel.router)
app.include_router(browser_api_router)
app.include_router(browser_ui_router)



# ---- NUOVO: endpoint per leggere la password DB di Cacti (solo admin via RBAC) ----
import re
from pathlib import Path

CACTI_DEBIAN_PHP = Path("/etc/cacti/debian.php")

@app.get("/cacti-dbpass", response_class=JSONResponse)
def cacti_dbpass(request: Request):
    try:
        txt = CACTI_DEBIAN_PHP.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Impossibile leggere {CACTI_DEBIAN_PHP}: {e}"}, status_code=500)
    m = re.search(r'^\$database_password\s*=\s*["\']([^"\']+)["\']', txt, re.M)
    if not m:
        return JSONResponse({"ok": False, "error": "Campo $database_password non trovato"}, status_code=404)
    return JSONResponse({"ok": True, "password": m.group(1)})

# (Opzionale) pannello admin Smokeping
try:
    from routes.sp_admin import router as sp_admin_router  # type: ignore
    app.include_router(sp_admin_router)
except Exception:
    pass
