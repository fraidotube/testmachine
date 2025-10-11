from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Routers principali
from routes.wan import router as wan_router
from routes.lan import router as lan_router
from routes.settings import router as settings_router

# Auth
from routes.auth import router as auth_router, verify_session_cookie

app = FastAPI()

# Static e templates
app.mount("/static", StaticFiles(directory="/opt/netprobe/app/static"), name="static")
templates = Jinja2Templates(directory="/opt/netprobe/app/templates")

# --------- middleware di protezione ---------
PROTECTED_PREFIXES = ("/wan", "/lan", "/settings", "/sp-admin")
ALLOW_PREFIXES = ("/auth", "/static", "/smokeping")  # sempre liberi

@app.middleware("http")
async def auth_gatekeeper(request: Request, call_next):
    path = request.url.path or "/"
    # liberi
    if path == "/" or path == "/favicon.ico":
        return await call_next(request)
    if any(path.startswith(p) for p in ALLOW_PREFIXES):
        return await call_next(request)
    # protetti
    if any(path.startswith(p) for p in PROTECTED_PREFIXES):
        user = verify_session_cookie(request)
        if not user:
            return RedirectResponse(url=f"/auth/login?next={path}", status_code=307)
        request.state.user = user
    return await call_next(request)

# --------- routes base ---------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Registra i router
app.include_router(wan_router, prefix="/wan")
app.include_router(lan_router, prefix="/lan")
app.include_router(settings_router, prefix="/settings")
app.include_router(auth_router)  # NEW

# (Opzionale) pannello admin Smokeping
try:
    from routes.sp_admin import router as sp_admin_router  # type: ignore
    app.include_router(sp_admin_router)
except Exception:
    pass
