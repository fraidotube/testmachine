from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Routers principali
from routes.wan import router as wan_router
from routes.lan import router as lan_router
from routes.settings import router as settings_router

app = FastAPI()

# Static e templates (percorsi assoluti per evitare problemi di cwd)
app.mount("/static", StaticFiles(directory="/opt/netprobe/app/static"), name="static")
templates = Jinja2Templates(directory="/opt/netprobe/app/templates")

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Registra i router
app.include_router(wan_router, prefix="/wan")
app.include_router(lan_router, prefix="/lan")
app.include_router(settings_router, prefix="/settings")

# (Opzionale) pannello admin Smokeping: non deve rompere se non esiste
try:
    from routes.sp_admin import router as sp_admin_router  # type: ignore
    app.include_router(sp_admin_router)
except Exception:
    # niente admin, ma l app deve comunque avviarsi
    pass
