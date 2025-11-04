# /opt/netprobe/app/routes/browser_settings.py
from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse
import subprocess, os, socket, pathlib, re, time, secrets

router = APIRouter(prefix="/api/browser", tags=["browser"])

HTPASS        = "/etc/apache2/.htpasswd-browser"
SITES_AVAIL   = "/etc/apache2/sites-available"
SITES_ENABLED = "/etc/apache2/sites-enabled"
VHOST_PREFIX  = "browser-ssl-"
DEFAULT_REALM = "TestMachine Browser"
VHOST_TEMPLATE = "/opt/netprobe/templates/browser-vhost-ssl.conf.tmpl"

# --------------------- helpers ---------------------

def sh(cmd, **kw):
    # Run a command, raising on non-zero, capture stdout/stderr as text
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)

def apache_reload():
    sh(["sudo", "/bin/systemctl", "reload", "apache2"])

def write_root_file(path, content):
    # Write a file as root via sudo tee to avoid permission problems
    sh(["sudo", "/usr/bin/tee", path], input=content)

def detect_wan_ip():
    """
    Best effort WAN IP:
    - try "hostname -I" and pick a non-loopback IPv4 (prefer non-private);
    - fallback: UDP connect trick to 8.8.8.8;
    - fallback: 127.0.0.1
    """
    try:
        out = sh(["/bin/hostname", "-I"]).stdout.strip().split()
        def is_private(ip):
            if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."):
                return True
            if ip.startswith("172."):
                try:
                    sec = int(ip.split(".")[1])
                    return 16 <= sec <= 31
                except Exception:
                    return False
            return False
        # prefer non-private IPv4
        for ip in out:
            if ":" in ip:
                continue
            if not is_private(ip):
                return ip
        # then first non-loopback IPv4
        for ip in out:
            if ip and ":" not in ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip:
            return ip
    except Exception:
        pass
    return "127.0.0.1"

def render_template(port, servername, cert, key, realm):
    tpl = pathlib.Path(VHOST_TEMPLATE).read_text(encoding="utf-8")
    # simple .replace to avoid f-strings with braces
    return (tpl
            .replace("{{PORT}}", str(port))
            .replace("{{SERVERNAME}}", str(servername))
            .replace("{{CERT_FILE}}", str(cert))
            .replace("{{CERT_KEY}}", str(key))
            .replace("{{REALM}}", str(realm)))

def disable_all_browser_sites():
    for f in pathlib.Path(SITES_AVAIL).glob(VHOST_PREFIX + "*.conf"):
        try:
            sh(["sudo", "/usr/sbin/a2dissite", f.name])
        except subprocess.CalledProcessError:
            # already disabled
            pass

def enable_site(port):
    sh(["sudo", "/usr/sbin/a2ensite", VHOST_PREFIX + str(port) + ".conf"])

def get_enabled_port():
    enabled = [p.name for p in pathlib.Path(SITES_ENABLED).glob(VHOST_PREFIX + "*.conf")]
    if not enabled:
        return None
    m = re.search(r"(\d+)", enabled[0])
    return int(m.group(1)) if m else None

# --------------------- endpoints ---------------------

@router.post("/auth")
def set_auth(enable: str = Form(...),
             username: str = Form("admin"),
             password: str = Form("")):
    """
    Enable/disable Basic Auth for /browser/ using htpasswd -Bbc.
    """
    try:
        enabled = str(enable).lower() in ("1", "true", "yes", "on")
        if enabled:
            if not username or not password:
                return JSONResponse({"ok": False, "err": "username/password richiesti"}, status_code=400)
            sh(["sudo", "/usr/bin/htpasswd", "-Bbc", HTPASS, username, password])
            try:
                os.chmod(HTPASS, 0o640)
            except Exception:
                pass
        else:
            try:
                if os.path.exists(HTPASS):
                    os.remove(HTPASS)
            except Exception:
                pass
        apache_reload()
        return {"ok": True, "auth_enabled": enabled}
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or str(e)).strip()
        return JSONResponse({"ok": False, "err": "htpasswd/a2* errore: " + msg}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "err": str(e)}, status_code=500)

@router.post("/force-logout")
@router.post("/force-relogin")
def force_logout():
    """
    Force re-login by changing the Basic Auth realm (AuthName) in the active vhost.
    """
    try:
        port = get_enabled_port()
        if not port:
            return JSONResponse({"ok": False, "err": "nessun vhost attivo"}, status_code=400)

        servername = detect_wan_ip()
        cert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
        key  = "/etc/ssl/private/ssl-cert-snakeoil.key"
        nonce = secrets.token_hex(3)
        realm = DEFAULT_REALM + " (" + str(int(time.time())) + "-" + nonce + ")"

        cfg = render_template(port, servername, cert, key, realm)
        conf_path = SITES_AVAIL + "/" + VHOST_PREFIX + str(port) + ".conf"
        write_root_file(conf_path, cfg)
        apache_reload()
        return {"ok": True, "realm": realm}
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or str(e)).strip()
        return JSONResponse({"ok": False, "err": msg}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "err": str(e)}, status_code=500)

@router.post("/port")
def set_port(port: int = Form(...),
             cert_file: str = Form("/etc/ssl/certs/ssl-cert-snakeoil.pem"),
             cert_key:  str = Form("/etc/ssl/private/ssl-cert-snakeoil.key"),
             realm:     str = Form(DEFAULT_REALM)):
    """
    Create/enable TLS vhost on the requested port and reload Apache.
    The URL uses the detected WAN IP automatically.
    """
    try:
        if port < 1024 or port > 65535:
            return JSONResponse({"ok": False, "err": "porta fuori range"}, status_code=400)

        servername = detect_wan_ip()
        conf_path  = SITES_AVAIL + "/" + VHOST_PREFIX + str(port) + ".conf"
        cfg = render_template(port, servername, cert_file, cert_key, realm)

        write_root_file(conf_path, cfg)
        disable_all_browser_sites()
        enable_site(port)
        apache_reload()

        return {"ok": True, "port": port, "servername": servername,
                "url": "https://" + servername + ":" + str(port) + "/browser/"}
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or str(e)).strip()
        return JSONResponse({"ok": False, "err": msg}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "err": str(e)}, status_code=500)

@router.get("/status")
def status():
    """
    Report active vhost port and suggested servername (WAN IP).
    """
    p = get_enabled_port()
    return {"ok": True, "port": p, "servername": detect_wan_ip()}
