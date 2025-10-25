from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from util.shell import run

try:
    # Se disponibile, allinea il logging agli altri moduli
    from util.audit import log_event
except Exception:  # fallback no-op
    def log_event(*args, **kwargs):  # type: ignore
        pass

router = APIRouter()


def head(title: str) -> str:
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


# ---- Rilevamento interfacce -------------------------------------------------
def _os_if_order():
    """Ordine nativo del sistema da `ip -o link show` (per indice)."""
    rc, out, _ = run(["/usr/sbin/ip", "-o", "link", "show"])
    order = []
    if rc == 0 and out:
        for line in out.splitlines():
            try:
                _idx, rest = line.split(":", 1)
                name = rest.split(":")[0].strip().split("@")[0]
                if name and name != "lo":
                    order.append(name)
            except Exception:
                continue
    return order


def _nmcli_physical_set():
    """Set di device fisici rilevati da nmcli (ethernet/wifi)."""
    rc, out, _ = run(["/usr/bin/nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"])
    s = set()
    if rc == 0 and out and out.strip():
        for line in out.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                dev, typ, _state = parts[:3]
                if dev and typ in ("ethernet", "wifi"):
                    s.add(dev)
    return s


def _list_physical_ifaces():
    """Lista ordinata (ordine OS) di interfacce fisiche utilizzabili."""
    order = _os_if_order()
    phys = _nmcli_physical_set()
    if phys:
        lst = [d for d in order if d in phys]
        return lst if lst else sorted(list(phys))
    return order


def _pick_wan_iface():
    lst = _list_physical_ifaces()
    return lst[0] if lst else None


# ---- Lettura configurazione corrente WAN ------------------------------------
def _read_current_wan():
    """
    Ritorna lo stato della connessione 'wan0' se esiste.
    Output:
      {
        "exists": bool,
        "ifname": str|None,          # interfaccia fisica associata
        "mode": "dhcp"|"static"|"pppoe",
        "ip": str|None,
        "prefix": int|None,
        "gw": str|None,
        "dns": list[str],
        "pppoe_user": str|None
      }
    """
    rc, out, err = run([
        "/usr/bin/nmcli", "-t", "-f",
        "connection.type,connection.interface-name,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,pppoe.username",
        "con", "show", "wan0"
    ])
    if rc != 0:
        return {
            "exists": False,
            "ifname": None,
            "mode": "dhcp",
            "ip": None, "prefix": None,
            "gw": None, "dns": [],
            "pppoe_user": None
        }

    kv = {}
    for line in (out or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv[k.strip().lower()] = (v or "").strip()

    ctype = kv.get("connection.type", "").lower()
    ifname0 = kv.get("connection.interface-name") or ""
    ipm = kv.get("ipv4.method", "").lower()
    addrs = kv.get("ipv4.addresses", "") or ""
    gateway = kv.get("ipv4.gateway") or None
    dns_raw = kv.get("ipv4.dns") or ""
    ppp_user = kv.get("pppoe.username") or None

    # Mode
    if ctype == "pppoe":
        mode = "pppoe"
    else:
        mode = "dhcp" if ipm == "auto" else ("static" if ipm == "manual" else "dhcp")

    # IP/prefix
    ip = None
    prefix = None
    if addrs:
        first = (addrs.split(",")[0] or "").strip()
        if "/" in first:
            ip, pref = first.split("/", 1)
            ip = ip.strip()
            try:
                prefix = int(pref)
            except Exception:
                prefix = None

    dns = []
    if dns_raw:
        dns = [d.strip() for d in dns_raw.split(",") if d.strip()]

    return {
        "exists": True,
        "ifname": ifname0 or None,
        "mode": mode,
        "ip": ip,
        "prefix": prefix,
        "gw": gateway,
        "dns": dns,
        "pppoe_user": ppp_user
    }


# ---- Pagine -----------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    wan_phys = _pick_wan_iface()
    if not wan_phys:
        return HTMLResponse(
            head("WAN") +
            "<div class='grid'><div class='card'>"
            "<h2>WAN</h2>"
            "<p class='danger'>Nessuna interfaccia fisica trovata.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div>"
            "<script src='/static/bg.js' defer></script>"
            "</body></html>"
        )

    cur = _read_current_wan()

    mode_val = cur.get("mode") or "dhcp"
    is_static = (mode_val == "static")
    is_pppoe = (mode_val == "pppoe")

    ip_val = cur.get("ip") or ""
    prefix_val = cur.get("prefix") if cur.get("prefix") is not None else 24
    gw_val = cur.get("gw") or ""
    dns_val = ",".join(cur.get("dns") or ["1.1.1.1", "8.8.8.8"])
    ppp_user_val = cur.get("pppoe_user") or ""

    # HTML
    return HTMLResponse(
        head("WAN") +
        "<div class='grid'><div class='card'>"
        "<h2>WAN</h2>"
        f"<p class='muted'>Interfaccia WAN (rilevata): <code>{escape(wan_phys)}</code></p>"
        "<form method='post' action='/wan/set' id='wanForm'>"

        "<label>Modalità</label>"
        "<select name='mode' id='mode'>"
        f"<option value='dhcp'{' selected' if mode_val=='dhcp' else ''}>DHCP</option>"
        f"<option value='static'{' selected' if mode_val=='static' else ''}>Static</option>"
        f"<option value='pppoe'{' selected' if mode_val=='pppoe' else ''}>PPPoE</option>"
        "</select>"

        "<div class='row'>"
        f"<div><label>IP</label><input name='ip' id='ip' placeholder='192.168.1.10' value='{escape(ip_val)}'/></div>"
        f"<div><label>Prefix</label><input name='prefix' id='prefix' value='{escape(str(prefix_val))}'/></div>"
        "</div>"

        "<div class='row'>"
        f"<div><label>Gateway</label><input name='gw' id='gw' placeholder='192.168.1.1' value='{escape(gw_val)}'/></div>"
        f"<div><label>DNS</label><input name='dns' id='dns' value='{escape(dns_val)}'/></div>"
        "</div>"

        "<div class='row'>"
        f"<div><label>PPPoE user</label><input name='pppoe_user' id='pppoe_user' value='{escape(ppp_user_val)}'/></div>"
        "<div><label>PPPoE pass</label><input type='password' name='pppoe_pass' id='pppoe_pass' placeholder='••••••••'/></div>"
        "</div>"

        "<button class='btn' type='submit'>Applica WAN</button>"
        "</form>"

        "<script>"
        "const modeEl=document.getElementById('mode');"
        "const ipEl=document.getElementById('ip');"
        "const prefEl=document.getElementById('prefix');"
        "const gwEl=document.getElementById('gw');"
        "const dnsEl=document.getElementById('dns');"
        "const puserEl=document.getElementById('pppoe_user');"
        "const ppassEl=document.getElementById('pppoe_pass');"
        "function sync(){"
        "  const m=modeEl.value;"
        "  const st=(m==='static');"
        "  const pe=(m==='pppoe');"
        "  ipEl.disabled=!st; prefEl.disabled=!st; gwEl.disabled=!st; dnsEl.disabled=!st;"
        "  puserEl.disabled=!pe; ppassEl.disabled=!pe;"
        "}"
        "sync(); modeEl.addEventListener('change',sync);"
        "</script>"

        "</div></div></div>"
        "<script src='/static/bg.js' defer></script>"
        "</body></html>"
    )


@router.post("/set")
def set_wan(
    request: Request,
    mode: str = Form(...),
    ip: str = Form(None), prefix: int = Form(None),
    gw: str = Form(None), dns: str = Form("1.1.1.1,8.8.8.8"),
    pppoe_user: str = Form(None), pppoe_pass: str = Form(None)
):
    ifname = _pick_wan_iface()
    if not ifname:
        return JSONResponse({"status": "error", "detail": "Nessuna interfaccia WAN disponibile"}, status_code=400)

    # Validazione minima per le modalità
    if mode not in ("dhcp", "static", "pppoe"):
        return JSONResponse({"status": "error", "detail": "mode unknown"}, status_code=400)

    if mode == "static":
        if not ip or prefix is None or not gw:
            return JSONResponse({"status": "error", "detail": "IP/Prefix/Gateway richiesti in modalità static"}, status_code=400)

    if mode == "pppoe":
        if not pppoe_user or not pppoe_pass:
            return JSONResponse({"status": "error", "detail": "Credenziali PPPoE richieste"}, status_code=400)

    # Scollega e rimuovi eventuale profilo preesistente
    run(["sudo", "-n", "nmcli", "dev", "disconnect", ifname])
    run(["sudo", "-n", "nmcli", "con", "del", "wan0"])

    # Applica nuova configurazione
    if mode == 'dhcp':
        rc, out, err = run([
            "sudo", "-n", "nmcli", "con", "add",
            "type", "ethernet", "ifname", ifname, "con-name", "wan0",
            "ipv4.method", "auto",
            "ipv6.method", "ignore"
        ])
    elif mode == 'static':
        # Normalizza DNS (lista separata da virgole)
        dns_norm = ",".join([d.strip() for d in (dns or "").split(",") if d.strip()]) if dns else ""
        args = [
            "sudo", "-n", "nmcli", "con", "add",
            "type", "ethernet", "ifname", ifname, "con-name", "wan0",
            "ipv4.method", "manual",
            "ipv4.addresses", f"{ip}/{int(prefix)}",
            "ipv4.gateway", gw,
            "ipv4.dns", dns_norm,
            "ipv6.method", "ignore"
        ]
        rc, out, err = run(args)
    else:  # pppoe
        rc, out, err = run([
            "sudo", "-n", "nmcli", "con", "add",
            "type", "pppoe", "ifname", ifname, "con-name", "wan0",
            "pppoe.username", pppoe_user,
            "pppoe.password", pppoe_pass
        ])

    if rc != 0:
        return JSONResponse({"status": "error", "out": out, "err": err}, status_code=500)

    rc_up, out_up, err_up = run(["sudo", "-n", "nmcli", "con", "up", "wan0"])
    if rc_up != 0:
        return JSONResponse({"status": "error", "out": out_up, "err": err_up}, status_code=500)

    # Audit
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    xip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("wan/set", ok=True, actor=actor or "unknown", ip=xip, req_path=str(request.url),
              extra={
                  "mode": mode, "ifname": ifname,
                  "ip": ip, "prefix": prefix, "gw": gw,
                  "dns": dns, "pppoe_user": pppoe_user,
              })

    return HTMLResponse(
        head("WAN") +
        "<div class='grid'><div class='card'>"
        "<h2 class='ok'>WAN aggiornata</h2>"
        "<a class='btn secondary' href='/wan'>Indietro</a>"
        "</div></div></div>"
        "<script src='/static/bg.js' defer></script>"
        "</body></html>"
    )
