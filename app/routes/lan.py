from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from html import escape
from util.shell import run
from util.audit import log_event

router = APIRouter()

def head(title:str)->str:
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
    rc, out, _ = run(["/usr/sbin/ip","-o","link","show"])
    order=[]
    if rc==0 and out:
        for line in out.splitlines():
            try:
                _idx, rest = line.split(":",1)
                name = rest.split(":")[0].strip().split("@")[0]
                if name and name != "lo":
                    order.append(name)
            except Exception:
                continue
    return order

def _nmcli_physical_set():
    rc, out, _ = run(["/usr/bin/nmcli","-t","-f","DEVICE,TYPE,STATE","dev","status"])
    s=set()
    if rc==0 and out.strip():
        for line in out.strip().splitlines():
            parts=line.split(":")
            if len(parts)>=3:
                dev, typ, _state = parts[:3]
                if dev and typ in ("ethernet","wifi"):
                    s.add(dev)
    return s

def _list_physical_ifaces():
    order = _os_if_order()
    phys  = _nmcli_physical_set()
    if phys:
        lst = [d for d in order if d in phys]
        return lst if lst else sorted(list(phys))
    return order

def _pick_wan_iface():
    lst = _list_physical_ifaces()
    return lst[0] if lst else None

def _lan_candidates():
    lst = _list_physical_ifaces()
    wan = _pick_wan_iface()
    return [d for d in lst if d != wan]

# ---- Lettura configurazioni correnti ----------------------------------------
def _read_current_lan():
    """
    Ritorna stato connessione 'lan0' se esiste.
    """
    rc, out, err = run([
        "/usr/bin/nmcli","-t","-f",
        "connection.type,connection.interface-name,ipv4.method,ipv4.addresses,"
        "ipv4.gateway,ipv4.dns,vlan.id,vlan.parent",
        "con","show","lan0"
    ])
    if rc != 0:
        return {
            "exists": False,
            "ifname": None,
            "mode": "dhcp",
            "ip": None, "prefix": None,
            "use_vlan": False, "vlan_id": None
        }

    kv = {}
    for line in (out or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv[k.strip().lower()] = v.strip() if v is not None else ""

    ctype   = kv.get("connection.type","").lower()
    ifname0 = kv.get("connection.interface-name") or ""
    ipm     = kv.get("ipv4.method","").lower()
    addrs   = kv.get("ipv4.addresses","") or ""
    vlanid  = kv.get("vlan.id") or ""
    vparent = kv.get("vlan.parent") or ""

    use_vlan = (ctype == "vlan")
    ifname_phys = vparent if use_vlan else ifname0
    mode = "dhcp" if ipm == "auto" else ("static" if ipm == "manual" else "dhcp")

    ip = None; prefix = None
    if addrs:
        first = (addrs.split(",")[0] or "").strip()
        if "/" in first:
            ip, pref = first.split("/", 1)
            ip = ip.strip()
            try:
                prefix = int(pref)
            except Exception:
                prefix = None

    vlan_id = None
    if use_vlan and vlanid:
        try:
            vlan_id = int(vlanid)
        except Exception:
            vlan_id = None

    return {
        "exists": True,
        "ifname": ifname_phys or None,
        "mode": mode,
        "ip": ip, "prefix": prefix,
        "use_vlan": use_vlan,
        "vlan_id": vlan_id
    }

def _read_current_bridge():
    """
    Ritorna stato connessione 'lan-bridge0' se esiste.
    """
    rc, out, err = run([
        "/usr/bin/nmcli","-t","-f",
        "connection.type,connection.interface-name,ipv4.method,ipv4.addresses",
        "con","show","lan-bridge0"
    ])
    if rc != 0:
        return {
            "exists": False,
            "ifname": None,
            "ip": None, "prefix": None,
            "has_ip": False
        }

    kv = {}
    for line in (out or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv[k.strip().lower()] = v.strip() if v is not None else ""

    ctype   = kv.get("connection.type","").lower()
    ifname0 = kv.get("connection.interface-name") or ""
    ipm     = kv.get("ipv4.method","").lower()
    addrs   = kv.get("ipv4.addresses","") or ""

    ip = None; prefix = None
    if addrs:
        first = (addrs.split(",")[0] or "").strip()
        if "/" in first:
            ip, pref = first.split("/", 1)
            ip = ip.strip()
            try:
                prefix = int(pref)
            except Exception:
                prefix = None

    has_ip = (ipm == "manual")

    return {
        "exists": True,
        "ifname": ifname0 or None,
        "ip": ip, "prefix": prefix,
        "has_ip": has_ip
    }

# ---- Pagine -----------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    wan = _pick_wan_iface()
    choices = _lan_candidates()
    cur = _read_current_lan()
    cur_br = _read_current_bridge()
    phys_ifaces = _list_physical_ifaces()

    if not wan:
        return HTMLResponse(
            head("LAN") +
            "<div class='grid'><div class='card'>"
            "<h2>LAN</h2>"
            "<p class='danger'>Nessuna interfaccia fisica trovata.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div>"
            "<script src='/static/bg.js' defer></script>"
            "</body></html>"
        )

    if not choices:
        return HTMLResponse(
            head("LAN") +
            "<div class='grid'><div class='card'>"
            "<h2>LAN</h2>"
            f"<p class='muted'>Interfaccia WAN: <code>{escape(wan)}</code></p>"
            "<p class='danger'>Non ci sono altre interfacce disponibili da usare come LAN.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div>"
            "<script src='/static/bg.js' defer></script>"
            "</body></html>"
        )

    # --- CARD LAN -----------------------------------------------------------
    selected_if = cur["ifname"] if cur.get("ifname") in choices else (choices[0] if choices else "")
    options = "".join(
        f"<option value='{escape(d)}'{' selected' if d==selected_if else ''}>{escape(d)}</option>"
        for d in choices
    )
    use_vlan_checked = " checked" if cur.get("use_vlan") else ""
    vlan_id_value = cur.get("vlan_id") if cur.get("vlan_id") else 100
    mode_val = cur.get("mode") or "dhcp"
    is_static = (mode_val == "static")
    ip_val    = cur.get("ip") or ""
    prefix_val= cur.get("prefix") if cur.get("prefix") is not None else 24

    # --- CARD BRIDGE --------------------------------------------------------
    # Abilitata solo se ci sono >=3 interfacce fisiche
    bridge_enabled = len(phys_ifaces) >= 3
    # Interfacce candidate al bridge: tutte le fisiche escluso WAN e esclusa la LAN attuale (fisica o parent)
    lan_phys = cur.get("ifname")
    br_choices = [d for d in choices if d != lan_phys]
    br_selected = (cur_br.get("ifname") if (cur_br.get("ifname") in br_choices) else (br_choices[0] if br_choices else ""))
    br_options = "".join(
        f"<option value='{escape(d)}'{' selected' if d==br_selected else ''}>{escape(d)}</option>"
        for d in br_choices
    )
    br_has_ip_checked = " checked" if cur_br.get("has_ip") else ""
    br_ip_val = cur_br.get("ip") or ""
    br_prefix_val = cur_br.get("prefix") if cur_br.get("prefix") is not None else 24

    # --- HTML ---------------------------------------------------------------
    return HTMLResponse(
        head("LAN") +
        "<div class='grid'>"

        # --------- CARD LAN ----------
        "<div class='card'>"
        "<h2>LAN</h2>"
        f"<p class='muted'>Interfaccia WAN (bloccata): <code>{escape(wan)}</code></p>"
        "<form method='post' action='/lan/set' id='lanForm'>"

        "<label>Interfaccia LAN</label>"
        f"<select name='ifname'>{options}</select>"

        "<div class='row' style='align-items:center;gap:10px'>"
        "<label class='row' style='gap:8px;align-items:center'>"
        f"<input type='checkbox' name='use_vlan' id='use_vlan'{use_vlan_checked}/> Usa VLAN"
        "</label>"
        "<div>"
        "<label>VLAN ID</label>"
        f"<input name='vlan_id' id='vlan_id' type='number' min='1' max='4094' value='{escape(str(vlan_id_value))}'/>"
        "</div>"
        "</div>"

        "<label>Modalità IP</label>"
        "<select name='mode' id='mode'>"
        f"<option value='dhcp'{' selected' if mode_val=='dhcp' else ''}>DHCP (senza default route/DNS)</option>"
        f"<option value='static'{' selected' if mode_val=='static' else ''}>Static</option>"
        "</select>"

        "<div class='row'>"
        f"<div><label>IP</label><input name='ip' id='ip' placeholder='192.168.100.10' value='{escape(ip_val)}'/></div>"
        f"<div><label>Prefix</label><input name='prefix' id='prefix' value='{escape(str(prefix_val))}'/></div>"
        "</div>"

        "<div class='muted tiny'>Nota: su DHCP non verrà impostata la default route né DNS; su Static non sono previsti gateway/DNS.</div>"
        "<button class='btn' type='submit'>Applica LAN</button>"
        "</form>"

        "<script>"
        "const modeEl=document.getElementById('mode');"
        "const ipEl=document.getElementById('ip');"
        "const pEl=document.getElementById('prefix');"
        "const vlanChk=document.getElementById('use_vlan');"
        "const vlanId=document.getElementById('vlan_id');"
        "function syncMode(){"
        "  const s=modeEl.value==='static';"
        "  ipEl.disabled=!s; pEl.disabled=!s;"
        "}"
        "function syncVlan(){ vlanId.disabled=!vlanChk.checked; }"
        "syncMode(); syncVlan();"
        "modeEl.addEventListener('change',syncMode);"
        "vlanChk.addEventListener('change',syncVlan);"
        "</script>"
        "</div>"

        # --------- CARD BRIDGE ----------
        "<div class='card'>"
        "<h2>LAN BRIDGE (porta mirror sniff)</h2>"
        + (
            # Se non abilitata, mostra solo messaggio
            ("<p class='danger'>Servono almeno 3 interfacce fisiche per abilitare il bridge.</p>"
             "<p class='muted'>WAN: esclusa; LAN attuale: esclusa; seleziona una terza interfaccia per sniffing.</p>")
            if not bridge_enabled else
            (
                "<form method='post' action='/lan/bridge_set' id='brForm'>"
                "<label>Interfaccia BRIDGE</label>"
                f"<select name='ifname'>{br_options}</select>"

                "<label class='row' style='gap:8px;align-items:center;margin-top:8px'>"
                f"<input type='checkbox' name='has_ip' id='br_has_ip'{br_has_ip_checked}/> Assegna IP statico"
                "</label>"

                "<div class='row'>"
                f"<div><label>IP</label><input name='ip' id='br_ip' placeholder='192.168.200.10' value='{escape(br_ip_val)}'/></div>"
                f"<div><label>Prefix</label><input name='prefix' id='br_prefix' value='{escape(str(br_prefix_val))}'/></div>"
                "</div>"

                "<div class='muted tiny'>Se disabilitato, l’interfaccia resta senza IP (ideale per sniffing in mirror). Nessun gateway/DNS in ogni caso.</div>"
                "<button class='btn' type='submit'>Applica BRIDGE</button>"
                "</form>"

                "<script>"
                "const brChk=document.getElementById('br_has_ip');"
                "const brIp=document.getElementById('br_ip');"
                "const brPref=document.getElementById('br_prefix');"
                "function syncBr(){ const on=brChk.checked; brIp.disabled=!on; brPref.disabled=!on; }"
                "syncBr(); brChk.addEventListener('change',syncBr);"
                "</script>"
            )
        ) +
        "</div>"

        "</div></div>"
        "<script src='/static/bg.js' defer></script>"
        "</body></html>"
    )

# ---- API: LAN ----------------------------------------------------------------
@router.post("/set")
def set_lan(
    request: Request,
    mode: str = Form(...),
    ifname: str = Form(...),
    ip: str = Form(None),
    prefix: int = Form(None),
    use_vlan: str = Form(None),
    vlan_id: int = Form(None),
):
    valid = _lan_candidates()
    if ifname not in valid:
        return JSONResponse({"status":"error","detail":"Interfaccia non valida per LAN"}, status_code=400)

    vlan_enabled = bool(use_vlan)
    if vlan_enabled:
        if vlan_id is None or not (1 <= int(vlan_id) <= 4094):
            return JSONResponse({"status":"error","detail":"VLAN ID non valido (1-4094)"}, status_code=400)

    if mode == "static":
        if not ip or prefix is None:
            return JSONResponse({"status":"error","detail":"IP/Prefix richiesti in modalità static"}, status_code=400)

    # disattiva/elimina precedente
    run(["sudo","-n","nmcli","dev","disconnect", ifname])
    run(["sudo","-n","nmcli","con","del","lan0"])

    # DHCP senza default route e senza DNS: ipv4.never-default yes + ipv4.ignore-auto-dns yes
    if vlan_enabled:
        vlan_if = f"{ifname}.{int(vlan_id)}"
        base_args = ["sudo","-n","nmcli","con","add",
                     "type","vlan",
                     "ifname", vlan_if,
                     "dev", ifname,
                     "id", str(int(vlan_id)),
                     "con-name","lan0"]
        if mode == 'dhcp':
            args = base_args + [
                "ipv4.method","auto",
                "ipv4.never-default","yes",
                "ipv4.ignore-auto-dns","yes",
                "ipv6.method","ignore"
            ]
        else:
            args = base_args + [
                "ipv4.method","manual",
                "ipv4.addresses", f"{ip}/{int(prefix)}",
                "ipv6.method","ignore"
            ]
        rc, out, err = run(args)
    else:
        if mode == 'dhcp':
            rc, out, err = run([
                "sudo","-n","nmcli","con","add",
                "type","ethernet","ifname", ifname,"con-name","lan0",
                "ipv4.method","auto",
                "ipv4.never-default","yes",
                "ipv4.ignore-auto-dns","yes",
                "ipv6.method","ignore"
            ])
        elif mode == 'static':
            args = ["sudo","-n","nmcli","con","add","type","ethernet","ifname", ifname,"con-name","lan0",
                    "ipv4.method","manual","ipv4.addresses", f"{ip}/{int(prefix)}","ipv6.method","ignore"]
            rc, out, err = run(args)
        else:
            return JSONResponse({"status":"error","detail":"mode unknown"}, status_code=400)

    if rc != 0:
        return JSONResponse({"status":"error","out":out,"err":err}, status_code=500)

    rc_up, out_up, err_up = run(["sudo","-n","nmcli","con","up","lan0"])
    if rc_up != 0:
        return JSONResponse({"status":"error","out":out_up,"err":err_up}, status_code=500)
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("lan/set", ok=True, actor=actor or "unknown", ip=ip, req_path=str(request.url),
              extra={"mode": mode, "ifname": ifname, "vlan": bool(use_vlan), "vlan_id": vlan_id, "ip": ip, "prefix": prefix})
        

    return HTMLResponse(
        head("LAN") +
        "<div class='grid'><div class='card'>"
        "<h2 class='ok'>LAN aggiornata</h2>"
        "<a class='btn secondary' href='/lan'>Indietro</a>"
        "</div></div></div>"
        "<script src='/static/bg.js' defer></script>"
        "</body></html>"
    )

# ---- API: LAN BRIDGE ---------------------------------------------------------
@router.post("/bridge_set")
def bridge_set(
    request: Request,
    ifname: str = Form(...),
    has_ip: str = Form(None),
    ip: str = Form(None),
    prefix: int = Form(None),
):
    phys_ifaces = _list_physical_ifaces()
    if len(phys_ifaces) < 3:
        return JSONResponse({"status":"error","detail":"Servono almeno 3 interfacce fisiche per il bridge"}, status_code=400)

    # Escludi WAN e LAN corrente
    wan = _pick_wan_iface()
    cur_lan = _read_current_lan()
    lan_phys = cur_lan.get("ifname")

    valid = [d for d in phys_ifaces if d not in (wan, lan_phys)]
    if ifname not in valid:
        return JSONResponse({"status":"error","detail":"Interfaccia non valida per BRIDGE"}, status_code=400)

    # Spegni connessione precedente e rimuovi
    run(["sudo","-n","nmcli","dev","disconnect", ifname])
    run(["sudo","-n","nmcli","con","del","lan-bridge0"])

    want_ip = bool(has_ip)
    if want_ip:
        if not ip or prefix is None:
            return JSONResponse({"status":"error","detail":"IP/Prefix richiesti quando si assegna IP"}, status_code=400)
        args = [
            "sudo","-n","nmcli","con","add",
            "type","ethernet","ifname", ifname,"con-name","lan-bridge0",
            "ipv4.method","manual","ipv4.addresses", f"{ip}/{int(prefix)}",
            "ipv4.never-default","yes",  # mai default route
            "ipv6.method","ignore"
        ]
        rc, out, err = run(args)
    else:
        # Senza IP: metodo disabled
        rc, out, err = run([
            "sudo","-n","nmcli","con","add",
            "type","ethernet","ifname", ifname,"con-name","lan-bridge0",
            "ipv4.method","disabled",
            "ipv6.method","ignore"
        ])

    if rc != 0:
        return JSONResponse({"status":"error","out":out,"err":err}, status_code=500)

    rc_up, out_up, err_up = run(["sudo","-n","nmcli","con","up","lan-bridge0"])
    if rc_up != 0:
        return JSONResponse({"status":"error","out":out_up,"err":err_up}, status_code=500)
    actor = None
    try:
        from routes.auth import verify_session_cookie as _vsc
        actor = _vsc(request)
    except Exception:
        pass
    xip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    log_event("lan/bridge_set", ok=True, actor=actor or "unknown", ip=xip, req_path=str(request.url),
              extra={"ifname": ifname, "has_ip": bool(has_ip), "ip": ip, "prefix": prefix})

    return HTMLResponse(
        head("LAN") +
        "<div class='grid'><div class='card'>"
        "<h2 class='ok'>BRIDGE aggiornato</h2>"
        "<a class='btn secondary' href='/lan'>Indietro</a>"
        "</div></div></div>"
        "<script src='/static/bg.js' defer></script>"
        "</body></html>"
    )
