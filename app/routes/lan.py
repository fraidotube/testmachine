from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from util.shell import run

router = APIRouter()

def head(title:str)->str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<title>{escape(title)}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'>"
        "<div class='nav'>"
          "<div class='brand'><img src='/static/img/logo.svg' class='logo'/></div>"
          "<div class='title-center'>TestMachine</div>"
          "<div class='spacer'><a class='btn secondary' href='/'>Home</a></div>"
        "</div>"
    )

# ---- Rilevamento interfacce (stessa logica di WAN) -------------------------
def _os_if_order():
    rc, out, _ = run(["/usr/sbin/ip","-o","link","show"])
    order=[]
    if rc==0 and out:
        for line in out.splitlines():
            try:
                idx_str, rest = line.split(":",1)
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

# ---- Pagine -----------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    wan = _pick_wan_iface()
    choices = _lan_candidates()

    if not wan:
        return HTMLResponse(
            head("LAN") +
            "<div class='grid'><div class='card'>"
            "<h2>LAN</h2>"
            "<p class='danger'>Nessuna interfaccia fisica trovata.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div></body></html>"
        )

    if not choices:
        return HTMLResponse(
            head("LAN") +
            "<div class='grid'><div class='card'>"
            "<h2>LAN</h2>"
            f"<p class='muted'>Interfaccia WAN: <code>{wan}</code></p>"
            "<p class='danger'>Non ci sono altre interfacce disponibili da usare come LAN.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div></body></html>"
        )

    options = "".join(f"<option value='{d}'>{d}</option>" for d in choices)
    return HTMLResponse(
        head("LAN") +
        "<div class='grid'><div class='card'>"
        "<h2>LAN</h2>"
        f"<p class='muted'>Interfaccia WAN (bloccata): <code>{wan}</code></p>"
        "<form method='post' action='/lan/set'>"
        "<label>Interfaccia LAN</label>"
        f"<select name='ifname'>{options}</select>"
        "<label>Modalità</label>"
        "<select name='mode'><option value='dhcp'>DHCP</option><option value='static'>Static</option></select>"
        "<div class='row'>"
        "<div><label>IP</label><input name='ip' placeholder='192.168.100.10'/></div>"
        "<div><label>Prefix</label><input name='prefix' value='24'/></div>"
        "</div>"
        "<div class='row'>"
        "<div><label>Gateway (opz.)</label><input name='gw'/></div>"
        "<div><label>DNS (opz.)</label><input name='dns'/></div>"
        "</div>"
        "<button class='btn' type='submit'>Applica LAN</button>"
        "</form></div></div></div></body></html>"
    )

@router.post("/set")
def set_lan(
    mode: str = Form(...), ifname: str = Form(...),
    ip: str = Form(None), prefix: int = Form(None),
    gw: str = Form(None), dns: str = Form("")
):
    # valida che l'utente abbia scelto una iface *non-WAN*
    valid = _lan_candidates()
    if ifname not in valid:
        return JSONResponse({"status":"error","detail":"Interfaccia non valida per LAN"}, status_code=400)

    run(["sudo","-n","nmcli","dev","disconnect", ifname])
    run(["sudo","-n","nmcli","con","del","lan0"])

    if mode == 'dhcp':
        rc, out, err = run(["sudo","-n","nmcli","con","add","type","ethernet","ifname",ifname,"con-name","lan0",
                            "ipv4.method","auto","ipv6.method","ignore"])
    elif mode == 'static':
        args = ["sudo","-n","nmcli","con","add","type","ethernet","ifname",ifname,"con-name","lan0",
                "ipv4.method","manual","ipv4.addresses",f"{ip}/{prefix}","ipv6.method","ignore"]
        if gw:  args += ["ipv4.gateway",gw]
        if dns: args += ["ipv4.dns",dns]
        rc, out, err = run(args)
    else:
        return JSONResponse({"status":"error","detail":"mode unknown"}, status_code=400)

    if rc != 0:
        return JSONResponse({"status":"error","out":out,"err":err}, status_code=500)

    run(["sudo","-n","nmcli","con","up","lan0"])
    return HTMLResponse(head("LAN") + "<div class='grid'><div class='card'><h2 class='ok'>LAN aggiornata</h2><a class='btn secondary' href='/lan'>Indietro</a></div></div></div></body></html>")
