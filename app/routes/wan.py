from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from util.shell import run

router = APIRouter()

def head(title:str)->str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{title}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>"
        "<div class='container'><div class='nav'><div class='brand'>"
        "<img src='/static/img/logo.svg' alt='Logo' class='logo'><span>TestMachine</span></div>"
        "<div class='links'><a href='/'>Home</a></div></div>"
    )

# ---- Rilevamento interfacce -------------------------------------------------
def _os_if_order():
    """Ordine nativo del sistema da `ip -o link show` (per indice)."""
    rc, out, _ = run(["/usr/sbin/ip","-o","link","show"])
    order=[]
    if rc==0 and out:
        for line in out.splitlines():
            # "2: enp1s0: <...>"
            try:
                idx_str, rest = line.split(":",1)
                name = rest.split(":")[0].strip().split("@")[0]
                if name and name != "lo":
                    order.append(name)
            except Exception:
                continue
    return order

def _nmcli_physical_set():
    """Set di device fisici rilevati da nmcli (ethernet/wifi)."""
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
    """Lista ordinata (ordine OS) di interfacce fisiche utilizzabili."""
    order = _os_if_order()
    phys  = _nmcli_physical_set()
    if phys:
        lst = [d for d in order if d in phys]
        return lst if lst else sorted(list(phys))
    return order

def _pick_wan_iface():
    lst = _list_physical_ifaces()
    return lst[0] if lst else None

# ---- Pagine -----------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    wan = _pick_wan_iface()
    if not wan:
        return HTMLResponse(
            head("WAN") +
            "<div class='grid'><div class='card'>"
            "<h2>WAN</h2>"
            "<p class='danger'>Nessuna interfaccia fisica trovata.</p>"
            "<a class='btn secondary' href='/'>Indietro</a>"
            "</div></div></div></body></html>"
        )

    # Nessuna select: WAN è bloccata sulla prima iface disponibile
    return HTMLResponse(
        head("WAN") + 
        "<div class='grid'><div class='card'>"
        "<h2>WAN</h2>"
        f"<p class='muted'>Interfaccia WAN (rilevata): <code>{wan}</code></p>"
        "<form method='post' action='/wan/set'>"
        "<label>Modalità</label>"
        "<select name='mode'>"
        "<option value='dhcp'>DHCP</option>"
        "<option value='static'>Static</option>"
        "<option value='pppoe'>PPPoE</option>"
        "</select>"
        "<div class='row'>"
        "<div><label>IP</label><input name='ip' placeholder='192.168.1.10'/></div>"
        "<div><label>Prefix</label><input name='prefix' value='24'/></div>"
        "</div>"
        "<div class='row'>"
        "<div><label>Gateway</label><input name='gw' placeholder='192.168.1.1'/></div>"
        "<div><label>DNS</label><input name='dns' value='1.1.1.1,8.8.8.8'/></div>"
        "</div>"
        "<div class='row'>"
        "<div><label>PPPoE user</label><input name='pppoe_user'/></div>"
        "<div><label>PPPoE pass</label><input type='password' name='pppoe_pass'/></div>"
        "</div>"
        "<button class='btn' type='submit'>Applica WAN</button>"
        "</form>"
        "</div></div></div></body></html>"
    )

@router.post("/set")
def set_wan(
    mode: str = Form(...),
    ip: str = Form(None), prefix: int = Form(None),
    gw: str = Form(None),  dns: str = Form("1.1.1.1,8.8.8.8"),
    pppoe_user: str = Form(None), pppoe_pass: str = Form(None)
):
    ifname = _pick_wan_iface()
    if not ifname:
        return JSONResponse({"status":"error","detail":"Nessuna interfaccia WAN disponibile"}, status_code=400)

    # Scollega e rimuovi eventuale profilo preesistente
    run(["sudo","-n","nmcli","dev","disconnect", ifname])
    run(["sudo","-n","nmcli","con","del","wan0"])

    # Applica
    if mode == 'dhcp':
        rc, out, err = run(["sudo","-n","nmcli","con","add","type","ethernet","ifname",ifname,"con-name","wan0",
                            "ipv4.method","auto","ipv6.method","ignore"])
    elif mode == 'static':
        rc, out, err = run(["sudo","-n","nmcli","con","add","type","ethernet","ifname",ifname,"con-name","wan0",
                            "ipv4.method","manual","ipv4.addresses",f"{ip}/{prefix}",
                            "ipv4.gateway",gw,"ipv4.dns",dns,"ipv6.method","ignore"])
    elif mode == 'pppoe':
        rc, out, err = run(["sudo","-n","nmcli","con","add","type","pppoe","ifname",ifname,"con-name","wan0",
                            "pppoe.username",pppoe_user,"pppoe.password",pppoe_pass])
    else:
        return JSONResponse({"status":"error","detail":"mode unknown"}, status_code=400)

    if rc != 0:
        return JSONResponse({"status":"error","out":out,"err":err}, status_code=500)

    run(["sudo","-n","nmcli","con","up","wan0"])
    return HTMLResponse(head("WAN") + "<div class='grid'><div class='card'><h2 class='ok'>WAN aggiornata</h2><a class='btn secondary' href='/wan'>Indietro</a></div></div></div></body></html>")
