from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from util.shell import run

router = APIRouter()

def head(title:str)->str:
    return f"""<!doctype html><html><head><meta charset='utf-8'/>
    <meta name='viewport' content='width=device-width,initial-scale=1'/>
    <title>{title}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>
    <div class='container'><div class='nav'><div class='brand'><img src='/static/img/CNS-21-LOGO-BIANCO.svg' alt='Logo' class='logo'/><span>TestMachine</span></div>
    <div class='links'><a href='/'>Home</a><a href='/wan'>WAN</a><a href='/settings'>Impostazioni</a></div></div>"""

def list_ifaces():
    rc, out, _ = run(["/usr/bin/nmcli","-t","-f","DEVICE,TYPE,STATE","dev","status"])
    devs=[]
    if rc==0 and out.strip():
        for line in out.strip().splitlines():
            parts=line.split(":")
            if len(parts)>=3:
                dev, typ, state = parts[:3]
                if dev and dev!="lo" and typ in ("ethernet","wifi"):
                    devs.append(dev)
    else:
        rc, out, _ = run(["/usr/sbin/ip","-o","link","show"])
        if rc==0:
            for line in out.splitlines():
                try: name=line.split(":")[1].strip().split("@")[0]
                except Exception: continue
                if name and name!="lo":
                    devs.append(name)
    return sorted(list(dict.fromkeys(devs)))

@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    options = "".join(f"<option value='{d}'>{d}</option>" for d in list_ifaces())
    return head("LAN") + f"""
    <div class='grid'><div class='card'>
      <h2>LAN</h2>
      <form method='post' action='/lan/set'>
        <label>Interfaccia</label>
        <select name='ifname'>{options}</select>
        <label>Modalità</label>
        <select name='mode'><option value='dhcp'>DHCP</option><option value='static'>Static</option></select>
        <div class='row'>
          <div><label>IP</label><input name='ip' placeholder='192.168.100.10'/></div>
          <div><label>Prefix</label><input name='prefix' value='24'/></div>
        </div>
        <div class='row'>
          <div><label>Gateway (opz.)</label><input name='gw'/></div>
          <div><label>DNS (opz.)</label><input name='dns'/></div>
        </div>
        <button class='btn' type='submit'>Applica LAN</button>
      </form>
    </div></div></div></body></html>"""

@router.post("/set")
def set_lan(mode: str = Form(...), ifname: str = Form(...), ip: str = Form(None), prefix: int = Form(None),
            gw: str = Form(None), dns: str = Form("")):
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
