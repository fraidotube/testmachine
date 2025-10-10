from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from util.shell import run

router = APIRouter()

def head(title:str)->str:
    return f"""<!doctype html><html><head><meta charset='utf-8'/>
    <meta name='viewport' content='width=device-width,initial-scale=1'/>
    <title>{title}</title><link rel='stylesheet' href='/static/styles.css'/></head><body>
    <div class='container'><div class='nav'><div class='brand'>🛠️ TestMachine</div>
    <div class='links'><a href='/'>Home</a><a href='/lan'>LAN</a><a href='/settings'>Impostazioni</a></div></div>"""

def list_ifaces():
    # prova nmcli
    rc, out, _ = run(["/usr/bin/nmcli","-t","-f","DEVICE,TYPE,STATE","dev","status"])
    if rc == 0 and out.strip():
        devs=[]
        for line in out.strip().splitlines():
            parts=line.split(":")
            if len(parts)>=3:
                dev, typ, state = parts[:3]
                if dev and dev!="lo" and typ in ("ethernet","wifi"):
                    devs.append(dev)
        if devs: return devs
    # fallback a ip link
    rc, out, _ = run(["/usr/sbin/ip","-o","link","show"])
    devs=[]
    if rc==0:
        for line in out.splitlines():
            # "2: enp1s0: <...>"
            try:
                name=line.split(":")[1].strip().split("@")[0]
            except Exception:
                continue
            if name and name!="lo":
                devs.append(name)
    # dedup
    return sorted(list(dict.fromkeys(devs)))

@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    options = "".join(f"<option value='{d}'>{d}</option>" for d in list_ifaces())
    return head("WAN") + f"""
    <div class='grid'><div class='card'>
      <h2>WAN</h2>
      <form method='post' action='/wan/set'>
        <label>Interfaccia</label>
        <select name='ifname'>{options}</select>
        <label>Modalità</label>
        <select name='mode'><option value='dhcp'>DHCP</option><option value='static'>Static</option><option value='pppoe'>PPPoE</option></select>
        <div class='row'>
          <div><label>IP</label><input name='ip' placeholder='192.168.1.10'/></div>
          <div><label>Prefix</label><input name='prefix' value='24'/></div>
        </div>
        <div class='row'>
          <div><label>Gateway</label><input name='gw' placeholder='192.168.1.1'/></div>
          <div><label>DNS</label><input name='dns' value='1.1.1.1,8.8.8.8'/></div>
        </div>
        <div class='row'>
          <div><label>PPPoE user</label><input name='pppoe_user'/></div>
          <div><label>PPPoE pass</label><input type='password' name='pppoe_pass'/></div>
        </div>
        <button class='btn' type='submit'>Applica WAN</button>
      </form>
      <p class='notice'>Suggerimento: se l'elenco è vuoto, verifica che nmcli/ip siano installati.</p>
    </div></div></div></body></html>"""

@router.post("/set")
def set_wan(mode: str = Form(...), ifname: str = Form(...), ip: str = Form(None), prefix: int = Form(None),
            gw: str = Form(None), dns: str = Form("1.1.1.1,8.8.8.8"),
            pppoe_user: str = Form(None), pppoe_pass: str = Form(None)):
    run(["sudo","-n","nmcli","dev","disconnect", ifname])
    run(["sudo","-n","nmcli","con","del","wan0"])
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
