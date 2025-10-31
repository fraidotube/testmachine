#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import os, json, time, sys, traceback
from pathlib import Path
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, AsyncSniffer, sendp, get_if_hwaddr

CFG  = Path("/etc/netprobe/dhcpsentinel.json")
BASE = Path("/var/lib/netprobe/dhcpsentinel")
LAST = BASE / "last.json"
EVTS = BASE / "events.jsonl"
ALERTS_JSON = Path("/etc/netprobe/alerts.json")

def _jwrite(path:Path, obj:dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def _jappend(path:Path, obj:dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",",":"))+"\n")

def _load_json(path:Path, default):
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return default

def _tg_send(msg:str):
    try:
        from util.notify import send_telegram
    except Exception:
        return (False, "util.notify non disponibile")
    cfg = _load_json(ALERTS_JSON, {})
    tg  = ((cfg.get("channels") or {}).get("telegram") or {})
    token = (tg.get("token") or "").strip()
    chat  = str(tg.get("chat_id") or "").strip()
    if not (tg.get("enabled") and token and chat):
        return (False, "Telegram non configurato")
    return send_telegram(token, chat, msg)

def _discover_once(iface:str, listen_sec:int)->set[str]:
    mac = get_if_hwaddr(iface)
    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(":","")) + b"\x00"*10, xid=0x12345678, flags=0x8000) /
        DHCP(options=[("message-type","discover"), ("param_req_list",[1,3,6,15,51,58,59,119]), "end"])
    )
    servers:set[str] = set()
    def on_pkt(pkt):
        if pkt.haslayer(DHCP):
            try:
                opts = dict([o for o in pkt[DHCP].options if isinstance(o, tuple)])
                if opts.get("message-type") == 2:  # OFFER
                    servers.add(pkt[IP].src)
            except Exception:
                pass
    snif = AsyncSniffer(iface=iface, filter="udp and (port 67 or 68)", store=False, prn=on_pkt)
    snif.start()
    time.sleep(0.2)
    sendp(discover, iface=iface, verbose=0)
    time.sleep(max(1, int(listen_sec)))
    snif.stop()
    return servers

def main()->int:
    cfg = _load_json(CFG, {})
    if not cfg or not cfg.get("enabled", False):
        return 0
    iface  = cfg.get("iface") or "ens4"
    allow  = cfg.get("allow") or []
    listen = int(cfg.get("listen_sec", 6))
    retries= int(cfg.get("retries", 1))
    rdelay = int(cfg.get("retry_delay_sec", 2))

    seen:set[str] = set()
    for i in range(1+max(0, retries)):
        seen |= _discover_once(iface, listen)
        if seen: break
        time.sleep(max(0, rdelay))

    ok=True; reason="ok"
    if not allow:
        ok=False; reason="allowlist_empty"
    else:
        unknown = [s for s in sorted(seen) if s not in allow]
        if unknown:
            ok=False; reason="rogue"

    out = {"ts": int(time.time()), "iface": iface, "seen": sorted(seen), "allow": allow, "ok": ok, "reason": reason}
    _jwrite(LAST, out)
    _jappend(EVTS, {"ts": out["ts"], "type":"dhcpsentinel_result", **{k:out[k] for k in ("iface","seen","allow","ok","reason")}})

    if not ok:
        if reason=="allowlist_empty":
            note = f"dhcpsentinel: DHCP server rilevato su {iface}: {', '.join(out['seen']) or '?'} (allowlist vuota)"
        elif reason=="rogue":
            note = f"dhcpsentinel: ROGUE DHCP su {iface}: {', '.join(out['seen']) or '?'} (non in allow)"
        else:
            note = f"dhcpsentinel: anomalia su {iface}: {', '.join(out['seen']) or '?'} (reason={reason})"
        _jappend(EVTS, {"ts": int(time.time()), "type":"dhcpsentinel_alert_try", "note": note})
        _tg_send(note)

    return 0

if __name__=="__main__":
    try:
        sys.exit(main())
    except Exception as e:
        _jappend(EVTS, {"ts": int(time.time()), "type":"dhcpsentinel_fatal", "err": repr(e), "trace": traceback.format_exc()})
        raise
