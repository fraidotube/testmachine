# /opt/netprobe/app/util/notify.py
from __future__ import annotations
import json, smtplib, socket, ssl, urllib.request

def send_telegram(token: str, chat_id: str, text: str, timeout: int = 10) -> tuple[bool,str]:
    if not token or not chat_id: return False, "missing token/chat_id"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({"chat_id": chat_id, "text": text, "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return (200 <= r.status < 300), f"HTTP {r.status}"
    except Exception as e:
        return False, str(e)

def send_slack(webhook_url: str, text: str, timeout: int = 10) -> tuple[bool,str]:
    if not webhook_url: return False, "missing webhook_url"
    data = json.dumps({"text": text}).encode()
    req  = urllib.request.Request(webhook_url, data=data, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return (200 <= r.status < 300), f"HTTP {r.status}"
    except Exception as e:
        return False, str(e)

def send_email(smtp_host: str, from_addr: str, to_addrs: list[str], subject: str, body: str) -> tuple[bool,str]:
    if not smtp_host or not to_addrs: return False, "missing smtp/to"
    msg = f"From: {from_addr}\r\nTo: {', '.join(to_addrs)}\r\nSubject: {subject}\r\n\r\n{body}"
    try:
        with smtplib.SMTP(smtp_host, 25, timeout=10) as s:
            s.sendmail(from_addr, to_addrs, msg.encode("utf-8"))
        return True, "sent"
    except Exception as e:
        return False, str(e)
