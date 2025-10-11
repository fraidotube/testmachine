# TestMachine

Toolkit di diagnostica rete per Debian 12 (FastAPI + Apache reverse proxy) con:
- **SmokePing** (grafici latenza/perdita)
- **WAN/LAN** (NetworkManager: WAN = prima scheda fisica, LAN = tutte le altre)
- **Autenticazione** (login, ruoli base, gestione utenti)

**Web UI:** `http://SERVER:8080`  
**Log installer:** `/var/log/testmachine-install.log`  
**Credenziali iniziali:** `admin / admin`

---

## 0) Portare online una Debian “vanilla” (senza pacchetti)

Se il sistema è appena installato e **non ha** NetworkManager/DHCP client, puoi usare **solo gli strumenti base** per andare online.

1. Trova una scheda non–`lo`:

IF=$(ip -o link show | awk -F': ' '$2!="lo"{print $2}' | head -n1)
echo "Uso interfaccia: $IF"

2A. Se hai già dhclient:

dhclient -v "$IF" || true


2B. Altrimenti IP statico temporaneo:


ip addr add 192.168.1.50/24 dev "$IF"   # ← adatta alla tua rete
ip link set "$IF" up
ip route add default via 192.168.1.1     # ← gateway della tua rete
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" >/etc/resolv.conf

Test:

ping -c1 1.1.1.1 && ping -c1 google.com
Dopo l’installazione, l’installer imposterà WAN in DHCP (NetworkManager) sulla prima scheda fisica.
Puoi poi rimuovere l’IP temporaneo con:

ip addr flush dev "$IF"


1) (Facoltativo) Sorgenti APT consigliate


cp -a /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%s)
cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main contrib non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware
EOF

apt-get update
apt-get -y full-upgrade


2) Installazione
Metodo A – One-liner (scarica e lancia lo script)

bash -c "$(curl -fsSL https://raw.githubusercontent.com/fraidotube/testmachine/main/install/install-testmachine.sh)"


Metodo B – Clona il repo e lancia localmente

apt-get install -y git
git clone https://github.com/fraidotube/testmachine.git /opt/netprobe
bash /opt/netprobe/install/install-testmachine.sh


Cosa fa l’installer

Installa pacchetti: FastAPI/uvicorn, Apache (reverse proxy), NetworkManager, SmokePing e fping.

Crea utente/gruppo netprobe, virtualenv in /opt/netprobe/venv.

Avvia uvicorn su 127.0.0.1:9000 (service netprobe-api) e Apache su :8080.

Inizializza /etc/netprobe/ con admin/admin e session.key.

Imposta SmokePing con Targets vuoti (gruppo TestMachine).

Aggiunge sudoers minimi per nmcli, smokeping reload/restart e install.

Configura WAN in DHCP sulla prima interfaccia fisica (ethernet/wifi); DNS 1.1.1.1, 8.8.8.8.

Log completo in /var/log/testmachine-install.log.

3) Primo accesso

Apri: http://SERVER:8080/
Login: admin / admin → cambia subito la password (card Utenti & accesso).

4) Aggiornamenti

Solo codice:

cd /opt/netprobe
sudo -u netprobe -H bash -lc 'git fetch --all && git pull --ff-only'
systemctl restart netprobe-api
Re-run installer (idempotente):

bash /opt/netprobe/install/install-testmachine.sh


5) WAN & LAN (logica interfacce)
WAN = prima scheda fisica in ordine OS (non selezionabile nei form).

LAN = tutte le altre interfacce (menu a tendina).

Funziona anche con nomi non-ens (es. enp1s0, eth0, wlp2s0, …).

6) Troubleshooting

Servizi e porte

systemctl status netprobe-api --no-pager -n 100
journalctl -u netprobe-api -n 200 --no-pager
ss -ltnp | egrep '(:9000|:8080)\s'



Apache

tail -n 200 /var/log/apache2/testmachine-error.log


SmokePing

/sbin/smokeping --check
systemctl reload smokeping


Reset rapido admin

python3 - <<'PY'
import json, os, secrets, hashlib, pathlib
p=pathlib.Path("/etc/netprobe/users.json"); p.parent.mkdir(exist_ok=True)
def pbk(password,salt,rounds=260000): return hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),rounds).hex()
def h(pw): s=secrets.token_hex(16); r=260000; return f"pbkdf2_sha256${r}${s}${pbk(pw,s,r)}"
data={"users":{"admin":{"pw":h("admin"),"roles":["admin"]}}}
tmp=p.with_suffix(".tmp"); open(tmp,"w").write(json.dumps(data,indent=2)); os.replace(tmp,p); os.chmod(p,0o660)
PY
chgrp netprobe /etc/netprobe/users.json || true



Pulizia IP temporaneo (se usato prima)

ip addr flush dev "$IF"


7) Disinstallazione base

systemctl disable --now netprobe-api
rm -f /etc/systemd/system/netprobe-api.service
systemctl daemon-reload
a2dissite testmachine.conf && systemctl reload apache2
# opzionale (ATTENZIONE: perderai utenti/dati):
# rm -rf /opt/netprobe /etc/netprobe




8) Opzioni avanzate
Variabili d’ambiente supportate dallo script:

REPO_URL – URL repo git (default: GitHub ufficiale)

BRANCH – branch (default: main)

CONFIGURE_WAN=0|1 – abilita/disabilita DHCP auto sulla WAN (default: 1)

Esempio:

CONFIGURE_WAN=0 BRANCH=main bash /opt/netprobe/install/install-testmachine.sh



--------------------------------------------

Roadmap
Ruoli aggiuntivi (operator, viewer)

Integrazione Wireshark/tcpdump (remote capture)

Packaging .deb
