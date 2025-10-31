# TestMachine

Appliance di diagnostica di rete per Debian.

- **Web UI** (FastAPI dietro Apache)
- **Home/Status**: uptime, disco, servizi, **Interfacce & IP** (con filtro automatico di `docker*` e `br-*`)
- **SmokePing** per latenza
- **Packet Capture (PCAP)**: avvio/stop, download, analisi rapida (protocol hierarchy, endpoints, conversations, DNS/HTTP/SNI, top porte)
- Cattura **non-root** tramite capability su `dumpcap`
- Pagine **Impostazioni Sniffer** (quota, durata massima, policy rotate/block, filtri BPF abilitabili)
- **Diagnostica VoIP**: indice chiamate SIP, **SIP ladder**, dettagli registrazioni/chiamate, reindicizzazione PCAP; prime statistiche **RTP** (beta)
- **Net Mapper**: scoperta host e servizi (ARP/Nmap), **Vendor OUI**, reverse DNS, **OS guess**, esportazione JSON/CSV, dashboard
- **Speedtest**: download/upload, latency/jitter/loss con storico locale
- **Flow Monitor (NetFlow v9)**: grafici e contatori basati su **softflowd → nfcapd/nfdump** (supporto istanze `netprobe-flow-exporter@IFACE`)
- **NAT info**: **UPnP** (lista/aggiungi/rimuovi), **MTU Pathfinder** (stima Path MTU e MSS), **Traceroute** con tabella hop/RTT
- **Rete (WAN/LAN & Bridge)**: configurazione interfacce via NetworkManager (**nmcli**), VLAN opzionale, **porta di sniffing** dedicata
- **Impostazioni di sistema**: **porta Apache**, **timezone**, **NTP** (timesyncd), **riavvio macchina**, **cambio hostname**, **Cacti Password (card dedicata in UI)**
- **Console**: shell bash in-browser (login con password di **root**; WebSocket proxato)
- **Cacti**: monitoring SNMP con grafici RRD, integrato su `/cacti/` (card in UI per password DB)
- **Graylog**: syslog con UI su `/graylog/` — **Porta esterne 1514 → 5514** (mappatura verso backend)
- **Alerts**: notifiche **Telegram** con timing/threshold; **etichetta/mittente personalizzabile** (campo `label`)
- **Logs (/logs)**: **audit log** consultabile dalla UI con **export CSV/JSONL**
- **DHCP Sentinel**: rilevazione server DHCP non autorizzati, storico eventi, integrazione Alerts

> UI predefinita: `http://<IP_SERVER>:8080/`  
> Credenziali iniziali: **admin / admin** (cambiale subito).

---

## 1) Requisiti

- Debian **12.x** “pulita”
- Accesso root (o sudo)
- Rete IPv4 raggiungibile

L’installer prepara:

- Pacchetti: `apache2`, venv Python con FastAPI/Uvicorn, `smokeping`, `tshark`, `dumpcap`, `tcpdump`, **`nmap`**, **`arp-scan`**, **`ieee-data`** (OUI), **Speedtest CLI (Ookla)** se disponibile, **`sngrep`**
- **Cacti** con PHP-FPM e cron **poller** attivo; `spine.conf` allineato a `/etc/cacti/debian.php`
- **Flow monitor**: `softflowd`, `nfcapd/nfdump`
- **Graylog stack** via Docker Compose e reverse proxy Apache su `/graylog/`; **Porta esterne 1514 → 5514** per input syslog
- Systemd unit `netprobe-api` (Uvicorn), vhost Apache su **8080** (modificabile con `WEB_PORT`)
- Directory/permessi:
  - `/opt/netprobe` (app)
  - `/var/lib/netprobe` (stato)
  - `/var/lib/netprobe/pcap` (catture)
  - `/var/lib/netprobe/voip` e `/var/lib/netprobe/voip/captures` (VoIP)
  - `/var/lib/netprobe/logs` (audit log)
  - `/var/lib/netprobe/flows` (symlink ai file rotati dei flow)
  - `/var/lib/netprobe/dhcpsentinel` (storico/last)
  - `/etc/netprobe/*.json` (config)
- **Capability/sudoers** per strumenti di cattura/scansione (`dumpcap`, `arp-scan`, `nmap`) e per ricarichi servizio controllati

---

## 2) Configurare a mano l’IP (senza pacchetti aggiuntivi)

Sostituisci i valori con quelli reali:

```bash
IFACE=ens4
IP=192.168.1.50/24
GW=192.168.1.1

ip addr add "$IP" dev "$IFACE"
ip link set "$IFACE" up
ip route add default via "$GW"

cat >/etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

ping -c1 1.1.1.1
ping -c1 google.com
```

---

## 3) Installazione

Esegui come **root**:

```bash
# (opzionale) porta web diversa da 8080
export WEB_PORT=8080

# scarica ed esegui l'installer
curl -fsSL https://raw.githubusercontent.com/fraidotube/testmachine/main/install/install-testmachine.sh | bash
```

Cosa fa lo script (in sintesi):

- Installa pacchetti e dipendenze
- Crea utente/gruppo `netprobe`
- Clona/aggiorna il repo in `/opt/netprobe` e crea il **venv**
- Imposta capability su `/usr/bin/dumpcap` (`cap_net_raw,cap_net_admin+eip`)
- **Seed** config (`/etc/netprobe/users.json` con `admin/admin`, `/etc/netprobe/pcap.json`, `/etc/netprobe/alerts.json`, `/etc/netprobe/dhcpsentinel.json`)
- Prepara percorsi **VoIP** (`/var/lib/netprobe/voip/captures`, `captures.json`, `index.json`)
- Abilita/avvia servizi:
  - `netprobe-api` (Uvicorn su 127.0.0.1:9000)
  - Apache vhost su `:${WEB_PORT}`
  - SmokePing
  - **Flow collector** e **softflowd**
  - **Graylog stack** + proxy `/graylog/` (**Porta esterne 1514 → 5514**)

Check rapidi:

```bash
systemctl status netprobe-api --no-pager -n 20
systemctl status apache2 --no-pager -n 20
systemctl status smokeping --no-pager -n 20
```

---

## 4) Primo accesso

- Utente: **admin**
- Password: **admin**  
Cambia subito la password dal menu **Utenti & accesso**.

---

## 5) Aggiornamento/Upgrade

```bash
cd /opt/netprobe && sudo chown -R netprobe:netprobe .
sudo -u netprobe -H bash -lc 'set -e
git checkout main
git fetch origin
git pull --rebase origin main'
python3 -m py_compile /opt/netprobe/app/routes/status.py /opt/netprobe/app/routes/alerts.py || true
sudo systemctl restart netprobe-api
sudo systemctl try-restart netprobe-alertd.timer || true
sudo systemctl try-restart netprobe-alertd.service || true
```

---

## 6) Packet Capture (PCAP)

**Avvio**: scegli Interfaccia, Durata, Snaplen, (opz.) filtro **BPF** → **Start** / **Stop**.  
**Download & Analisi**: scarica `.pcapng` e usa l’analisi rapida (overview, gerarchie, endpoints, conversations, DNS/HTTP/SNI, top porte).

> **Impostazioni Sniffer**: quota (GB), durata max, **policy** `rotate`/`block`, abilitazione filtri BPF.

Esempi BPF: `host 8.8.8.8`, `tcp port 443`, `net 192.168.1.0/24`, `portrange 1000-2000`, `icmp and not host <me>`.

---

## 7) Diagnostica VoIP (SIP/RTP)

- **Indice chiamate SIP** (Call-ID, numeri A/B, IP/porta, durata)
- **SIP ladder** (REGISTER/INVITE/1xx/200/ACK/BYE, SDP)
- **Reindicizza** PCAP in `/var/lib/netprobe/voip/captures`
- **Download PCAP** per singola chiamata/stream
- **RTP (beta)**: rilevamento stream e conteggi base

---

## 8) Net Mapper

- **ARP scan** host attivi
- **Nmap** porte/servizi, **OS guess**
- **Vendor OUI** e **reverse DNS**
- Dashboard + **export JSON/CSV**

---

## 9) Speedtest

- Misura **download/upload** e **latency/jitter/loss**
- Storico locale dei test
- Backend: **Speedtest CLI (Ookla)** quando presente

---

## 10) NAT info (UPnP, MTU, Traceroute)

- **UPnP**: elenca mapping, **aggiungi/rimuovi** inoltri porta
- **MTU Pathfinder**: stima **Path MTU** e **MSS** consigliato
- **Traceroute** con tabella hop/RTT

---

## 11) Rete: WAN/LAN & Bridge

- **WAN**: DHCP o Statico (IP/gateway/DNS)
- **LAN**: IP locale, **VLAN ID** opzionale
- **Bridge di sniffing**: terza NIC dedicata (no default route/DNS)

Profili creati: `wan0` / `lan0`.

---

## 12) Flow Monitor (NetFlow v9)

Pipeline:

- **softflowd** (export) → `127.0.0.1:2055/UDP`
- **nfcapd** (collector) con rotazione ~60s →  
  `/var/lib/nfsen-ng/profiles-data/live/netprobe`
- Symlink: `/var/lib/netprobe/flows`

Verifica:

```bash
ss -lunp | grep 2055
ls -1 /var/lib/netprobe/flows | tail -n 3
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```

---

## 13) **DHCP Sentinel**

Rileva server **DHCP non autorizzati**:

- Config: `/etc/netprobe/dhcpsentinel.json`  
  (`enabled`, `iface`, `allow[]`, `listen_sec`, `retries`, `retry_delay_sec`)
- Storage: `/var/lib/netprobe/dhcpsentinel/{events.jsonl,last.json,alerts.clear.ts}`
- UI: pagina **/dhcpsentinel** con **Esegui ora**, storico ultimi eventi, ultimi alert
- Timer/Service: `netprobe-dhcpsentinel.timer` / `netprobe-dhcpsentinel.service`
- Integrazione **Alerts**: invio Telegram quando rileva **rogue DHCP**

---

## 14) **Alerts** (Telegram)

- **Etichetta/Mittente** personalizzabile (`label`) mostrata nei messaggi:
  - Test: `🔔 <LABEL>: test notifica`
  - Alert: `⚠️ <LABEL> Alerts:
- …`
- **Check disponibili**:
  - `services` (systemd down), `disk` (soglia %), `smokeping` (RRD bloccati),  
    `cacti` (HTTP/log stalli), `speedtest` (soglie DL/UL/ping),  
    `flow` (flussi fermi), `auth` (tentativi login falliti),  
    `dhcpsentinel` (rogue DHCP).
- **Timing**:
  - `throttle_min` (dedupe/frequenza), `silence_until` (epoch), **Reset dedupe**
- Config: `/etc/netprobe/alerts.json`

---

## 15) Console

Shell bash **in-browser** (WebSocket) dietro autenticazione:

- Accesso con **password di root**
- Percorso WebSocket proxato su `/shell/ws`

---

## 16) Cacti

Grafici **SNMP** e trend:

- Accesso: `http://<IP_SERVER>:8080/cacti/`
- Poller via **cron** (5 minuti)
- **Spine** legge credenziali DB da `/etc/cacti/debian.php`
- **Card UI Cacti Password**: mostra/cambia password DB
- Permessi corretti per `www-data` su RRA/log/script

---

## 17) Graylog

Piattaforma **syslog** con UI proxata:

- UI: `http://<IP_SERVER>:8080/graylog/`
- **Porte esterne**: **1514/TCP+UDP → 5514** (mappatura verso backend)
- Reverse proxy Apache con header/URL corretti

Test rapidi:

```bash
# Proxy Apache
curl -I http://<IP_SERVER>:8080/graylog/

# Invio di prova (UDP)
logger -n 127.0.0.1 -P 1514 -d -t testmachine "hello graylog via udp"
```

---

## 18) Logs (/logs)

- File: `/var/lib/netprobe/logs/audit.jsonl`
- Filtro/ricerca dalla UI e **export CSV/JSONL**
- Card a **larghezza piena** in fondo alla pagina

---

## 19) Impostazioni di sistema

- **Porta Apache** (redirect automatico dopo il cambio)
- **Timezone** di sistema
- **NTP** (`systemd-timesyncd`)
- **Riavvio macchina**, **Cambia hostname**
- **Cacti Password** (card dedicata)

---

## 20) Impostazioni Sniffer

Pagina **/pcap/settings**:

- **Durata massima**
- **Quota storage** (GB)
- **Policy** a quota piena: `rotate` / `block`
- **Refresh UI** (ms)
- **Consenti filtri BPF** (on/off)

Config in `/etc/netprobe/pcap.json`.

---

## 21) Gestione servizi

```bash
# API (FastAPI / Uvicorn)
systemctl status netprobe-api
systemctl restart netprobe-api

# Web (Apache)
systemctl status apache2
systemctl reload apache2

# SmokePing
systemctl status smokeping
systemctl reload smokeping

# Flow monitor
systemctl status netprobe-flow-collector
systemctl status netprobe-flow-exporter@*

# DHCP Sentinel
systemctl status netprobe-dhcpsentinel.timer
systemctl status netprobe-dhcpsentinel.service
```

Log utili:

```bash
less /var/log/testmachine-install.log
journalctl -u apache2 -n 200 --no-pager
journalctl -u netprobe-api -n 200 --no-pager
journalctl -u netprobe-dhcpsentinel\* -n 200 --no-pager
```

---

## 22) **Porte & Path utili**

- **Web UI**: `:8080` (di default)
- **API**: `127.0.0.1:9000`
- **Flow UDP**: `2055/udp`
- **Graylog syslog**: **1514/TCP+UDP → 5514**
- **SmokePing**: `/smokeping/`
- **Cacti**: `/cacti/`
- **Graylog**: `/graylog/`

---

## 23) **Struttura directory**

```
/opt/netprobe/                 # sorgenti applicazione
/var/lib/netprobe/
  pcap/                        # catture
  voip/                        # dati VoIP
    captures/
  flows/                       # symlink ai file nfcapd
  logs/audit.jsonl             # audit log
  dhcpsentinel/                # eventi/stato DHCP Sentinel
/etc/netprobe/
  users.json
  pcap.json
  alerts.json
  dhcpsentinel.json
```

---

## 24) Sicurezza

- Cattura con **dumpcap** + capabilities (no root)
- Una sola cattura attiva e nomi file sicuri
- Possibilità di disabilitare i **filtri BPF**
- **Console** accessibile solo con password di **root**
- **Token/Chat ID Telegram**: trattarli come segreti
- **Net Mapper**, **UPnP**, **PCAP**: usare solo su reti/sistemi autorizzati

---

## 25) Troubleshooting

**503 su /** (Apache) → API giù:

```bash
systemctl status netprobe-api --no-pager -n 50
journalctl -u netprobe-api -n 200 --no-pager
```

**PCAP non parte**

```bash
getcap /usr/bin/dumpcap                # cap_net_admin,cap_net_raw+eip
ls -ld /var/lib/netprobe/pcap          # netprobe:netprobe 2770
```

**Flow vuoti**

```bash
ss -lunp | grep 2055
ls -1 /var/lib/netprobe/flows | tail -n 5
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```

**Alerts non arrivano**

- Verifica `token`/`chat_id`, `throttle_min`, `silence_until`
- Controlla `/var/lib/netprobe/tmp/alertd.debug`
- Timer servizio alert attivo

**DHCP Sentinel senza eventi**

- Controlla `iface`, `allow[]`, `listen_sec`
- Verifica capabilities (RAW/ADMIN) e timer
- Leggi `events.jsonl` e `last.json`

**Graylog /graylog/ 502**

- Proxy Apache attivo, backend raggiungibile
- Mappatura **1514 → 5514** corretta per syslog
- Reload Apache

---

## 26) Disinstallazione

```bash
# stop servizi
systemctl disable --now netprobe-api
a2dissite testmachine.conf
systemctl reload apache2

# rimuovi app/unit (mantieni dati se vuoi)
rm -rf /opt/netprobe
rm -f /etc/systemd/system/netprobe-api.service
systemctl daemon-reload

# opzionale: rimuovi dati/config
rm -rf /var/lib/netprobe
rm -rf /etc/netprobe

# opzionale: rimuovi capability
setcap -r /usr/bin/dumpcap || true
```

---

## 27) Sviluppo

```bash
git clone https://github.com/fraidotube/testmachine.git
cd testmachine
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 9000
# in prod sta dietro Apache; in dev puoi andare diretto su :9000
```

## Licenza

MIT.
