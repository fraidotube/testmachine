# TestMachine

Appliance di diagnostica di rete per Debian:

- **Web UI** (FastAPI dietro Apache)
- **SmokePing** per latenza
- **Packet Capture (PCAP)**: avvio/stop, download, analisi rapida (protocol hierarchy, endpoints, conversations, DNS/HTTP/SNI, top porte)
- Cattura **non-root** tramite capability su `dumpcap`
- Pagine **Impostazioni Sniffer** (quota, durata massima, policy)
- **Diagnostica VoIP**: indice chiamate SIP, **SIP ladder**, dettagli registrazioni/chiamate, reindicizzazione PCAP; prime statistiche **RTP** (beta)
- **Net Mapper**: scoperta host e servizi (ARP/Nmap), **Vendor OUI**, reverse DNS, **OS guess**, esportazione JSON/CSV, dashboard
- **Speedtest**: download/upload, latency/jitter/loss con storico locale
- **Flow Monitor (NetFlow v9)**: grafici e contatori basati su **softflowd → nfcapd/nfdump**
- **NAT info**: **UPnP** (lista/aggiungi/rimuovi), **MTU Pathfinder** (stima Path MTU e MSS), **Traceroute** con tabella hop/RTT
- **Rete (WAN/LAN & Bridge)**: configurazione interfacce via NetworkManager (**nmcli**), VLAN opzionale, **porta di sniffing** dedicata
- **Impostazioni di sistema**: cambio **porta Apache**, **timezone**, **NTP** (timesyncd), **riavvio macchina**, **cambio hostname**
- **Console**: shell bash in-browser (login con password di **root**; WebSocket proxato)
- **Cacti**: monitoring SNMP con grafici RRD, integrato su `/cacti/`
- **Graylog**: syslog con UI web su `/graylog/` (input esterni su **1514/TCP+UDP**)
- **Alerts**: notifiche **Telegram** con timing e threshold configurabili
- **Logs (/logs)**: **audit log** consultabile dalla UI con **export CSV/JSONL**

> UI predefinita: `http://<IP_SERVER>:8080/`  
> Credenziali iniziali: **admin / admin** (cambiale subito).

## 1) Requisiti

- Debian **12.x** “pulita”
- Accesso root (o sudo)
- Rete IPv4 raggiungibile

L’installer prepara:

- Pacchetti: `apache2`, venv Python con FastAPI/Uvicorn, `smokeping`, `tshark`, `dumpcap`, `tcpdump`, **`nmap`**, **`arp-scan`**, **`ieee-data`** (OUI), **Speedtest CLI (Ookla)** se disponibile, **`sngrep`**
- **Cacti** con PHP-FPM e cron **poller** attivo; `spine.conf` allineato a `/etc/cacti/debian.php`
- **Flow monitor**: `softflowd`, `nfcapd/nfdump`
- **Graylog stack** via Docker Compose (con tuning `vm.max_map_count`) e reverse proxy Apache su `/graylog/`; input syslog esposto su **1514/TCP+UDP** (host)
- Systemd unit `netprobe-api` (Uvicorn), vhost Apache su **8080** (modificabile con `WEB_PORT`)
- Directory e permessi:
  - `/opt/netprobe` (app)
  - `/var/lib/netprobe` (stato)
  - `/var/lib/netprobe/pcap` (catture)
  - `/var/lib/netprobe/voip` e `/var/lib/netprobe/voip/captures` (VoIP)
  - `/var/lib/netprobe/logs` (audit log)
  - `/var/lib/netprobe/flows` (symlink ai file rotati dei flow)
  - `/etc/netprobe/users.json`, `/etc/netprobe/pcap.json` (config)
- **Capability/sudoers** per strumenti di cattura/scansione (`dumpcap`, `arp-scan`, `nmap`) e per ricarichi servizio controllati

## 2) Configurare a mano l’IP (senza pacchetti aggiuntivi)

Sostituisci i valori con quelli reali:

```
IFACE=ens4
IP=192.168.1.50/24
GW=192.168.1.1
```

Imposta indirizzo e route:

```
ip addr add "$IP" dev "$IFACE"
ip link set "$IFACE" up
ip route add default via "$GW"
```

DNS semplice:

```
printf "nameserver 1.1.1.1
nameserver 8.8.8.8
" > /etc/resolv.conf
```

Verifica:

```
ping -c1 1.1.1.1
ping -c1 google.com
```

## 3) Installazione

Esegui come **root**:

```
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
- **Seed** config (`/etc/netprobe/users.json` con `admin/admin`, `/etc/netprobe/pcap.json`)
- Prepara percorsi **VoIP** (`/var/lib/netprobe/voip/captures`, `captures.json`, `index.json`)
- Abilita/avvia servizi:
  - `netprobe-api` (Uvicorn su 127.0.0.1:9000)
  - Apache vhost su `:${WEB_PORT}`
  - SmokePing
  - **Flow collector** e **softflowd** (esportatore)
  - **Graylog stack** (Docker Compose) + reverse proxy `/graylog/` e input syslog **1514/TCP+UDP**

Check rapidi:

```
systemctl status netprobe-api --no-pager -n 20
systemctl status apache2 --no-pager -n 20
systemctl status smokeping --no-pager -n 20
systemctl status graylog-stack --no-pager -n 20
```

## 4) Primo accesso

- Utente: **admin**
- Password: **admin**  
Cambia subito la password dal menu utenti.

## 5) Packet Capture (PCAP)

### Avvio

1. Vai su **Packet Capture**.
2. Seleziona **Interfaccia**, **Durata**, **Snaplen**, (opz.) **Filtro BPF**.
3. **Avvia** e monitora countdown/file/size. Puoi **Stop**.

### Snaplen

- Byte massimi per pacchetto (`262144` ≈ pacchetto completo).

### Filtri BPF — esempi

- Host: `host 8.8.8.8` — `src host 192.168.1.10` — `dst host 1.1.1.1`
- Rete: `net 192.168.1.0/24`
- Porta: `port 53`, `tcp port 443`, `portrange 1000-2000`
- Protocollo: `icmp`, `arp`, `tcp`, `udp`, `vlan`
- Combinazioni: `tcp and port 80 and host 1.2.3.4`
- Escludere se stesso: `and not host 192.168.1.5`

> Puoi disabilitare i filtri BPF custom in **Impostazioni Sniffer**.

### Download & Analisi

- Scarica `.pcapng` e usa l’**analisi rapida**: overview, protocol hierarchy, endpoints, conversations, DNS/HTTP/SNI, top porte.

## 6) Diagnostica VoIP (SIP/RTP)

- **Indice chiamate SIP** (Call-ID, A/B number, IP/porta, durata)
- **SIP ladder** (REGISTER/INVITE/100/180/200/ACK/BYE, SDP)
- **Reindicizza** PCAP sotto `/var/lib/netprobe/voip/captures`
- **Download PCAP** per singola chiamata/flusso
- **RTP (beta)**: rilevamento stream e conteggi di base

Percorsi:

- `/var/lib/netprobe/voip`, `/var/lib/netprobe/voip/captures`
- `captures.json` (catture), `index.json` (chiamate/stream)

## 7) Net Mapper (Scansione rete)

- **ARP scan** host attivi
- **Nmap** porte/servizi, **OS guess**
- **Vendor OUI** (`ieee-data`) e reverse DNS
- Dashboard + **export JSON/CSV**

## 8) Speedtest

- Misura **download/upload** e **latency/jitter/loss**
- Storico locale dei test
- Backend: **Speedtest CLI (Ookla)** quando disponibile

## 9) NAT info (UPnP, MTU, Traceroute)

- **UPnP**: elenca mapping, **aggiungi/rimuovi** inoltri porta (gateway UPnP rilevato automaticamente)
- **MTU Pathfinder**: stima **Path MTU** e **MSS** consigliato; suggerimenti per interfaccia `wan0`
- **Traceroute**: esegue traceroute verso una destinazione e mostra **hop** e **RTT**

> Usa questa scheda per verificare raggiungibilità, MTU sub-ottimale e port-forward del router/NAT.

## 10) Rete: WAN/LAN & Bridge (sniffer)

- **WAN**: DHCP o Statico (IP/gateway/DNS)
- **LAN**: IP locale, **VLAN ID** opzionale
- **Bridge di sniffing**: terza NIC dedicata al mirroring; senza default route/DNS

I profili creati sono `wan0` / `lan0`.

## 11) Flow Monitor (NetFlow v9)

Pipeline:

- **softflowd** (esportatore) → **127.0.0.1:2055/UDP**
- **nfcapd** (collector) con rotazione ~60s →  
  `/var/lib/nfsen-ng/profiles-data/live/netprobe`
- Symlink comodo: `/var/lib/netprobe/flows`

Verifica:

```
ss -lunp | grep 2055
ls -1 /var/lib/netprobe/flows | tail -n 3
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```

## 12) Console

Shell bash **in-browser** (WebSocket) dietro autenticazione:

- Accesso con **password di root**
- Utile per diagnostica senza SSH
- Percorso WebSocket proxato su `/shell/ws`

> Usa con cautela su ambienti esposti: limitare l’accesso alla UI.

## 13) Cacti

Grafici **SNMP** e trend di rete/sistemi:

- Accesso: `http://<IP_SERVER>:8080/cacti/`
- Poller eseguito via **cron** (5 minuti)
- Lo **spine** legge le credenziali DB da `/etc/cacti/debian.php` (gestito dall’installer)
- Directory RRA e log configurate con permessi corretti per `www-data`

> Aggiungi device SNMP dalla UI Cacti e associa i template desiderati.

## 14) Graylog

Piattaforma **syslog** con UI web integrata:

- Accesso: `http://<IP_SERVER>:8080/graylog/`
- **Input syslog** esposto sul **host**: **1514/TCP** e **1514/UDP**  
  (mappati al backend Graylog)
- Reverse proxy Apache con header `X-Graylog-Server-URL` impostato

Test rapidi:

```
# Backend (porta interna esposta localmente)
curl -I http://127.0.0.1:9001/

# Proxy Apache
curl -I http://<IP_SERVER>:8080/graylog/

# Invio di prova (UDP)
logger -n 127.0.0.1 -P 1514 -d -t testmachine "hello graylog via udp"
```

## 15) Alerts (Telegram)

Notifiche **Telegram**:

- Configura **Bot Token** e **Chat ID** nella pagina **Alerts**
- Imposta **timing** (frequenza) e **threshold** per i controlli supportati
- Ideale per ricevere alert su raggiungibilità/metriche base

> Il modulo usa richieste HTTPS verso le API Telegram; conservare con cura token e chat ID.

## 16) Logs (/logs)

- File: `/var/lib/netprobe/logs/audit.jsonl`
- Filtro/ricerca dalla UI e **export CSV/JSONL**
- Card a **larghezza piena** nella parte bassa della pagina

## 17) Impostazioni di sistema

- **Porta Apache** (redirect automatico dopo il cambio)
- **Timezone** di sistema
- **NTP** (`systemd-timesyncd`)
- **Riavvia macchina**, **Cambia hostname**

## 18) Impostazioni Sniffer

Pagina **/pcap/settings**:

- **Durata massima**
- **Quota storage** (GB)
- **Policy** a quota piena: `rotate` / `block`
- **Refresh UI** (ms)
- **Consenti filtri BPF** (on/off)

Config in `/etc/netprobe/pcap.json`.

## 19) Gestione servizi

```
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

# Graylog stack
systemctl status graylog-stack
systemctl restart graylog-stack
```

Log utili:

```
less /var/log/testmachine-install.log
journalctl -u apache2 -n 200 --no-pager
journalctl -u netprobe-api -n 200 --no-pager
journalctl -u graylog-stack -n 200 --no-pager
```

## 20) Sicurezza

- Cattura con **dumpcap** + capabilities (no root)
- Nomi file sicuri e una sola cattura attiva
- Possibilità di disabilitare i **filtri BPF**
- **Console** accessibile solo con password di **root**
- **Net Mapper** e **UPnP**: usare solo su reti/sistemi autorizzati
- **VoIP/Flow**: dati potenzialmente sensibili (policy interne)

## 21) Troubleshooting generale

**503 Service Unavailable (Apache)** – API giù:

```
systemctl status netprobe-api --no-pager -n 50
journalctl -u netprobe-api -n 200 --no-pager
```

**PCAP non parte**

```
getcap /usr/bin/dumpcap   # cap_net_admin,cap_net_raw+eip
ls -ld /var/lib/netprobe/pcap  # netprobe:netprobe 2770
```

**Flow vuoti**

```
ss -lunp | grep 2055
ls -1 /var/lib/netprobe/flows | tail -n 5
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```

**Graylog 502 su /graylog/**

- Verifica che il **backend** sia su `127.0.0.1:9001`
- Controlla `GRAYLOG_HTTP_EXTERNAL_URI=http://<HOST>:<PORT>/graylog/`
- `systemctl restart graylog-stack && systemctl reload apache2`

## 22) Disinstallazione

```
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

## 23) Sviluppo

```
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
