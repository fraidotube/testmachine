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
- **Rete (WAN/LAN & Bridge)**: configurazione interfacce via NetworkManager (**nmcli**), VLAN opzionale, **porta di sniffing** dedicata  
- **Impostazioni di sistema**: cambio **porta Apache**, **timezone**, **NTP** (timesyncd), **Impostazioni avanzate**: **riavvio macchina** e **cambio hostname**  
- **Logs (/logs)**: **audit log** consultabile dalla UI con **export CSV/JSONL**

> UI predefinita: `http://<IP_SERVER>:8080/`  
> Credenziali iniziali: **admin / admin** (cambiale subito).


## 1) Requisiti

- Debian **12.6** “pulita”  
- Accesso root (o sudo)  
- Rete IPv4 raggiungibile

L’installer prepara:

- Pacchetti: `apache2`, venv Python con FastAPI/Uvicorn, `smokeping`, `tshark`, `dumpcap`, `tcpdump`, **`nmap`**, **`arp-scan`**, **`ieee-data`** (OUI), **Speedtest CLI (Ookla)** se disponibile, **`sngrep`**  
- Systemd unit `netprobe-api`  
- VHost Apache su **8080** (modificabile con `WEB_PORT`)  
- Directory e permessi:
  - `/opt/netprobe` (app)
  - `/var/lib/netprobe` (stato)
  - `/var/lib/netprobe/pcap` (catture)
  - `/var/lib/netprobe/voip` e `/var/lib/netprobe/voip/captures` (VoIP)
  - `/var/lib/netprobe/logs` (audit log)
  - `/etc/netprobe/users.json`, `/etc/netprobe/pcap.json` (config)
- **Capability/sudoers** per strumenti di cattura/scansione (es. `dumpcap`, `arp-scan`, `nmap`) dove necessario


## 2) Configurare a mano l’IP (senza pacchetti aggiuntivi)

Sostituisci i valori con quelli reali (senza le `<>`). Esempio per interfaccia `ens4`, IP `192.168.1.50/24` e gateway `192.168.1.1`:

```
IFACE=ens4
IP=192.168.1.50/24
GW=192.168.1.1
```

Imposta indirizzo, porta l’interfaccia su *up* e aggiungi la route di default:

```
ip addr add "$IP" dev "$IFACE"
ip link set "$IFACE" up
ip route add default via "$GW"
```

DNS di base (scrive un file `/etc/resolv.conf` semplice):

```
printf "nameserver 1.1.1.1
nameserver 8.8.8.8
" > /etc/resolv.conf
```

**Nota**: se `/etc/resolv.conf` è un *symlink* (p.es. a systemd-resolved), puoi forzare un file reale così:

```
rm -f /etc/resolv.conf
printf "nameserver 1.1.1.1
nameserver 8.8.8.8
" > /etc/resolv.conf
```

Verifica con:

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

Cosa fa lo script:

- Installa pacchetti (vedi elenco in **Requisiti**)  
- Crea utente/gruppo `netprobe`  
- Clona/aggiorna il repo in `/opt/netprobe`  
- Crea venv Python + dipendenze  
- Imposta capability su `/usr/bin/dumpcap` (`cap_net_raw,cap_net_admin+eip`)  
- **Seed** config:
  - `/etc/netprobe/users.json` → `admin/admin`
  - `/etc/netprobe/pcap.json`:
    ```
    {
      "duration_max": 3600,
      "quota_gb": 5,
      "policy": "rotate",
      "poll_ms": 1000,
      "allow_bpf": true
    }
    ```
- Prepara percorsi **VoIP**:
  - `mkdir -p /var/lib/netprobe/voip/captures`
  - crea/gestisce `captures.json` e `index.json` al primo avvio
- Abilita/avvia servizi:
  - `netprobe-api` (Uvicorn su 127.0.0.1:9000)
  - Apache vhost su `:${WEB_PORT}`
  - SmokePing

Check rapidi:

```
systemctl status netprobe-api --no-pager -n 20
systemctl status apache2 --no-pager -n 20
systemctl status smokeping --no-pager -n 20
```

Apri la UI: `http://<IP_SERVER>:8080/` (o la porta scelta).


## 4) Primo accesso

- Utente: **admin**  
- Password: **admin**

> Cambia subito la password dal menu utenti.


## 5) Packet Capture (PCAP)

### Avvio

1. Vai su **Packet Capture**.  
2. Seleziona **Interfaccia**, **Durata**, **Snaplen**, (opz.) **Filtro BPF**.  
3. **Avvia**. Durante la cattura vedi **countdown**, **file/size** e il bottone **Stop**.

### Snaplen

- Byte massimi **per pacchetto**.  
- `262144` ≈ pacchetto completo.  
- Ridurre il valore limita lo spazio ma può troncare i payload.

### Filtri BPF — esempi

- Host: `host 8.8.8.8` — `src host 192.168.1.10` — `dst host 1.1.1.1`  
- Rete: `net 192.168.1.0/24`  
- Porta: `port 53`, `tcp port 443`, `portrange 1000-2000`  
- Protocollo: `icmp`, `arp`, `tcp`, `udp`, `vlan`  
- Combinazioni: `tcp and port 80 and host 1.2.3.4`  
- HTTP/DNS/TLS: `port 80 or port 443`, `port 53`  
- Escludere se stesso: `and not host 192.168.1.5`

> Puoi **disabilitare** i filtri BPF personalizzati in **Impostazioni Sniffer**.

### Download & Analisi

- **Catture recenti** → _Scarica_ (`.pcapng`)  
- **Analizza**: mostra  
  - Overview (packets/bytes/duration)  
  - Protocol hierarchy  
  - Top endpoints  
  - Top conversations  
  - Top DNS queries, HTTP Host, TLS SNI  
  - Top porte (TCP/UDP)


## 6) Diagnostica VoIP (SIP/RTP)

Strumenti per ispezionare registrazioni e chiamate **SIP** a partire da PCAP, con **SIP ladder** e prime metriche **RTP**.

### Funzioni principali

- **Indice chiamate SIP** (Call-ID, A/B number, IP/porta, durata)  
- **Dettaglio chiamata** con **SIP ladder** (REGISTER/INVITE/100/180/200/ACK/BYE, SDP)  
- **Reindicizza** PCAP esistenti sotto `/var/lib/netprobe/voip/captures`  
- **Download PCAP** per singola chiamata/flusso  
- **RTP (beta)**: rilevamento stream e conteggi di base; metriche avanzate (jitter/MOS) in evoluzione

### Percorsi & file

- Directory:  
  - `/var/lib/netprobe/voip`  
  - `/var/lib/netprobe/voip/captures`  
- Metadati:  
  - `captures.json` → elenco catture `{file, iface, start_ts, duration_s, pid, filter}`  
  - `index.json` → indice chiamate/stream

### Come usare (rapido)

1. Cattura traffico **SIP/RTP** (es. filtro BPF: `udp port 5060` oppure nessun filtro).  
2. Vai in **VoIP** → **Reindicizza** per costruire/aggiornare l’indice.  
3. Apri **Chiamate** → scegli una chiamata → **SIP ladder**.  
4. (Se disponibile) apri **RTP** per gli stream associati.

> **Suggerimenti**
> - Per analisi RTP, preferisci flussi **non SRTP** o fornire chiavi/PCAP in chiaro.  
> - Per traffico su porte dinamiche, amplia il filtro (es. `udp portrange 10000-20000`).  
> - `sngrep` è installato sul sistema per analisi da shell.

### Troubleshooting VoIP

```
# Verifica tshark
tshark -Y sip -r /percorso/file.pcapng -T fields -e sip.Call-ID | head

# Verifica sngrep
sngrep -V
```


## 7) Net Mapper (Scansione rete)

Mappa la LAN: **host**, **MAC/Vendor**, **servizi** e **OS guess**, con grafici e esportazioni.

### Cosa fa

- **ARP scan** per individuare host attivi sull’interfaccia selezionata  
- **Nmap** per porte/servizi comuni e tentativo di **OS guess**  
- **Vendor OUI** tramite database `ieee-data`  
- **Reverse DNS** dove possibile  
- **Dashboard** con conteggi, top servizi/porte, distribuzione vendor  
- **Esporta** risultati in **JSON/CSV**

### Uso

1. Vai su **Net Mapper**.  
2. Seleziona **Interfaccia** (o rete/CIDR, se previsto) e **Avvia**.  
3. Segui la **barra di progresso**; al termine consulta **Risultati** e **Grafici**.  
4. Usa **Esporta** per salvare in JSON/CSV.

> I dati vengono salvati nello storage locale dell’app (sotto `/var/lib/netprobe`) e restano disponibili nella UI.
>
> **Nota legale**: esegui scansioni **solo** su reti/sistemi di tua proprietà o con autorizzazione.


## 8) Speedtest

Esegue test di **download/upload** e misura **latency/jitter/loss** con storico locale.

### Uso

- Apri **Speedtest** dalla UI e premi **Avvia**.  
- Al termine, il risultato viene salvato e appare nello **storico**.  
- Backend: **Speedtest CLI (Ookla)** con fallback integrato se l’eseguibile non è disponibile.

### Consigli

- Evita test in parallelo con catture/scan pesanti per non falsare i risultati.  
- Ripeti più volte e considera la media.


## 9) Rete: WAN/LAN & Bridge (sniffer)

Gestione interfacce via **NetworkManager** (`nmcli`):

- **WAN**: selezione interfaccia, **DHCP** o **statico** (IP/gateway/DNS)  
- **LAN**: configurazione IP locale, **VLAN ID** opzionale  
- **Bridge di sniffing** (terza NIC): porta dedicata al mirroring/capture; **nessun default route/DNS**

> Le modifiche applicano profili `wan0` / `lan0`. Usare con cautela su sistemi in produzione.


## 10) Impostazioni di sistema (Porta, Timezone, NTP, Avanzate)

Pagina **Impostazioni**:

- **Porta Apache** della Web UI (default **8080**) con **redirect** automatico post-cambio  
- **Timezone** di sistema  
- **NTP** via `systemd-timesyncd` (server, stato, sync)
- **Impostazioni avanzate**:
  - **Riavvia macchina** (azione con conferma)
  - **Cambia hostname** (richiede privilegi admin; la propagazione può richiedere riavvio)

> Le azioni sono applicate tramite **sudoers** limitato e controlli di sicurezza.


## 11) Flow Monitor (NetFlow v9)

Monitor in tempo quasi reale dei **flow** di rete con grafici aggiornati periodicamente.

### Pipeline effettiva

- **Esportatore**: `softflowd` (es. su `ens4`) → **UDP 127.0.0.1:2055** (**NetFlow v9**)  
- **Collector**: `nfcapd` scrive i file ruotando ~**60s** in  
  `/var/lib/nfsen-ng/profiles-data/live/netprobe`  
- **Symlink** comodo:  
  `/var/lib/netprobe/flows` → `/var/lib/nfsen-ng/profiles-data/live/netprobe`

**Nota**: dopo l’avvio, i grafici possono restare vuoti finché non arriva la **prima rotazione** (~60s).

### Verifiche rapide

```
# Collector in ascolto su UDP/2055
ss -lunp | grep 2055

# Flows presenti nell'ultimo file ruotato
ls -1 /var/lib/netprobe/flows | tail -n 3
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```


## 12) Logs (/logs)

Pagina per consultare i **log di audit** dell’applicazione.

- File principale: `/var/lib/netprobe/logs/audit.jsonl`  
- **Filtro/ricerca** dalla UI e **export** in **CSV** o **JSONL**  
- La card dei log è visibile nella riga inferiore della pagina con **larghezza piena**

> I log includono azioni e eventi salienti della Web UI, utili per audit e diagnostica.


## 13) SmokePing (latenza)

### Accesso ai grafici

- URL: `http://<IP_SERVER>:8080/smokeping/`  
- I grafici sono serviti dal modulo **CGI** di Apache già configurato dall’installer.

### Aggiungere target (metodo consigliato)

- Dalla Web UI, se presente la card **SmokePing Admin**: `http://<IP_SERVER>:8080/sp-admin`  
  - Aggiungi/edita gli host, poi **Salva** → il servizio verrà ricaricato automaticamente.

> Se la pagina `/sp-admin` non è disponibile, usa la modifica manuale (vedi sotto).

### Aggiungere target (metodo manuale)

File principali (Debian):

- `/etc/smokeping/config.d/Probes` – definizione dei probe (usa **FPing** di default)  
- `/etc/smokeping/config.d/Targets` – elenco host/gerarchie  
- `/etc/smokeping/config.d/Alerts` – regole di alert (opzionale)

Esempio minimo in **Targets** (FPing):

```
+ TestMachine
menu = TestMachine
title = TestMachine targets

++ gateway
menu = Gateway
title = Router di casa
host = 192.168.1.1
```

Salva, poi verifica e ricarica:

```
smokeping --check 2>/dev/null || /usr/sbin/smokeping --check
systemctl reload smokeping
```

### Dove finiscono i dati

- RRD in: `/var/lib/smokeping`  
- Per azzerare i dati di un target, rimuovi le RRD relative (poi reload).

### Permessi & sicurezza

- L’installer imposta permessi/ownership perché **www-data** e **smokeping** possano leggere/scrivere:  
  - `/etc/smokeping/config.d` (gruppo `netprobe`)  
  - `/var/lib/smokeping` (smokeping:netprobe, mode 2770)
- Reload servizio gestito dalla webapp tramite **sudoers** limitato.

### Troubleshooting SmokePing

```
# Stato e log
systemctl status smokeping --no-pager -n 100
journalctl -u smokeping -n 200 --no-pager

# Convalida configurazione
smokeping --check 2>/dev/null || /usr/sbin/smokeping --check

# Apache (CGI)
a2enconf smokeping
systemctl reload apache2
journalctl -u apache2 -n 200 --no-pager
```


## 14) Impostazioni Sniffer

Pagina **/pcap/settings**:

- **Durata massima** per cattura  
- **Quota storage** (GB) su `/var/lib/netprobe/pcap`  
- **Policy** a quota piena:
  - `rotate` → elimina le catture più vecchie
  - `block` → blocca nuove catture
- **Refresh UI** (ms)  
- **Consenti filtri BPF** (on/off)

I valori sono in `/etc/netprobe/pcap.json`.


## 15) Gestione servizi

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
```

Log utili:

```
# Log installer
less /var/log/testmachine-install.log

# Apache
journalctl -u apache2 -n 200 --no-pager

# API
journalctl -u netprobe-api -n 200 --no-pager
```


## 16) Sicurezza

- Cattura con **dumpcap** + **capabilities** (no root).  
- Solo **interfacce enumerate** sono valide.  
- Nomi file generati server-side (niente traversal).  
- **Una** cattura attiva alla volta (rate-limit soft).  
- Possibile disabilitare i **filtri BPF** custom.  
- Limita l’accesso alla UI (password robuste; opzionalmente **Access Control** su Apache).  
- **Net Mapper**: esegui scansioni solo su reti autorizzate.  
- **VoIP**: i PCAP possono contenere dati sensibili (numerazioni, SIP URI, SDP); trattali in conformità alle policy.  
- **Flow Monitor**: i dati di flusso includono metadati (IP, porte, tempi); gestiscili in modo conforme alle policy.


## 17) Troubleshooting generale

**503 Service Unavailable (Apache)** – API giù o non avviata:

```
systemctl status netprobe-api --no-pager -n 50
journalctl -u netprobe-api -n 200 --no-pager
```

**Avvio PCAP fallisce**

```
# capability su dumpcap
getcap /usr/bin/dumpcap   # atteso: cap_net_admin,cap_net_raw+eip

# permessi directory
ls -ld /var/lib/netprobe/pcap   # netprobe:netprobe 2770

# quota piena e policy=block → libera spazio o passa a rotate
```

**Nessuna interfaccia in lista** – `dumpcap -D` dovrebbe elencarle; se vuoto, verifica driver e `ip link`.

**Analisi vuota** – Verifica `tshark` / `capinfos`:

```
tshark -v
capinfos -h
```

**Speedtest non parte** – Verifica presenza `speedtest` CLI o usa il fallback integrato.

**Net Mapper** – Se `arp-scan` o `nmap` falliscono, verifica capability/sudoers e connettività L2.

**Flow Monitor** – Nessun dato nei grafici?

```
# Collector attivo?
ss -lunp | grep 2055

# Ultimi file ruotati presenti?
ls -1 /var/lib/netprobe/flows | tail -n 5

# Dati dentro l'ultimo file
nfdump -r "/var/lib/netprobe/flows/$(ls -1 /var/lib/netprobe/flows | tail -n 1)" -o long -c 10
```


## 18) Disinstallazione

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


## 19) Sviluppo

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
