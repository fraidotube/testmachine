TestMachine
===========

Appliance di diagnostica di rete per Debian:

-   **Web UI** (FastAPI dietro Apache)

-   **SmokePing** per latenza

-   **Packet Capture (PCAP)**: avvio/stop, download, analisi rapida (protocol hierarchy, endpoints, conversations, DNS/HTTP/SNI, top porte)

-   Cattura **non-root** tramite capability su `dumpcap`

-   Pagine **Impostazioni Sniffer** (quota, durata massima, policy)

> UI predefinita: `http://<IP_SERVER>:8080/`\
> Credenziali iniziali: **admin / admin** (cambiale subito).

* * * * *

1) Requisiti
------------

-   Debian **12.6** "pulita"

-   Accesso root (o sudo)

-   Rete IPv4 raggiungibile

L'installer prepara:

-   Pacchetti: `apache2`, venv Python con FastAPI/Uvicorn, `smokeping`, `tshark`, `dumpcap`, `tcpdump`, ...

-   Systemd unit `netprobe-api`

-   VHost Apache su **8080** (modificabile con `WEB_PORT`)

-   Directory e permessi:

    -   `/opt/netprobe` (app)

    -   `/var/lib/netprobe` (stato)

    -   `/var/lib/netprobe/pcap` (catture)

    -   `/etc/netprobe/users.json` e `/etc/netprobe/pcap.json` (config)

* * * * *

2) Configurare **a mano** l'IP (funziona anche senza rete/pacchetti)
--------------------------------------------------------------------

Sostituisci i valori tra `<>`:

`IFACE=<es. ens18>
IP=192.168.1.50/24
GW=192.168.1.1

# IP e link up
ip addr add "$IP" dev "$IFACE"
ip link set "$IFACE" up

# Default route
ip route add default via "$GW"

# DNS (scrive un resolv.conf semplice)
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf`

> **Nota**: se `/etc/resolv.conf` è un *symlink* (es. a systemd-resolved), puoi forzare un file reale così:
>
> `rm -f /etc/resolv.conf
> printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf`
>
> Verifica:
>
> `ping -c1 1.1.1.1
> ping -c1 google.com`

* * * * *

3) Installazione
----------------

Esegui come **root**:

`# (opzionale) porta web diversa da 8080
export WEB_PORT=8080

# scarica ed esegui l'installer
curl -fsSL https://raw.githubusercontent.com/<TUO_USER_O_ORG>/testmachine/main/install/install-testmachine.sh | bash`

Cosa fa lo script:

-   Installa pacchetti

-   Crea utente/gruppo `netprobe`

-   Clona/aggiorna il repo in `/opt/netprobe`

-   Crea venv Python + dipendenze

-   Imposta capability su `/usr/bin/dumpcap` (`cap_net_raw,cap_net_admin+eip`)

-   **Seed** config:

    -   `/etc/netprobe/users.json` → `admin/admin`

    -   `/etc/netprobe/pcap.json`:

        `{
          "duration_max": 3600,
          "quota_gb": 5,
          "policy": "rotate",
          "poll_ms": 1000,
          "allow_bpf": true
        }`

-   Abilita/avvia servizi:

    -   `netprobe-api` (Uvicorn su 127.0.0.1:9000)

    -   Apache vhost su `:${WEB_PORT}`

    -   SmokePing

Check rapidi:

`systemctl status netprobe-api --no-pager -n 20
systemctl status apache2 --no-pager -n 20
systemctl status smokeping --no-pager -n 20`

Apri la UI: `http://<IP_SERVER>:8080/` (o la porta scelta)

* * * * *

4) Primo accesso
----------------

-   Utente: **admin**

-   Password: **admin**

> Cambia la password dal menu utente.

* * * * *

5) Packet Capture (PCAP)
------------------------

### Avvio

1.  Vai su **Packet Capture**.

2.  Seleziona **Interfaccia**, **Durata**, **Snaplen**, (opz.) **Filtro BPF**.

3.  **Avvia**.\
    Durante la cattura vedi **countdown**, **file/size** e un bottone **Stop**.

### Snaplen

-   Byte massimi **per pacchetto**.

-   `262144` ≈ pacchetto completo.

-   Ridurre il valore limita lo spazio ma può troncare i payload.

### Filtri BPF --- esempi

-   Host: `host 8.8.8.8` --- `src host 192.168.1.10` --- `dst host 1.1.1.1`

-   Rete: `net 192.168.1.0/24`

-   Porta: `port 53`, `tcp port 443`, `portrange 1000-2000`

-   Protocollo: `icmp`, `arp`, `tcp`, `udp`, `vlan`

-   Combinazioni: `tcp and port 80 and host 1.2.3.4`

-   HTTP/DNS/TLS: `port 80 or port 443`, `port 53`

-   Escludere se stesso: `and not host 192.168.1.5`

> Puoi **disabilitare** i filtri BPF personalizzati in **Impostazioni Sniffer**.

### Download & Analisi

-   **Catture recenti** → *Scarica* (`.pcapng`)

-   **Analizza**: mostra

    -   Overview (packets/bytes/duration)

    -   Protocol hierarchy

    -   Top endpoints

    -   Top conversations

    -   Top DNS queries, HTTP Host, TLS SNI

    -   Top porte (TCP/UDP)

* * * * *

6) Impostazioni Sniffer
-----------------------

Pagina **/pcap/settings**:

-   **Durata massima** per cattura

-   **Quota storage** (GB) su `/var/lib/netprobe/pcap`

-   **Policy** a quota piena:

    -   `rotate` → elimina le catture più vecchie

    -   `block` → blocca nuove catture

-   **Refresh UI** (ms)

-   **Consenti filtri BPF** (on/off)

I valori sono in `/etc/netprobe/pcap.json`.

* * * * *

7) Gestione servizi
-------------------

`# API (FastAPI / Uvicorn)
systemctl status netprobe-api
systemctl restart netprobe-api

# Web (Apache)
systemctl status apache2
systemctl reload apache2

# SmokePing
systemctl status smokeping
systemctl reload smokeping`

Log utili:

`# Log installer
less /var/log/testmachine-install.log

# Apache
journalctl -u apache2 -n 200 --no-pager

# API
journalctl -u netprobe-api -n 200 --no-pager`

* * * * *

8) Sicurezza
------------

-   Cattura con **dumpcap** + **capabilities** (no root).

-   Solo **interfacce enumerate** sono valide.

-   Nomi file generati server-side (niente traversal).

-   **Una** cattura attiva alla volta (rate-limit soft).

-   Possibile disabilitare i **filtri BPF** custom.

-   Proteggi l'accesso alla UI (cambia password, eventualmente limita IP su Apache).

* * * * *

9) Troubleshooting
------------------

**503 Service Unavailable (Apache)**\
API giù o non avviata:

`systemctl status netprobe-api --no-pager -n 50
journalctl -u netprobe-api -n 200 --no-pager`

**Avvio PCAP fallisce**

`# capability su dumpcap
getcap /usr/bin/dumpcap
# atteso: cap_net_admin,cap_net_raw+eip

# permessi directory
ls -ld /var/lib/netprobe/pcap   # netprobe:netprobe 2770

# quota piena e policy=block → libera spazio o passa a rotate`

**Nessuna interfaccia in lista**\
`dumpcap -D` dovrebbe elencarle; se vuoto, verifica driver e `ip link`.

**Analisi vuota**\
Verifica `tshark` / `capinfos`:

`tshark -v
capinfos -h`

* * * * *

10) Disinstallazione
--------------------

`# stop servizi
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
setcap -r /usr/bin/dumpcap || true`

* * * * *

11) Sviluppo
------------

`git clone https://github.com/<TUO_USER_O_ORG>/testmachine.git
cd testmachine
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cd app
../venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 9000
# in prod sta dietro Apache; in dev puoi andare diretto su :9000`

* * * * *

Licenza
-------

MIT (o altra licenza a tua scelta).
