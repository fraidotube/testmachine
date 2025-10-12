TestMachine
===========

Small network-diagnostics appliance for Debian.Includes:

*   **Web UI** (FastAPI + Apache reverse proxy)
    
*   **SmokePing** latency charts
    
*   **Packet Capture (PCAP)**: start/stop captures, download, quick analysis (protocol hierarchy, endpoints, conversations, DNS/HTTP/SNI, top ports)
    
*   Safe, non-root packet capture via dumpcap capabilities
    
*   Simple **settings** for capture limits (quota, max duration, policy)
    

> Default web UI: http://:8080/Default admin credentials: admin / admin (change after first login).

1) Requirements
---------------

*   Debian **12.6** (fresh install recommended)
    
*   Internet access for APT
    
*   Root access (or sudo) to run the installer
    

The installer will set up:

*   Packages: apache2, fastapi/uvicorn (via venv), smokeping, tshark, dumpcap, tcpdump, …
    
*   Systemd unit: netprobe-api
    
*   Apache vhost on port **8080** (configurable via env WEB\_PORT)
    
*   Directories & permissions:
    
    *   /opt/netprobe (app)
        
    *   /var/lib/netprobe (state)
        
    *   /var/lib/netprobe/pcap (captures)
        
    *   /etc/netprobe/users.json and /etc/netprobe/pcap.json (config)
        

2) Set a static IP on Debian 12.6 (vanilla)
-------------------------------------------

You can use **nmtui** (easy) or **nmcli** (scriptable).

### Option A – nmtui (TUI)

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   sudo apt-get update && sudo apt-get install -y network-manager  sudo nmtui   `

In the TUI:

1.  “Edit a connection” → select your interface (e.g., ens18).
    
2.  IPv4 configuration: **Manual**Address: 192.168.1.50/24Gateway: 192.168.1.1DNS: 1.1.1.1,8.8.8.8
    
3.  Save and **Activate connection** (or reboot).
    

### Option B – nmcli

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   IFACE=ens18  IP=192.168.1.50/24  GW=192.168.1.1  DNS1=1.1.1.1  DNS2=8.8.8.8  sudo apt-get update && sudo apt-get install -y network-manager  sudo nmcli con mod "$IFACE" ipv4.method manual ipv4.addresses "$IP" ipv4.gateway "$GW" ipv4.dns "$DNS1,$DNS2" ipv6.method ignore  sudo nmcli con up "$IFACE"   `

Verify:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   ip -4 a show dev "$IFACE"  ip r  resolvectl status   `

3) Install TestMachine
----------------------

Run as **root** (or with sudo):

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Choose a web port (optional, default 8080)  export WEB_PORT=8080  # Fetch and run the installer  curl -fsSL https://raw.githubusercontent.com//testmachine/main/install/install-testmachine.sh \    | bash   `

What the installer does:

*   Installs system packages
    
*   Creates netprobe user/group
    
*   Clones/updates this repo under /opt/netprobe
    
*   Creates Python venv and installs dependencies
    
*   Sets capabilities on /usr/bin/dumpcap (cap\_net\_raw,cap\_net\_admin+eip)
    
*   Seeds config:
    
    *   /etc/netprobe/users.json with admin/admin
        
    *   { "duration\_max": 3600, "quota\_gb": 5, "policy": "rotate", "poll\_ms": 1000, "allow\_bpf": true}
        
*   Enables & starts:
    
    *   netprobe-api (Uvicorn on 127.0.0.1:9000)
        
    *   Apache vhost reverse-proxy on :${WEB\_PORT}
        
    *   SmokePing
        

Quick checks:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   systemctl status netprobe-api --no-pager -n 20  systemctl status apache2 --no-pager -n 20  systemctl status smokeping --no-pager -n 20   `

Open the UI: http://:8080/ (or chosen port)

4) First login
--------------

*   Username: **admin**
    
*   Password: **admin**
    

> Change the password immediately from the UI.

5) Packet Capture (PCAP)
------------------------

### Start a capture

1.  Go to **Packet Capture** from the sidebar/home.
    
2.  Choose **Interface**, **Duration**, **Snaplen**, optional **BPF filter**.
    
3.  Click **Avvia**.
    
4.  While running, you’ll see a **countdown**, file name and size, and a **Stop** button.
    

### Snaplen

*   Maximum bytes saved **per packet**.
    
*   262144 ≈ full frame (no truncation).
    
*   Lower values reduce disk usage but may truncate payloads.
    

### BPF filter quick guide

Examples:

*   Host: host 8.8.8.8 — src host 192.168.1.10 — dst host 1.1.1.1
    
*   Network: net 192.168.1.0/24
    
*   Port: port 53, tcp port 443, portrange 1000-2000
    
*   Protocol: icmp, arp, tcp, udp, vlan
    
*   Combine: tcp and port 80 and host 1.2.3.4
    
*   HTTP/DNS/TLS: port 80 or port 443, port 53
    
*   Exclude yourself: and not host 192.168.1.5
    

> You can disable custom BPF filters in **Impostazioni Sniffer** if needed.

### Download & Analyze

*   **Catture recenti** → _Scarica_ (gets .pcapng)
    
*   **Analizza**: in-browser quick analysis shows:
    
    *   Overview (packets / bytes / duration)
        
    *   Protocol hierarchy
        
    *   Top endpoints
        
    *   Top conversations
        
    *   Top DNS queries, HTTP Host headers, TLS SNI
        
    *   Top ports (TCP/UDP)
        

6) Sniffer Settings
-------------------

**/pcap/settings** page controls:

*   **Durata massima** per cattura
    
*   **Quota storage** (GB) on /var/lib/netprobe/pcap
    
*   **Policy** when quota is full:
    
    *   rotate → delete oldest captures to make space
        
    *   block → reject new captures
        
*   **Refresh UI** (ms)
    
*   **Consenti filtri BPF** (on/off)
    

Values are saved to /etc/netprobe/pcap.json.

7) Service management
---------------------

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # API (FastAPI / Uvicorn)  sudo systemctl status netprobe-api  sudo systemctl restart netprobe-api  # Web server (Apache)  sudo systemctl status apache2  sudo systemctl reload apache2  # SmokePing  sudo systemctl status smokeping  sudo systemctl reload smokeping   `

Logs:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Installer log  sudo less /var/log/testmachine-install.log  # Apache  sudo journalctl -u apache2 -n 200 --no-pager  # API  sudo journalctl -u netprobe-api -n 200 --no-pager   `

8) Security notes
-----------------

*   Packet capture runs via **dumpcap** with Linux **capabilities** (no root).
    
*   Only **listed interfaces** are allowed.
    
*   File names are generated server-side; traversal is blocked.
    
*   One active capture at a time (soft rate-limit).
    
*   Optional **BPF filter** sanitization via UI setting.
    
*   Protect access to the web UI (change default password, consider limiting access at the Apache layer if needed).
    

9) Troubleshooting
------------------

**503 Service Unavailable (Apache)**API may be down or slow to start:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   systemctl status netprobe-api --no-pager -n 50  journalctl -u netprobe-api -n 200 --no-pager   `

**PCAP start fails**

*   getcap /usr/bin/dumpcap# expected: cap\_net\_admin,cap\_net\_raw+eip
    
*   ls -ld /var/lib/netprobe/pcap# netprobe:netprobe 2770
    
*   Quota reached & policy=block → free space or switch to rotate.
    

**No interfaces listed**

*   NetworkManager not controlling the interface? Still shown via dumpcap -D. If empty, verify drivers and ip link.
    

**Analyze page empty**

*   tshark -vcapinfos -h
    

10) Uninstall
-------------

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   # Stop services  sudo systemctl disable --now netprobe-api  sudo a2dissite testmachine.conf  sudo systemctl reload apache2  # Remove app & units (keep data/config if you want)  sudo rm -rf /opt/netprobe  sudo rm -f /etc/systemd/system/netprobe-api.service  sudo systemctl daemon-reload  # Optional: remove data/config (careful!)  sudo rm -rf /var/lib/netprobe  sudo rm -rf /etc/netprobe  # Optionally revert capabilities  sudo setcap -r /usr/bin/dumpcap || true   `

11) Development
---------------

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   git clone https://github.com//testmachine.git  cd testmachine  python3 -m venv venv && ./venv/bin/pip install -r requirements.txt  cd app && ../venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 9000  # Fronted by Apache in production; for dev, visit http://:9000/   `

License
-------

MIT (or your chosen license).
