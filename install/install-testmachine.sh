#!/usr/bin/env bash
set -Eeuo pipefail

LOG=/var/log/testmachine-install.log
exec > >(tee -a "$LOG") 2>&1
exec 2>&1
step(){ echo -e "\n== $* =="; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Lancia come root"; exit 1; }

APP_DIR=/opt/netprobe
APP_USER=netprobe
APP_GROUP=netprobe
API_PORT=9000                      # API (socket activation) 127.0.0.1:9000
WEB_PORT=${WEB_PORT:-8080}         # Apache listener esterno

# =====================================================================
# APT / SISTEMA
# =====================================================================
step "APT: abilito repo standard (main contrib non-free)"
. /etc/os-release
CODENAME="${VERSION_CODENAME:-bookworm}"
SRC=/etc/apt/sources.list
[[ -f "$SRC" ]] || touch "$SRC"
cp -n "$SRC" "${SRC}.bak.$(date +%F_%H%M%S)" || true
need1="deb http://deb.debian.org/debian ${CODENAME} main contrib non-free"
need2="deb http://security.debian.org/debian-security ${CODENAME}-security main contrib non-free"
need3="deb http://deb.debian.org/debian ${CODENAME}-updates main contrib non-free"
grep -qxF "$need1" "$SRC" || echo "$need1" >> "$SRC"
grep -qxF "$need2" "$SRC" || echo "$need2" >> "$SRC"
grep -qxF "$need3" "$SRC" || echo "$need3" >> "$SRC"

step "APT update & pacchetti base"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git ca-certificates curl sudo jq debconf-utils gnupg \
  python3 python3-venv python3-pip \
  apache2 apache2-utils \
  smokeping fping \
  network-manager \
  tshark wireshark-common tcpdump libcap2-bin \
  psmisc nfdump softflowd rrdtool snmp snmpd \
  nmap arp-scan bind9-dnsutils avahi-utils ieee-data \
  cron
# Dipendenze extra per NAT/UPnP + MTU/MSS + traceroute
apt-get install -y --no-install-recommends \
  iproute2 iputils-tracepath mtr-tiny miniupnpc iptables
# === DHCPSENTINEL === scapy lato sistema (fallback a pip nel venv già previsto)
apt-get install -y --no-install-recommends python3-scapy

# opzionale: MIBs
if candidate="$(apt-cache policy snmp-mibs-downloader 2>/dev/null | awk '/Candidate:/ {print $2}')"; then
  [[ -n "$candidate" && "$candidate" != "(none)" ]] && apt-get install -y --no-install-recommends snmp-mibs-downloader || true
fi

# SNMP: abilita caricamento MIB
step "SNMP: commento 'mibs :' in /etc/snmp/snmp.conf"
SNMPCFG=/etc/snmp/snmp.conf
if [[ -f "$SNMPCFG" ]]; then
  cp -n "$SNMPCFG" "${SNMPCFG}.bak.$(date +%F_%H%M%S)" || true
  sed -i 's/^[[:space:]]*mibs[[:space:]]*:.*/# mibs :/g' "$SNMPCFG" || true
fi

# ---------------------------------------------------------------------
# Docker CE (repo ufficiale) + compose wrapper
# ---------------------------------------------------------------------
step "Docker CE + compose (repo ufficiale)"
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi
arch="$(dpkg --print-architecture)"
echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# wrapper: usa 'docker compose' o 'docker-compose' se presente
cat >/usr/local/bin/dcompose <<'EOF'
#!/usr/bin/env bash
set -e
if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@"
elif command -v docker-compose >/dev/null 2>&1; then
  exec docker-compose "$@"
else
  echo "Errore: nè 'docker compose' nè 'docker-compose' sono disponibili." >&2
  exit 127
fi
EOF
chmod +x /usr/local/bin/dcompose

# =====================================================================
# UTENTE/REPO APP
# =====================================================================
step "Creo utente/gruppo ${APP_USER}"
getent group  "${APP_GROUP}" >/dev/null || groupadd -r "${APP_GROUP}"
id -u "${APP_USER}" >/dev/null 2>&1 || useradd -r -g "${APP_GROUP}" -d "${APP_DIR}" -s /usr/sbin/nologin "${APP_USER}"

step "Sorgenti app in ${APP_DIR}"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}"
if [[ ! -d "${APP_DIR}/.git" ]]; then
  sudo -u "${APP_USER}" -H git clone https://github.com/fraidotube/testmachine.git "${APP_DIR}"
else
  pushd "${APP_DIR}" >/dev/null
  sudo -u "${APP_USER}" -H git fetch --all || true
  sudo -u "${APP_USER}" -H git pull --ff-only || true
  popd >/dev/null
fi

step "Python venv + deps"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}/venv"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip
if [[ -f "${APP_DIR}/requirements.txt" ]]; then
  "${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
else
  "${APP_DIR}/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart speedtest-cli websockets wsproto scapy
fi
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"

# =====================================================================
# SYSTEMD (apply incorporato)
# =====================================================================
deploy_systemd() {
  local SCRIPT_DIR="${APP_DIR}/deploy/systemd"
  local SYSTEMD_DIR="/etc/systemd/system"
  local UNIT_API_SVC="netprobe-api.service"
  local UNIT_API_SOCK="netprobe-api.socket"
  local UNIT_COLLECTOR="netprobe-flow-collector.service"
  local UNIT_EXPORTER_TMPL="netprobe-flow-exporter@.service"

  step "Systemd: copio unit file API/Flows"
  install -D -m 0644 "${SCRIPT_DIR}/${UNIT_API_SVC}"       "${SYSTEMD_DIR}/${UNIT_API_SVC}"
  install -D -m 0644 "${SCRIPT_DIR}/${UNIT_API_SOCK}"      "${SYSTEMD_DIR}/${UNIT_API_SOCK}"
  install -D -m 0644 "${SCRIPT_DIR}/${UNIT_COLLECTOR}"     "${SYSTEMD_DIR}/${UNIT_COLLECTOR}"
  install -D -m 0644 "${SCRIPT_DIR}/${UNIT_EXPORTER_TMPL}" "${SYSTEMD_DIR}/${UNIT_EXPORTER_TMPL}"

  copy_dropins() {
    local name="$1"
    local src="${SCRIPT_DIR}/${name}.d"
    local dst="${SYSTEMD_DIR}/${name}.d"
    if [[ -d "$src" ]]; then
      mkdir -p "$dst"
      cp -a "$src/." "$dst/"
    fi
  }
  copy_dropins "netprobe-api.service"
  copy_dropins "netprobe-api.socket"
  copy_dropins "netprobe-flow-collector.service"
  copy_dropins "netprobe-flow-exporter@.service"

  local d="${SYSTEMD_DIR}/netprobe-flow-collector.service.d"
  mkdir -p "$d"
  [[ -s "${d}/10-free-port.conf" ]] || cat >"${d}/10-free-port.conf" <<'EOF'
[Service]
ExecStartPre=-/usr/bin/fuser -k -n udp 2055
EOF
  [[ -s "${d}/override.conf" ]] || cat >"${d}/override.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/nfcapd -w /var/lib/nfsen-ng/profiles-data/live/netprobe -S 1 -p 2055 -t 60 -P /run/netprobe/nfcapd.pid
RuntimeDirectory=netprobe
PIDFile=/run/netprobe/nfcapd.pid
Restart=on-failure
RestartSec=2
EOF

  step "Prep directory/symlink flussi"
  install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe
  install -d -m 2770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/nfsen-ng/profiles-data/live/netprobe
  ln -snf /var/lib/nfsen-ng/profiles-data/live/netprobe /var/lib/netprobe/flows
  chown -h "${APP_USER}:${APP_GROUP}" /var/lib/netprobe/flows || true

  step "Sudoers per flow & hostname"
  cat >/etc/sudoers.d/netprobe <<'EOF'
Defaults:netprobe !requiretty
netprobe ALL=(root) NOPASSWD: \
  /usr/bin/systemctl start netprobe-flow-collector, \
  /usr/bin/systemctl stop netprobe-flow-collector, \
  /usr/bin/systemctl restart netprobe-flow-collector, \
  /usr/bin/systemctl start netprobe-flow-exporter@*, \
  /usr/bin/systemctl stop netprobe-flow-exporter@*, \
  /usr/bin/systemctl restart netprobe-flow-exporter@*, \
  /usr/bin/fuser -k -n udp 2055, \
  /usr/bin/install -d -m 2770 -o netprobe -g netprobe /var/lib/nfsen-ng/profiles-data/live/netprobe, \
  /bin/ln -snf /var/lib/nfsen-ng/profiles-data/live/netprobe /var/lib/netprobe/flows
EOF
  chmod 0440 /etc/sudoers.d/netprobe
  visudo -cf /etc/sudoers.d/netprobe >/dev/null || true

  cat >/etc/sudoers.d/netprobe-hostname <<'EOF'
Defaults:netprobe !requiretty
netprobe ALL=(root) NOPASSWD: /usr/bin/hostnamectl set-hostname *, /usr/bin/hostnamectl status
netprobe ALL=(root) NOPASSWD: /usr/bin/install -m 644 /var/lib/netprobe/tmp/hostname.* /etc/hostname
netprobe ALL=(root) NOPASSWD: /usr/bin/install -m 644 /var/lib/netprobe/tmp/hosts.* /etc/hosts
EOF
  chmod 0440 /etc/sudoers.d/netprobe-hostname
  visudo -cf /etc/sudoers.d/netprobe-hostname >/dev/null || true

  # ------------------ ALERTD: service + timer ------------------
  step "Systemd: alertd (service + timer)"
  cat > /etc/systemd/system/netprobe-alertd.service <<'EOF'
[Unit]
Description=TestMachine Alerts sweep
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=/opt/netprobe/app
Environment=PYTHONPATH=/opt/netprobe/app
User=netprobe
Group=netprobe
ExecStart=/opt/netprobe/venv/bin/python /opt/netprobe/app/jobs/alertd.py
EOF
  cat > /etc/systemd/system/netprobe-alertd.timer <<'EOF'
[Unit]
Description=Run TestMachine Alerts sweep every minute
[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
AccuracySec=1s
Unit=netprobe-alertd.service
[Install]
WantedBy=timers.target
EOF

  # ------------------ SPEEDTESTD: service + timer ------------------
  step "Systemd: speedtestd (service + timer)"
  cat > /etc/systemd/system/netprobe-speedtestd.service <<'EOF'
[Unit]
Description=TestMachine Speedtest sweep
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=/opt/netprobe/app
Environment=PYTHONPATH=/opt/netprobe/app
User=netprobe
Group=netprobe
ExecStart=/opt/netprobe/venv/bin/python /opt/netprobe/app/jobs/speedtestd.py
EOF
  cat > /etc/systemd/system/netprobe-speedtestd.timer <<'EOF'
[Unit]
Description=Run TestMachine Speedtest sweep every minute
[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
AccuracySec=1s
Unit=netprobe-speedtestd.service
[Install]
WantedBy=timers.target
EOF

  # ------------------ === DHCPSENTINEL === ------------------
  step "Systemd: DHCP Sentinel (service + timer)"
  cat > /etc/systemd/system/netprobe-dhcpsentinel.service <<'EOF'
[Unit]
Description=NetProbe DHCP Sentinel (one-shot)
Wants=network-online.target
After=network-online.target
ConditionPathExists=/opt/netprobe/app/workers/dhcpsentinel.py

[Service]
Type=oneshot
User=netprobe
Group=netprobe
WorkingDirectory=/opt/netprobe/app
ExecStart=/usr/bin/python3 /opt/netprobe/app/workers/dhcpsentinel.py
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=no
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=full
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/netprobe-dhcpsentinel.timer <<'EOF'
[Unit]
Description=Run NetProbe DHCP Sentinel periodically
[Timer]
OnBootSec=30s
OnUnitActiveSec=120s
AccuracySec=15s
Unit=netprobe-dhcpsentinel.service
[Install]
WantedBy=timers.target
EOF
  cat > /etc/sudoers.d/netprobe-dhcpsentinel <<'EOF'
Cmnd_Alias NETPROBE_DHCP = /bin/systemctl start netprobe-dhcpsentinel.service
netprobe ALL=(root) NOPASSWD: NETPROBE_DHCP
EOF
  chmod 0440 /etc/sudoers.d/netprobe-dhcpsentinel
  visudo -cf /etc/sudoers.d/netprobe-dhcpsentinel >/dev/null || true
}
deploy_systemd

# =====================================================================
# APACHE (main vhost + moduli)
# =====================================================================
step "Apache: moduli & porta ${WEB_PORT}"
a2enmod proxy proxy_http proxy_wstunnel headers rewrite cgid >/dev/null || true
a2enmod proxy_fcgi setenvif ssl >/dev/null || true
sed -ri 's/^[[:space:]]*Listen[[:space:]]+80[[:space:]]*$/# Listen 80/' /etc/apache2/ports.conf
grep -qE "^[[:space:]]*Listen[[:space:]]+${WEB_PORT}\b" /etc/apache2/ports.conf || echo "Listen ${WEB_PORT}" >> /etc/apache2/ports.conf

step "Site testmachine.conf (API/WS + Graylog + esclusioni /smokeping /cgi-bin /cacti)"
cat >/etc/apache2/sites-available/testmachine.conf <<EOF
<VirtualHost *:${WEB_PORT}>
  ServerName testmachine.local
  ErrorLog  /var/log/apache2/testmachine-error.log
  CustomLog /var/log/apache2/testmachine-access.log combined

  ProxyPreserveHost On
  ProxyRequests Off
  ProxyTimeout 120
  AllowEncodedSlashes NoDecode

  RequestHeader set X-Forwarded-Proto "http"

  ProxyPass /smokeping/ !
  ProxyPass /cgi-bin/   !
  ProxyPass /cacti/     !

  ProxyPass        /api/ws   ws://127.0.0.1:${API_PORT}/api/ws
  ProxyPassReverse /api/ws   ws://127.0.0.1:${API_PORT}/api/ws
  ProxyPass        /shell/ws ws://127.0.0.1:${API_PORT}/shell/ws
  ProxyPassReverse /shell/ws ws://127.0.0.1:${API_PORT}/shell/ws

  RequestHeader set X-Graylog-Server-URL "http://%{HTTP_HOST}s/graylog/"
  <Location "/graylog/">
    ProxyPassReverseCookiePath / /graylog/
  </Location>
  ProxyPass        /graylog/        http://127.0.0.1:9001/
  ProxyPassReverse /graylog/        http://127.0.0.1:9001/
  ProxyPass        /graylog/api/ws  ws://127.0.0.1:9001/api/ws
  ProxyPassReverse /graylog/api/ws  ws://127.0.0.1:9001/api/ws

  ProxyPass        /  http://127.0.0.1:${API_PORT}/
  ProxyPassReverse /  http://127.0.0.1:${API_PORT}/
</VirtualHost>
EOF
a2ensite testmachine.conf >/dev/null || true
a2enconf smokeping >/dev/null || true

# =====================================================================
# EMBEDDED BROWSER (linuxserver/webtop + vhost TLS gestito da UI)
# =====================================================================

# Directory stack + data
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" /opt/netprobe/webtop /opt/netprobe/webtop/data

step "Embedded Browser: servizio Docker linuxserver/webtop su 127.0.0.1:6902"
cat >/etc/systemd/system/netprobe-webtop.service <<'EOF'
[Unit]
Description=NetProbe Embedded Browser (linuxserver/webtop)
After=docker.service network-online.target
Wants=docker.service

[Service]
Type=simple
ExecStartPre=/usr/bin/docker pull lscr.io/linuxserver/webtop:latest
ExecStartPre=/bin/bash -lc 'docker rm -f netprobe-webtop >/dev/null 2>&1 || true'
ExecStartPre=/bin/bash -lc 'docker create --name netprobe-webtop \
  -e PUID=0 -e PGID=0 -e TZ=Europe/Rome \
  -p 127.0.0.1:6902:3000 \
  --restart unless-stopped \
  --shm-size=1g \
  -v /opt/netprobe/webtop/data:/config \
  lscr.io/linuxserver/webtop:latest'
ExecStart=/usr/bin/docker start -a netprobe-webtop
ExecStop=/usr/bin/docker stop netprobe-webtop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now netprobe-webtop.service || true

# --- TLS prerequisiti per vhost HTTPS del Browser ---
step "Apache TLS: ssl-cert + snakeoil + mod_ssl"
apt-get install -y --no-install-recommends ssl-cert openssl
a2enmod ssl >/dev/null || true
if [[ ! -s /etc/ssl/certs/ssl-cert-snakeoil.pem || ! -s /etc/ssl/private/ssl-cert-snakeoil.key ]]; then
  make-ssl-cert generate-default-snakeoil --force-overwrite || true
fi
chgrp ssl-cert /etc/ssl/private/ssl-cert-snakeoil.key 2>/dev/null || true
chmod 0640 /etc/ssl/private/ssl-cert-snakeoil.key 2>/dev/null || true

step "Embedded Browser: template vhost TLS per UI (versione WebSocket corretta)"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" /opt/netprobe/templates
cat >/opt/netprobe/templates/browser-vhost-ssl.conf.tmpl <<'EOF'
Listen {{PORT}}
<VirtualHost *:{{PORT}}>
  ServerName {{SERVERNAME}}

  SSLEngine on
  SSLCertificateFile {{CERT_FILE}}
  SSLCertificateKeyFile {{CERT_KEY}}

  ProxyPreserveHost On
  RequestHeader set X-Forwarded-Proto "https"
  RequestHeader set X-Forwarded-Port "{{PORT}}"

  <Location "/browser/">
    AuthType Basic
    AuthName "{{REALM}}"
    AuthUserFile /etc/apache2/.htpasswd-browser
    <RequireAny>
      Require expr "! -f '/etc/apache2/.htpasswd-browser'"
      Require valid-user
    </RequireAny>
  </Location>

  ProxyPass        "/browser/" "ws://127.0.0.1:6902/"
  ProxyPassReverse "/browser/" "ws://127.0.0.1:6902/"
  ProxyPass        "/browser/" "http://127.0.0.1:6902/"
  ProxyPassReverse "/browser/" "http://127.0.0.1:6902/"

  ErrorLog  ${APACHE_LOG_DIR}/browser_{{PORT}}_error.log
  CustomLog ${APACHE_LOG_DIR}/browser_{{PORT}}_access.log combined
</VirtualHost>
EOF
chown ${APP_USER}:${APP_GROUP} /opt/netprobe/templates/browser-vhost-ssl.conf.tmpl
chmod 0644 /opt/netprobe/templates/browser-vhost-ssl.conf.tmpl

# Seed vhost di default (8446) – può essere sovrascritto dalla UI
SELF_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
SELF_IP="${SELF_IP:-127.0.0.1}"
if [[ ! -e /etc/apache2/sites-available/browser-ssl-8446.conf ]]; then
  sed -e "s/{{PORT}}/8446/g" \
      -e "s/{{SERVERNAME}}/${SELF_IP}/g" \
      -e "s#{{CERT_FILE}}#/etc/ssl/certs/ssl-cert-snakeoil.pem#g" \
      -e "s#{{CERT_KEY}}#/etc/ssl/private/ssl-cert-snakeoil.key#g" \
      -e "s/{{REALM}}/TestMachine Browser/g" \
      /opt/netprobe/templates/browser-vhost-ssl.conf.tmpl \
      > /etc/apache2/sites-available/browser-ssl-8446.conf
  a2ensite browser-ssl-8446.conf >/dev/null || true
  apachectl -t && systemctl reload apache2 || true
fi

# Sudoers per la UI Browser (htpasswd, a2ensite/a2dissite, tee, reload)
step "Sudoers: permessi UI Embedded Browser"
cat >/etc/sudoers.d/netprobe-browser <<'EOF'
Defaults:netprobe !requiretty
Cmnd_Alias NP_BROWSER = \
  /usr/bin/htpasswd -Bbc /etc/apache2/.htpasswd-browser *, \
  /usr/sbin/a2ensite browser-ssl-*.conf, \
  /usr/sbin/a2dissite browser-ssl-*.conf, \
  /usr/bin/tee /etc/apache2/sites-available/browser-ssl-*.conf, \
  /bin/systemctl reload apache2, /usr/bin/systemctl reload apache2
netprobe ALL=(root) NOPASSWD: NP_BROWSER
EOF
chmod 0440 /etc/sudoers.d/netprobe-browser
visudo -cf /etc/sudoers.d/netprobe-browser >/dev/null || true

# =====================================================================
# WORKDIR & SUDOERS GENERALI APP
# =====================================================================
step "Workdir app /var/lib/netprobe (+pcap/speedtest/voip/netmap/logs)"
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe /var/lib/netprobe/tmp
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/pcap
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/speedtest
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/voip /var/lib/netprobe/voip/captures
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/netmap /var/lib/netprobe/netmap/scans
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/logs
[[ -f /var/lib/netprobe/voip/captures.json ]] || { echo '{"captures":[]}' >/var/lib/netprobe/voip/captures.json; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/voip/captures.json; chmod 0660 /var/lib/netprobe/voip/captures.json; }
[[ -f /var/lib/netprobe/voip/index.json    ]] || { echo '{"calls":{}, "rtp_streams":[], "built_ts":0}' >/var/lib/netprobe/voip/index.json; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/voip/index.json; chmod 0660 /var/lib/netprobe/voip/index.json; }
[[ -f /var/lib/netprobe/netmap/index.json  ]] || { echo '{"scans":[]}' >/var/lib/netprobe/netmap/index.json; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/netmap/index.json; chmod 0660 /var/lib/netprobe/netmap/index.json; }

# === DHCPSENTINEL === workdir + seed file
step "DHCP Sentinel: workdir e seed file"
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/dhcpsentinel
[[ -f /var/lib/netprobe/dhcpsentinel/events.jsonl ]] || { : > /var/lib/netprobe/dhcpsentinel/events.jsonl; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/dhcpsentinel/events.jsonl; chmod 0660 /var/lib/netprobe/dhcpsentinel/events.jsonl; }
[[ -f /var/lib/netprobe/dhcpsentinel/last.json   ]] || { echo '{}' > /var/lib/netprobe/dhcpsentinel/last.json; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/dhcpsentinel/last.json; chmod 0660 /var/lib/netprobe/dhcpsentinel/last.json; }
[[ -f /var/lib/netprobe/dhcpsentinel/alerts.clear.ts ]] || { echo 0 > /var/lib/netprobe/dhcpsentinel/alerts.clear.ts; chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/dhcpsentinel/alerts.clear.ts; chmod 0644 /var/lib/netprobe/dhcpsentinel/alerts.clear.ts; }

step "Sudoers operazioni UI"
cat >/etc/sudoers.d/netprobe-ops <<'EOF'
Defaults:netprobe !requiretty
Cmnd_Alias NP_COPY = \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/ports.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/sites-available/testmachine.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/systemd/timesyncd.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/smokeping/config.d/Database, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/smokeping/config.d/Targets
Cmnd_Alias NP_SVC = \
  /bin/systemctl reload apache2, /usr/bin/systemctl reload apache2, \
  /bin/systemctl restart apache2, /usr/bin/systemctl restart apache2, \
  /bin/systemctl reload smokeping, /usr/bin/systemctl reload smokeping, \
  /bin/systemctl try-reload-or-restart systemd-timesyncd, /usr/bin/systemctl try-reload-or-restart systemd-timesyncd, \
  /bin/systemctl start netprobe-flow-collector,   /usr/bin/systemctl start netprobe-flow-collector, \
  /bin/systemctl stop  netprobe-flow-collector,   /usr/bin/systemctl stop  netprobe-flow-collector, \
  /bin/systemctl restart netprobe-flow-collector, /usr/bin/systemctl restart netprobe-flow-collector, \
  /bin/systemctl start netprobe-flow-exporter@*,  /usr/bin/systemctl start netprobe-flow-exporter@*, \
  /bin/systemctl stop  netprobe-flow-exporter@*,  /usr/bin/systemctl stop  netprobe-flow-exporter@*, \
  /bin/systemctl restart netprobe-flow-exporter@*, /usr/bin/systemctl restart netprobe-flow-exporter@*, \
  /bin/systemctl restart netprobe-api.service,     /usr/bin/systemctl restart netprobe-api.service, \
  /bin/systemctl start netprobe-dhcpsentinel.service, /usr/bin/systemctl start netprobe-dhcpsentinel.service
Cmnd_Alias NP_TIME = /usr/bin/timedatectl *, /bin/timedatectl *
Cmnd_Alias NP_NM   = /usr/bin/nmcli *
Cmnd_Alias NP_CACTI = /usr/bin/cat /etc/cacti/debian.php, /bin/cat /etc/cacti/debian.php
Cmnd_Alias NP_UPDATE = \
  /usr/bin/env DEBIAN_FRONTEND=noninteractive /opt/netprobe/install-testmachine.sh *, \
  /bin/bash /opt/netprobe/install-testmachine.sh *, \
  /usr/bin/env DEBIAN_FRONTEND=noninteractive /opt/netprobe/install/install-testmachine.sh *, \
  /bin/bash /opt/netprobe/install/install-testmachine.sh *
Cmnd_Alias NP_POWER = \
  /sbin/reboot, /usr/sbin/reboot, \
  /bin/systemctl reboot, /usr/bin/systemctl reboot, \
  /usr/sbin/shutdown -r now *, /usr/sbin/shutdown -r +* *, \
  /bin/systemd-run *, /usr/bin/systemd-run *
netprobe ALL=(root) NOPASSWD: NP_COPY, NP_SVC, NP_TIME, NP_NM, NP_CACTI, NP_UPDATE, NP_POWER
EOF
chmod 440 /etc/sudoers.d/netprobe-ops
visudo -cf /etc/sudoers.d/netprobe-ops || { echo "Errore in /etc/sudoers.d/netprobe-ops"; exit 1; }

# Capability strumenti non-root
step "Capability: dumpcap/arp-scan/nmap non-root"
setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true
getcap /usr/bin/dumpcap || true
command -v setcap >/dev/null 2>&1 || apt-get install -y libcap2-bin
setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan || true
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

# Gruppi utili
usermod -aG "${APP_GROUP}" smokeping || true
usermod -aG "${APP_GROUP}" www-data  || true
usermod -aG www-data "${APP_USER}"    || true

# =====================================================================
# PHP + CACTI + SPINE
# =====================================================================
step "PHP (FPM) + moduli Required per Cacti"
apt-get install -y php php-fpm php-mysql php-xml php-gd php-mbstring php-snmp php-gmp php-intl php-ldap php-curl

PHPVER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
tee /etc/php/${PHPVER}/apache2/conf.d/90-cacti.ini >/dev/null <<'EOF'
memory_limit = 512M
max_execution_time = 120
post_max_size = 32M
upload_max_filesize = 32M
date.timezone = Europe/Rome
EOF
tee /etc/php/${PHPVER}/cli/conf.d/90-cacti.ini >/dev/null <<'EOF'
memory_limit = 512M
max_execution_time = 120
date.timezone = Europe/Rome
EOF

a2enmod proxy_fcgi setenvif >/dev/null || true
a2enconf cacti >/dev/null || true

step "Installazione MariaDB + Cacti + Spine (dbconfig-common abilitato)"
echo "cacti cacti/dbconfig-install boolean true" | debconf-set-selections
apt-get install -y mariadb-server cacti cacti-spine
systemctl enable --now mariadb

install -d -m 0775 -o www-data -g www-data /usr/share/cacti/site/log || true
install -d -m 0775 -o www-data -g www-data /var/lib/cacti/rra       || true
install -d -m 0775 -o www-data -g www-data /var/lib/cacti/csrf       || true
install -d -m 0775 -o www-data -g www-data /var/log/cacti            || true

step "Spine: allineo /etc/cacti/spine.conf a /etc/cacti/debian.php"
if [[ -f /etc/cacti/spine.conf ]] && [[ -f /etc/cacti/debian.php ]]; then
  php -r 'include "/etc/cacti/debian.php"; printf("%s|%s|%s|%s|%s\n",$database_hostname,$database_username,$database_password,$database_default,$database_port);' >/tmp/.cactidb || true
  if [[ -s /tmp/.cactidb ]]; then
    IFS="|" read -r DBH DBU DBP DBD DBPORT < /tmp/.cactidb
    sed -i \
      -e "s~^\(DB_Host[ \t]*\).*~\1${DBH:-localhost}~" \
      -e "s~^\(DB_Database[ \t]*\).*~\1${DBD:-cacti}~" \
      -e "s~^\(DB_User[ \t]*\).*~\1${DBU:-cacti}~" \
      -e "s~^\(DB_Pass[ \t]*\).*~\1${DBP:-}~" \
      -e "s~^\(DB_Port[ \t]*\).*~\1${DBPORT:-3306}~" \
      /etc/cacti/spine.conf || true
    chown root:www-data /etc/cacti/spine.conf || true
    chmod 0640 /etc/cacti/spine.conf || true
  fi
fi

step "Verifica schema Cacti e fallback import se necessario"
CNT=$(mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='cacti';" || echo 0)
if [[ "${CNT:-0}" -eq 0 ]]; then
  SCHEMA="$(dpkg -L cacti | grep -E '/cacti\.sql(\.gz)?$' | head -n1 || true)"
  if [[ -n "$SCHEMA" ]]; then
    case "$SCHEMA" in
      *.gz) zcat "$SCHEMA" | mysql cacti ;;
      *)     mysql cacti < "$SCHEMA"     ;;
    esac
  fi
fi

# =====================================================================
# CRON per CACTI
# =====================================================================
step "Abilito e avvio cron; verifico job Cacti"
systemctl enable --now cron
if [[ -f /etc/cron.d/cacti ]] && grep -q 'poller\.php' /etc/cron.d/cacti; then
  echo "Job cron Cacti presente in /etc/cron.d/cacti"
else
  echo "ATTENZIONE: /etc/cron.d/cacti mancante o senza poller.php."
fi
sudo -u www-data -- php /usr/share/cacti/site/poller.php --force || true

# ---- Host tuning per OpenSearch/Mongo ----
step "Tuning host per OpenSearch/Mongo (vm.max_map_count, file-max, AVX check)"
sysctl -w vm.max_map_count=262144 >/dev/null
sysctl -w fs.file-max=131072 >/dev/null
cat >/etc/sysctl.d/99-opensearch.conf <<'EOF'
vm.max_map_count=262144
fs.file-max=131072
EOF
sysctl --system >/dev/null || true
if ! grep -q -m1 -E 'avx(2)?' /proc/cpuinfo; then
  echo "ATTENZIONE: CPU senza AVX -> OpenSearch 2.x e MongoDB 6 potrebbero non avviarsi."
fi

# =====================================================================
# GRAYLOG (Docker stack)
# =====================================================================
step "Graylog stack (docker compose)"

GL_DIR=/opt/netprobe/graylog
install -d -m 0755 -o ${APP_USER} -g ${APP_GROUP} "${GL_DIR}"

SELF_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
SELF_IP="${SELF_IP:-127.0.0.1}"

GL_SECRET="$(openssl rand -hex 64)"
GL_SHA="$(printf %s 'admin' | sha256sum | awk '{print $1}')"
GL_EXT_URI="http://${SELF_IP}:${WEB_PORT}/graylog/"

ENV_FILE="${GL_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
  sed -i "s|^GRAYLOG_HTTP_EXTERNAL_URI=.*|GRAYLOG_HTTP_EXTERNAL_URI=${GL_EXT_URI}|" "${ENV_FILE}"
else
  cat >"${ENV_FILE}" <<EOF
GRAYLOG_PASSWORD_SECRET=${GL_SECRET}
GRAYLOG_ROOT_PASSWORD_SHA2=${GL_SHA}
GRAYLOG_HTTP_EXTERNAL_URI=${GL_EXT_URI}
EOF
  chown ${APP_USER}:${APP_GROUP} "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
fi

if [[ ! -s "${GL_DIR}/docker-compose.yml" ]]; then
  cat > "${GL_DIR}/docker-compose.yml" <<'YAML'
services:
  mongodb:
    image: mongo:6
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.runCommand({ ping: 1 })"]
      interval: 10s
      timeout: 5s
      retries: 10
    volumes:
      - mongo_data:/data/db

  opensearch:
    image: opensearchproject/opensearch:2.11.0
    restart: unless-stopped
    environment:
      discovery.type: single-node
      plugins.security.disabled: "true"
      OPENSEARCH_JAVA_OPTS: "-Xms512m -Xmx512m"
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile:  { soft: 65536, hard: 65536 }
    ports:
      - "127.0.0.1:9200:9200"
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:9200 >/dev/null"]
      interval: 10s
      timeout: 5s
      retries: 30
    volumes:
      - os_data:/usr/share/opensearch/data

  graylog:
    image: graylog/graylog:6.0
    restart: unless-stopped
    depends_on: [mongodb, opensearch]
    ports:
      - "127.0.0.1:9001:9000"
      - "0.0.0.0:5514:1514/tcp"
      - "0.0.0.0:5514:1514/udp"
    environment:
      TZ: "Europe/Rome"
      GRAYLOG_PASSWORD_SECRET: "${GRAYLOG_PASSWORD_SECRET}"
      GRAYLOG_ROOT_PASSWORD_SHA2: "${GRAYLOG_ROOT_PASSWORD_SHA2}"
      GRAYLOG_ROOT_USERNAME: "admin"
      GRAYLOG_HTTP_BIND_ADDRESS: "0.0.0.0:9000"
      GRAYLOG_HTTP_PUBLISH_URI:  "http://0.0.0.0:9000/"
      GRAYLOG_HTTP_EXTERNAL_URI: "${GRAYLOG_HTTP_EXTERNAL_URI}"
      GRAYLOG_OPENSEARCH_HOSTS:  "http://opensearch:9200"
      GRAYLOG_ELASTICSEARCH_HOSTS: "http://opensearch:9200"
      GRAYLOG_MONGODB_URI:       "mongodb://mongodb:27017/graylog"
      GRAYLOG_HTTP_ENABLE_CORS:  "true"
      GRAYLOG_HTTP_ENABLE_GZIP:  "true"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:9000/ >/dev/null || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 30
    volumes:
      - gl_data:/usr/share/graylog/data

volumes:
  mongo_data: {}
  os_data: {}
  gl_data: {}
YAML
  chown ${APP_USER}:${APP_GROUP} "${GL_DIR}/docker-compose.yml"
fi

if [[ ! -s /etc/systemd/system/graylog-stack.service ]]; then
  cat >/etc/systemd/system/graylog-stack.service <<'EOF'
[Unit]
Description=Graylog stack (docker compose)
After=docker.service network-online.target
Wants=docker.service
[Service]
Type=oneshot
WorkingDirectory=/opt/netprobe/graylog
RemainAfterExit=yes
ExecStart=/usr/local/bin/dcompose up -d
ExecStop=/usr/local/bin/dcompose down
ExecReload=/usr/local/bin/dcompose up -d
[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now graylog-stack.service || true

# =====================================================================
# SPEEDTEST CLI (Ookla) opzionale
# =====================================================================
step "Ookla speedtest (opzionale)"
if ! command -v speedtest >/dev/null 2>&1; then
  curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash || true
  apt-get update || true
  apt-get install -y speedtest || true
fi

# =====================================================================
# SEED UTENTI APP + CONFIG
# =====================================================================
step "Seed /etc/netprobe/users.json (admin/admin se assente)"
install -d -m 0770 -o root -g "${APP_GROUP}" /etc/netprobe
if [[ ! -s /etc/netprobe/users.json ]]; then
python3 - <<'PY'
import json, secrets, hashlib, pathlib, os
def pbk(pw,s,r=260000): return hashlib.pbkdf2_hmac("sha256",pw.encode(),bytes.fromhex(s),r).hex()
def h(p): s=secrets.token_hex(16); r=260000; return f"pbkdf2_sha256${r}${s}${pbk(p,s,r)}"
p=pathlib.Path("/etc/netprobe/users.json")
p.write_text(json.dumps({"users":{"admin":{"pw":h("admin"),"roles":["admin"]}}},indent=2))
os.chmod(p,0o660)
PY
  chgrp "${APP_GROUP}" /etc/netprobe/users.json
fi

# Config speedtest (scheduler UI)
if [[ ! -s /etc/netprobe/speedtest.json ]]; then
cat >/etc/netprobe/speedtest.json <<'EOF'
{
  "enabled": true,
  "interval_min": 120,
  "retention_max": 10000,
  "prefer": "auto",
  "server_id": "",
  "tag": ""
}
EOF
  chown root:${APP_GROUP} /etc/netprobe/speedtest.json
  chmod 0660 /etc/netprobe/speedtest.json
fi

# === DHCPSENTINEL === seed config (idempotente)
if [[ ! -s /etc/netprobe/dhcpsentinel.json ]]; then
cat >/etc/netprobe/dhcpsentinel.json <<'EOF'
{
  "enabled": true,
  "iface": "ens4",
  "allow": [],
  "listen_sec": 6,
  "retries": 1,
  "retry_delay_sec": 2
}
EOF
  chown root:${APP_GROUP} /etc/netprobe/dhcpsentinel.json
  chmod 0660 /etc/netprobe/dhcpsentinel.json
fi

# =====================================================================
# RIAVVII & CHECK FINALI
# =====================================================================
step "Riavvio servizi (PHP-FPM/Apache/SmokePing) + timer alert/speedtest + webtop"
systemctl reload php${PHPVER}-fpm || true
systemctl restart smokeping || true
systemctl reload apache2 || systemctl restart apache2
systemctl enable --now netprobe-alertd.timer  || true
systemctl enable --now netprobe-speedtestd.timer || true
systemctl enable --now netprobe-dhcpsentinel.timer || true
systemctl enable --now netprobe-webtop.service || true

step "Check finali"
systemctl is-active --quiet netprobe-api.socket && echo "API socket OK"
systemctl is-active --quiet smokeping && echo "SmokePing OK"
systemctl is-active --quiet cron && echo "cron OK (attivo)"
systemctl is-active --quiet netprobe-webtop.service && echo "WebTop OK (127.0.0.1:6902)"
apachectl -t || true
echo -n "HTTP /            : "; curl -sI "http://127.0.0.1:${WEB_PORT}/" | head -n1 || true
echo -n "HTTP /smokeping/  : "; curl -sI "http://127.0.0.1:${WEB_PORT}/smokeping/" | head -n1 || true
echo -n "HTTP /cacti/      : "; curl -sI "http://127.0.0.1:${WEB_PORT}/cacti/" | head -n1 || true
echo -n "Graylog backend   : "; curl -sI "http://127.0.0.1:9001/" | head -n1 || true
echo -n "Graylog via proxy : "; curl -sI "http://127.0.0.1:${WEB_PORT}/graylog/" | head -n1 || true
echo -n "Webtop 6902       : "; curl -sI "http://127.0.0.1:6902/" | head -n1 || true
echo -n "Browser vhost URL : "; echo "https://$(hostname -I | awk '{print $1}'):8446/browser/"
echo "Container:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/^/  /'

command -v speedtest >/dev/null 2>&1 && echo "Speedtest CLI presente." || echo "Speedtest CLI assente; fallback Python disponibile."
echo -e "\nFATTO. Log: ${LOG}"
echo "Benvenuto nel mondo del domani!"
