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
API_PORT=9000                    # API (socket activation) 127.0.0.1:9000
WEB_PORT=${WEB_PORT:-8080}       # Apache listener esterno

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
  git ca-certificates curl sudo jq debconf-utils \
  python3 python3-venv python3-pip \
  apache2 apache2-utils \
  smokeping fping \
  network-manager \
  tshark wireshark-common tcpdump libcap2-bin \
  psmisc nfdump softflowd rrdtool snmp snmpd \
  nmap arp-scan bind9-dnsutils avahi-utils ieee-data \
  cron
# Dipendenze aggiuntive per NAT/UPnP + MTU/MSS + Traceroute
apt-get install -y --no-install-recommends \
  iproute2 iputils-tracepath mtr-tiny miniupnpc iptables

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
# Docker
# ---------------------------------------------------------------------
step "Docker + compose"
apt-get install -y --no-install-recommends docker.io docker-compose-plugin
systemctl enable --now docker

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
  # include websockets/wsproto per la console
  "${APP_DIR}/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart speedtest-cli websockets wsproto
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

  step "systemctl daemon-reload & setup"
  systemctl daemon-reload
  command -v fuser >/dev/null 2>&1 && /usr/bin/fuser -k -n udp 2055 || true
  pkill -f '(^| )nfcapd( |$)' 2>/dev/null || true
  systemctl reset-failed netprobe-flow-collector 2>/dev/null || true
  sleep 0.2

  systemctl enable --now netprobe-api.socket
  systemctl stop netprobe-api.service 2>/dev/null || true
  systemctl enable --now netprobe-flow-collector || true
  systemctl stop 'netprobe-flow-exporter@*' 2>/dev/null || true
  for link in /etc/systemd/system/multi-user.target.wants/netprobe-flow-exporter@*.service; do
    [[ -L "$link" ]] && systemctl disable "$(basename "$link")" || true
  done

  # abilita i timer alert/speedtest
  systemctl enable --now netprobe-alertd.timer
  systemctl enable --now netprobe-speedtestd.timer
}
deploy_systemd

# =====================================================================
# APACHE
# =====================================================================
step "Apache: moduli & porta ${WEB_PORT}"
a2enmod proxy proxy_http proxy_wstunnel headers rewrite cgid >/dev/null || true
a2enmod proxy_fcgi setenvif >/dev/null || true
sed -ri 's/^[[:space:]]*Listen[[:space:]]+80[[:space:]]*$/# Listen 80/' /etc/apache2/ports.conf
grep -qE "^[[:space:]]*Listen[[:space:]]+${WEB_PORT}\b" /etc/apache2/ports.conf || echo "Listen ${WEB_PORT}" >> /etc/apache2/ports.conf

step "Site testmachine.conf (API/WS + Graylog + esclusioni /smokeping /cgi-bin /cacti)"
cat >/etc/apache2/sites-available/testmachine.conf <<EOF
<VirtualHost *:${WEB_PORT}>
  ServerName testmachine

  ErrorLog  /var/log/apache2/testmachine-error.log
  CustomLog /var/log/apache2/testmachine-access.log combined

  ProxyPreserveHost On
  ProxyRequests Off
  RequestHeader set X-Forwarded-Proto "http"

  # WebSocket verso l'app FastAPI
  ProxyPass        /api/ws   ws://127.0.0.1:${API_PORT}/api/ws
  ProxyPassReverse /api/ws   ws://127.0.0.1:${API_PORT}/api/ws
  ProxyPass        /shell/ws ws://127.0.0.1:${API_PORT}/shell/ws
  ProxyPassReverse /shell/ws ws://127.0.0.1:${API_PORT}/shell/ws

  # Non proxy verso l'app
  ProxyPass /smokeping/ !
  ProxyPass /cgi-bin/   !
  ProxyPass /cacti/     !

  # Graylog pubblicato su sottopercorso /graylog/
  ProxyPass        /graylog/        http://127.0.0.1:9001/
  ProxyPassReverse /graylog/        http://127.0.0.1:9001/
  ProxyPass        /graylog/api/ws  ws://127.0.0.1:9001/api/ws
  ProxyPassReverse /graylog/api/ws  ws://127.0.0.1:9001/api/ws
  ProxyPassReverseCookiePath / /graylog/

  # App FastAPI (default)
  ProxyPass        / http://127.0.0.1:${API_PORT}/
  ProxyPassReverse / http://127.0.0.1:${API_PORT}/
</VirtualHost>
EOF
a2ensite testmachine.conf >/dev/null || true
a2enconf smokeping >/dev/null || true

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
  /bin/systemctl restart netprobe-api.service,     /usr/bin/systemctl restart netprobe-api.service
Cmnd_Alias NP_TIME = /usr/bin/timedatectl *, /bin/timedatectl *
Cmnd_Alias NP_NM   = /usr/bin/nmcli *
# iptables (solo tabella mangle) per MSS clamp da UI
Cmnd_Alias NP_IPT  = \
  /usr/sbin/iptables -t mangle -S, \
  /usr/sbin/iptables -t mangle -A FORWARD -o *, \
  /usr/sbin/iptables -t mangle -D FORWARD -o *
# Lettura sicura password DB Cacti dalla UI
Cmnd_Alias NP_CACTI = /usr/bin/cat /etc/cacti/debian.php, /bin/cat /etc/cacti/debian.php
# Esecuzione installer da UI (entrambe le posizioni)
Cmnd_Alias NP_UPDATE = \
  /usr/bin/env DEBIAN_FRONTEND=noninteractive /opt/netprobe/install-testmachine.sh *, \
  /bin/bash /opt/netprobe/install-testmachine.sh *, \
  /usr/bin/env DEBIAN_FRONTEND=noninteractive /opt/netprobe/install/install-testmachine.sh *, \
  /bin/bash /opt/netprobe/install/install-testmachine.sh *
netprobe ALL=(root) NOPASSWD: NP_COPY, NP_SVC, NP_TIME, NP_NM, NP_IPT, NP_CACTI, NP_UPDATE
EOF
chmod 440 /etc/sudoers.d/netprobe-ops
visudo -cf /etc/sudoers.d/netprobe-ops || { echo "Errore in /etc/sudoers.d/netprobe-ops"; exit 1; }

# Packet capture / net mapper caps
step "Capability: dumpcap/arp-scan/nmap non-root"
setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true
getcap /usr/bin/dumpcap || true
command -v setcap >/dev/null 2>&1 || apt-get install -y libcap2-bin
setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan || true
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

# Gruppi utili
usermod -aG "${APP_GROUP}" smokeping || true
usermod -aG "${APP_GROUP}" www-data  || true
usermod -aG www-data "${APP_USER}"    || true   # per cacti/debian.php (640 root:www-data)

# =====================================================================
# PHP + CACTI + SPINE (dbconfig-common = TRUE)
# =====================================================================
step "PHP (FPM) + moduli Required per Cacti"
apt-get install -y \
  php php-fpm php-mysql php-xml php-gd php-mbstring php-snmp php-gmp php-intl php-ldap php-curl

# PHP tuning base per Cacti
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

# Cartelle base utili (incluso log per cron)
install -d -m 0775 -o www-data -g www-data /usr/share/cacti/site/log || true
install -d -m 0775 -o www-data -g www-data /var/lib/cacti/rra       || true
install -d -m 0775 -o www-data -g www-data /var/lib/cacti/csrf       || true
install -d -m 0775 -o www-data -g www-data /var/log/cacti            || true

# Spine: allinea credenziali con /etc/cacti/debian.php
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

# Fallback schema: se DB cacti vuoto, importa dallo schema del pacchetto
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
  echo "ATTENZIONE: /etc/cron.d/cacti mancante o senza poller.php (il pacchetto dovrebbe fornirlo)."
fi

# (opzionale) prima esecuzione del poller
sudo -u www-data -- php /usr/share/cacti/site/poller.php -f || true

# =====================================================================
# GRAYLOG (Docker stack)
# =====================================================================
step "Graylog stack (docker compose)"

GL_DIR=/opt/netprobe/graylog
install -d -m 0755 -o ${APP_USER} -g ${APP_GROUP} "${GL_DIR}"

# Rileva IP locale per HTTP_EXTERNAL_URI
SELF_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
SELF_IP="${SELF_IP:-127.0.0.1}"

# Genera segreti/password (default admin/admin)
GL_SECRET="$(openssl rand -hex 64)"
GL_SHA="$(printf %s 'admin' | sha256sum | awk '{print $1}')"
GL_EXT_URI="http://${SELF_IP}:${WEB_PORT}/graylog/"

# .env (idempotente: se esiste conserva SECRET e SHA, aggiorna solo l'URL)
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

# docker-compose.yml
if [[ ! -s "${GL_DIR}/docker-compose.yml" ]]; then
  cat > "${GL_DIR}/docker-compose.yml" <<'YAML'
services:
  mongodb:
    image: mongo:6
    restart: unless-stopped
    healthcheck:
      test: ["CMD","mongosh","--eval","db.adminCommand('ping')"]
      interval: 10s
      timeout: 5s
      retries: 10
    volumes:
      - mongo_data:/data/db

  opensearch:
    image: opensearchproject/opensearch:2.11.0
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile:  { soft: 65536, hard: 65536 }
    restart: unless-stopped
    healthcheck:
      test: ["CMD","curl","-sSf","http://localhost:9200/_cluster/health"]
      interval: 10s
      timeout: 5s
      retries: 20
    ports:
      - "127.0.0.1:9200:9200"
    volumes:
      - os_data:/usr/share/opensearch/data

  graylog:
    image: graylog/graylog:6.0
    depends_on:
      mongodb:   { condition: service_healthy }
      opensearch:{ condition: service_healthy }
    restart: unless-stopped
    environment:
      - GRAYLOG_PASSWORD_SECRET=${GRAYLOG_PASSWORD_SECRET}
      - GRAYLOG_ROOT_PASSWORD_SHA2=${GRAYLOG_ROOT_PASSWORD_SHA2}
      - GRAYLOG_ROOT_USERNAME=admin
      - GRAYLOG_HTTP_PUBLISH_URI=http://0.0.0.0:9000/
      - GRAYLOG_HTTP_EXTERNAL_URI=${GRAYLOG_HTTP_EXTERNAL_URI}
    healthcheck:
      test: ["CMD","curl","-sSf","http://localhost:9000/api/system/lbstatus"]
      interval: 10s
      timeout: 5s
      retries: 30
    ports:
      - "127.0.0.1:9001:9000"
      - "0.0.0.0:5514:1514/tcp"
      - "0.0.0.0:5514:1514/udp"
    volumes:
      - gl_data:/usr/share/graylog/data

volumes:
  mongo_data: {}
  os_data: {}
  gl_data: {}
YAML
  chown ${APP_USER}:${APP_GROUP} "${GL_DIR}/docker-compose.yml"
fi

# systemd unit
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
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose up -d

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now graylog-stack.service

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

# =====================================================================
# RIAVVII & CHECK FINALI
# =====================================================================
step "Riavvio servizi (PHP-FPM/Apache/SmokePing) + timer alert/speedtest"
systemctl reload php${PHPVER}-fpm || true
systemctl restart smokeping || true
systemctl reload apache2 || systemctl restart apache2
systemctl enable --now netprobe-alertd.timer  || true
systemctl enable --now netprobe-speedtestd.timer || true

step "Check finali"
systemctl is-active --quiet netprobe-api.socket && echo "API socket OK"
systemctl is-active --quiet smokeping && echo "SmokePing OK"
systemctl is-active --quiet cron && echo "cron OK (attivo)"
apachectl -t || true
echo -n "HTTP /            : "; curl -sI "http://127.0.0.1:${WEB_PORT}/" | head -n1 || true
echo -n "HTTP /smokeping/  : "; curl -sI "http://127.0.0.1:${WEB_PORT}/smokeping/" | head -n1 || true
echo -n "HTTP /cacti/      : "; curl -sI "http://127.0.0.1:${WEB_PORT}/cacti/" | head -n1 || true
echo -n "Graylog backend   : "; curl -sI "http://127.0.0.1:9001/" | head -n1 || true
echo -n "Graylog via proxy : "; curl -sI "http://127.0.0.1:${WEB_PORT}/graylog/" | head -n1 || true
echo "Container:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/^/  /'

command -v speedtest >/dev/null 2>&1 && echo "Speedtest CLI presente." || echo "Speedtest CLI assente; fallback Python disponibile."

echo -e "\nFATTO. Log: ${LOG}"
echo "Benvenuto nel mondo del domani!"
