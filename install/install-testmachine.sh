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
API_PORT=9000
WEB_PORT=${WEB_PORT:-8080}

# --- APT: abilita contrib/non-free/non-free-firmware PRIMA di ogni update ---
step "Abilito componenti APT: contrib non-free non-free-firmware"
. /etc/os-release
CODENAME="${VERSION_CODENAME:-bookworm}"
SRC=/etc/apt/sources.list
if [[ -f "$SRC" ]]; then
  cp -n "$SRC" "${SRC}.bak.$(date +%F_%H%M%S)" || true
  tmp=$(mktemp)
  awk '
    BEGIN{OFS=" "}
    /^deb\s+http/ {
      line=$0
      if (line !~ / main/) line=line" main"
      if (line !~ / contrib/) line=line" contrib"
      if (line !~ / non-free[^-]/) line=line" non-free"
      if (line !~ / non-free-firmware/) line=line" non-free-firmware"
      print line; next
    }
    {print}
  ' "$SRC" > "$tmp" && mv "$tmp" "$SRC"
else
  cat >"$SRC" <<EOF
deb http://deb.debian.org/debian $CODENAME main contrib non-free non-free-firmware
deb http://deb.debian.org/debian $CODENAME-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security $CODENAME-security main contrib non-free non-free-firmware
EOF
fi

# --- pacchetti base ---
step "APT update & install base"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git ca-certificates curl sudo jq \
  python3 python3-venv python3-pip \
  apache2 apache2-utils \
  smokeping fping \
  network-manager \
  tshark wireshark-common tcpdump libcap2-bin

# --- pacchetti Net Mapper (nmap/arp-scan/dns/snmp/bonjour/oui) ---
step "Install Net Mapper deps"
apt-get install -y --no-install-recommends \
  nmap arp-scan dnsutils snmp snmp-mibs-downloader avahi-utils ieee-data

# --- SNMP MIBs: abilita caricamento (Debian ha spesso 'mibs :' disabilitante) ---
step "SNMP: abilito caricamento MIB (commento 'mibs :')"
SNMPCFG=/etc/snmp/snmp.conf
if [[ -f "$SNMPCFG" ]]; then
  cp -n "$SNMPCFG" "${SNMPCFG}.bak.$(date +%F_%H%M%S)" || true
  sed -i 's/^[[:space:]]*mibs[[:space:]]*:.*/# mibs :/g' "$SNMPCFG" || true
fi

# --- utente/gruppo app ---
step "Utente/gruppo ${APP_USER}"
getent group  "${APP_GROUP}" >/dev/null || groupadd -r "${APP_GROUP}"
id -u "${APP_USER}" >/dev/null 2>&1 || useradd -r -g "${APP_GROUP}" -d "${APP_DIR}" -s /usr/sbin/nologin "${APP_USER}"

# --- sorgenti applicazione ---
step "Sorgenti applicazione in ${APP_DIR}"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}"
if [[ ! -d "${APP_DIR}/.git" ]]; then
  git clone https://github.com/fraidotube/testmachine.git "${APP_DIR}"
else
  pushd "${APP_DIR}" >/dev/null
  sudo -u "${APP_USER}" -H git fetch --all || true
  sudo -u "${APP_USER}" -H git pull --ff-only || true
  popd >/dev/null
fi

# --- venv + deps ---
step "Python venv + dipendenze"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}/venv"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip
if [[ -f "${APP_DIR}/requirements.txt" ]]; then
  "${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
else
  "${APP_DIR}/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart speedtest-cli
fi
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"

# --- Systemd: API ---
step "Systemd unit netprobe-api"
cat >/etc/systemd/system/netprobe-api.service <<EOF
[Unit]
Description=TestMachine API (FastAPI)
After=network.target

[Service]
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}/app
ExecStart=${APP_DIR}/venv/bin/uvicorn main:app --host 127.0.0.1 --port ${API_PORT}
Restart=on-failure
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now netprobe-api

# --- Apache: moduli + porta + vhost ---
step "Apache moduli"
a2enmod proxy proxy_http headers rewrite cgid >/dev/null

step "Apache porta ${WEB_PORT}"
sed -ri 's/^[[:space:]]*Listen[[:space:]]+80[[:space:]]*$/# Listen 80/' /etc/apache2/ports.conf
grep -qE "^[[:space:]]*Listen[[:space:]]+${WEB_PORT}\b" /etc/apache2/ports.conf || echo "Listen ${WEB_PORT}" >> /etc/apache2/ports.conf

step "Site testmachine.conf"
cat >/etc/apache2/sites-available/testmachine.conf <<EOF
<VirtualHost *:${WEB_PORT}>
  ServerName testmachine

  ErrorLog  \${APACHE_LOG_DIR}/testmachine-error.log
  CustomLog \${APACHE_LOG_DIR}/testmachine-access.log combined

  ProxyPreserveHost On
  RequestHeader set X-Forwarded-Proto "http"
  ProxyPass        / http://127.0.0.1:${API_PORT}/
  ProxyPassReverse / http://127.0.0.1:${API_PORT}/

  <Location /smokeping/>
    ProxyPass !
    Require all granted
  </Location>
</VirtualHost>
EOF
a2ensite testmachine.conf >/dev/null || true

# --- SmokePing: conf Apache e permessi ---
step "SmokePing: conf Apache + permessi"
a2enconf smokeping >/dev/null || true

# --- Packet capture: capability dumpcap ---
step "Packet capture: abilita dumpcap non-root"
setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true
getcap /usr/bin/dumpcap || true
getent group wireshark >/dev/null && usermod -aG wireshark "${APP_USER}" || true

# --- Net Mapper: capability per arp-scan / nmap ---
step "Net Mapper: capability per arp-scan e nmap (non-root)"
command -v setcap >/dev/null 2>&1 || apt-get install -y libcap2-bin
setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan || true
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true
getcap /usr/sbin/arp-scan || true
getcap /usr/bin/nmap || true

# --- gruppi/permessi per file e config ---
usermod -aG "${APP_GROUP}" smokeping || true
usermod -aG "${APP_GROUP}" www-data  || true

install -d -m 2770 -o root -g "${APP_GROUP}" /etc/smokeping/config.d
chown -R root:"${APP_GROUP}" /etc/smokeping/config.d
chmod 0660 /etc/smokeping/config.d/* 2>/dev/null || true

chown -R smokeping:"${APP_GROUP}" /var/lib/smokeping
chmod 2770 /var/lib/smokeping

# Targets default
if [[ ! -s /etc/smokeping/config.d/Targets ]]; then
  cat >/etc/smokeping/config.d/Targets <<'EOF'
+ TestMachine
menu = TestMachine
title = TestMachine targets
# Aggiungi host da UI
EOF
  chown ${APP_USER}:${APP_GROUP} /etc/smokeping/config.d/Targets
  chmod 0660 /etc/smokeping/config.d/Targets
fi

# --- Workdir app & PCAP & SPEEDTEST & VOIP & NETMAP ---
step "Workdir app + PCAP + SPEEDTEST + VOIP + NETMAP"
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe /var/lib/netprobe/tmp
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/pcap
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/speedtest

# VOIP
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/voip
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/voip/captures
if [[ ! -f /var/lib/netprobe/voip/captures.json ]]; then
  echo '{"captures":[]}' >/var/lib/netprobe/voip/captures.json
  chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/voip/captures.json
  chmod 0660 /var/lib/netprobe/voip/captures.json
fi
if [[ ! -f /var/lib/netprobe/voip/index.json ]]; then
  echo '{"calls":{}, "rtp_streams":[], "built_ts":0}' >/var/lib/netprobe/voip/index.json
  chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/voip/index.json
  chmod 0660 /var/lib/netprobe/voip/index.json
fi
install -d -m 0770 -o root -g "${APP_GROUP}" /etc/netprobe
if [[ ! -f /etc/netprobe/voip.json ]]; then
  cat >/etc/netprobe/voip.json <<'JSON'
{
  "sip_ports": [5060, 5061],
  "rtp_range": [10000, 20000],
  "duration_max": 3600,
  "quota_gb": 5,
  "policy": "rotate",
  "allow_bpf": true,
  "privacy_mask_user": false,
  "ui_poll_ms": 1000,
  "admin_required_actions": ["start","stop","delete"],
  "default_codec": "PCMU"
}
JSON
  chown root:${APP_GROUP} /etc/netprobe/voip.json
  chmod 0660 /etc/netprobe/voip.json
fi

# NETMAP
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/netmap
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/netmap/scans
if [[ ! -f /var/lib/netprobe/netmap/index.json ]]; then
  echo '{"scans":[]}' >/var/lib/netprobe/netmap/index.json
  chown ${APP_USER}:${APP_GROUP} /var/lib/netprobe/netmap/index.json
  chmod 0660 /var/lib/netprobe/netmap/index.json
fi

# --- SUDOERS ---
step "Sudoers per netprobe"
cat >/etc/sudoers.d/netprobe-ops <<'EOF'
Defaults:netprobe !requiretty
Cmnd_Alias NP_COPY = \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/ports.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/sites-available/testmachine.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/systemd/timesyncd.conf
Cmnd_Alias NP_SVC = \
  /bin/systemctl reload apache2, /usr/bin/systemctl reload apache2, \
  /bin/systemctl restart apache2, /usr/bin/systemctl restart apache2, \
  /bin/systemctl reload smokeping, /usr/bin/systemctl reload smokeping, \
  /bin/systemctl try-reload-or-restart systemd-timesyncd, /usr/bin/systemctl try-reload-or-restart systemd-timesyncd
Cmnd_Alias NP_TIME = /usr/bin/timedatectl *, /bin/timedatectl *
Cmnd_Alias NP_NM = /usr/bin/nmcli *
netprobe ALL=(root) NOPASSWD: NP_COPY, NP_SVC, NP_TIME, NP_NM
EOF
chmod 440 /etc/sudoers.d/netprobe-ops
visudo -c

# --- Speedtest (Ookla CLI) + fallback Python ---
step "Installazione Ookla Speedtest CLI (repo packagecloud)"
if ! command -v speedtest >/dev/null 2>&1; then
  curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash || true
  apt-get update || true
  apt-get install -y speedtest || true
fi
if command -v speedtest >/dev/null 2>&1; then
  echo "Ookla speedtest: $(speedtest --version 2>&1 | head -n1 || true)"
else
  echo "Ookla speedtest non installato: userò il fallback Python (speedtest-cli)."
fi

# --- Seed utenti ---
step "Seed /etc/netprobe/users.json (admin/admin)"
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

# --- servizi ---
step "Riavvio servizi"
systemctl restart smokeping || true
systemctl reload apache2 || systemctl restart apache2

# --- check ---
step "Check finali"
systemctl is-active --quiet netprobe-api && echo "API OK"
systemctl is-active --quiet smokeping && echo "SmokePing OK"
apachectl -t || true
echo -n "HTTP / (via :${WEB_PORT}): "; curl -sI "http://127.0.0.1:${WEB_PORT}/" | head -n1 || true
echo -n "HTTP /smokeping/ (via Apache): "; curl -sI "http://127.0.0.1:${WEB_PORT}/smokeping/" | head -n1 || true
if command -v speedtest >/dev/null 2>&1; then
  echo "Speedtest CLI presente."
else
  echo "Speedtest CLI assente; fallback Python disponibile (speedtest-cli in venv)."
fi

echo -e "\nFATTO. Log: ${LOG}"
