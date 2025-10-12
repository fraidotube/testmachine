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
API_PORT=9000                         # uvicorn
WEB_PORT=${WEB_PORT:-8080}            # Apache (puoi esportare WEB_PORT=xxxx prima di lanciare)

# --- pacchetti base ---
step "APT update & install"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git ca-certificates curl sudo jq \
  python3 python3-venv python3-pip \
  apache2 apache2-utils \
  smokeping fping \
  network-manager \
  tshark wireshark-common tcpdump libcap2-bin

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
step "Python venv"
install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}/venv"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip
if [[ -f "${APP_DIR}/requirements.txt" ]]; then
  "${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
else
  "${APP_DIR}/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart
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
grep -qE "^[[:space:]]*Listen[[:space:]]+${WEB_PORT}\b" /etc/apache2/ports.conf || \
  echo "Listen ${WEB_PORT}" >> /etc/apache2/ports.conf

step "Site testmachine.conf"
cat >/etc/apache2/sites-available/testmachine.conf <<EOF
<VirtualHost *:${WEB_PORT}>
  ServerName testmachine
  ErrorLog  \${APACHE_LOG_DIR}/testmachine-error.log
  CustomLog \${APACHE_LOG_DIR}/testmachine-access.log combined

  # Reverse proxy verso FastAPI
  ProxyPreserveHost On
  RequestHeader set X-Forwarded-Proto "http"
  ProxyPass        / http://127.0.0.1:${API_PORT}/
  ProxyPassReverse / http://127.0.0.1:${API_PORT}/

  # Esclusione SmokePing dal proxy: usa la sua conf di Apache
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


# --- Packet capture (dumpcap non-root via capability) ---
step "Packet capture: abilita dumpcap non-root"
# abilita la capability per catturare pacchetti senza root
setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true
getcap /usr/bin/dumpcap || true

# se esiste il gruppo wireshark, aggiungi netprobe (alcune distro lo usano per i permessi di dumpcap)
if getent group wireshark >/dev/null 2>&1; then
  usermod -aG wireshark "${APP_USER}" || true
fi

# seed configurazione PCAP (se non presente)
install -d -m 0755 /etc/netprobe
if [[ ! -s /etc/netprobe/pcap.json ]]; then
  cat >/etc/netprobe/pcap.json <<'JSON'
{
  "duration_max": 3600,
  "quota_gb": 5,
  "policy": "rotate",
  "poll_ms": 1000,
  "allow_bpf": true
}
JSON
  chmod 0644 /etc/netprobe/pcap.json
fi




# gruppi/permessi: CGI (www-data) e demone (smokeping) devono poter leggere/scrivere
usermod -aG "${APP_GROUP}" smokeping || true
usermod -aG "${APP_GROUP}" www-data  || true

install -d -m 2770 -o root -g "${APP_GROUP}" /etc/smokeping/config.d
chown -R root:"${APP_GROUP}" /etc/smokeping/config.d
chmod 0660 /etc/smokeping/config.d/* 2>/dev/null || true

chown -R smokeping:"${APP_GROUP}" /var/lib/smokeping
chmod 2770 /var/lib/smokeping

# Targets default (vuoti ma validi)
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

# --- SUDOERS: nmcli + NTP + Apache/Smokeping + install ---
step "Sudoers per netprobe"
cat >/etc/sudoers.d/netprobe-ops <<'EOF'
Defaults:netprobe !requiretty

# Copie file generate dalla webapp (porta, vhost, timesyncd)
Cmnd_Alias NP_COPY = \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/ports.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/apache2/sites-available/testmachine.conf, \
  /usr/bin/install -m 644 /var/lib/netprobe/tmp/* /etc/systemd/timesyncd.conf

# Reload/restart servizi usati dalla webapp
Cmnd_Alias NP_SVC = \
  /bin/systemctl reload apache2, /usr/bin/systemctl reload apache2, \
  /bin/systemctl restart apache2, /usr/bin/systemctl restart apache2, \
  /bin/systemctl reload smokeping, /usr/bin/systemctl reload smokeping, \
  /bin/systemctl try-reload-or-restart systemd-timesyncd, /usr/bin/systemctl try-reload-or-restart systemd-timesyncd

# NTP / timezone
Cmnd_Alias NP_TIME = \
  /usr/bin/timedatectl *, \
  /bin/timedatectl *

# NetworkManager (WAN/LAN)
Cmnd_Alias NP_NM = \
  /usr/bin/nmcli *

netprobe ALL=(root) NOPASSWD: NP_COPY, NP_SVC, NP_TIME, NP_NM
EOF
chmod 440 /etc/sudoers.d/netprobe-ops
visudo -c

# --- Workdir temporaneo dell’app ---
step "Workdir temporaneo dell’app"
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe /var/lib/netprobe/tmp

# directory per i file PCAP
install -d -m 0770 -o "${APP_USER}" -g "${APP_GROUP}" /var/lib/netprobe/pcap



# --- Utenti/app default ---
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
systemctl restart netprobe-api || true

# --- check ---
step "Check finali"
systemctl is-active --quiet netprobe-api && echo "API OK"
systemctl is-active --quiet smokeping && echo "SmokePing OK"
apachectl -t || true
echo -n "HTTP / (via :${WEB_PORT}): "; curl -sI "http://127.0.0.1:${WEB_PORT}/" | head -n1 || true
echo -n "HTTP /smokeping/ (via Apache): "; curl -sI "http://127.0.0.1:${WEB_PORT}/smokeping/" | head -n1 || true

echo -e "\nFATTO. Log: ${LOG}"
