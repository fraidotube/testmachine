#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/testmachine-install.log
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=== TestMachine installer avviato: $(date -Is) ==="

# ---- Parametri modificabili via env -----------------------------------------
REPO_URL="${REPO_URL:-https://github.com/fraidotube/testmachine.git}"
BRANCH="${BRANCH:-main}"
CONFIGURE_WAN="${CONFIGURE_WAN:-1}"

APP_DIR="/opt/netprobe"
APP_APPDIR="$APP_DIR/app"
VENV_DIR="$APP_DIR/venv"

SYSTEM_USER="netprobe"
SYSTEM_GROUP="netprobe"

# ---- Funzioni utili ---------------------------------------------------------
need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Esegui come root (sudo -i)."
    exit 1
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends "$@"
}

ensure_user_group() {
  getent group  "$SYSTEM_GROUP" >/dev/null || groupadd --system "$SYSTEM_GROUP"
  getent passwd "$SYSTEM_USER"  >/dev/null || useradd  --system -g "$SYSTEM_GROUP" -d "$APP_DIR" -s /usr/sbin/nologin "$SYSTEM_USER"
}

list_phys_ifaces() {
  # 1) nmcli se presente
  if command -v nmcli >/dev/null 2>&1; then
    nmcli -t -f DEVICE,TYPE,STATE dev status 2>/dev/null \
    | awk -F: '($2=="ethernet" || $2=="wifi") && $1!="lo"{print $1}'
    return 0
  fi
  # 2) fallback: ip link
  ip -o link show | awk -F': ' '$2!="lo"{print $2}' | cut -d'@' -f1
}

ensure_dirs_and_creds() {
  mkdir -p /etc/netprobe
  chown root:"$SYSTEM_GROUP" /etc/netprobe
  chmod 0770 /etc/netprobe

  # users.json iniziale (admin/admin) se assente
  if [ ! -f /etc/netprobe/users.json ]; then
    python3 - <<'PY'
import json, os, secrets, hashlib, pathlib
p=pathlib.Path("/etc/netprobe/users.json")
p.parent.mkdir(parents=True, exist_ok=True)
def pbk(password,salt,rounds=260000): return hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),rounds).hex()
def h(pw): s=secrets.token_hex(16); r=260000; return f"pbkdf2_sha256${r}${s}${pbk(pw,s,r)}"
data={"users":{"admin":{"pw":h("admin"),"roles":["admin"]}}}
tmp=p.with_suffix(".tmp")
with open(tmp,"w") as f: json.dump(data,f,indent=2)
os.replace(tmp,p)
PY
    chown root:"$SYSTEM_GROUP" /etc/netprobe/users.json
    chmod 0660 /etc/netprobe/users.json
  fi

  # session.key (leggibile dal gruppo)
  if [ ! -f /etc/netprobe/session.key ]; then
    head -c 32 /dev/urandom >/etc/netprobe/session.key
    chown root:"$SYSTEM_GROUP" /etc/netprobe/session.key
    chmod 0640 /etc/netprobe/session.key
  fi
}

install_packages() {
  apt_install ca-certificates curl git sudo \
              python3 python3-venv python3-pip \
              apache2 \
              network-manager \
              smokeping fping
  systemctl enable --now NetworkManager || true
}

deploy_repo_and_venv() {
  if [ -d "$APP_DIR/.git" ]; then
    echo "[GIT] Repo esistente, aggiornamento..."
    sudo -u "$SYSTEM_USER" -H bash -lc "cd '$APP_DIR' && git fetch --all && git checkout '$BRANCH' && git pull --ff-only"
  else
    echo "[GIT] Clono $REPO_URL in $APP_DIR"
    git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
    chown -R "$SYSTEM_USER:$SYSTEM_GROUP" "$APP_DIR"
  fi

  if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    chown -R "$SYSTEM_USER:$SYSTEM_GROUP" "$VENV_DIR"
  fi

  "$VENV_DIR/bin/pip" install -U pip wheel
  "$VENV_DIR/bin/pip" install fastapi "uvicorn[standard]" jinja2 python-multipart
}

install_systemd_service() {
  cat >/etc/systemd/system/netprobe-api.service <<'EOF'
[Unit]
Description=TestMachine API (FastAPI)
After=network.target

[Service]
User=netprobe
Group=netprobe
WorkingDirectory=/opt/netprobe/app
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/netprobe/venv/bin/uvicorn main:app --host 127.0.0.1 --port 9000
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now netprobe-api
}

configure_apache() {
  # Abilita ascolto su 8080 se mancante
  if ! grep -qE '^\s*Listen\s+8080' /etc/apache2/ports.conf; then
    echo "Listen 8080" >> /etc/apache2/ports.conf
  fi
  a2enmod proxy proxy_http headers >/dev/null

  cat >/etc/apache2/sites-available/testmachine.conf <<'EOF'
<VirtualHost *:8080>
  ServerName testmachine.local

  ProxyPreserveHost On
  RequestHeader set X-Forwarded-Proto "http"

  ProxyPass        / http://127.0.0.1:9000/
  ProxyPassReverse / http://127.0.0.1:9000/

  ErrorLog ${APACHE_LOG_DIR}/testmachine-error.log
  CustomLog ${APACHE_LOG_DIR}/testmachine-access.log combined
</VirtualHost>
EOF

  a2ensite testmachine.conf >/dev/null
  systemctl reload apache2
}

configure_smokeping() {
  # Targets vuoti con blocco gestito
  TGT=/etc/smokeping/config.d/Targets
  if [ ! -f "$TGT" ]; then
    cat >"$TGT" <<'EOF'
*** Targets ***

# BEGIN_TM_MANAGED
+ TestMachine
menu = TestMachine
title = Hosts gestiti da TestMachine

# END_TM_MANAGED
EOF
  fi
  mkdir -p /var/lib/smokeping/TestMachine
  chown -R smokeping:smokeping /var/lib/smokeping/TestMachine || true
  /usr/sbin/smokeping --check || true
  systemctl reload smokeping || true
}

configure_sudoers() {
  S=/etc/sudoers.d/testmachine
  cat >"$S" <<'EOF'
Defaults:netprobe !requiretty
netprobe ALL=(root) NOPASSWD: /bin/systemctl reload smokeping, /bin/systemctl restart smokeping, /usr/bin/nmcli *, /usr/bin/install *
EOF
  chmod 0440 "$S"
  visudo -cf "$S"
}

configure_wan_dhcp() {
  [ "$CONFIGURE_WAN" = "1" ] || { echo "CONFIGURE_WAN=0 → salto config WAN"; return; }

  IFACE="$(list_phys_ifaces | head -n1 || true)"
  if [ -z "${IFACE:-}" ]; then
    echo "Nessuna interfaccia fisica trovata, salto configurazione WAN."
    return
  fi

  echo "Configuro WAN DHCP su: $IFACE"
  nmcli dev disconnect "$IFACE" >/dev/null 2>&1 || true
  nmcli con del "wan0" >/dev/null 2>&1 || true
  # crea connessione ethernet DHCP
  nmcli con add type ethernet ifname "$IFACE" con-name "wan0" ipv4.method auto ipv6.method ignore >/dev/null
  nmcli con mod "wan0" ipv4.dns "1.1.1.1 8.8.8.8" ipv4.ignore-auto-dns yes >/dev/null
  nmcli con up "wan0" || nmcli dev connect "$IFACE" || true
}

final_report() {
  echo
  echo "=== Installazione completata ==="
  echo " - Log: $LOG"
  echo " - Web UI: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080/"
  echo " - Login iniziale: admin / admin"
  echo
}

# ---- Esecuzione -------------------------------------------------------------
need_root
install_packages
ensure_user_group
ensure_dirs_and_creds
deploy_repo_and_venv
install_systemd_service
configure_apache
configure_smokeping
configure_sudoers
configure_wan_dhcp
final_report

exit 0
