#!/usr/bin/env bash
set -Eeuo pipefail

log(){ echo "[apply] $*"; }

# --- requisiti ---
if [[ $EUID -ne 0 ]]; then
  echo "Esegui come root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSTEMD_DIR="/etc/systemd/system"

UNIT_API_SVC="netprobe-api.service"
UNIT_API_SOCK="netprobe-api.socket"
UNIT_COLLECTOR="netprobe-flow-collector.service"
UNIT_EXPORTER_TMPL="netprobe-flow-exporter@.service"

# --- copia unit file ---
log "Copio unit file in ${SYSTEMD_DIR}…"
install -D -m 0644 "${SCRIPT_DIR}/${UNIT_API_SVC}"       "${SYSTEMD_DIR}/${UNIT_API_SVC}"
install -D -m 0644 "${SCRIPT_DIR}/${UNIT_API_SOCK}"      "${SYSTEMD_DIR}/${UNIT_API_SOCK}"
install -D -m 0644 "${SCRIPT_DIR}/${UNIT_COLLECTOR}"     "${SYSTEMD_DIR}/${UNIT_COLLECTOR}"
install -D -m 0644 "${SCRIPT_DIR}/${UNIT_EXPORTER_TMPL}" "${SYSTEMD_DIR}/${UNIT_EXPORTER_TMPL}"

# --- copia eventuali drop-in dal repo ---
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

# --- crea drop-in minimi del collector se mancanti (rete pulita) ---
ensure_collector_dropins() {
  local d="${SYSTEMD_DIR}/netprobe-flow-collector.service.d"
  mkdir -p "$d"
  # libera porta 2055 sempre, se non già definito
  if [[ ! -s "${d}/10-free-port.conf" ]]; then
    cat >"${d}/10-free-port.conf" <<'EOF'
[Service]
ExecStartPre=/usr/bin/fuser -k -n udp 2055 || true
EOF
  fi
  # PIDFile + RuntimeDirectory + comando completo, se assente
  if [[ ! -s "${d}/override.conf" ]]; then
    cat >"${d}/override.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/nfcapd -w /var/lib/nfsen-ng/profiles-data/live/netprobe -S 1 -p 2055 -t 60 -P /run/netprobe/nfcapd.pid
RuntimeDirectory=netprobe
PIDFile=/run/netprobe/nfcapd.pid
Restart=on-failure
RestartSec=2
EOF
  fi
}
ensure_collector_dropins

# --- prepara directory e symlink flussi ---
log "Preparo directory/symlink flussi…"
# cartella padre (mancava sulle macchine vergini)
install -d -m 0770 -o netprobe -g netprobe /var/lib/netprobe
# destinazione stile nfsen-ng + ACL di gruppo
install -d -m 2770 -o netprobe -g netprobe /var/lib/nfsen-ng/profiles-data/live/netprobe
# symlink visto dalla UI
ln -snf /var/lib/nfsen-ng/profiles-data/live/netprobe /var/lib/netprobe/flows
chown -h netprobe:netprobe /var/lib/netprobe/flows || true

# --- ricarica unit ---
log "systemctl daemon-reload"
systemctl daemon-reload

# --- chiudi eventuali nfcapd orfani / libera 2055 ---
command -v fuser >/dev/null 2>&1 && /usr/bin/fuser -k -n udp 2055 || true
pkill -f '(^| )nfcapd( |$)' 2>/dev/null || true
sleep 0.2

# --- API: socket-activation ---
log "Abilito e avvio netprobe-api.socket (service partirà on-demand)…"
systemctl enable --now "${UNIT_API_SOCK}"
# la service può restare disabilitata; parte al primo accept()
systemctl stop "${UNIT_API_SVC}" 2>/dev/null || true

# --- Collector: abilita e parti ora ---
log "Abilito e (ri)avvio il collector…"
systemctl enable --now "${UNIT_COLLECTOR}" || true

# --- Exporter: nessuna istanza abilitata al boot ---
log "Stoppo ed eventuale disable di istanze exporter residue…"
systemctl stop 'netprobe-flow-exporter@*' 2>/dev/null || true
for link in /etc/systemd/system/multi-user.target.wants/netprobe-flow-exporter@*.service; do
  [[ -L "$link" ]] && systemctl disable "$(basename "$link")" || true
done

echo "[i] Stato riassunto:"
systemctl is-enabled "${UNIT_API_SOCK}" || true
systemctl is-active  "${UNIT_API_SOCK}" || true
systemctl is-enabled "${UNIT_COLLECTOR}" || true
systemctl is-active  "${UNIT_COLLECTOR}" || true

echo
echo "[✓] Deploy completato."
echo "   - API: socket su 127.0.0.1:9000 (la service parte al primo accesso)"
echo "   - Collector: attivo e abilitato al boot (nfcapd su UDP/2055)"
echo "   - Exporter: avvialo dalla UI o con: systemctl start netprobe-flow-exporter@ens4"
