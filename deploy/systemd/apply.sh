#!/usr/bin/env bash
set -euo pipefail

# --- requisiti ---
if [[ $EUID -ne 0 ]]; then
  echo "Esegui come root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSTEMD_DIR="/etc/systemd/system"

echo "[i] Copio unit file in ${SYSTEMD_DIR}…"

install -D -m 0644 "${SCRIPT_DIR}/netprobe-api.service"          "${SYSTEMD_DIR}/netprobe-api.service"
install -D -m 0644 "${SCRIPT_DIR}/netprobe-api.socket"            "${SYSTEMD_DIR}/netprobe-api.socket"
install -D -m 0644 "${SCRIPT_DIR}/netprobe-flow-collector.service" "${SYSTEMD_DIR}/netprobe-flow-collector.service"
install -D -m 0644 "${SCRIPT_DIR}/netprobe-flow-exporter@.service" "${SYSTEMD_DIR}/netprobe-flow-exporter@.service"

# Copia eventuali drop-in se presenti nella cartella del repo
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

echo "[i] systemctl daemon-reload"
systemctl daemon-reload

# --- prerequisiti runtime per i flussi ---
echo "[i] Preparo directory e symlink flussi…"
install -d -m 2770 -o netprobe -g netprobe /var/lib/nfsen-ng/profiles-data/live/netprobe
ln -snf /var/lib/nfsen-ng/profiles-data/live/netprobe /var/lib/netprobe/flows

# --- chiudo eventuali nfcapd orfani che tengono la 2055 ---
pkill -f '(^| )nfcapd( |$)' 2>/dev/null || true
sleep 0.2

# --- API: socket-activation ---
echo "[i] Abilito e avvio netprobe-api.socket (service partirà on-demand)…"
systemctl enable --now netprobe-api.socket
# La service può restare disabilitata; verrà attivata dal socket
systemctl stop netprobe-api 2>/dev/null || true

# --- Collector: abilitato e avviato al boot ---
echo "[i] Abilito e (ri)avvio il collector…"
systemctl enable --now netprobe-flow-collector || true

# --- Exporter: NESSUNA istanza abilitata al boot; la UI le controlla ---
echo "[i] Stoppo ed eventuale disable di istanze exporter residue…"
systemctl stop 'netprobe-flow-exporter@*' 2>/dev/null || true
# disabilito link accidentalmente creati:
for link in /etc/systemd/system/multi-user.target.wants/netprobe-flow-exporter@*.service; do
  [[ -L "$link" ]] && systemctl disable "$(basename "$link")" || true
done

echo "[i] Stato riassunto:"
systemctl is-enabled netprobe-api.socket || true
systemctl is-active  netprobe-api.socket || true
systemctl is-enabled netprobe-flow-collector || true
systemctl is-active  netprobe-flow-collector || true

echo
echo "[✓] Deploy completato."
echo "   - API: socket su 127.0.0.1:9000 (la service parte al primo accesso)"
echo "   - Collector: attivo e abilitato al boot"
echo "   - Exporter: avvialo dalla UI (Start exporter) oppure: systemctl start netprobe-flow-exporter@ens4"
