#!/usr/bin/env bash
set -euo pipefail
UNITDIR=/etc/systemd/system
cd "$(dirname "$0")"

sudo install -m 0644 netprobe-api.socket               "$UNITDIR/netprobe-api.socket"
sudo install -m 0644 netprobe-api.service              "$UNITDIR/netprobe-api.service"
sudo install -m 0644 netprobe-flow-collector.service   "$UNITDIR/netprobe-flow-collector.service"
sudo install -m 0644 'netprobe-flow-exporter@.service' "$UNITDIR/netprobe-flow-exporter@.service"

sudo systemctl daemon-reload
sudo systemctl enable --now netprobe-api.socket
sudo systemctl enable --now netprobe-flow-collector
# NB: l’exporter NON lo abilitiamo: la UI lo avvia/ferma quando serve.
echo "Done. API socket + collector attivi. Exporter gestito da UI."
