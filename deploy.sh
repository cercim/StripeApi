#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  deploy.sh — single-command Gate API deploy
#  Usage: bash deploy.sh [--port 80] [--workers 4]
#
#  Auto-detects Docker. If Docker is present → docker-compose.
#  If no Docker → Python venv + systemd service.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────
PORT=80
WORKERS=350
SERVICE_NAME="gate-api"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
die()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)    PORT="$2";    shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}   Gate API — Deploy Script${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
info "Directory : $DIR"
info "Port      : $PORT"
info "Workers   : $WORKERS"
echo ""

# ── check if running as root (needed for port 80) ─────────────────
if [[ "$PORT" -lt 1024 && "$EUID" -ne 0 ]]; then
  warn "Port $PORT requires root. Re-running with sudo..."
  exec sudo bash "$0" --port "$PORT" --workers "$WORKERS"
fi

cd "$DIR"

# ══════════════════════════════════════════════════════════════════
#  PATH A — Docker
# ══════════════════════════════════════════════════════════════════
if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
  info "Docker detected → using docker-compose"

  # update port in compose if changed
  sed -i "s/\"[0-9]*:80\"/\"${PORT}:80\"/" docker-compose.yml
  sed -i "s/WORKERS: [0-9]*/WORKERS: ${WORKERS}/" docker-compose.yml

  # stop old container if running
  docker-compose down --remove-orphans 2>/dev/null || true

  info "Building image..."
  docker-compose build --no-cache

  info "Starting container..."
  docker-compose up -d

  ok "Gate API is live!"
  echo ""
  echo -e "  ${GREEN}http://YOUR_VPS_IP:${PORT}/stripe?=CC|MM|YY|CVV${RESET}"
  echo ""
  echo -e "  Logs    : ${CYAN}docker-compose logs -f${RESET}"
  echo -e "  Stop    : ${CYAN}docker-compose down${RESET}"
  echo -e "  Restart : ${CYAN}docker-compose restart${RESET}"
  exit 0
fi

# ══════════════════════════════════════════════════════════════════
#  PATH B — No Docker → Python venv + systemd
# ══════════════════════════════════════════════════════════════════
info "Docker not found → using Python venv + systemd"

# ── Python ────────────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv gcc libssl-dev curl nginx
ok "Python3: $(python3 --version)"

# ── nginx config ──────────────────────────────────────────────────
NGINX_CONF="/etc/nginx/sites-available/gate-api"
info "Writing nginx config → $NGINX_CONF"

cat > "$NGINX_CONF" <<NGINXEOF
upstream gate_backend {
    server 127.0.0.1:8000;
    keepalive 512;
}

limit_req_zone \$binary_remote_addr zone=gate:10m rate=200r/s;

server {
    listen 80;

    location = /health {
        proxy_pass http://gate_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    location / {
        limit_req zone=gate burst=500 nodelay;
        proxy_pass         http://gate_backend;
        proxy_http_version 1.1;
        proxy_set_header   Connection       "";
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_connect_timeout 10s;
        proxy_send_timeout    95s;
        proxy_read_timeout    95s;
        error_page 502 503 504 @backend_down;
    }

    location @backend_down {
        default_type application/json;
        return 503 '{"status":"error","message":"All workers busy — retry in a moment","reason":"overloaded","time":0}';
    }
}
NGINXEOF

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/gate-api
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx && systemctl enable nginx --quiet
ok "nginx configured and running"

# ── venv ──────────────────────────────────────────────────────────
VENV="$DIR/.venv"
if [[ ! -d "$VENV" ]]; then
  info "Creating venv..."
  python3 -m venv "$VENV"
fi

info "Installing requirements..."
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$DIR/requirements.txt"
ok "Dependencies installed"

# ── stop old service if running ───────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  info "Stopping existing $SERVICE_NAME service..."
  systemctl stop "$SERVICE_NAME"
fi

# ── systemd service file ──────────────────────────────────────────
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "Writing systemd unit → $UNIT_FILE"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Gate API Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${DIR}
ExecStart=${VENV}/bin/python3 ${DIR}/server.py
Environment=PORT=8000
Environment=WORKERS=${WORKERS}
Environment=HOST=0.0.0.0
Environment=LOG_LEVEL=info
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
systemctl start  "$SERVICE_NAME"

sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Gate API is live via systemd!"
  echo ""
  echo -e "  ${GREEN}http://YOUR_VPS_IP:${PORT}/stripe?=CC|MM|YY|CVV${RESET}"
  echo ""
  echo -e "  Logs    : ${CYAN}journalctl -u ${SERVICE_NAME} -f${RESET}"
  echo -e "  Stop    : ${CYAN}systemctl stop ${SERVICE_NAME}${RESET}"
  echo -e "  Restart : ${CYAN}systemctl restart ${SERVICE_NAME}${RESET}"
  echo -e "  Status  : ${CYAN}systemctl status ${SERVICE_NAME}${RESET}"
else
  die "Service failed to start. Check: journalctl -u ${SERVICE_NAME} -xe"
fi
