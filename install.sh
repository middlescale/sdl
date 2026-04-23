#!/usr/bin/env bash
set -euo pipefail

log_step() {
  printf '[install] %s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

Options:
  --source-dir <dir>    Directory containing sdl and sdl-service binaries
  --install-dir <dir>   Install root for binaries and env files (default: /opt/sdl)
  --link-dir <dir>      Directory for sdl/sdl-service symlinks (default: /usr/local/bin)
  --service-name <name> systemd service name (default: sdl-service)
  --user <name>         Non-root user that should own env files and command.sock
  -h, --help            Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}"
INSTALL_DIR="/opt/sdl"
LINK_DIR="/usr/local/bin"
SERVICE_NAME="sdl-service"
TARGET_USER="${SUDO_USER:-root}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      SOURCE_DIR="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --link-dir)
      LINK_DIR="$2"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="$2"
      shift 2
      ;;
    --user)
      TARGET_USER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh must run as root (for example: sudo ./install.sh)" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "install.sh currently supports only systemd hosts (missing systemctl)" >&2
  exit 1
fi

if [[ ! -d /run/systemd/system ]]; then
  echo "install.sh currently supports only systemd hosts (/run/systemd/system not found)" >&2
  exit 1
fi

if [[ ! -x "${SOURCE_DIR}/sdl" ]]; then
  echo "missing executable: ${SOURCE_DIR}/sdl" >&2
  exit 1
fi
if [[ ! -x "${SOURCE_DIR}/sdl-service" ]]; then
  echo "missing executable: ${SOURCE_DIR}/sdl-service" >&2
  exit 1
fi

TARGET_UID="$(id -u "${TARGET_USER}")"
TARGET_GID="$(id -g "${TARGET_USER}")"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

log_step "Stopping existing service if present: ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true

log_step "Preparing install directories under ${INSTALL_DIR}"
install -d -m 755 "${INSTALL_DIR}"
install -d -m 700 "${INSTALL_DIR}/env"
install -d -m 755 "${LINK_DIR}"

log_step "Installing sdl and sdl-service binaries"
install -m 755 "${SOURCE_DIR}/sdl" "${INSTALL_DIR}/sdl"
install -m 755 "${SOURCE_DIR}/sdl-service" "${INSTALL_DIR}/sdl-service"

log_step "Copying persisted env files (if present)"
for name in config.json device-id; do
  if [[ -f "${SOURCE_DIR}/env/${name}" ]]; then
    install -m 600 "${SOURCE_DIR}/env/${name}" "${INSTALL_DIR}/env/${name}"
  fi
done

log_step "Applying env ownership for ${TARGET_USER} (${TARGET_UID}:${TARGET_GID})"
chown "${TARGET_UID}:${TARGET_GID}" "${INSTALL_DIR}/env"
chmod 700 "${INSTALL_DIR}/env"
for name in config.json device-id; do
  if [[ -f "${INSTALL_DIR}/env/${name}" ]]; then
    chown "${TARGET_UID}:${TARGET_GID}" "${INSTALL_DIR}/env/${name}"
    chmod 600 "${INSTALL_DIR}/env/${name}"
  fi
done

log_step "Updating CLI symlinks in ${LINK_DIR}"
ln -sfn "${INSTALL_DIR}/sdl" "${LINK_DIR}/sdl"
ln -sfn "${INSTALL_DIR}/sdl-service" "${LINK_DIR}/sdl-service"

log_step "Writing systemd unit: ${UNIT_PATH}"
cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=SDL Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/sdl-service
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
KillMode=control-group
Environment=RUST_LOG=info
Environment=SUDO_UID=${TARGET_UID}
Environment=SUDO_GID=${TARGET_GID}
Environment=SDL_DEVICE_KEY_PATH=${INSTALL_DIR}/env/device.key

[Install]
WantedBy=multi-user.target
EOF

log_step "Reloading systemd manager"
systemctl daemon-reload
log_step "Enabling and starting ${SERVICE_NAME} (this may take a few seconds)"
systemctl enable --now "${SERVICE_NAME}"

echo "Installed SDL to ${INSTALL_DIR}"
echo "Symlinked CLI tools into ${LINK_DIR}"
echo "Started systemd service ${SERVICE_NAME}"
echo "env ownership user: ${TARGET_USER} (${TARGET_UID}:${TARGET_GID})"
