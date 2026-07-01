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
  --service-name <name> Service name/label basename (default: sdl-service)
  --user <name>         Non-root user that should own env files and command.sock
  --overwrite-config    Replace an existing env/config.json with the installer copy
  --preserve-config     Keep an existing env/config.json without prompting (default)
  -h, --help            Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}"
INSTALL_DIR="/opt/sdl"
LINK_DIR="/usr/local/bin"
SERVICE_NAME="sdl-service"
TARGET_USER="${SUDO_USER:-root}"
OS_NAME="$(uname -s)"
CONFIG_INSTALL_MODE="preserve"
INSTALLER_CONFIG_VERSION=2
CONFIG_VERSION_FALLBACK=1

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
    --overwrite-config)
      CONFIG_INSTALL_MODE="overwrite"
      shift
      ;;
    --preserve-config)
      CONFIG_INSTALL_MODE="preserve"
      shift
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

copy_env_file_if_present() {
  local name="$1"
  if [[ -f "${SOURCE_DIR}/env/${name}" ]]; then
    install -m 600 "${SOURCE_DIR}/env/${name}" "${INSTALL_DIR}/env/${name}"
  fi
}

generate_device_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
    return 0
  fi

  local hex
  hex="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s-%s-%s-%s-%s\n' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

ensure_device_id_file() {
  local path="${INSTALL_DIR}/env/device-id"
  if [[ -f "${path}" ]]; then
    if [[ ! -s "${path}" ]]; then
      echo "invalid empty device-id at ${path}; remove it to generate a new identity" >&2
      exit 1
    fi
    log_step "Keeping existing device-id from install env"
    return 0
  fi

  log_step "Generating persistent device-id"
  generate_device_id > "${path}"
  chmod 600 "${path}"
}

ensure_device_key_file() {
  local path="${INSTALL_DIR}/env/device.key"
  if [[ -f "${path}" ]]; then
    local size
    size="$(wc -c < "${path}" | tr -d ' ')"
    if [[ "${size}" != "32" ]]; then
      echo "invalid device key length at ${path}: expected 32 bytes, got ${size}" >&2
      exit 1
    fi
    log_step "Keeping existing device key from install env"
    return 0
  fi

  log_step "Generating persistent device key"
  dd if=/dev/urandom of="${path}" bs=32 count=1 2>/dev/null
  chmod 600 "${path}"
}

backup_existing_file() {
  local path="$1"
  local backup_path="${path}.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "${path}" "${backup_path}"
  log_step "Backed up ${path} to ${backup_path}"
}

config_version_of() {
  local path="$1"
  local version
  if [[ ! -f "${path}" ]]; then
    return 1
  fi
  version="$(sed -nE 's/.*"config_version"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "${path}" | head -n 1)"
  if [[ -z "${version}" ]]; then
    printf '%s\n' "${CONFIG_VERSION_FALLBACK}"
  else
    printf '%s\n' "${version}"
  fi
}

json_string_value_of() {
  local path="$1"
  local key="$2"
  if [[ ! -f "${path}" ]]; then
    return 1
  fi
  sed -nE 's/.*"'"${key}"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "${path}" | head -n 1
}

encode_profile_name() {
  local input="$1"
  local out=""
  local i ch hex
  LC_ALL=C
  for ((i = 0; i < ${#input}; i++)); do
    ch="${input:i:1}"
    case "${ch}" in
      [a-zA-Z0-9._-])
        out+="${ch}"
        ;;
      *)
        printf -v hex '%02X' "'${ch}"
        out+="%${hex}"
        ;;
    esac
  done
  if [[ -z "${out}" ]]; then
    out="_"
  fi
  printf '%s\n' "${out}"
}

migrate_config_file_v1_to_v2() {
  local target_path="$1"
  if [[ "$(config_version_of "${target_path}")" != "1" ]]; then
    return 1
  fi

  log_step "Migrating existing config.json from config_version=1 to config_version=2"
  backup_existing_file "${target_path}"
  local tmp_path
  tmp_path="$(mktemp "${target_path}.tmp.XXXXXX")"
  sed -E \
    -e 's/"config_version"[[:space:]]*:[[:space:]]*1/"config_version": 2/' \
    -e 's/"use_channel"[[:space:]]*:[[:space:]]*"all"/"use_channel": "auto"/' \
    -e 's/"ports"[[:space:]]*:[[:space:]]*null/"ports": [29873]/' \
    -e '/"in_ips"[[:space:]]*:/d' \
    -e '/"out_ips"[[:space:]]*:/d' \
    "${target_path}" > "${tmp_path}"
  chmod 600 "${tmp_path}"
  mv "${tmp_path}" "${target_path}"
  return 0
}

sanitize_config_file_v2() {
  local target_path="$1"
  if [[ ! -f "${target_path}" ]]; then
    return 0
  fi
  if [[ "$(config_version_of "${target_path}")" != "2" ]]; then
    return 0
  fi
  if ! grep -Eq '"in_ips"[[:space:]]*:|"out_ips"[[:space:]]*:|"use_channel"[[:space:]]*:[[:space:]]*"all"|"ports"[[:space:]]*:[[:space:]]*null' "${target_path}"; then
    return 0
  fi

  log_step "Sanitizing config schema for ${target_path}"
  backup_existing_file "${target_path}"
  local tmp_path
  tmp_path="$(mktemp "${target_path}.tmp.XXXXXX")"
  sed -E \
    -e 's/"use_channel"[[:space:]]*:[[:space:]]*"all"/"use_channel": "auto"/' \
    -e 's/"ports"[[:space:]]*:[[:space:]]*null/"ports": [29873]/' \
    -e '/"in_ips"[[:space:]]*:/d' \
    -e '/"out_ips"[[:space:]]*:/d' \
    "${target_path}" > "${tmp_path}"
  chmod 600 "${tmp_path}"
  mv "${tmp_path}" "${target_path}"
}

sanitize_profile_configs() {
  local profile
  if [[ ! -d "${INSTALL_DIR}/profiles" ]]; then
    return 0
  fi
  while IFS= read -r profile; do
    sanitize_config_file_v2 "${profile}"
  done < <(find "${INSTALL_DIR}/profiles" -maxdepth 1 -type f -name '*.json' -print)
}

migrate_legacy_config_to_profile_if_possible() {
  local target_path="${INSTALL_DIR}/env/config.json"
  local state_path="${INSTALL_DIR}/env/service-state.json"
  if [[ ! -f "${target_path}" ]]; then
    return 0
  fi
  if grep -Eq '"active_user_id"[[:space:]]*:' "${target_path}"; then
    return 0
  fi
  if [[ "$(config_version_of "${target_path}")" != "2" ]]; then
    return 0
  fi

  local user_id profile_name profile_path tmp_profile tmp_active
  user_id="$(json_string_value_of "${state_path}" "authenticated_user_id" || true)"
  if [[ -z "${user_id}" ]]; then
    return 0
  fi

  profile_name="$(encode_profile_name "${user_id}")"
  profile_path="${INSTALL_DIR}/profiles/${profile_name}.json"
  if [[ ! -f "${profile_path}" ]]; then
    log_step "Migrating legacy config.json to profile for user_id=${user_id}"
    tmp_profile="$(mktemp "${profile_path}.tmp.XXXXXX")"
    if grep -Eq '"user_id"[[:space:]]*:' "${target_path}"; then
      sed -E 's/"user_id"[[:space:]]*:[[:space:]]*null/"user_id": "'"${user_id}"'"/' "${target_path}" > "${tmp_profile}"
    else
      sed -E '0,/"config_version"[[:space:]]*:[[:space:]]*2/s//"config_version": 2,\n  "user_id": "'"${user_id}"'"/' "${target_path}" > "${tmp_profile}"
    fi
    chmod 600 "${tmp_profile}"
    mv "${tmp_profile}" "${profile_path}"
  fi

  backup_existing_file "${target_path}"
  tmp_active="$(mktemp "${target_path}.tmp.XXXXXX")"
  cat > "${tmp_active}" <<EOF
{
  "config_version": 2,
  "active_user_id": "${user_id}"
}
EOF
  chmod 600 "${tmp_active}"
  mv "${tmp_active}" "${target_path}"
}

overwrite_config_file() {
  local source_path="$1"
  local target_path="$2"
  if [[ -f "${target_path}" ]]; then
    backup_existing_file "${target_path}"
  fi
  install -m 600 "${source_path}" "${target_path}"
}

is_interactive_install() {
  [[ -t 0 && -t 1 ]]
}

prompt_overwrite_existing_config() {
  local prompt_message="$1"
  local reply
  while true; do
    printf '%s [y/N] ' "${prompt_message}" >&2
    if ! IFS= read -r reply; then
      return 1
    fi
    case "${reply}" in
      [Yy]|[Yy][Ee][Ss])
        return 0
        ;;
      ""|[Nn]|[Nn][Oo])
        return 1
        ;;
      *)
        echo "Please answer y or n." >&2
        ;;
    esac
  done
}

install_config_file_if_present() {
  local source_path="${SOURCE_DIR}/env/config.json"
  local target_path="${INSTALL_DIR}/env/config.json"
  local source_version existing_version
  if [[ ! -f "${source_path}" ]]; then
    log_step "No installer env/config.json found; keeping any existing config.json"
    if [[ -f "${target_path}" ]]; then
      migrate_config_file_v1_to_v2 "${target_path}" || true
    fi
    return 0
  fi
  if [[ ! -f "${target_path}" ]]; then
    log_step "Installing initial config.json"
    install -m 600 "${source_path}" "${target_path}"
    return 0
  fi
  if cmp -s "${source_path}" "${target_path}"; then
    log_step "Existing config.json already matches installer config"
    return 0
  fi

  source_version="$(config_version_of "${source_path}")"
  existing_version="$(config_version_of "${target_path}")"
  if [[ "${source_version}" =~ ^[0-9]+$ && "${source_version}" -lt "${INSTALLER_CONFIG_VERSION}" && "${CONFIG_INSTALL_MODE}" != "overwrite" ]]; then
    log_step "Ignoring older installer env/config.json with config_version=${source_version}; current installer schema is config_version=${INSTALLER_CONFIG_VERSION}"
    return 0
  fi
  if [[ -n "${source_version}" && -n "${existing_version}" && "${source_version}" != "${existing_version}" ]]; then
    if [[ "${existing_version}" == "1" && "${source_version}" == "2" ]] && migrate_config_file_v1_to_v2 "${target_path}"; then
      return 0
    fi
    if [[ "${existing_version}" =~ ^[0-9]+$ && "${source_version}" =~ ^[0-9]+$ && "${existing_version}" -gt "${source_version}" && "${CONFIG_INSTALL_MODE}" != "overwrite" ]]; then
      log_step "Keeping existing config.json with newer config_version=${existing_version}; installer config uses config_version=${source_version}"
      return 0
    fi
    local mismatch_message="Existing config.json uses config_version=${existing_version}, installer config uses config_version=${source_version}. Keeping the old file may be incompatible with this build."
    if [[ "${CONFIG_INSTALL_MODE}" == "overwrite" ]]; then
      log_step "${mismatch_message}"
      overwrite_config_file "${source_path}" "${target_path}"
      return 0
    fi
    if is_interactive_install; then
      echo "${mismatch_message}" >&2
      if prompt_overwrite_existing_config "Overwrite existing config.json with the installer copy?"; then
        overwrite_config_file "${source_path}" "${target_path}"
        return 0
      fi
    fi
    echo "Refusing to continue with a possibly incompatible existing config.json. Review ${target_path} and rerun with --overwrite-config if you want to replace it." >&2
    exit 1
  fi

  if [[ "${CONFIG_INSTALL_MODE}" == "overwrite" ]]; then
    log_step "Replacing existing config.json (--overwrite-config)"
    overwrite_config_file "${source_path}" "${target_path}"
    return 0
  fi
  if is_interactive_install; then
    if prompt_overwrite_existing_config "Existing config.json found. Overwrite it with the installer copy?"; then
      overwrite_config_file "${source_path}" "${target_path}"
    else
      log_step "Keeping existing config.json"
    fi
    return 0
  fi
  log_step "Keeping existing config.json (default non-interactive behavior)"
}

apply_env_ownership() {
  log_step "Applying env ownership for ${TARGET_USER} (${TARGET_UID}:${TARGET_GID})"
  chown "${TARGET_UID}:${TARGET_GID}" "${INSTALL_DIR}/env"
  chmod 700 "${INSTALL_DIR}/env"
  chown "${TARGET_UID}:${TARGET_GID}" "${INSTALL_DIR}/profiles"
  chmod 700 "${INSTALL_DIR}/profiles"
  for name in config.json device-id device.key service-state.json; do
    if [[ -f "${INSTALL_DIR}/env/${name}" ]]; then
      chown "${TARGET_UID}:${TARGET_GID}" "${INSTALL_DIR}/env/${name}"
      chmod 600 "${INSTALL_DIR}/env/${name}"
    fi
  done
}

prepare_install_tree() {
  log_step "Preparing install directories under ${INSTALL_DIR}"
  install -d -m 755 "${INSTALL_DIR}"
  install -d -m 700 "${INSTALL_DIR}/env"
  install -d -m 700 "${INSTALL_DIR}/profiles"
  install -d -m 755 "${INSTALL_DIR}/log"
  install -d -m 755 "${LINK_DIR}"

  log_step "Installing sdl and sdl-service binaries"
  install -m 755 "${SOURCE_DIR}/sdl" "${INSTALL_DIR}/sdl"
  install -m 755 "${SOURCE_DIR}/sdl-service" "${INSTALL_DIR}/sdl-service"

  log_step "Copying persisted env files (if present)"
  for name in service-state.json; do
    copy_env_file_if_present "${name}"
  done
  install_config_file_if_present
  migrate_config_file_v1_to_v2 "${INSTALL_DIR}/env/config.json" || true
  sanitize_config_file_v2 "${INSTALL_DIR}/env/config.json"
  migrate_legacy_config_to_profile_if_possible
  sanitize_profile_configs
  ensure_device_id_file
  ensure_device_key_file

  apply_env_ownership

  log_step "Updating CLI symlinks in ${LINK_DIR}"
  ln -sfn "${INSTALL_DIR}/sdl" "${LINK_DIR}/sdl"
  ln -sfn "${INSTALL_DIR}/sdl-service" "${LINK_DIR}/sdl-service"
}

install_systemd_service() {
  local unit_path="/etc/systemd/system/${SERVICE_NAME}.service"
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "install.sh currently supports only systemd hosts (missing systemctl)" >&2
    exit 1
  fi
  if [[ ! -d /run/systemd/system ]]; then
    echo "install.sh currently supports only systemd hosts (/run/systemd/system not found)" >&2
    exit 1
  fi

  log_step "Stopping existing service if present: ${SERVICE_NAME}"
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true

  prepare_install_tree

  log_step "Writing systemd unit: ${unit_path}"
  cat > "${unit_path}" <<EOF
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
}

install_launchd_service() {
  local launchd_label="net.middlescale.${SERVICE_NAME}"
  local plist_path="/Library/LaunchDaemons/${launchd_label}.plist"

  if ! command -v launchctl >/dev/null 2>&1; then
    echo "install.sh currently supports only launchd hosts (missing launchctl)" >&2
    exit 1
  fi

  log_step "Stopping existing launchd service if present: ${launchd_label}"
  launchctl bootout system "${plist_path}" >/dev/null 2>&1 || true

  prepare_install_tree

  log_step "Writing launchd plist: ${plist_path}"
  cat > "${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${launchd_label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/sdl-service</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${INSTALL_DIR}/log/${SERVICE_NAME}.out.log</string>
  <key>StandardErrorPath</key>
  <string>${INSTALL_DIR}/log/${SERVICE_NAME}.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
    <key>SUDO_UID</key>
    <string>${TARGET_UID}</string>
    <key>SUDO_GID</key>
    <string>${TARGET_GID}</string>
    <key>SDL_DEVICE_KEY_PATH</key>
    <string>${INSTALL_DIR}/env/device.key</string>
  </dict>
</dict>
</plist>
EOF

  chown root:wheel "${plist_path}"
  chmod 644 "${plist_path}"

  log_step "Bootstrapping launchd service ${launchd_label}"
  launchctl bootstrap system "${plist_path}"
  launchctl enable "system/${launchd_label}" >/dev/null 2>&1 || true
  launchctl kickstart -k "system/${launchd_label}"

  echo "Installed SDL to ${INSTALL_DIR}"
  echo "Symlinked CLI tools into ${LINK_DIR}"
  echo "Started launchd service ${launchd_label}"
  echo "Logs: ${INSTALL_DIR}/log/${SERVICE_NAME}.out.log / ${INSTALL_DIR}/log/${SERVICE_NAME}.err.log"
  echo "env ownership user: ${TARGET_USER} (${TARGET_UID}:${TARGET_GID})"
}

case "${OS_NAME}" in
  Linux)
    install_systemd_service
    ;;
  Darwin)
    install_launchd_service
    ;;
  *)
    echo "install.sh currently supports only Linux(systemd) and macOS(launchd) hosts (detected: ${OS_NAME})" >&2
    exit 1
    ;;
esac
