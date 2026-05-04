#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-x86_64-pc-windows-gnu}"
PROFILE="${PROFILE:-release}"
FEATURES="${FEATURES:-default-feature}"
PACKAGE="${PACKAGE:-sdl-cli}"

if [[ "${TARGET}" != "x86_64-pc-windows-gnu" ]]; then
  echo "build-windows-local.sh defaults to local Windows GNU target; got TARGET=${TARGET}" >&2
fi

if [[ "${PROFILE}" != "debug" && "${PROFILE}" != "release" ]]; then
  echo "PROFILE must be debug or release" >&2
  exit 1
fi

echo "[local-build] target=${TARGET} profile=${PROFILE} package=${PACKAGE} features=${FEATURES}"
rustup target add "${TARGET}"

if [[ "${PROFILE}" == "release" ]]; then
  cargo build --package "${PACKAGE}" --target "${TARGET}" --release --features "${FEATURES}"
else
  cargo build --package "${PACKAGE}" --target "${TARGET}" --features "${FEATURES}"
fi
