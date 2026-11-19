#!/usr/bin/env bash
set -euo pipefail

MTVEIL_REPO="${MTVEIL_REPO:-RsNest/mtevil}"
MTVEIL_VERSION="${MTVEIL_VERSION:-v0.1.0-alpha.2}"
MTVEIL_DIR="${MTVEIL_DIR:-$HOME/mtveil}"
REPO_LOWER="$(printf '%s' "$MTVEIL_REPO" | tr '[:upper:]' '[:lower:]')"
MTVEIL_IMAGE="${MTVEIL_IMAGE:-ghcr.io/${REPO_LOWER}:${MTVEIL_VERSION}}"

missing=()
if ! command -v docker >/dev/null 2>&1; then
  missing+=("docker (https://docs.docker.com/engine/install/)")
elif ! docker compose version >/dev/null 2>&1; then
  missing+=("docker-compose-plugin (Docker Compose v2)")
fi
if ! command -v python3 >/dev/null 2>&1; then
  missing+=("python3")
fi
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  missing+=("curl или wget")
fi

if [ "${#missing[@]}" -gt 0 ]; then
  echo "Не хватает обязательных компонентов:" >&2
  for item in "${missing[@]}"; do
    echo "  - $item" >&2
  done
  echo "Установите их (для Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y python3 curl) и запустите скрипт снова." >&2
  exit 1
fi

mkdir -p "$MTVEIL_DIR"
SETUP_URL="https://github.com/${MTVEIL_REPO}/releases/download/${MTVEIL_VERSION}/setup.py"
echo "Скачивание мастера настройки mtveil (${MTVEIL_VERSION})..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$SETUP_URL" -o "${MTVEIL_DIR}/setup.py"
else
  wget -qO "${MTVEIL_DIR}/setup.py" "$SETUP_URL"
fi

echo "Загрузка Docker-образа ${MTVEIL_IMAGE}..."
docker pull "$MTVEIL_IMAGE"

exec python3 "${MTVEIL_DIR}/setup.py" \
  --dir "$MTVEIL_DIR" \
  --image "$MTVEIL_IMAGE" \
  --no-build \
  "$@"
