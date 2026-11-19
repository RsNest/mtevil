#!/usr/bin/env bash
set -euo pipefail

MTEVIL_REPO="${MTEVIL_REPO:-${MTVEIL_REPO:-RsNest/mtevil}}"
MTEVIL_PINNED_VERSION="__AUTO__"
USER_VERSION="${MTEVIL_VERSION:-${MTVEIL_VERSION:-}}"
MTEVIL_RELEASE_BASE_URL="${MTEVIL_RELEASE_BASE_URL:-https://github.com/${MTEVIL_REPO}/releases/download}"
MTEVIL_RELEASES_API_URL="${MTEVIL_RELEASES_API_URL:-https://api.github.com/repos/${MTEVIL_REPO}/releases?per_page=30}"

if [[ -z "${MTEVIL_DIR:-${MTVEIL_DIR:-}}" && -f "$HOME/mtveil/compose.yaml" ]]; then
  if [[ ! -e "$HOME/mtevil" && ! -L "$HOME/mtevil" ]]; then
    # Keep existing bind mounts valid while exposing the new path.
    ln -s -- "$HOME/mtveil" "$HOME/mtevil"
  elif [[ ! "$HOME/mtevil" -ef "$HOME/mtveil" ]]; then
    echo 'Найдены два разных каталога. Укажите каталог нужной установки через MTEVIL_DIR и повторите запуск.' >&2
    exit 1
  fi
fi
MTEVIL_DIR="${MTEVIL_DIR:-${MTVEIL_DIR:-$HOME/mtevil}}"

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

fetch_url() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  else
    wget -qO "$out" "$url"
  fi
}

if [[ -n "$USER_VERSION" ]]; then
  MTEVIL_VERSION="$USER_VERSION"
elif [[ "$MTEVIL_PINNED_VERSION" != "__AUTO__" ]]; then
  MTEVIL_VERSION="$MTEVIL_PINNED_VERSION"
else
  mkdir -p "$MTEVIL_DIR"
  RELEASES_JSON="${MTEVIL_DIR}/.releases.json.$$"
  trap 'rm -f "$RELEASES_JSON"' EXIT
  if ! fetch_url "$MTEVIL_RELEASES_API_URL" "$RELEASES_JSON"; then
    echo "Не удалось получить список релизов из GitHub API (${MTEVIL_RELEASES_API_URL})." >&2
    echo "Дальше: проверьте доступ к api.github.com или укажите версию явно: MTEVIL_VERSION=v0.1.0-alpha.5 bash install.sh" >&2
    exit 1
  fi
  if ! RESOLVED_VERSION="$(python3 - "$RELEASES_JSON" <<'PY'
import json, re, sys
path = sys.argv[1]
try:
    data = json.loads(open(path, encoding="utf-8").read())
except Exception as exc:
    print(f"Ошибка разбора ответа GitHub API: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(data, list) or not data:
    print("Список релизов пуст.", file=sys.stderr)
    raise SystemExit(1)
pat = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")
ranks = {"alpha": 1, "beta": 2, "rc": 3, None: 4}
cands = []
for rel in data:
    if not isinstance(rel, dict) or rel.get("draft"):
        continue
    tag = str(rel.get("tag_name") or "").strip()
    m = pat.match(tag)
    if not m:
        continue
    assets = rel.get("assets")
    if not isinstance(assets, list):
        continue
    names = {
        str(a.get("name") or "")
        for a in assets
        if isinstance(a, dict) and a.get("state") in (None, "uploaded") and a.get("browser_download_url")
    }
    if {"install.sh", "setup.py"}.issubset(names):
        key = (int(m.group(1)), int(m.group(2)), int(m.group(3)), ranks[m.group(4)], int(m.group(5) or 0))
        cands.append((key, tag))
if not cands:
    print("Не найден ни один опубликованный релиз с готовыми файлами install.sh и setup.py.", file=sys.stderr)
    raise SystemExit(1)
cands.sort(key=lambda x: x[0])
print(cands[-1][1])
PY
  )"; then
    exit 1
  fi
  rm -f "$RELEASES_JSON"
  trap - EXIT
  PINNED_INSTALL="${MTEVIL_DIR}/install.${RESOLVED_VERSION}.sh"
  PINNED_INSTALL_URL="${MTEVIL_RELEASE_BASE_URL}/${RESOLVED_VERSION}/install.sh"
  if ! fetch_url "$PINNED_INSTALL_URL" "$PINNED_INSTALL"; then
    echo "Не удалось скачать установщик релиза ${RESOLVED_VERSION} (${PINNED_INSTALL_URL})." >&2
    exit 1
  fi
  exec bash "$PINNED_INSTALL" "$@"
fi

if ! docker_err="$(docker info 2>&1 >/dev/null)"; then
  echo "Docker не отвечает: не удалось подключиться к Docker Engine." >&2
  if printf '%s' "$docker_err" | grep -qi "permission denied"; then
    echo "Дальше: добавьте пользователя в группу docker (sudo usermod -aG docker \"\$USER\"), перелогиньтесь и повторите запуск." >&2
  elif [ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi microsoft /proc/version 2>/dev/null; then
    echo "Дальше: откройте Docker Desktop на Windows, включите интеграцию с WSL для этого дистрибутива и повторите запуск." >&2
  else
    echo "Дальше: проверьте службу Docker (sudo systemctl start docker && sudo systemctl status docker) и повторите запуск." >&2
  fi
  exit 1
fi

REPO_LOWER="$(printf '%s' "$MTEVIL_REPO" | tr '[:upper:]' '[:lower:]')"
MTEVIL_IMAGE="${MTEVIL_IMAGE:-${MTVEIL_IMAGE:-ghcr.io/${REPO_LOWER}:${MTEVIL_VERSION}}}"

mkdir -p "$MTEVIL_DIR"
SETUP_URL="${MTEVIL_RELEASE_BASE_URL}/${MTEVIL_VERSION}/setup.py"
echo "Скачивание мастера настройки mtevil (${MTEVIL_VERSION})..."
if ! fetch_url "$SETUP_URL" "${MTEVIL_DIR}/setup.py"; then
  echo "Не удалось скачать setup.py для версии ${MTEVIL_VERSION} (${SETUP_URL})." >&2
  exit 1
fi

echo "Загрузка Docker-образа ${MTEVIL_IMAGE}..."
if ! docker pull "$MTEVIL_IMAGE"; then
  echo "Не удалось загрузить Docker-образ ${MTEVIL_IMAGE}." >&2
  echo "Дальше: проверьте интернет-соединение и доступ к ghcr.io, затем повторите запуск." >&2
  exit 1
fi

exec python3 "${MTEVIL_DIR}/setup.py" \
  --dir "$MTEVIL_DIR" \
  --image "$MTEVIL_IMAGE" \
  --no-build \
  "$@"
