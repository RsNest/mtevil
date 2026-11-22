#!/usr/bin/env bash
set -euo pipefail

MTEVIL_REPO="${MTEVIL_REPO:-${MTVEIL_REPO:-RsNest/mtevil}}"
MTEVIL_PINNED_VERSION="__AUTO__"
USER_VERSION="${MTEVIL_VERSION:-${MTVEIL_VERSION:-}}"
MTEVIL_CHANNEL="${MTEVIL_CHANNEL:-${MTVEIL_CHANNEL:-stable}}"
MTEVIL_RELEASE_BASE_URL="${MTEVIL_RELEASE_BASE_URL:-https://github.com/${MTEVIL_REPO}/releases/download}"
MTEVIL_RELEASES_API_URL="${MTEVIL_RELEASES_API_URL:-https://api.github.com/repos/${MTEVIL_REPO}/releases?per_page=30}"

FORWARD_ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--prerelease" ]]; then
    MTEVIL_CHANNEL="prerelease"
  else
    FORWARD_ARGS+=("$arg")
  fi
done
set -- ${FORWARD_ARGS[@]+"${FORWARD_ARGS[@]}"}

print_banner() {
  local ver="$1"
  if [ ! -t 1 ] || [ "${MTEVIL_BANNER_SHOWN:-0}" = "1" ]; then
    return 0
  fi
  local use_color=1
  if [ -n "${NO_COLOR:-}" ] || [ "${TERM:-}" = "dumb" ]; then
    use_color=0
  fi
  local use_utf8=0
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf-8*|*UTF8*|*utf8*) use_utf8=1 ;;
  esac
  local g="" b="" d="" r=""
  if [ "$use_color" -eq 1 ]; then
    g=$'\033[1;32m'
    b=$'\033[1m'
    d=$'\033[2m'
    r=$'\033[0m'
  fi
  if [ "$use_utf8" -eq 1 ]; then
    printf '\n'
    printf ' %s▄▄▄▄▄%s   %smtevil%s %s%s%s\n' "$g" "$r" "$b" "$r" "$d" "$ver" "$r"
    printf ' %s█ █ █%s   %sMTProto-прокси для Telegram%s\n' "$g" "$r" "$d" "$r"
    printf ' %s▀ ▀ ▀%s\n\n' "$g" "$r"
  else
    printf '\n'
    printf ' %s__ __%s   %smtevil%s %s%s%s\n' "$g" "$r" "$b" "$r" "$d" "$ver" "$r"
    printf ' %s| | |%s   %sMTProto-proxy for Telegram%s\n' "$g" "$r" "$d" "$r"
    printf " %s' ' '%s\n\n" "$g" "$r"
  fi
  export MTEVIL_BANNER_SHOWN=1
}

MTEVIL_CHANNEL_NORM="$(printf '%s' "$MTEVIL_CHANNEL" | tr '[:upper:]' '[:lower:]')"
case "$MTEVIL_CHANNEL_NORM" in
  ""|stable)
    ALLOW_PRERELEASE="0"
    ;;
  prerelease|pre|alpha|beta|rc)
    ALLOW_PRERELEASE="1"
    ;;
  *)
    echo "Неизвестный канал релизов MTEVIL_CHANNEL='${MTEVIL_CHANNEL}'. Используйте 'stable' или 'prerelease'." >&2
    exit 1
    ;;
esac

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

# Stage each release payload before replacing installed files or executing any of it.
fetch_release_assets() {
  python3 - "$MTEVIL_RELEASE_BASE_URL" "$@" <<'PYTHON'
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base, version, directory, *assets = sys.argv[1:]
tag = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-(?:alpha|beta|rc)\.\d+)?", version)
if tag is None:
    sys.exit(f"Недопустимый тег релиза: {version}")

def fetch(name):
    request = Request(f"{base}/{version}/{name}", headers={"User-Agent": "mtevil-install"})
    with urlopen(request, timeout=30) as response:
        return response.read()

try:
    try:
        manifest = fetch("SHA256SUMS").decode("utf-8")
    except HTTPError as exc:
        if exc.code != 404 or tuple(map(int, tag.groups())) > (0, 1, 1):
            raise
        manifest = None
        print("SHA256SUMS отсутствует в старом релизе.", file=sys.stderr)

    checksums = {}
    if manifest is not None:
        for line in manifest.splitlines():
            match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?([^\s]+)", line.strip())
            if match is None:
                continue
            digest, name = match.groups()
            if name in checksums:
                raise ValueError(f"повторная запись в SHA256SUMS: {name}")
            checksums[name] = digest.lower()
        if not set(assets).issubset(checksums):
            raise ValueError("в SHA256SUMS отсутствуют нужные файлы")

    with tempfile.TemporaryDirectory(prefix=".release-", dir=directory) as tmp:
        staged = []
        for name in assets:
            try:
                data = fetch(name)
            except HTTPError as exc:
                if manifest is None and name == "mtevilctl" and exc.code == 404:
                    continue
                raise
            if manifest is not None and hashlib.sha256(data).hexdigest() != checksums[name]:
                raise ValueError(f"контрольная сумма {name} не совпала")
            candidate = Path(tmp) / name
            candidate.write_bytes(data)
            candidate.chmod(0o755)
            output = f"install.{version}.sh" if name == "install.sh" else name
            staged.append((candidate, Path(directory) / output))
        for candidate, destination in staged:
            os.replace(candidate, destination)
except (OSError, ValueError) as exc:
    sys.exit(f"Не удалось проверить файлы релиза {version}: {exc}")
PYTHON
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
  if ! RESOLVED_VERSION="$(python3 - "$RELEASES_JSON" "$ALLOW_PRERELEASE" <<'PY'
import json, re, sys
path = sys.argv[1]
allow_prerelease = sys.argv[2] == "1"
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
all_cands = []
stable_cands = []
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
        all_cands.append((key, tag))
        if m.group(4) is None and not rel.get("prerelease"):
            stable_cands.append((key, tag))
if not all_cands:
    print("Не найден ни один опубликованный релиз с готовыми файлами install.sh и setup.py.", file=sys.stderr)
    raise SystemExit(1)
if allow_prerelease:
    all_cands.sort(key=lambda x: x[0])
    print(all_cands[-1][1])
else:
    if not stable_cands:
        all_cands.sort(key=lambda x: x[0])
        latest_pre = all_cands[-1][1]
        print(
            "Не найден ни один стабильный релиз с готовыми файлами install.sh и setup.py. "
            f"Доступен предварительный релиз {latest_pre}.\n"
            f"Для установки предварительного релиза укажите канал: MTEVIL_CHANNEL=prerelease bash install.sh "
            f"(или флаг --prerelease) либо зафиксируйте версию явно: MTEVIL_VERSION={latest_pre} bash install.sh",
            file=sys.stderr,
        )
        raise SystemExit(1)
    stable_cands.sort(key=lambda x: x[0])
    print(stable_cands[-1][1])
PY
  )"; then
    exit 1
  fi
  rm -f "$RELEASES_JSON"
  trap - EXIT
  PINNED_INSTALL="${MTEVIL_DIR}/install.${RESOLVED_VERSION}.sh"
  fetch_release_assets "$RESOLVED_VERSION" "$MTEVIL_DIR" install.sh
  exec bash "$PINNED_INSTALL" "$@"
fi

print_banner "$MTEVIL_VERSION"
export MTEVIL_SELECTED_VERSION="$MTEVIL_VERSION"

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
rm -f "${MTEVIL_DIR}"/install.v*.sh 2>/dev/null || true
echo "Скачивание мастера настройки mtevil (${MTEVIL_VERSION})..."
fetch_release_assets "$MTEVIL_VERSION" "$MTEVIL_DIR" setup.py mtevilctl
if [ -x "${MTEVIL_DIR}/mtevilctl" ]; then
  if [ -w "/usr/local/bin" ]; then
    ln -sf -- "${MTEVIL_DIR}/mtevilctl" "/usr/local/bin/mtevilctl" 2>/dev/null || true
  fi
  if [ -n "${HOME:-}" ]; then
    mkdir -p "$HOME/.local/bin" 2>/dev/null || true
    ln -sf -- "${MTEVIL_DIR}/mtevilctl" "$HOME/.local/bin/mtevilctl" 2>/dev/null || true
    if [ -d "$HOME/bin" ]; then
      ln -sf -- "${MTEVIL_DIR}/mtevilctl" "$HOME/bin/mtevilctl" 2>/dev/null || true
    fi
  fi
fi

echo "Загрузка Docker-образа ${MTEVIL_IMAGE}..."
pull_image() {
  # Show Docker's progress only for an interactive terminal; keep logs clean otherwise.
  if [ -t 1 ]; then
    docker pull "$MTEVIL_IMAGE"
  else
    docker pull -q "$MTEVIL_IMAGE" >/dev/null
  fi
}
if ! pull_image; then
  echo "Не удалось загрузить Docker-образ ${MTEVIL_IMAGE}." >&2
  echo "Дальше: проверьте интернет-соединение и доступ к ghcr.io, затем повторите запуск." >&2
  exit 1
fi

exec python3 "${MTEVIL_DIR}/setup.py" \
  --dir "$MTEVIL_DIR" \
  --image "$MTEVIL_IMAGE" \
  --no-build \
  "$@"
