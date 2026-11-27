#!/usr/bin/env python3
"""Interactive Docker Compose setup wizard for mtevil (Direct, Egress, Edge)."""
import argparse
import base64
import copy
import datetime
import errno
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DEFAULT_IMAGE = "mtevil:local"
DEFAULT_TPROXY_IMAGE = "mtevil-tproxy:local"
TPROXY_SERVER_COMMIT = "c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8"
TPROXY_SERVER_TARBALL_SHA256 = "a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549"
DEFAULT_TPROXY_LISTEN = "127.0.0.1:8080"
DEFAULT_TPROXY_ADMIN = "127.0.0.1:8081"
DEFAULT_TPROXY_BACKEND_PORT = 2398
TPROXY_CARRIER_MODES = ("websocket", "https", "https-lanes", "websocket-lanes")
SEMVER_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")
STAGE_RANKS = {"alpha": 1, "beta": 2, "rc": 3, None: 4}


def parse_semver_tag(tag: str) -> tuple[int, int, int, int, int] | None:
    m = SEMVER_TAG_RE.match(tag.strip())
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    stage = m.group(4)
    pre_num = int(m.group(5)) if m.group(5) is not None else 0
    return (major, minor, patch, STAGE_RANKS[stage], pre_num)


def is_prerelease_tag(tag: str) -> bool:
    key = parse_semver_tag(tag)
    return key is not None and key[3] < STAGE_RANKS[None]


def version_supports_me_config(version: str | None) -> bool:
    if not version:
        return True
    parsed = parse_semver_tag(version)
    if parsed is None:
        return True
    return (parsed[0], parsed[1]) >= (0, 3)


def strip_me_block_for_legacy_version(
    cfg_file: Path, target_version: str | None
) -> tuple[bool, Path | None]:
    """Strip the `me` block from `config.json` when downgrading/rolling back to `< v0.3.0`,
    saving a 0600 backup `config.json.pre-me-downgrade` before modifying `config.json`."""
    if version_supports_me_config(target_version) or not cfg_file.is_file():
        return False, None
    raw = cfg_file.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict) or "me" not in data:
        return False, None
    backup_path = cfg_file.with_name(f"{cfg_file.name}.pre-me-downgrade")
    backup_path.write_text(raw, encoding="utf-8")
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    data.pop("me", None)
    tmp = cfg_file.with_name(f".{cfg_file.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, cfg_file)
    return True, backup_path


def select_latest_release(
    releases: list[dict[str, object]],
    *,
    allow_prerelease: bool = False,
) -> str:
    if not isinstance(releases, list) or not releases:
        raise ValueError("no releases found")
    candidates: list[tuple[tuple[int, int, int, int, int], str]] = []
    prerelease_candidates: list[tuple[tuple[int, int, int, int, int], str]] = []
    for rel in releases:
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        tag = str(rel.get("tag_name") or "").strip()
        key = parse_semver_tag(tag)
        if key is None:
            continue
        assets = rel.get("assets")
        if not isinstance(assets, list):
            continue
        ready_names = {
            str(a.get("name") or "")
            for a in assets
            if isinstance(a, dict)
            and a.get("state") in (None, "uploaded")
            and a.get("browser_download_url")
        }
        if not {"install.sh", "setup.py"}.issubset(ready_names):
            continue
        if rel.get("prerelease") or key[3] < STAGE_RANKS[None]:
            prerelease_candidates.append((key, tag))
            if allow_prerelease:
                candidates.append((key, tag))
        else:
            candidates.append((key, tag))
    if not candidates:
        if not allow_prerelease and prerelease_candidates:
            prerelease_candidates.sort(key=lambda item: item[0])
            newest_pre = prerelease_candidates[-1][1]
            raise ValueError(
                f"Стабильный релиз ещё не опубликован (последняя предварительная версия: {newest_pre}). "
                f"Чтобы установить предварительную версию, укажите MTEVIL_CHANNEL=prerelease (или --prerelease), "
                f"либо зафиксируйте тег явно: MTEVIL_VERSION={newest_pre}"
            )
        raise ValueError("no eligible published release with install.sh and setup.py assets")
    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


def compute_release_publish_flags(
    tag: str,
    published_releases: list[dict[str, object]],
) -> tuple[str, str]:
    """Return (prerelease_flag, latest_flag) for `gh release edit`.

    Supported alpha/beta/rc tags are always published as prereleases and explicitly
    excluded from GitHub Latest (`--prerelease=true`, `--latest=false`).
    Stable tags are compared only against other non-draft stable releases so an older
    stable tag gets `--latest=false` while a newer stable tag gets `--latest`.
    """
    if is_prerelease_tag(tag):
        return ("--prerelease=true", "--latest=false")

    target_key = parse_semver_tag(tag)
    is_newest = True
    if target_key is not None:
        for rel in published_releases:
            if not isinstance(rel, dict) or rel.get("isDraft") or rel.get("draft"):
                continue
            other_tag = str(rel.get("tagName") or rel.get("tag_name") or "").strip()
            if rel.get("isPrerelease") or rel.get("prerelease") or is_prerelease_tag(other_tag):
                continue
            other_key = parse_semver_tag(other_tag)
            if other_key is not None and other_key > target_key:
                is_newest = False
                break
    return ("--prerelease=false", "--latest" if is_newest else "--latest=false")


def resolve_commit_release_tag(
    sha_tags: list[str],
    all_tags: list[str],
    min_alpha: int = 5,
) -> tuple[str, bool]:
    """Return (tag, is_new). Reuses an existing v* semver tag on the commit if present."""
    existing: list[tuple[tuple[int, int, int, int, int], str]] = []
    for t in sha_tags:
        key = parse_semver_tag(t)
        if key is not None:
            existing.append((key, t.strip()))
    if existing:
        existing.sort(key=lambda item: item[0])
        return existing[-1][1], False
    max_n = min_alpha
    for t in all_tags:
        key = parse_semver_tag(t)
        if key is not None and key[:4] == (0, 1, 0, 1):
            max_n = max(max_n, key[4])
    return f"v0.1.0-alpha.{max_n + 1}", True
DEFAULT_DCS = [
    "1=149.154.175.50:443",
    "2=149.154.167.51:443",
    "3=149.154.175.100:443",
    "4=149.154.167.91:443",
    "5=91.108.56.100:443",
]
DEFAULT_SNI = "mozilla.org"
POPULAR_SNIS: tuple[tuple[str, str], ...] = (
    ("mozilla.org", "Mozilla (TLS 1.3, X25519, 3 записи, [51, 43], 0 NST — ближайший профиль)"),
    ("wikipedia.org", "Wikipedia (TLS 1.3, X25519, нейтральный международный домен)"),
    ("kernel.org", "Linux Kernel (TLS 1.3, X25519, стабильный cover)"),
    ("ya.ru", "Яндекс (TLS 1.3, X25519, только если входной VPS в РФ)"),
    ("vk.com", "ВКонтакте (TLS 1.3, X25519, только если входной VPS в РФ)"),
)
HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SNI_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def fail(msg: str) -> "NoReturn":
    print(f"Ошибка: {msg}", file=sys.stderr)
    raise SystemExit(1)


def use_color() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    return True


def supports_unicode() -> bool:
    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    if "utf" in enc:
        return True
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        if "utf" in os.environ.get(var, "").lower():
            return True
    return False


def resolve_banner_version(image_ref: str) -> str:
    env_ver = (os.environ.get("MTEVIL_SELECTED_VERSION") or "").strip()
    if env_ver:
        return env_ver
    if image_ref and ":" in image_ref and "@sha256:" not in image_ref:
        tail = image_ref.rsplit(":", 1)[-1].strip()
        if tail and tail != "latest":
            return tail
    return "dev"


def render_banner(
    version: str,
    *,
    color: bool | None = None,
    unicode_ok: bool | None = None,
) -> str:
    c = use_color() if color is None else color
    u = supports_unicode() if unicode_ok is None else unicode_ok
    g = "\033[1;32m" if c else ""
    b = "\033[1m" if c else ""
    d = "\033[2m" if c else ""
    r = "\033[0m" if c else ""
    if u:
        lines = [
            "",
            f" {g}▄▄▄▄▄{r}   {b}mtevil{r} {d}{version}{r}",
            f" {g}█ █ █{r}   {d}MTProto-прокси для Telegram{r}",
            f" {g}▀ ▀ ▀{r}",
            "",
        ]
    else:
        lines = [
            "",
            f" {g}__ __{r}   {b}mtevil{r} {d}{version}{r}",
            f" {g}| | |{r}   {d}MTProto-proxy for Telegram{r}",
            f" {g}' ' '{r}",
            "",
        ]
    return "\n".join(lines)


def print_wizard_banner(image_ref: str) -> None:
    if not sys.stdout.isatty() or os.environ.get("MTEVIL_BANNER_SHOWN") == "1":
        return
    print(render_banner(resolve_banner_version(image_ref)))
    os.environ["MTEVIL_BANNER_SHOWN"] = "1"


def style(text: str, code: str) -> str:
    if not use_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def heading(text: str) -> str:
    return style(text, "1;36")


def ok_text(text: str) -> str:
    return style(text, "32")


def warn_text(text: str) -> str:
    return style(text, "33")


def err_text(text: str) -> str:
    return style(text, "31")


def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def is_port_conflict_error(detail: str) -> bool:
    low = detail.lower()
    return any(
        needle in low
        for needle in (
            "port is already allocated",
            "address already in use",
            "failed to bind",
            "bind for",
        )
    )


def diagnose_docker_error(detail: str, image: str = "") -> tuple[str, str]:
    low = detail.lower()
    if "permission denied" in low and "docker.sock" in low:
        return (
            "Нет прав на доступ к сокету Docker (/var/run/docker.sock).",
            "Добавьте пользователя в группу docker (sudo usermod -aG docker $USER), перелогиньтесь и повторите запуск.",
        )
    if any(k in low for k in ("cannot connect to the docker daemon", "is the docker daemon running", "error during connect")):
        hint = (
            "Откройте Docker Desktop на Windows и включите интеграцию с WSL, затем повторите запуск."
            if is_wsl()
            else "Запустите службу Docker (например: sudo systemctl start docker) и повторите запуск."
        )
        return ("Docker Engine не запущен или недоступен.", hint)
    if any(k in low for k in ("pull access denied", "manifest unknown", "not found", "unauthorized")):
        target = f" ({image})" if image else ""
        return (
            f"Не удалось получить Docker-образ{target}.",
            "Проверьте имя и тег образа или соберите его локально из исходников.",
        )
    return ("Команда Docker завершилась с ошибкой.", detail.splitlines()[-1] if detail else "Проверьте вывод docker compose.")


def run(argv: list[str], *, capture: bool = True, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=capture,
    )
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"command failed ({' '.join(argv[:6])}): {detail}")
    return proc


def check_prerequisites() -> None:
    try:
        run(["docker", "info"], capture=True)
    except Exception as exc:
        summary, action = diagnose_docker_error(str(exc))
        print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
        raise SystemExit(1)
    try:
        run(["docker", "compose", "version"], capture=True)
    except Exception as exc:
        fail(f"Требуется плагин Docker Compose v2 ({exc})")


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        print("Значение обязательно.")


def ask_yes_no(prompt: str, *, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes", "д", "да", "у"):
            return True
        if raw in ("n", "no", "н", "нет"):
            return False
        print("Ответьте y (да) или n (нет).")


def validate_host(value: str) -> str:
    v = value.strip()
    if not v or len(v) > 253 or any(c.isspace() for c in v):
        raise ValueError("invalid hostname or IP")
    if "://" in v or "/" in v:
        raise ValueError("enter only a hostname or IP (no URL scheme or path)")
    try:
        return str(ipaddress.ip_address(v.strip("[]")))
    except ValueError:
        pass
    if ":" in v:
        raise ValueError("enter only a hostname or IP (no port)")
    if not v.isascii() or not all(SNI_LABEL_RE.match(lbl) for lbl in v.rstrip(".").split(".")):
        raise ValueError("invalid DNS hostname")
    return v.rstrip(".")


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def resolve_domain_records(host: str) -> dict[str, list[str]]:
    a_records: list[str] = []
    aaaa_records: list[str] = []
    cnames: list[str] = []
    for family, target in ((socket.AF_INET, a_records), (socket.AF_INET6, aaaa_records)):
        try:
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in target:
                    target.append(ip)
        except socket.gaierror:
            pass
    try:
        dig = subprocess.run(["dig", "+short", "CNAME", host], capture_output=True, text=True, timeout=3)
        if dig.returncode == 0:
            cnames = [line.strip().rstrip(".") for line in dig.stdout.splitlines() if line.strip()]
    except OSError:
        pass
    return {"a": a_records, "aaaa": aaaa_records, "cnames": cnames}


def compare_dns_records(records: dict[str, list[str]], expected_ips: list[str]) -> tuple[bool, list[str]]:
    exp_v4 = sorted({str(ipaddress.ip_address(x)) for x in expected_ips if ipaddress.ip_address(x).version == 4})
    exp_v6 = sorted({str(ipaddress.ip_address(x)) for x in expected_ips if ipaddress.ip_address(x).version == 6})
    got_v4 = sorted(records.get("a", []))
    got_v6 = sorted(records.get("aaaa", []))
    lines: list[str] = []
    ok = True
    if not got_v4 and not got_v6:
        return False, ["DNS error: domain resolved to neither A nor AAAA records."]
    if records.get("cnames"):
        lines.append(f"CNAME chain: {' -> '.join(records['cnames'])}")
    if exp_v4:
        if got_v4 == exp_v4:
            lines.append(f"A records: OK ({', '.join(got_v4)})")
        else:
            ok = False
            lines.append(f"A records: MISMATCH (resolved {got_v4 or ['none']}, expected {exp_v4})")
    else:
        lines.append(f"A records: {got_v4 or ['none']}")
    if exp_v6:
        if got_v6 == exp_v6:
            lines.append(f"AAAA records: OK ({', '.join(got_v6)})")
        else:
            ok = False
            lines.append(f"AAAA records: MISMATCH (resolved {got_v6 or ['none']}, expected {exp_v6})")
    elif got_v6:
        if exp_v4:
            ok = False
            lines.append(f"AAAA records: WARNING unexpected AAAA {got_v6} while only IPv4 {exp_v4} was expected")
        else:
            lines.append(f"AAAA records: {got_v6}")
    return ok, lines


def detect_local_global_ipv4() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        addr = sock.getsockname()[0]
        ip = ipaddress.ip_address(addr)
        if ip.version == 4 and ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    except OSError:
        return None
    finally:
        sock.close()
    return None


def prompt_client_address(default_host: str | None = None) -> tuple[str, dict[str, list[str]] | None]:
    print("\nКакой адрес Telegram будет использовать для подключения?")
    print("Введите публичный IP этого сервера или домен, который на него указывает.")
    host = ask_validated("Адрес", validate_host, default_host)
    if is_ip_literal(host):
        return host, None
    records = resolve_domain_records(host)
    if records["cnames"]:
        print(f"  DNS CNAME: {' -> '.join(records['cnames'])}")
    if records["a"]:
        print(f"  DNS IPv4 (A): {', '.join(records['a'])}")
    if records["aaaa"]:
        print(f"  DNS IPv6 (AAAA): {', '.join(records['aaaa'])}")
    if not records["a"] and not records["aaaa"]:
        print(warn_text("  DNS: домен пока не разрешился ни в IPv4, ни в IPv6."))
        if not ask_yes_no("Продолжить настройку с этим доменом?", default=False):
            raise SystemExit(1)
    else:
        print("  Примечание: проверка DNS не подтверждает, что порт открыт снаружи.")
    return host, records


def check_domain_expected_ips(records: dict[str, list[str]]) -> None:
    while True:
        raw_exp = input("Ожидаемые публичные IPv4/IPv6-адреса (через запятую, Enter — пропустить): ").strip()
        if not raw_exp:
            return
        expected: list[str] = []
        try:
            for item in raw_exp.split(","):
                item = item.strip()
                if item:
                    expected.append(validate_ip(item))
            break
        except ValueError as exc:
            print(f"Некорректный IP-адрес: {exc}")
    ok, lines = compare_dns_records(records, expected)
    for line in lines:
        print(f"  {line}")
    if not ok:
        print(warn_text("  Некоторые DNS-записи не совпадают с ожидаемыми адресами (проверьте A и AAAA в панели DNS)."))
        if not ask_yes_no("Всё равно продолжить с этим доменом?", default=False):
            raise SystemExit(1)


def check_cover_from_container(base: list[str], cover: str, sni: str) -> tuple[bool, str]:
    proc = run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "openssl",
            compose_service(base),
            "s_client",
            "-connect",
            cover,
            "-servername",
            sni,
            "-verify_hostname",
            sni,
            "-verify_return_error",
            "-brief",
        ],
        input_text="",
        check=False,
    )
    out = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, out


def validate_sni(value: str) -> str:
    v = value.strip()
    if not v or len(v) > 253 or not v.isascii():
        raise ValueError("invalid SNI hostname")
    if not all(SNI_LABEL_RE.match(lbl) for lbl in v.split(".")):
        raise ValueError("SNI must be a valid DNS hostname (no scheme or port)")
    return v


DEFAULT_CADDY_IMAGE = "caddy:2.8-alpine"
SNI_HYGIENE_STOPWORDS = (
    "mtevil",
    "mtveil",
    "mtproto",
    "tproxy",
    "webproxy",
    "proxy",
    "vpn",
    "xray",
    "vless",
    "vmess",
    "trojan",
)


def lint_sni_hygiene(domain: str) -> list[str]:
    """Return non-fatal DPI hygiene warnings for a chosen SNI or webproxy domain."""
    host = (domain or "").strip().lower().rstrip(".")
    if not host:
        return []
    matched: list[str] = []
    for kw in SNI_HYGIENE_STOPWORDS:
        if kw in host and kw not in matched:
            matched.append(kw)
    if not matched:
        return []
    joined = ", ".join(f"'{m}'" for m in matched)
    return [
        f"Гигиена домена/SNI: имя '{domain}' содержит маркеры прокси ({joined}) — "
        "ТСПУ и цензоры могут фильтровать такие поддомены по открытому полю SNI/Certificate Transparency. "
        "Рекомендуется нейтральное имя домена."
    ]


def warn_if_sni_suspicious(domain: str) -> None:
    for msg in lint_sni_hygiene(domain):
        print(warn_text(f"  Предупреждение: {msg}"))


WEBPROXY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def validate_webproxy_hostname(value: str) -> str:
    raw = (value or "").strip()
    if not raw or any(ch in raw for ch in ":/@?#[]") or raw.endswith("."):
        raise ValueError("укажите DNS-домен без https://, порта, пути и точки в конце")
    if not raw.isascii():
        try:
            raw = raw.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"некорректный IDN-домен ({exc})") from exc
    host = raw.lower()
    if len(host) > 253 or is_ip_literal(host) or "." not in host:
        raise ValueError("IP-адрес и одноуровневые имена не допускаются для WEB Proxy")
    for label in host.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError(f"некорректная метка DNS '{label}'")
        if not all(("a" <= ch <= "z") or ("0" <= ch <= "9") or ch == "-" for ch in label):
            raise ValueError("домен должен быть в нижнем регистре ASCII / Punycode (xn--...)")
    return host


def validate_webproxy_base_path(value: str) -> str:
    path = (value or "").strip()
    if path == "":
        return ""
    if len(path) > 128:
        raise ValueError("base_path не должен превышать 128 символов")
    if path.startswith("/") or path.endswith("/"):
        raise ValueError("указывайте base_path без начального и конечного '/' (например, app/bridge)")
    for segment in path.split("/"):
        if not segment or not WEBPROXY_SEGMENT_RE.match(segment):
            raise ValueError("сегменты base_path должны соответствовать [A-Za-z0-9][A-Za-z0-9_-]*")
    return path


def validate_loopback_endpoint(value: str) -> str:
    parsed = parse_cover_host_port(value)
    if parsed is None:
        raise ValueError("укажите числовой loopback-адрес с портом (например, 127.0.0.1:8080)")
    host, port = parsed
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("требуется числовой loopback IP (127.0.0.1 или ::1)") from exc
    if not ip.is_loopback:
        raise ValueError("адрес должен быть loopback (127.0.0.1 или ::1)")
    if ":" in host:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def validate_webproxy_upstream(value: str) -> str:
    raw = (value or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("укажите http://<loopback_ip>:<port> без пути и параметров (например, http://127.0.0.1:3000)")
    endpoint = validate_loopback_endpoint(parsed.netloc)
    return f"http://{endpoint}"


def validate_webproxy_carrier_mode(value: str) -> str:
    mode = (value or "").strip().lower()
    if mode not in TPROXY_CARRIER_MODES:
        raise ValueError(f"допустимые режимы: {', '.join(TPROXY_CARRIER_MODES)}")
    return mode


def _decode_webproxy_secret_bytes(secret_hex: str) -> bytes:
    cleaned = (secret_hex or "").strip().lower()
    if len(cleaned) not in (32, 34):
        raise ValueError("secret must be 32 hex chars (or 34 with dd prefix)")
    raw = bytes.fromhex(cleaned)
    if len(raw) == 17 and raw[0] != 0xDD:
        raise ValueError("17-byte secret must start with dd")
    return raw


def derive_webproxy_capability(hostname: str, base_path: str, secret_hex: str) -> str:
    host = validate_webproxy_hostname(hostname)
    prefix = validate_webproxy_base_path(base_path)
    secret_bytes = _decode_webproxy_secret_bytes(secret_hex)
    if prefix == "":
        ctx = f"tdesktop-web-proxy-bridge-v1\n{host}".encode("utf-8")
    else:
        ctx = f"tdesktop-web-proxy-bridge-v2\n{host}\n{prefix}".encode("utf-8")
    digest = hmac.new(secret_bytes, ctx, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def format_webproxy_links(hostname: str, base_path: str, secret_hex: str) -> dict[str, str]:
    host = validate_webproxy_hostname(hostname)
    prefix = validate_webproxy_base_path(base_path)
    secret_bytes = _decode_webproxy_secret_bytes(secret_hex)
    raw16 = secret_bytes[1:] if len(secret_bytes) == 17 else secret_bytes
    if prefix == "":
        server_val = host
        link_secret = raw16.hex()
        server_q = host
    else:
        server_val = f"{host}/{prefix}"
        link_secret = base64.urlsafe_b64encode(b"\x70" + raw16).rstrip(b"=").decode("ascii")
        server_q = urllib.parse.quote(server_val, safe=".-_")
    return {
        "server": server_val,
        "secret": link_secret,
        "tme": f"https://t.me/webproxy?server={server_q}&secret={link_secret}",
        "tg": f"tg://webproxy?server={server_q}&secret={link_secret}",
    }


def render_tproxy_dockerfile() -> str:
    return f"""# Reproducible build of telegramdesktop/tproxy-server pinned by commit & SHA-256
FROM golang:1.22-alpine AS build
ARG TPROXY_COMMIT={TPROXY_SERVER_COMMIT}
ARG TPROXY_SHA256={TPROXY_SERVER_TARBALL_SHA256}
WORKDIR /build
RUN wget -qO tproxy.tar.gz "https://codeload.github.com/telegramdesktop/tproxy-server/tar.gz/${{TPROXY_COMMIT}}" \\
    && echo "${{TPROXY_SHA256}}  tproxy.tar.gz" | sha256sum -c - \\
    && tar -xzf tproxy.tar.gz --strip-components=1 \\
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tproxy-server ./cmd/tproxy-server

FROM alpine:3.20
LABEL org.opencontainers.image.title="mtevil-tproxy-sidecar" \\
      org.opencontainers.image.revision="{TPROXY_SERVER_COMMIT}"
RUN apk add --no-cache ca-certificates \\
    && addgroup -g 10001 -S mtevil \\
    && adduser -u 10001 -G mtevil -S -D -H -s /sbin/nologin mtevil
COPY --from=build /out/tproxy-server /usr/local/bin/tproxy-server
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/tproxy-server"]
CMD ["-config", "/etc/tproxy-server/config.json"]
"""


def render_tproxy_config(
    public_hostname: str,
    base_path: str,
    listen: str,
    admin_listen: str,
    *,
    public_dir: str | None = None,
    public_upstream: str | None = None,
    token_key_file: str = "/var/lib/mtevil/tproxy-token.key",
    profiles_file: str = "/var/lib/mtevil/tproxy-profiles.json",
) -> dict[str, object]:
    if bool(public_dir) == bool(public_upstream):
        raise ValueError("ровно один из public_dir или public_upstream должен быть задан")
    cfg: dict[str, object] = {
        "public_hostname": validate_webproxy_hostname(public_hostname),
        "base_path": validate_webproxy_base_path(base_path),
        "listen": validate_loopback_endpoint(listen),
        "admin_listen": validate_loopback_endpoint(admin_listen),
        "static_routes": "exact",
        "token_key_file": token_key_file,
        "profiles_file": profiles_file,
        "enable_pprof": False,
        "limits": {
            "max_header_bytes": 16384,
            "max_body_bytes": 2097152,
            "max_frame_payload": 1048576,
            "carrier_batch_bytes": 2097152,
            "max_streams_per_session": 128,
            "max_closed_stream_ids": 4096,
            "max_pending_per_session": 33554432,
            "max_pending_global": 536870912,
            "max_pending_items_per_session": 16384,
            "max_pending_items_global": 262144,
            "max_sessions_per_ip": 0,
            "max_sessions_global": 128,
            "max_streams_global": 4096,
            "max_backend_dials_in_flight": 256,
            "new_sessions_per_minute": 600,
            "new_sessions_burst": 128,
            "new_streams_per_minute": 6000,
            "new_streams_burst": 512,
            "max_bootstraps_per_ip": 0,
            "max_bootstraps_global": 512,
            "new_bootstraps_per_minute": 1200,
            "new_bootstraps_burst": 256,
            "max_profiles": 32,
        },
        "timeouts": {
            "backend_dial": "5s",
            "long_poll": "25s",
            "reconnect_grace": "2m",
            "bootstrap_lifetime": "2m",
            "read_header": "10s",
            "idle": "75s",
            "shutdown": "15s",
        },
    }
    if public_dir:
        cfg["public_dir"] = public_dir
    else:
        cfg["public_upstream"] = validate_webproxy_upstream(str(public_upstream))
    return cfg


def build_tproxy_profiles_data(
    default_secret_hex: str | None,
    users_map: dict[str, str],
    backend: str,
    carrier_mode: str = "websocket",
) -> dict[str, object]:
    backend_ep = validate_loopback_endpoint(backend)
    carrier = validate_webproxy_carrier_mode(carrier_mode)
    profiles: list[dict[str, object]] = []
    seen_secrets: set[str] = set()
    if default_secret_hex:
        sec_clean = default_secret_hex.strip().lower()
        _decode_webproxy_secret_bytes(sec_clean)
        profiles.append(
            {
                "name": "default",
                "secret": sec_clean,
                "backend": backend_ep,
                "carrier_mode": carrier,
            }
        )
        seen_secrets.add(sec_clean)
    for name in sorted(users_map.keys()):
        if name == "default":
            continue
        sec_clean = str(users_map[name]).strip().lower()
        _decode_webproxy_secret_bytes(sec_clean)
        if sec_clean in seen_secrets:
            continue
        profiles.append(
            {
                "name": name[:64],
                "secret": sec_clean,
                "backend": backend_ep,
                "carrier_mode": carrier,
            }
        )
        seen_secrets.add(sec_clean)
    if not profiles:
        raise ValueError("не найден ни один клиентский секрет для формирования profiles.json")
    return {"profiles": profiles}


def render_webproxy_reverse_proxy_snippets(
    hostname: str,
    base_path: str,
    tproxy_listen: str,
    *,
    cdn_mode: bool = False,
) -> tuple[str, str]:
    host = validate_webproxy_hostname(hostname)
    prefix = validate_webproxy_base_path(base_path)
    listen_ep = validate_loopback_endpoint(tproxy_listen)
    cdn_note = (
        "# Режим за CDN (Cloudflare): включите SSL/TLS -> Full (Strict) и Network -> WebSockets: ON.\n"
        if cdn_mode
        else ""
    )
    if prefix == "":
        caddy = f"""{cdn_note}# Caddyfile (рекомендуемый вариант: весь домен идёт через tproxy-server)
{{
    servers {{
        protocols h1 h2
        timeouts {{
            read_header 10s
            read_body 60s
        }}
    }}
}}

{host} {{
    encode zstd gzip
    header {{
        -Via
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
    }}
    reverse_proxy {listen_ep} {{
        transport http {{
            response_header_timeout 40s
        }}
    }}
}}
"""
        loc_path = "/"
    else:
        caddy = f"""{cdn_note}# Caddyfile (режим сосуществования на существующем сайте по префиксу /{prefix}/)
{host} {{
    handle /{prefix}/* {{
        encode zstd gzip
        header -Via
        reverse_proxy {listen_ep} {{
            transport http {{
                response_header_timeout 40s
            }}
        }}
    }}
    # Ниже — ваша обычная конфигурация сайта для остальных маршрутов
}}
"""
        loc_path = f"/{prefix}/"

    xff_expr = "$http_cf_connecting_ip" if cdn_mode else "$remote_addr"
    cdn_nginx_note = (
        "    # При работе за Cloudflare разрешайте порт 443 в firewall только для подсетей Cloudflare!\n"
        if cdn_mode
        else ""
    )
    nginx = f"""{cdn_note}# nginx (HTTPS 443 -> tproxy-server; НЕ включайте access_log с query-строкой!)
map $http_upgrade $connection_upgrade {{
    default upgrade;
    ''      close;
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {host};
{cdn_nginx_note}
    ssl_certificate     /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;
    access_log off;

    location {loc_path} {{
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For {xff_expr};
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 65s;
        proxy_send_timeout 65s;
        proxy_pass http://{listen_ep};
    }}
}}
"""
    return caddy, nginx


def validate_egress_ws_path(value: str) -> str:
    path = (value or "").strip()
    if not path.startswith("/"):
        raise ValueError("путь WebSocket должен начинаться с '/' (например, /ws/9f3c8a...)")
    if len(path) < 2 or len(path) > 256:
        raise ValueError("длина пути WebSocket должна быть от 2 до 256 символов (корень '/' не допускается)")
    if any((ord(ch) <= 32 or ord(ch) >= 127 or ch in "?#\"'\\<>") for ch in path):
        raise ValueError("путь WebSocket содержит недопустимые символы")
    return path


def validate_egress_upstream(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("адрес egress не может быть пустым")
    if raw.startswith("tcp://"):
        return f"tcp://{validate_endpoint(raw[len('tcp://'):])}"
    if raw.startswith(("wss://", "ws://")):
        parsed = urllib.parse.urlsplit(raw)
        scheme = parsed.scheme.lower()
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("userinfo и '#' не допускаются в URL egress")
        host = (parsed.hostname or "").strip()
        if not host:
            raise ValueError("не указан хост в URL egress")
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_unspecified:
                raise ValueError("wildcard IP (0.0.0.0 / ::) не допускается в URL egress")
            host_fmt = f"[{ip}]" if ip.version == 6 else str(ip)
        except ValueError as exc:
            if "wildcard" in str(exc):
                raise
            host_l = host.lower()
            if host_l != "localhost":
                validate_sni(host_l)
            host_fmt = host_l
        default_port = 443 if scheme == "wss" else 80
        try:
            port = parsed.port if parsed.port is not None else default_port
        except ValueError as exc:
            raise ValueError("некорректный порт в URL egress") from exc
        validate_port(str(port))
        ws_path = validate_egress_ws_path(parsed.path)
        conn_q = ""
        if parsed.query:
            params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in params:
                if k != "connect":
                    raise ValueError(f"неподдерживаемый параметр '?{k}=' (поддерживается только ?connect=IP:PORT)")
                ep = validate_endpoint(v)
                conn_q = f"?connect={ep}"
        port_part = "" if port == default_port else f":{port}"
        return f"{scheme}://{host_fmt}{port_part}{ws_path}{conn_q}"
    return validate_endpoint(raw)


def redact_egress_upstream(value: str) -> str:
    raw = (value or "").strip()
    if raw.startswith(("wss://", "ws://")):
        parsed = urllib.parse.urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 443 if scheme == "wss" else 80
        port = parsed.port or default_port
        return f"{scheme}://{host}:{port}/***"
    return raw


def render_egress_ws_reverse_proxy_snippets(
    hostname: str,
    ws_path: str,
    egress_listen: str,
) -> tuple[str, str]:
    host = validate_sni(hostname).lower()
    path = validate_egress_ws_path(ws_path)
    listen_ep = validate_loopback_endpoint(egress_listen)
    caddy = f"""# Caddyfile на узле egress (принимает WSS от RU edge на :443 без внешнего SSH/VPN)
# ВНИМАНИЕ (H2): egress_ws_path работает как секретный HTTP-токен доступа.
# По умолчанию Caddy не пишет access log; если вы включаете директиву `log`,
# обязательно исключите маршрут `@mtevil_egress` через `log_skip @mtevil_egress`
# (или маскируйте путь), чтобы секрет не попадал в журналы.
{host} {{
    @mtevil_egress path {path}
    log_skip @mtevil_egress
    handle @mtevil_egress {{
        reverse_proxy {listen_ep}
    }}
    handle {{
        respond "OK" 200
    }}
}}
"""
    nginx = f"""# nginx на узле egress (принимает WSS от RU edge на :443)
# ВНИМАНИЕ (H2): egress_ws_path работает как секретный HTTP-токен доступа.
# Для секретного location обязательно отключите `access_log off;` (или маскируйте $request_uri).
map $http_upgrade $connection_upgrade {{
    default upgrade;
    ''      close;
}}

# Опциональное маскирование пути, если в вашей конфигурации требуется общий access_log на уровне server/http:
# map $request_uri $mtevil_masked_uri {{
#     ~^{path}(\\?.*)?$  "/ws/***";
#     default             $request_uri;
# }}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {host};

    ssl_certificate     /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;

    location = {path} {{
        access_log off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 360s;
        proxy_send_timeout 360s;
        proxy_pass http://{listen_ep};
    }}

    location / {{
        return 200 'OK';
        add_header Content-Type text/plain;
    }}
}}
"""
    return caddy, nginx


def render_shared_443_snippets(sni: str, backend_listen: str) -> tuple[str, str]:
    host = validate_sni(sni).lower()
    listen_ep = validate_loopback_endpoint(backend_listen)
    xray_snip = f"""// Фрагмент для Xray (VLESS + TLS / REALITY) с делением порта 443 через fallbacks (PROXY protocol v2):
// Если в Xray используется REALITY на другом домене, поставьте перед Xray и mtevil nginx stream (см. nginx.stream443.example.conf),
// либо добавьте этот объект в массив "fallbacks" вашего VLESS-inbound на :443:
{{
  "dest": "{listen_ep}",
  "xver": 2
}}
"""
    nginx_stream = f"""# nginx stream (L4 SNI-маршрутизатор на :443 без расшифровки TLS — совместим с Xray REALITY и mtevil!)
# Поместите блок stream на верхнем уровне /etc/nginx/nginx.conf (рядом с http {{ ... }}):
stream {{
    map $ssl_preread_server_name $sni_443_backend {{
        {host}   mtevil_shared443;
        default  existing_443_service;
    }}

    upstream mtevil_shared443 {{
        server {listen_ep};
    }}

    upstream existing_443_service {{
        # Укажите внутренний порт вашего Xray REALITY / веб-сервера (перенесите его с 0.0.0.0:443 на 127.0.0.1:8444)
        server 127.0.0.1:8444;
    }}

    server {{
        listen 443 reuseport;
        listen [::]:443 reuseport;
        ssl_preread on;
        proxy_protocol on;
        proxy_pass $sni_443_backend;
    }}
}}
"""
    return xray_snip, nginx_stream


def validate_port(value: str) -> int:
    p = int(value)
    if not (1 <= p <= 65535):
        raise ValueError("port must be 1..65535")
    return p


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def validate_egress_ip(value: str) -> str:
    ip = ipaddress.ip_address(value.strip())
    if ip.is_unspecified:
        raise ValueError("wildcard address (0.0.0.0 / ::) is not allowed for egress; enter the specific tunnel interface IP")
    return str(ip)


def validate_endpoint(value: str) -> str:
    v = value.strip()
    if ":" not in v:
        raise ValueError("endpoint must be IP:PORT")
    host, port_s = v.rsplit(":", 1)
    host_clean = host.strip("[]")
    ipaddress.ip_address(host_clean)
    validate_port(port_s)
    return f"{host}:{port_s}"


def ask_validated(prompt: str, validator, default: str | None = None):
    while True:
        val = ask(prompt, default)
        try:
            return validator(val)
        except Exception as exc:
            print(f"Invalid input: {exc}")


def ask_hidden_token(prompt: str) -> str:
    while True:
        if sys.stdin.isatty():
            val = getpass.getpass(f"{prompt} (32 hex chars, hidden): ").strip().lower()
        else:
            print(f"{prompt} (32 hex chars, hidden): ", end="", flush=True)
            val = sys.stdin.readline().strip().lower()
        if HEX32_RE.match(val):
            return val
        print("Некорректный токен: требуется ровно 32 шестнадцатеричных символа.")


def _proc_net_port_in_use(port: int) -> bool:
    hex_port = f":{port:04X}"
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        p = Path(proc_file)
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == "0A" and parts[1].endswith(hex_port):
                return True
    return False


def is_port_available(bind_ip: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in bind_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if family == socket.AF_INET6:
            sock.bind((bind_ip, port, 0, 0))
        else:
            sock.bind((bind_ip, port))
        return True
    except OSError as exc:
        if exc.errno == errno.EACCES:
            return not _proc_net_port_in_use(port)
        return False
    finally:
        sock.close()


def deployment_owns_port(deploy_dir: Path, project: str, bind_ip: str, port: int) -> bool:
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    if not compose_file.is_file() or not env_file.is_file():
        return False
    base = compose_cmd(deploy_dir, project)
    proc = run(base + ["ps", "-q", compose_service(base)], check=False)
    cid = proc.stdout.strip()
    if not cid:
        return False
    insp = run(["docker", "inspect", cid], check=False)
    if insp.returncode != 0:
        return False
    try:
        info = json.loads(insp.stdout)[0]
    except Exception:
        return False
    if not info.get("State", {}).get("Running"):
        return False
    if info.get("HostConfig", {}).get("NetworkMode") == "host":
        cfg_file = deploy_dir / "config.json"
        if cfg_file.is_file():
            try:
                listen = json.loads(cfg_file.read_text(encoding="utf-8")).get("listen", "")
                if listen.endswith(f":{port}"):
                    return True
            except Exception:
                pass
    ports = info.get("NetworkSettings", {}).get("Ports") or {}
    for bindings in ports.values():
        if not bindings:
            continue
        for b in bindings:
            if str(b.get("HostPort", "")) == str(port):
                host_ip = b.get("HostIp") or "0.0.0.0"
                if host_ip in ("0.0.0.0", "::", bind_ip) or bind_ip in ("0.0.0.0", "::"):
                    return True
    return False


def find_free_port(bind_ip: str, exclude_port: int) -> int | None:
    for cand in (25443, 24443, 26443, 27443, 28443, 8443, 9443):
        if cand != exclude_port and is_port_available(bind_ip, cand):
            return cand
    return None


def describe_port_owner(port: int) -> str | None:
    """Best-effort identification of the process or Docker container holding `port`."""
    owners: list[str] = []
    if shutil.which("ss"):
        proc = subprocess.run(
            ["ss", "-tulpnH", f"sport = :{int(port)}"],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.splitlines():
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if m:
                    entry = f"{m.group(1)} (pid {m.group(2)})"
                    if entry not in owners:
                        owners.append(entry)
    if shutil.which("docker"):
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            needle = f":{int(port)}->"
            for line in proc.stdout.splitlines():
                name, _, ports_str = line.partition("\t")
                if needle in ports_str and name.strip():
                    entry = f"контейнер {name.strip()}"
                    if entry not in owners:
                        owners.append(entry)
    return ", ".join(owners) if owners else None


def ensure_available_port(
    deploy_dir: Path,
    project: str,
    bind_ip: str,
    pub_port: int,
    *,
    show_link_note: bool = True,
) -> int:
    while True:
        if deployment_owns_port(deploy_dir, project, bind_ip, pub_port) or is_port_available(bind_ip, pub_port):
            if show_link_note and pub_port != 443:
                print(
                    warn_text(
                        f"Примечание: нестандартный порт {pub_port} (отличный от 443) может чаще попадать под фильтрацию."
                    )
                )
            return pub_port
        owner = describe_port_owner(pub_port)
        print(warn_text(f"\nПорт {pub_port} уже занят на этом сервере."))
        if owner:
            print(f"  Занято процессом/контейнером: {owner}")
        if pub_port == 443 and show_link_note:
            print(
                "  Подсказка (self-steal): для маскировки под свой сайт освободите 443 "
                "(перенесите nginx/caddy на 127.0.0.1:8443) или выберите другой порт."
            )
            print(
                "  Подсказка (делить порт 443 без выхода на высокие порты): используйте "
                "'mtevilctl setup --shared-443' (за Xray/nginx SNI-роутером) или 'mtevilctl setup --webproxy'."
            )
        alt = find_free_port(bind_ip, pub_port)
        if alt is not None:
            if show_link_note:
                print(f"Можно использовать {alt}. В ссылке Telegram порт подставится автоматически.")
            else:
                print(f"Можно использовать {alt}.")
            pub_port = ask_validated("Другой порт", validate_port, str(alt))
        else:
            pub_port = ask_validated("Другой порт", validate_port)


def restore_backup_files(
    deploy_dir: Path,
    names: tuple[str, ...] | list[str] = ("compose.yaml", ".env", "config.json"),
) -> bool:
    restored = False
    for name in names:
        bak = deploy_dir / f"{name}.bak"
        live = deploy_dir / name
        if bak.is_file():
            os.replace(bak, live)
            restored = True
    return restored


def compute_listen_and_health(bind_ip: str, pub_port: int, network_host: bool) -> tuple[str, str]:
    if not network_host:
        return "", "127.0.0.1"
    if bind_ip == "::":
        return f"[::]:{pub_port}", "::1"
    if ":" in bind_ip:
        return f"[{bind_ip}]:{pub_port}", bind_ip
    return f"{bind_ip}:{pub_port}", ("127.0.0.1" if bind_ip == "0.0.0.0" else bind_ip)


def compute_compose_nofile(max_connections: int) -> int:
    return max(4096, int(max_connections) * 2 + 512)


def render_compose(
    repo_root: Path,
    deploy_dir: Path,
    role: str,
    config_name: str = "config.json",
    network_host: bool = False,
    health_host: str = "127.0.0.1",
    health_port: int | None = None,
    include_build: bool = True,
    extra_volumes: list[str] | None = None,
    max_connections: int | None = None,
    extra_hosts: list[str] | None = None,
    tproxy_sidecar: dict[str, object] | None = None,
    managed_caddy: dict[str, object] | None = None,
) -> str:
    try:
        rel_context = os.path.relpath(repo_root, deploy_dir).replace("\\", "/")
    except ValueError:
        rel_context = str(repo_root).replace("\\", "/")
    internal_port = 29443 if role == "egress" else 24443
    hc_port = health_port if (network_host and health_port is not None) else internal_port
    effective_max_conn = max_connections if max_connections is not None else (512 if role == "egress" else 256)
    nofile = compute_compose_nofile(effective_max_conn)
    build_block = (
        f"\n  build:\n    context: {rel_context}\n    dockerfile: Dockerfile"
        if include_build
        else ""
    )
    net_block = (
        "    network_mode: host"
        if network_host
        else f'    ports:\n      - "${{MTEVIL_BIND:-127.0.0.1}}:${{MTEVIL_PORT:-{internal_port}}}:{internal_port}/tcp"'
    )
    extra_hosts_block = ""
    if not network_host and extra_hosts:
        extra_hosts_block = "\n    extra_hosts:\n" + "".join(f'      - "{h}"\n' for h in extra_hosts).rstrip("\n")
    extra_vol_lines = "".join(f"\n      - {v}" for v in (extra_volumes or []))
    tproxy_block = ""
    if tproxy_sidecar:
        tp_cfg_name = str(tproxy_sidecar.get("config_name") or "tproxy.json")
        tp_admin = str(tproxy_sidecar.get("admin_listen") or DEFAULT_TPROXY_ADMIN)
        tp_build = bool(tproxy_sidecar.get("include_build", True))
        tp_site_mount = str(tproxy_sidecar.get("site_host_dir") or "").strip()
        tp_df_name = str(tproxy_sidecar.get("dockerfile_name") or "tproxy.Dockerfile")
        tp_build_lines = (
            f"\n    build:\n      context: .\n      dockerfile: {tp_df_name}"
            if tp_build
            else ""
        )
        tp_site_line = f"\n      - {tp_site_mount}:/srv/tproxy-site:ro" if tp_site_mount else ""
        tproxy_block = f"""
  tproxy:
    image: ${{MTEVIL_TPROXY_IMAGE:-{DEFAULT_TPROXY_IMAGE}}}{tp_build_lines}
    init: true
    restart: unless-stopped
    network_mode: host
    depends_on:
      {deployment_service(deploy_dir)}:
        condition: service_healthy
    volumes:
      - ./{tp_cfg_name}:/etc/tproxy-server/config.json:ro
      - state:/var/lib/mtevil:ro{tp_site_line}
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: "0.50"
    pids_limit: 128
    ulimits:
      nofile:
        soft: {nofile}
        hard: {nofile}
    stop_grace_period: 15s
    healthcheck:
      test: [CMD, /usr/bin/wget, -q, -O, /dev/null, "http://{tp_admin}/readyz"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
"""
    caddy_block = ""
    caddy_volumes = ""
    if managed_caddy:
        cf_name = str(managed_caddy.get("caddyfile_name") or "Caddyfile")
        caddy_block = f"""
  caddy:
    image: ${{MTEVIL_CADDY_IMAGE:-{DEFAULT_CADDY_IMAGE}}}
    init: true
    restart: unless-stopped
    network_mode: host
    depends_on:
      tproxy:
        condition: service_healthy
    volumes:
      - ./{cf_name}:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: "0.50"
    pids_limit: 128
    stop_grace_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
"""
        caddy_volumes = "  caddy_data:\n  caddy_config:\n"
    return f"""name: ${{MTEVIL_PROJECT:-mtevil-{role}}}

x-image: &image
  image: ${{MTEVIL_IMAGE:-{DEFAULT_IMAGE}}}{build_block}

services:
  {deployment_service(deploy_dir)}:
    <<: *image
    init: true
    restart: unless-stopped
{net_block}{extra_hosts_block}
    volumes:
      - ./{config_name}:/etc/mtevil/config.json:ro
      - state:/var/lib/mtevil:ro
      - replay:/var/lib/mtevil-replay{extra_vol_lines}
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: "0.50"
    pids_limit: 128
    ulimits:
      nofile:
        soft: {nofile}
        hard: {nofile}
    stop_grace_period: 10s
    healthcheck:
      test: [CMD, /usr/local/bin/mtevil, health, --address, "{health_host}:{hc_port}"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
{tproxy_block}{caddy_block}
  init:
    <<: *image
    profiles: [tools]
    volumes:
      - state:/var/lib/mtevil
      - replay:/var/lib/mtevil-replay
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 32

volumes:
  state:
  replay:
{caddy_volumes}"""


def deployment_service(deploy_dir: Path) -> str:
    # Compose identifies an existing container by project and service.
    compose = deploy_dir / "compose.yaml"
    if compose.is_file() and "\n  mtveil:\n" in compose.read_text(encoding="utf-8"):
        return "mtveil"
    return "mtevil"


def compose_service(base: list[str]) -> str:
    return deployment_service(Path(base[-1]).parent)


def compose_write_service(base: list[str]) -> str:
    compose = Path(base[-1])
    if compose.is_file() and "\n  init:\n" in compose.read_text(encoding="utf-8"):
        return "init"
    return compose_service(base)


def compose_cmd(deploy_dir: Path, project: str, compose_name: str = "compose.yaml", env_name: str = ".env") -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        project,
        "--env-file",
        str(deploy_dir / env_name),
        "-f",
        str(deploy_dir / compose_name),
    ]


def volume_file_exists(base: list[str], path_in_container: str) -> bool:
    p = run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/bin/sh",
            compose_service(base),
            "-c",
            f"test -s {path_in_container}",
        ],
        check=False,
    )
    return p.returncode == 0


def ensure_generated_secret(base: list[str], path_in_container: str) -> bool:
    """Return True if newly generated, False if already existed."""
    if volume_file_exists(base, path_in_container):
        return False
    run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/usr/local/bin/mtevil",
            compose_write_service(base),
            "secret",
            "--output",
            path_in_container,
        ],
        capture=True,
    )
    return True


def write_volume_secret_stdin(base: list[str], path_in_container: str, hex_secret: str) -> None:
    run(
        base
        + [
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "--entrypoint",
            "/bin/sh",
            compose_write_service(base),
            "-c",
            f"umask 077 && cat > {path_in_container}",
        ],
        input_text=hex_secret + "\n",
    )


def remove_volume_file(base: list[str], path_in_container: str) -> None:
    run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/bin/rm",
            compose_write_service(base),
            "-f",
            path_in_container,
        ],
        check=False,
    )


def read_volume_secret(base: list[str], path_in_container: str) -> str:
    return run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/bin/cat",
            compose_service(base),
            path_in_container,
        ]
    ).stdout.strip()


def read_allowed_snis_from_volume(base: list[str]) -> list[str]:
    if not volume_file_exists(base, "/var/lib/mtevil/allowed-sni.txt"):
        return []
    try:
        raw = read_volume_secret(base, "/var/lib/mtevil/allowed-sni.txt")
    except Exception:
        return []
    out: list[str] = []
    for tok in re.split(r"[\r\n,]+", raw):
        s = tok.strip().lower()
        if not s:
            continue
        try:
            v = validate_sni(s)
            if v not in out:
                out.append(v)
        except Exception:
            pass
    return out


def record_allowed_snis_in_volume(base: list[str], snis: list[str]) -> list[str]:
    existing = read_allowed_snis_from_volume(base)
    merged: list[str] = []
    for item in [*snis, *existing]:
        s = (item or "").strip().lower()
        if not s:
            continue
        try:
            v = validate_sni(s)
            if v not in merged:
                merged.append(v)
        except Exception:
            pass
    if merged:
        write_volume_secret_stdin(base, "/var/lib/mtevil/allowed-sni.txt", "\n".join(merged))
    return merged


def ensure_tproxy_token_key(
    base: list[str],
    path_in_container: str = "/var/lib/mtevil/tproxy-token.key",
) -> bool:
    """Ensure a 32-byte raw random signing key (mode 0600) exists in the state volume."""
    if volume_file_exists(base, path_in_container):
        return False
    run(
        base
        + [
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "--entrypoint",
            "/bin/sh",
            compose_write_service(base),
            "-c",
            f'umask 077 && head -c 32 /dev/urandom > {path_in_container} && test "$(wc -c < {path_in_container})" -eq 32',
        ],
        capture=True,
    )
    return True


def read_users_map_from_volume(
    base: list[str],
    users_path: str = "/var/lib/mtevil/users.json",
) -> dict[str, str]:
    if not volume_file_exists(base, users_path):
        return {}
    raw = read_volume_secret(base, users_path)
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v).strip().lower() for k, v in parsed.items() if str(k).strip() and str(v).strip()}


def sync_tproxy_profiles_in_volume(
    base: list[str],
    backend: str,
    carrier_mode: str = "websocket",
    *,
    secret_path: str = "/var/lib/mtevil/proxy-secret",
    users_path: str = "/var/lib/mtevil/users.json",
    profiles_path: str = "/var/lib/mtevil/tproxy-profiles.json",
) -> dict[str, object]:
    default_sec = read_volume_secret(base, secret_path) if volume_file_exists(base, secret_path) else None
    users_map = read_users_map_from_volume(base, users_path)
    profiles_data = build_tproxy_profiles_data(default_sec, users_map, backend, carrier_mode)
    write_volume_secret_stdin(base, profiles_path, json.dumps(profiles_data, indent=2))
    return profiles_data


def wait_service_healthy(base: list[str], service_name: str, timeout_s: int = 45) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cid = run(base + ["ps", "-q", service_name]).stdout.strip()
        if cid:
            raw = run(["docker", "inspect", cid]).stdout
            info = json.loads(raw)[0]
            status = info.get("State", {}).get("Health", {}).get("Status")
            if status == "healthy":
                return
        time.sleep(1.0)
    raise TimeoutError(f"{service_name} container did not become healthy within {timeout_s}s")


def wait_healthy(base: list[str], timeout_s: int = 45) -> None:
    wait_service_healthy(base, compose_service(base), timeout_s=timeout_s)


def print_failed_container_logs(base: list[str]) -> None:
    try:
        result = run(base + ["logs", "--no-color", "--tail=30", compose_service(base)], check=False)
    except Exception as exc:
        print(f"Не удалось прочитать логи нового контейнера: {exc}", file=sys.stderr)
        return
    detail = (result.stdout or result.stderr or "").strip()
    if detail:
        print("Последние логи нового контейнера перед откатом:", file=sys.stderr)
        print(detail, file=sys.stderr)


def read_unprivileged_port_start() -> int | None:
    try:
        raw = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text(encoding="utf-8").strip()
        return int(raw)
    except (OSError, ValueError):
        return None


def resolve_network_host_port(
    deploy_dir: Path,
    project: str,
    bind_ip: str,
    pub_port: int,
    use_network_host: bool,
    *,
    explicit_network_host: bool = False,
    show_link_note: bool = True,
    allow_bridge_fallback: bool = True,
) -> tuple[int, bool]:
    if not use_network_host:
        return pub_port, False
    port_start = read_unprivileged_port_start()
    if port_start is None:
        print(
            warn_text(
                "Не удалось проверить порог непривилегированных портов (/proc/sys/net/ipv4/ip_unprivileged_port_start)."
            )
        )
        if pub_port < 1024:
            print(f"  Примечание: в режиме host порт {pub_port} (< 1024) может не открыться без привилегий.")
        return pub_port, True
    if pub_port >= port_start:
        return pub_port, True

    min_port = max(1024, port_start)
    print(
        warn_text(
            f"\nПорт {pub_port} ниже порога непривилегированных портов на этом сервере "
            f"(ip_unprivileged_port_start = {port_start})."
        )
    )
    print(f"В режиме host контейнер запускается без привилегий и не сможет открыть порт {pub_port}.")
    if not allow_bridge_fallback:
        print(
            "Для loopback-cover (127.0.0.1 / localhost) нужен режим host, поэтому автоматический переход в bridge недоступен."
        )
        print(
            f"Выберите другой порт (>= {min_port}) или поднимите локальный HTTPS-бэкенд на не-loopback адресе (например, docker0 / IP сервера)."
        )

        def validate_unpriv_port_only(val: str) -> int:
            p = validate_port(val)
            if p < min_port:
                raise ValueError(f"для режима host требуется порт >= {min_port}")
            return p

        alt = find_free_port(bind_ip, pub_port)
        default_alt = str(alt) if (alt is not None and alt >= min_port) else (str(min_port) if is_port_available(bind_ip, min_port) else None)
        new_port = ask_validated(f"Другой порт (>= {min_port})", validate_unpriv_port_only, default_alt)
        new_port = ensure_available_port(deploy_dir, project, bind_ip, new_port, show_link_note=show_link_note)
        return new_port, True

    print(f"  1. Оставить порт {pub_port} и перейти в сетевой режим bridge")
    print(f"  2. Остаться в режиме host и выбрать другой порт (>= {min_port})")
    while True:
        choice = ask("Ваш выбор [1/2]", "1").strip().lower()
        if choice in ("1", "bridge"):
            if explicit_network_host:
                if not ask_yes_no("Флаг --network-host задан явно. Перейти в режим bridge?", default=False):
                    print("Выберите вариант 2 для указания порта в режиме host.")
                    continue
            return pub_port, False
        if choice in ("2", "host"):
            def validate_unpriv_port(val: str) -> int:
                p = validate_port(val)
                if p < min_port:
                    raise ValueError(f"для режима host требуется порт >= {min_port}")
                return p

            alt = find_free_port(bind_ip, pub_port)
            default_alt = str(alt) if (alt is not None and alt >= min_port) else (str(min_port) if is_port_available(bind_ip, min_port) else None)
            new_port = ask_validated(f"Другой порт (>= {min_port})", validate_unpriv_port, default_alt)
            new_port = ensure_available_port(deploy_dir, project, bind_ip, new_port, show_link_note=show_link_note)
            return new_port, True
        print("Некорректный выбор: введите 1 (bridge) или 2 (host).")


def print_step(index: int, total: int, title: str) -> None:
    print("\n" + heading(f"[{index}/{total}] {title}"))


def check_public_port_reachable(host: str, port: int, timeout_s: float = 3.0) -> tuple[str, str]:
    """Connect to host:port from this server. Returns (status, detail): ok | unreachable | skipped.

    This only proves that the listener answers on the public address from the server itself.
    It cannot prove that the provider firewall allows connections from the Internet.
    """
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            if infos:
                ip = ipaddress.ip_address(infos[0][4][0])
        except (socket.gaierror, ValueError):
            ip = None
    if ip is None:
        return "skipped", "адрес не разрешился в IP"
    if not ip.is_global:
        return "skipped", "адрес не публичный"
    try:
        with socket.create_connection((str(ip), port), timeout=timeout_s):
            return "ok", ""
    except OSError as exc:
        return "unreachable", str(exc)


def choose_wizard_mode(default: str = "simple") -> str:
    default_num = {
        "simple": "1",
        "advanced": "2",
        "self-steal": "3",
        "webproxy": "4",
        "shared-443": "5",
    }.get(default, "1")
    print()
    print(heading("Выберите режим установки"))
    print("  1. Простая установка · один VPS [по умолчанию]")
    print("  2. Расширенная настройка · ручные параметры и несколько серверов")
    print("  3. self-steal · маскировка под свой локальный HTTPS-сайт (nginx/Caddy)")
    print("  4. webproxy · Telegram WEB Proxy через tproxy-server за Caddy/nginx")
    print("  5. shared-443 · делить порт 443 с Xray/nginx через SNI-роутер (PROXY protocol v2)")
    print()
    while True:
        choice = ask("Ваш выбор", default_num).lower()
        if choice in ("1", "simple", "s", "простая"):
            return "simple"
        if choice in ("2", "advanced", "a", "adv", "расширенная"):
            return "advanced"
        if choice in ("3", "self-steal", "self_steal", "selfsteal"):
            return "self-steal"
        if choice in ("4", "webproxy", "web-proxy", "web_proxy", "tproxy"):
            return "webproxy"
        if choice in ("5", "shared-443", "shared_443", "shared443"):
            return "shared-443"
        print("Некорректный выбор: введите 1 (простая), 2 (расширенная), 3 (self-steal), 4 (webproxy) или 5 (shared-443).")


def ask_simple_confirm() -> str:
    while True:
        raw = (
            input(
                "Продолжить? [Enter — установить / s — сменить SNI / a — расширенная настройка / n — отмена] [Y/s/a/n]: "
            )
            .strip()
            .lower()
        )
        if raw in ("", "y", "yes", "д", "да", "у"):
            return "install"
        if raw in ("s", "sni", "с"):
            return "sni"
        if raw in ("a", "adv", "advanced", "2", "р"):
            return "advanced"
        if raw in ("n", "no", "н", "нет"):
            return "cancel"
        print("Некорректный выбор: введите y (установить), s (сменить SNI), a (расширенная настройка) или n (отмена).")


def parse_cover_host_port(cover: str) -> tuple[str, int] | None:
    raw = (cover or "").strip()
    if not raw:
        return None
    if raw.startswith("["):
        host, _, port_str = raw.rpartition(":")
        if not host.endswith("]"):
            return None
        host = host[1:-1]
    else:
        host, sep, port_str = raw.rpartition(":")
        if not sep:
            return raw, 443
    try:
        port = validate_port(port_str)
    except Exception:
        return None
    return host, port


def is_loopback_cover_addr(cover: str) -> bool:
    parsed = parse_cover_host_port(cover)
    if parsed is None:
        return False
    host = parsed[0].strip().lower()
    return host in ("127.0.0.1", "localhost", "::1")


def is_local_cover_addr(cover: str) -> bool:
    parsed = parse_cover_host_port(cover)
    if parsed is None:
        return False
    host = parsed[0].strip().lower()
    return host in ("127.0.0.1", "localhost", "::1", "host.docker.internal")


def cover_loops_to_public_entry(
    cover: str,
    bind_ip: str,
    pub_port: int,
    public_host: str,
    sni: str,
) -> bool:
    parsed = parse_cover_host_port(cover)
    if parsed is None:
        return False
    host, port = parsed
    if int(port) != int(pub_port):
        return False
    h = host.strip().lower()
    b = (bind_ip or "").strip().lower()
    pub = (public_host or "").strip().lower()
    sni_l = (sni or "").strip().lower()
    if h in (b, pub, sni_l):
        return True
    if b in ("0.0.0.0", "::") and h in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::", "host.docker.internal"):
        return True
    return False


def probe_cover_reachable(cover: str, sni: str, timeout_s: float = 4.0) -> tuple[bool, str]:
    """Verify TLS reachability, SNI, and certificate validity of `cover` from this VPS."""
    import ssl

    parsed = parse_cover_host_port(cover)
    if parsed is None:
        return False, f"некорректный адрес cover: {cover}"
    host, port = parsed
    if host.lower() == "host.docker.internal":
        host = "127.0.0.1"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                ver = tls_sock.version() or "TLS"
                cert = tls_sock.getpeercert()
                if not cert:
                    return False, f"{ver}, но сервер не предъявил сертификат для SNI {sni}"
                return True, f"{ver}, сертификат OK"
    except ssl.SSLCertVerificationError as exc:
        return False, f"сертификат не подходит для SNI {sni}: {exc}"
    except Exception as exc:
        return False, str(exc)


def probe_cover_status(host: str, port: int, sni: str, timeout_s: float = 5.0) -> tuple[bool, str, int | None]:
    """Perform a real HTTPS GET with SNI/cert validation and return (ok, detail, cert_days_left)."""
    import ssl

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                ver = tls_sock.version() or "TLS"
                cert = tls_sock.getpeercert()
                if not cert:
                    return False, f"{ver}, но сервер не предъявил сертификат для SNI {sni}", None
                days_left: int | None = None
                not_after = cert.get("notAfter")
                if isinstance(not_after, str) and not_after:
                    try:
                        exp_ts = ssl.cert_time_to_seconds(not_after)
                        days_left = int((exp_ts - time.time()) // 86400)
                    except Exception:
                        days_left = None
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {sni}\r\n"
                    f"User-Agent: mtevilctl-check/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
                tls_sock.sendall(req)
                buf = bytearray()
                while b"\r\n" not in buf and len(buf) < 8192:
                    chunk = tls_sock.recv(1024)
                    if not chunk:
                        break
                    buf.extend(chunk)
                if not buf:
                    return False, f"{ver}, пустой ответ на HTTPS GET /", days_left
                if b"\r\n" not in buf:
                    preview = bytes(buf[:80]).decode("latin-1", errors="replace").strip()
                    return False, f"{ver}, неполный HTTP-ответ: {preview}", days_left
                status_line = bytes(buf).split(b"\r\n", 1)[0].decode("latin-1", errors="replace").strip()
                m = re.match(r"^HTTP/(?:1\.[01]|2(?:\.0)?)\s+(\d{3})(?:\s.*)?$", status_line)
                if not m:
                    return False, f"{ver}, некорректная строка статуса HTTP: {status_line[:80]}", days_left
                status_code = int(m.group(1))
                if status_code >= 500 or status_code < 100:
                    return False, f"{ver}, сервер вернул ошибку {status_line}", days_left
                return True, f"{ver}, {status_line}", days_left
    except ssl.SSLCertVerificationError as exc:
        return False, f"сертификат не подходит для SNI {sni}: {exc}", None
    except Exception as exc:
        return False, str(exc), None


def probe_local_https_get(host: str, port: int, sni: str, timeout_s: float = 5.0) -> tuple[bool, str]:
    """Perform a real HTTPS GET with SNI and certificate validation against host:port."""
    ok, detail, _days = probe_cover_status(host, port, sni, timeout_s=timeout_s)
    return ok, detail


def prompt_masking_config(
    default_sni: str,
    default_cover: str,
) -> tuple[str, str]:
    print("\n" + heading("Шаг 3. Маскировка (HTTPS-cover)"))
    print("Подсказка: после настройки можно уточнить fake_tls_cert_bytes в config.json под размер цепочки сертификата выбранного домена.")
    sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, default_sni)
    warn_if_sni_suspicious(sni)
    cover_default = default_cover if sni == default_sni else f"{sni}:443"
    cover = ask("Адрес HTTPS-cover (host:port)", cover_default)
    cover_ok_host, cover_detail_host = probe_cover_reachable(cover, sni)
    if not cover_ok_host:
        print(f"Предупреждение: cover {cover} (SNI {sni}) не отвечает с этого VPS ({cover_detail_host}).")
    return sni, cover


def prompt_sni_choice(default_sni: str = DEFAULT_SNI) -> str:
    print()
    print(heading("Выбор домена для HTTPS-маскировки (SNI)"))
    for idx, (dom, desc) in enumerate(POPULAR_SNIS, start=1):
        mark = " [текущий]" if dom == default_sni else ""
        print(f"  {idx}. {dom:<14} — {desc}{mark}")
    print("  Или введите любой другой домен с поддержкой TLS 1.3 (без https:// и порта).")
    print("  Подсказка: для лучшего сходства подбирайте fake_tls_cert_bytes под выбранный домен (см. docs/dpi-audit/REPORT.md).")
    while True:
        raw = ask(f"Домен SNI (номер 1-{len(POPULAR_SNIS)} или имя домена)", default_sni).strip()
        chosen: str | None = None
        if raw.isdigit():
            num = int(raw)
            if 1 <= num <= len(POPULAR_SNIS):
                chosen = POPULAR_SNIS[num - 1][0]
            else:
                print(f"Введите номер от 1 до {len(POPULAR_SNIS)} или доменное имя.")
                continue
        else:
            try:
                chosen = validate_sni(raw)
            except Exception as exc:
                print(f"Некорректный домен SNI: {exc}")
                continue
        ok, detail = probe_cover_reachable(f"{chosen}:443", chosen)
        warn_if_sni_suspicious(chosen)
        if not ok:
            print(f"Предупреждение: cover {chosen}:443 не отвечает с этого VPS ({detail}).")
            if sys.stdin.isatty() and not ask_yes_no("Всё равно выбрать этот домен?", default=False):
                continue
        return chosen


def choose_advanced_role(default_role: str = "direct") -> str:
    default_map = {"direct": "1", "edge": "2", "egress": "3"}
    default_num = default_map.get(default_role, "1")
    print()
    print(heading("Шаг 1. Роль сервера"))
    print("  1. direct — один зарубежный VPS")
    print("  2. edge   — входной сервер (принимает Telegram и передаёт на egress)")
    print("  3. egress — зарубежный сервер выхода (настраивается до edge)")
    print()
    mapping = {
        "1": "direct",
        "direct": "direct",
        "2": "edge",
        "edge": "edge",
        "3": "egress",
        "egress": "egress",
    }
    while True:
        choice = ask("Роль", default_num).lower()
        if choice in mapping:
            return mapping[choice]
        print("Некорректный выбор: введите 1 (direct), 2 (edge) или 3 (egress).")


def ask_egress_upstreams(default_upstreams: str | None) -> list[str]:
    while True:
        raw_list = ask(
            "Основной (или список через запятую) адрес egress (IP:port или wss://host/path)",
            default_upstreams,
        )
        try:
            upstreams = [validate_egress_upstream(item) for item in raw_list.split(",") if item.strip()]
            if not upstreams:
                raise ValueError("укажите хотя бы один адрес IP:port или wss://host/path")
            return upstreams
        except ValueError as exc:
            print(
                f"Некорректный адрес egress: {exc}. Формат: IP:PORT или wss://host/ws/... "
                "(например, 10.203.0.9:29443 или wss://egress.example.com/ws/9f3c...)."
            )


def choose_egress_strategy(default_strategy: str = "ordered") -> str:
    print("\nСтратегия распределения новых подключений между узлами egress:")
    print("  1. ordered     — сначала основной egress; при сбое — резервные по порядку")
    print("  2. round-robin — равномерно по кругу между всеми egress")
    default_strat = "2" if default_strategy == "round-robin" else "1"
    mapping = {"1": "ordered", "ordered": "ordered", "2": "round-robin", "round-robin": "round-robin"}
    while True:
        strat_choice = ask("Стратегия [1/2]", default_strat).lower()
        if strat_choice in mapping:
            return mapping[strat_choice]
        print("Некорректный выбор: введите 1 (ordered) или 2 (round-robin).")


def format_status_command(deploy_dir: Path) -> str:
    ctl_path = deploy_dir / "mtevilctl"
    resolved = deploy_dir.resolve()
    home = Path.home()
    if ctl_path.is_file():
        if resolved in ((home / "mtevil").resolve(), (home / "mtveil").resolve()):
            return "mtevilctl status"
        return f'MTEVIL_DIR="{resolved}" "{ctl_path.resolve()}" status'
    return f'python3 "{(deploy_dir / "setup.py").resolve()}" status --dir "{resolved}"'


def configure_role() -> str:
    return choose_advanced_role("direct")


def load_existing_defaults(deploy_dir: Path) -> dict[str, object]:
    defaults: dict[str, object] = {}
    env_file = deploy_dir / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                defaults[k.strip().replace("MTVEIL_", "MTEVIL_", 1)] = v.strip()
    cfg_file = deploy_dir / "config.json"
    if cfg_file.is_file():
        try:
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
            if isinstance(cfg, dict):
                defaults["config"] = cfg
        except Exception:
            pass
    compose_file = deploy_dir / "compose.yaml"
    if compose_file.is_file():
        try:
            compose_txt = compose_file.read_text(encoding="utf-8", errors="ignore")
            defaults["network_host"] = "network_mode: host" in compose_txt
        except Exception:
            pass
    tproxy_file = deploy_dir / "tproxy.json"
    if tproxy_file.is_file():
        try:
            tp_cfg = json.loads(tproxy_file.read_text(encoding="utf-8"))
            if isinstance(tp_cfg, dict):
                defaults["tproxy_config"] = tp_cfg
        except Exception:
            pass
    defaults["webproxy"] = bool(
        str(defaults.get("MTEVIL_WEBPROXY") or "").strip() == "1"
        or "tproxy_config" in defaults
    )
    defaults["shared_443"] = bool(str(defaults.get("MTEVIL_SHARED_443") or "").strip() == "1")
    defaults["managed_caddy"] = bool(str(defaults.get("MTEVIL_MANAGED_CADDY") or "").strip() == "1")
    return defaults


def default_deploy_dir(repo_root: Path) -> Path:
    env_dir = os.environ.get("MTEVIL_DIR") or os.environ.get("MTVEIL_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "compose.yaml").is_file() and (script_dir / "config.json").is_file():
        return script_dir
    home = Path.home()
    if (home / "mtevil" / "compose.yaml").is_file():
        return (home / "mtevil").resolve()
    if (home / "mtveil" / "compose.yaml").is_file():
        return (home / "mtveil").resolve()
    return (repo_root / "deploy" / "wizard").resolve()


def inspect_image_metadata(image_ref: str) -> tuple[str | None, str | None, str | None]:
    """Return (image_id, repo_digest, version_label_or_tag) for a local Docker image or container image ID."""
    if not image_ref:
        return None, None, None
    proc = run(["docker", "image", "inspect", image_ref], check=False)
    if proc.returncode != 0:
        return None, None, None
    try:
        info = json.loads(proc.stdout)[0]
    except Exception:
        return None, None, None
    image_id = str(info.get("Id") or "").strip() or None
    digests = info.get("RepoDigests") or []
    repo_digest = str(digests[0]).strip() if digests else None
    labels = (info.get("Config") or {}).get("Labels") or {}
    version = str(labels.get("org.opencontainers.image.version") or "").strip() or None
    if not version and ":" in image_ref and "@sha256:" not in image_ref:
        tail = image_ref.rsplit(":", 1)[-1]
        if parse_semver_tag(tail) is not None:
            version = tail
    if not version:
        for tag in info.get("RepoTags") or []:
            if isinstance(tag, str) and ":" in tag:
                cand = tag.rsplit(":", 1)[-1]
                if parse_semver_tag(cand) is not None:
                    version = cand
                    break
    return image_id, repo_digest, version


def inspect_current_deployment(deploy_dir: Path, project: str, configured_image: str) -> tuple[str | None, str | None, str | None]:
    """Inspect the running container first (if any), falling back to the configured image in .env."""
    base = compose_cmd(deploy_dir, project)
    cid_proc = run(base + ["ps", "-q", compose_service(base)], check=False)
    cid = cid_proc.stdout.strip() if cid_proc.returncode == 0 else ""
    if cid:
        c_proc = run(["docker", "inspect", cid], check=False)
        if c_proc.returncode == 0:
            try:
                c_info = json.loads(c_proc.stdout)[0]
                c_image_id = str(c_info.get("Image") or "").strip()
                if c_image_id:
                    img_id, digest, ver = inspect_image_metadata(c_image_id)
                    if not ver and ":" in configured_image:
                        cand = configured_image.rsplit(":", 1)[-1]
                        if parse_semver_tag(cand) is not None:
                            ver = cand
                    return img_id or c_image_id, digest, ver
            except Exception:
                pass
    return inspect_image_metadata(configured_image)


def fetch_json_url(url: str) -> object:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mtevilctl",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


class ChecksumError(RuntimeError):
    """Raised when a downloaded release asset does not match the published SHA256SUMS."""


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse `sha256sum` output ("<hex>  <name>" or "<hex> *<name>") into {name: hex}."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].lower(), parts[1].strip().lstrip("*")
        if re.fullmatch(r"[0-9a-f]{64}", digest) and name:
            if name in sums:
                raise ChecksumError(f"повторная запись в SHA256SUMS: {name}")
            sums[name] = digest
    return sums


def fetch_release_checksums(release_base_url: str, version: str) -> dict[str, str] | None:
    """Return the release SHA256SUMS mapping, or None if the release does not publish one (older releases)."""
    url = f"{release_base_url}/{version}/SHA256SUMS"
    req = urllib.request.Request(url, headers={"User-Agent": "mtevilctl"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        key = parse_semver_tag(version)
        if exc.code == 404 and key is not None and key[:3] <= (0, 1, 1):
            return None
        raise ChecksumError(f"не удалось получить SHA256SUMS релиза {version} (HTTP {exc.code})") from exc
    except OSError as exc:
        raise ChecksumError(f"не удалось получить SHA256SUMS релиза {version}: {exc}") from exc
    sums = parse_sha256sums(text)
    if not sums:
        raise ChecksumError(f"файл SHA256SUMS релиза {version} пуст или повреждён")
    return sums


def download_url_atomic(
    url: str,
    dest: Path,
    mode: int | None = None,
    expected_sha256: str | None = None,
) -> None:
    tmp = dest.with_name(f".{dest.name}.tmp.{os.getpid()}")
    req = urllib.request.Request(url, headers={"User-Agent": "mtevilctl"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
        if expected_sha256 is not None:
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected_sha256.lower():
                raise ChecksumError(
                    f"контрольная сумма {dest.name} не совпала (ожидалась {expected_sha256[:12]}…, получена {actual[:12]}…)"
                )
        tmp.write_bytes(data)
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                pass
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


class MigrationError(ValueError):
    """Raised when an existing compose.yaml/config.json cannot be safely migrated to v0.2 layout."""


def _plan_compose_v02_migration(compose_text: str, svc_name: str) -> tuple[bool, str]:
    """Surgically patch compose.yaml for v0.2 (state:ro, replay volume, init service).

    Preserves all user customizations (ports, environment, extra volumes, ulimits,
    labels, cpus/mem_limit, extra services). Raises MigrationError if the compose
    file is malformed or cannot be patched safely.
    """
    if "\t" in compose_text:
        raise MigrationError("compose.yaml содержит символы табуляции (некорректный YAML)")
    if not compose_text.strip():
        raise MigrationError("compose.yaml пуст")

    lines = compose_text.splitlines()
    services_idx = None
    volumes_idx = None
    for i, line in enumerate(lines):
        if re.match(r"^services\s*:\s*(#.*)?$", line):
            services_idx = i
        elif re.match(r"^volumes\s*:\s*(#.*)?$", line):
            volumes_idx = i

    if services_idx is None:
        raise MigrationError("в compose.yaml отсутствует секция services:")

    services_end = len(lines)
    for i in range(services_idx + 1, len(lines)):
        if lines[i] and not lines[i].startswith(" ") and not lines[i].startswith("#"):
            services_end = i
            break

    svc_start = None
    svc_indent = None
    has_init_svc = False
    for i in range(services_idx + 1, services_end):
        m = re.match(r"^( +)([A-Za-z0-9_.-]+)\s*:\s*(#.*)?$", lines[i])
        if m:
            ind = len(m.group(1))
            name = m.group(2)
            if svc_indent is None or ind == svc_indent:
                if name == svc_name and svc_start is None:
                    svc_start = i
                    svc_indent = ind
                elif name == "init":
                    has_init_svc = True

    if svc_start is None or svc_indent is None:
        raise MigrationError(f"в compose.yaml не найден сервис '{svc_name}:' в секции services:")

    svc_end = services_end
    for i in range(svc_start + 1, services_end):
        if lines[i].strip() and not lines[i].lstrip().startswith("#"):
            cur_ind = len(lines[i]) - len(lines[i].lstrip(" "))
            if cur_ind <= svc_indent:
                svc_end = i
                break

    svc_vol_hdr = None
    svc_vol_indent = None
    for i in range(svc_start + 1, svc_end):
        m = re.match(r"^( +)volumes\s*:\s*(#.*)?$", lines[i])
        if m and len(m.group(1)) > svc_indent:
            svc_vol_hdr = i
            svc_vol_indent = len(m.group(1))
            break

    if svc_vol_hdr is None or svc_vol_indent is None:
        if "state:/var/lib/mtevil" not in compose_text:
            return False, compose_text
        raise MigrationError(f"в сервисе '{svc_name}' не найдена секция volumes:")

    svc_vol_end = svc_end
    for i in range(svc_vol_hdr + 1, svc_end):
        if lines[i].strip() and not lines[i].lstrip().startswith("#"):
            cur_ind = len(lines[i]) - len(lines[i].lstrip(" "))
            if cur_ind <= svc_vol_indent and not lines[i].lstrip().startswith("-"):
                svc_vol_end = i
                break

    state_line_idx = None
    has_state_ro = False
    has_replay_mount = False
    for i in range(svc_vol_hdr + 1, svc_vol_end):
        stripped = lines[i].strip()
        if re.match(r'^-\s*["\']?state:/var/lib/mtevil:ro["\']?\s*(#.*)?$', stripped):
            state_line_idx = i
            has_state_ro = True
        elif re.match(r'^-\s*["\']?state:/var/lib/mtevil(?::rw)?["\']?\s*(#.*)?$', stripped):
            state_line_idx = i
        elif "replay:/var/lib/mtevil-replay" in stripped:
            has_replay_mount = True

    if state_line_idx is None:
        if "state:/var/lib/mtevil" not in compose_text:
            return False, compose_text
        raise MigrationError(f"не удалось безопасно распознать монтирование state:/var/lib/mtevil в сервисе '{svc_name}'")

    has_top_replay = False
    if volumes_idx is not None:
        for i in range(volumes_idx + 1, len(lines)):
            if lines[i] and not lines[i].startswith(" ") and not lines[i].startswith("#"):
                break
            if re.match(r"^ +replay\s*:", lines[i]):
                has_top_replay = True
                break
    else:
        raise MigrationError("в compose.yaml отсутствует корневая секция volumes: для тома state")

    if has_state_ro and has_replay_mount and has_init_svc and has_top_replay:
        return False, compose_text

    out = list(lines)

    # 1. Switch state mount to :ro and add replay mount right below it.
    state_ind = " " * (len(out[state_line_idx]) - len(out[state_line_idx].lstrip(" ")))
    if not has_state_ro:
        out[state_line_idx] = f"{state_ind}- state:/var/lib/mtevil:ro"
    inserted_offset = 0
    if not has_replay_mount:
        out.insert(state_line_idx + 1, f"{state_ind}- replay:/var/lib/mtevil-replay")
        inserted_offset += 1

    # 2. Insert `init` service if absent (reusing `<<: *image` if anchor exists, else matching image line).
    if not has_init_svc:
        has_image_anchor = any("&image" in l for l in out[:services_idx])
        img_spec = "<<: *image"
        if not has_image_anchor:
            found_img = f"image: ${{MTEVIL_IMAGE:-{DEFAULT_IMAGE}}}"
            for i in range(svc_start + 1, svc_end + inserted_offset):
                m_img = re.match(r"^ +(image\s*:\s*.+)$", out[i])
                if m_img:
                    found_img = m_img.group(1).strip()
                    break
            img_spec = found_img
        pad = " " * svc_indent
        init_block = [
            "",
            f"{pad}init:",
            f"{pad}  {img_spec}",
            f"{pad}  profiles: [tools]",
            f"{pad}  volumes:",
            f"{pad}    - state:/var/lib/mtevil",
            f"{pad}    - replay:/var/lib/mtevil-replay",
            f"{pad}  read_only: true",
            f"{pad}  cap_drop: [ALL]",
            f"{pad}  security_opt: [no-new-privileges:true]",
            f"{pad}  mem_limit: 64m",
            f"{pad}  pids_limit: 32",
        ]
        insert_at = services_end + inserted_offset
        while insert_at > services_idx + 1 and out[insert_at - 1].strip() == "":
            insert_at -= 1
        for offset_i, bl in enumerate(init_block):
            out.insert(insert_at + offset_i, bl)
        inserted_offset += len(init_block)

    # 3. Declare `replay:` under top-level `volumes:` if absent.
    if not has_top_replay:
        vol_pos = None
        state_vol_pos = None
        state_vol_ind = "  "
        for i, l in enumerate(out):
            if re.match(r"^volumes\s*:\s*(#.*)?$", l):
                vol_pos = i
                break
        if vol_pos is None:
            raise MigrationError("в compose.yaml отсутствует корневая секция volumes:")
        for i in range(vol_pos + 1, len(out)):
            if out[i] and not out[i].startswith(" ") and not out[i].startswith("#"):
                break
            m_sv = re.match(r"^( +)state\s*:", out[i])
            if m_sv:
                state_vol_pos = i
                state_vol_ind = m_sv.group(1)
                break
        if state_vol_pos is not None:
            out.insert(state_vol_pos + 1, f"{state_vol_ind}replay:")
        else:
            out.insert(vol_pos + 1, f"{state_vol_ind}replay:")

    return True, "\n".join(out) + "\n"


def migrate_compose_and_replay_on_update(
    deploy_dir: Path,
    cfg_file: Path,
    compose_file: Path,
    *,
    dry_run: bool = False,
) -> bool:
    """Safely migrate pre-v0.2 compose.yaml and config.json to isolated state:ro + replay.

    - Preserves compose.yaml.pre-v0.2 and config.json.pre-v0.2 before the first edit (never overwrites existing).
    - Surgically patches compose.yaml to keep all user customizations (ports, env, volumes, ulimits, labels, cpus/mem, extra services).
    - Raises MigrationError without modifying any file if compose.yaml or config.json cannot be safely migrated.
    """
    try:
        compose_text = compose_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise MigrationError(f"не удалось прочитать compose.yaml: {exc}") from exc
    try:
        cfg_text = cfg_file.read_text(encoding="utf-8")
        cfg = json.loads(cfg_text)
    except (OSError, ValueError) as exc:
        raise MigrationError(f"некорректный config.json: {exc}") from exc
    if not isinstance(cfg, dict):
        raise MigrationError("config.json должен содержать JSON-объект")

    svc_name = deployment_service(deploy_dir)
    compose_changed, new_compose = _plan_compose_v02_migration(compose_text, svc_name)

    role = str(cfg.get("role") or "direct")
    cfg_changed = False
    new_cfg = dict(cfg)
    if compose_changed or "replay:/var/lib/mtevil-replay" in new_compose:
        if new_cfg.get("replay_file") == "/var/lib/mtevil/replay.bin" or (
            role in ("direct", "edge") and "replay_file" not in new_cfg
        ):
            new_cfg["replay_file"] = "/var/lib/mtevil-replay/replay.bin"
            cfg_changed = True

    if not compose_changed and not cfg_changed:
        return False
    if dry_run:
        return True

    pre_compose = deploy_dir / "compose.yaml.pre-v0.2"
    if not pre_compose.exists():
        pre_compose.write_text(compose_text, encoding="utf-8")
    pre_cfg = deploy_dir / "config.json.pre-v0.2"
    if not pre_cfg.exists():
        pre_cfg.write_text(cfg_text, encoding="utf-8")

    if compose_changed:
        compose_file.write_text(new_compose, encoding="utf-8")
    if cfg_changed:
        cfg_file.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")
    return True


def copy_legacy_replay_bin_to_replay_volume(base: list[str]) -> bool:
    """Copy existing /var/lib/mtevil/replay.bin bytes into /var/lib/mtevil-replay/replay.bin via init service."""
    if compose_write_service(base) != "init":
        return False
    proc = run(
        base
        + [
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "--entrypoint",
            "/bin/sh",
            "init",
            "-c",
            "if [ -f /var/lib/mtevil/replay.bin ] && [ ! -f /var/lib/mtevil-replay/replay.bin ]; then "
            "cp -p /var/lib/mtevil/replay.bin /var/lib/mtevil-replay/replay.bin && echo COPIED; fi",
        ],
        check=False,
    )
    return proc.returncode == 0 and "COPIED" in (proc.stdout or "")


def _parse_listen_host_ip(listen_val: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(listen_val, str) or not listen_val.strip():
        raise MigrationError("отсутствует или пусто строковое поле listen")
    raw = listen_val.strip()
    if ":" not in raw:
        raise MigrationError(f"некорректный формат listen='{raw}' (ожидается IP:PORT)")
    host_part, port_part = raw.rsplit(":", 1)
    try:
        port = int(port_part)
    except ValueError as exc:
        raise MigrationError(f"некорректный порт в listen='{raw}'") from exc
    if not (1 <= port <= 65535):
        raise MigrationError(f"порт вне диапазона 1..65535 в listen='{raw}'")
    host_clean = host_part.strip("[]")
    try:
        return ipaddress.ip_address(host_clean)
    except ValueError as exc:
        raise MigrationError(f"некорректный IP в listen='{raw}': {exc}") from exc


def _is_canonical_loopback_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_loopback:
        return True
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped.is_loopback
    return False


def _validate_cidr_list_csv(value: str) -> list[str]:
    cidrs: list[str] = []
    for part in value.split(","):
        tok = part.strip()
        if not tok:
            continue
        net = ipaddress.ip_network(tok, strict=False)
        norm = str(net)
        if norm not in cidrs:
            cidrs.append(norm)
    if not cidrs:
        raise ValueError("укажите хотя бы один корректный CIDR (например, 172.17.0.1/32 или 10.203.0.0/24)")
    return cidrs


def _detect_docker_bridge_gateway_cidrs(deploy_dir: Path, project: str) -> list[str]:
    candidates: list[str] = []
    for net_name in (f"{project}_default", "bridge"):
        proc = run(["docker", "network", "inspect", net_name], check=False)
        if proc.returncode != 0 or not proc.stdout:
            continue
        try:
            info = json.loads(proc.stdout)
        except ValueError:
            continue
        items = info if isinstance(info, list) else [info]
        for item in items:
            if not isinstance(item, dict):
                continue
            ipam = item.get("IPAM") if isinstance(item.get("IPAM"), dict) else {}
            configs = ipam.get("Config") if isinstance(ipam.get("Config"), list) else []
            for entry in configs:
                if not isinstance(entry, dict):
                    continue
                gw = str(entry.get("Gateway") or "").strip()
                if gw:
                    try:
                        ip_gw = ipaddress.ip_address(gw)
                        cidr = f"{ip_gw}/32" if ip_gw.version == 4 else f"{ip_gw}/128"
                        if cidr not in candidates:
                            candidates.append(cidr)
                            continue
                    except ValueError:
                        pass
                sub = str(entry.get("Subnet") or "").strip()
                if sub:
                    try:
                        cidr = str(ipaddress.ip_network(sub, strict=False))
                        if cidr not in candidates:
                            candidates.append(cidr)
                    except ValueError:
                        pass
        if candidates:
            break
    if not candidates:
        candidates.append("172.17.0.1/32")
    return candidates


def _detect_host_proxy_source_cidrs(listen_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    if not listen_ip.is_unspecified and not _is_canonical_loopback_ip(listen_ip):
        if listen_ip.version == 4:
            return [str(ipaddress.ip_network(f"{listen_ip}/24", strict=False))]
        return [str(ipaddress.ip_network(f"{listen_ip}/64", strict=False))]

    candidates: list[str] = []
    proc = run(["ip", "-o", "-4", "addr", "show"], check=False)
    if proc.returncode == 0 and proc.stdout:
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            addr_cidr = parts[3]
            if not any(iface.startswith(pfx) for pfx in ("wg", "awg", "amnezia", "docker", "br-")):
                continue
            try:
                iface_net = ipaddress.ip_network(addr_cidr, strict=False)
            except ValueError:
                continue
            if iface.startswith(("docker", "br-")):
                gw_ip = addr_cidr.split("/", 1)[0]
                cidr = f"{gw_ip}/32"
            elif iface_net.prefixlen < 24:
                ip_only = addr_cidr.split("/", 1)[0]
                cidr = str(ipaddress.ip_network(f"{ip_only}/24", strict=False))
            else:
                cidr = str(iface_net)
            if cidr not in candidates:
                candidates.append(cidr)
    if not candidates:
        candidates.append("127.0.0.1/32")
    elif "127.0.0.1/32" not in candidates:
        candidates.append("127.0.0.1/32")
    return candidates


def suggest_proxy_protocol_allow_from(
    deploy_dir: Path,
    project: str,
    cfg: dict[str, object],
    *,
    network_mode: str | None = None,
    compose_text: str | None = None,
) -> tuple[list[str], str]:
    mode = network_mode
    if mode is None:
        txt = compose_text
        if txt is None:
            comp_file = deploy_dir / "compose.yaml"
            if comp_file.is_file():
                txt = comp_file.read_text(encoding="utf-8", errors="ignore")
            else:
                txt = ""
        mode = "host" if re.search(r"(?m)^\s*network_mode\s*:\s*[\"']?host[\"']?\s*$", txt) else "bridge"

    listen_ip = _parse_listen_host_ip(cfg.get("listen"))
    if mode == "bridge":
        return (
            _detect_docker_bridge_gateway_cidrs(deploy_dir, project),
            "шлюз Docker bridge-сети (режим bridge + HAProxy/обратный прокси)",
        )
    return (
        _detect_host_proxy_source_cidrs(listen_ip),
        "подсеть туннеля (WireGuard/AWG) или локальный прокси в режиме host-network",
    )


def inspect_proxy_protocol_config(
    deploy_dir: Path,
    cfg_file: Path,
    *,
    override_cfg: dict[str, object] | None = None,
    network_mode: str | None = None,
    project: str | None = None,
) -> tuple[str, list[str], str, dict[str, object]]:
    if override_cfg is not None:
        cfg = override_cfg
    else:
        try:
            raw_text = cfg_file.read_text(encoding="utf-8")
            cfg = json.loads(raw_text)
        except (OSError, ValueError) as exc:
            raise MigrationError(f"повреждённая конфигурация {cfg_file.name}: {exc}") from exc
    if not isinstance(cfg, dict):
        raise MigrationError(f"повреждённая конфигурация {cfg_file.name}: ожидается JSON-объект")

    if cfg.get("proxy_protocol") is not True:
        return ("ok", [], "", cfg)

    if str(cfg.get("role") or "direct") == "egress":
        raise MigrationError("proxy_protocol=true не поддерживается при role='egress'")

    listen_ip = _parse_listen_host_ip(cfg.get("listen"))
    raw_allow = cfg.get("proxy_protocol_allow_from")
    parsed_allow: list[str] = []
    if raw_allow is not None:
        if not isinstance(raw_allow, list) or not all(isinstance(x, str) for x in raw_allow):
            raise MigrationError(
                "повреждённое поле proxy_protocol_allow_from в config.json: ожидается список CIDR-строк"
            )
        for item in raw_allow:
            try:
                parsed_allow.append(str(ipaddress.ip_network(item.strip(), strict=False)))
            except ValueError as exc:
                raise MigrationError(
                    f"повреждённый CIDR '{item}' в proxy_protocol_allow_from: {exc}"
                ) from exc

    if not _is_canonical_loopback_ip(listen_ip) and not parsed_allow:
        proj = project or f"mtevil-{cfg.get('role') or 'direct'}"
        suggested, reason = suggest_proxy_protocol_allow_from(
            deploy_dir, proj, cfg, network_mode=network_mode
        )
        return ("needs_allow_from", suggested, reason, cfg)
    return ("ok", [], "", cfg)


def ensure_proxy_protocol_migration(
    deploy_dir: Path,
    cfg_file: Path,
    *,
    project: str,
    target_label: str = "v0.4.1+",
    interactive: bool | None = None,
    apply_to_file: bool = True,
    override_cfg: dict[str, object] | None = None,
    network_mode: str | None = None,
) -> tuple[bool, dict[str, object]]:
    """Verify proxy_protocol config compatibility before pulling images or touching containers."""
    status, suggested, reason, cfg = inspect_proxy_protocol_config(
        deploy_dir,
        cfg_file,
        override_cfg=override_cfg,
        network_mode=network_mode,
        project=project,
    )
    if status == "ok":
        return True, cfg

    listen_disp = str(cfg.get("listen") or "")
    suggested_csv = ", ".join(suggested)
    print(
        warn_text(
            f"Несовместимость {target_label} (P2): в config.json включён proxy_protocol=true, "
            f"но listen='{listen_disp}' не на loopback и не задано поле proxy_protocol_allow_from."
        ),
        file=sys.stderr,
    )
    print(
        f"  Источник ({reason}): {suggested_csv}\n"
        f"  Вариант 1: переведите listen на loopback (127.0.0.1:PORT) в режиме --shared-443.\n"
        f"  Вариант 2: укажите доверенные CIDR в proxy_protocol_allow_from: {json.dumps(suggested)}",
        file=sys.stderr,
    )

    is_tty = sys.stdin.isatty() if interactive is None else interactive
    if not is_tty:
        print(
            err_text(
                "Операция остановлена до замены контейнера: в неинтерактивном режиме требуется явное "
                "разрешение proxy_protocol_allow_from или привязка listen к 127.0.0.1."
            ),
            file=sys.stderr,
        )
        return False, cfg

    if not ask_yes_no(
        f"Записать предложенное proxy_protocol_allow_from = [{suggested_csv}] и продолжить?",
        default=True,
    ):
        print(
            err_text("Операция отменена до замены контейнера. Конфигурация и работающий сервис не изменены."),
            file=sys.stderr,
        )
        return False, cfg

    while True:
        raw_entry = ask("Доверенные CIDR для proxy_protocol_allow_from (через запятую)", suggested_csv)
        try:
            chosen = _validate_cidr_list_csv(raw_entry)
            break
        except ValueError as exc:
            print(warn_text(f"Некорректный CIDR: {exc}"))

    new_cfg = copy.deepcopy(cfg)
    new_cfg["proxy_protocol_allow_from"] = chosen
    if apply_to_file and cfg_file.is_file():
        bak = cfg_file.with_name(f"{cfg_file.name}.pre-v041-pp.bak")
        if not bak.exists():
            shutil.copyfile(cfg_file, bak)
            try:
                os.chmod(bak, 0o600)
            except OSError:
                pass
        cfg_file.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")
    print(ok_text(f"Добавлено proxy_protocol_allow_from={json.dumps(chosen)} в config.json."))
    return True, new_cfg


def strip_legacy_default_mss(cfg_file: Path) -> bool:
    """Remove legacy default client_mss=100 / client_mss_bulk=1380 that clamped client SYN-ACK MSS."""
    if not cfg_file.is_file():
        return False
    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    changed = False
    if data.get("client_mss") == 100:
        data.pop("client_mss", None)
        changed = True
    if data.get("client_mss_bulk") == 1380:
        data.pop("client_mss_bulk", None)
        changed = True
    if changed:
        cfg_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


def set_env_image(env_text: str, new_image: str) -> str:
    lines: list[str] = []
    replaced = False
    for line in env_text.splitlines():
        if line.startswith("MTEVIL_IMAGE=") or line.startswith("MTVEIL_IMAGE="):
            lines.append(f"MTEVIL_IMAGE={new_image}")
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"MTEVIL_IMAGE={new_image}")
    return "\n".join(lines) + "\n"


def save_rollback_snapshot(
    deploy_dir: Path,
    project: str,
    prev_version: str | None,
    prev_image_ref: str,
    prev_image_id: str | None,
    prev_digest: str | None,
) -> str:
    rollback_tag = f"mtevil:rollback-{project}"
    source_ref = prev_image_id or prev_image_ref
    tag_proc = run(["docker", "image", "tag", source_ref, rollback_tag], check=False)
    if tag_proc.returncode != 0 and prev_image_ref and source_ref != prev_image_ref:
        tag_proc = run(["docker", "image", "tag", prev_image_ref, rollback_tag], check=False)
    if tag_proc.returncode != 0:
        detail = (tag_proc.stderr or tag_proc.stdout or "").strip()
        raise RuntimeError(f"Не удалось сохранить локальный тег образа для отката ({rollback_tag}): {detail}")

    for name in ("compose.yaml", ".env", "config.json"):
        src = deploy_dir / name
        if src.is_file():
            shutil.copyfile(src, deploy_dir / f"{name}.rollback")

    # Ensure .env.rollback points directly to the local rollback tag so rollback needs no internet.
    env_rb = deploy_dir / ".env.rollback"
    if env_rb.is_file():
        env_rb.write_text(
            set_env_image(env_rb.read_text(encoding="utf-8", errors="ignore"), rollback_tag),
            encoding="utf-8",
        )

    meta = {
        "project": project,
        "version": prev_version or prev_image_ref,
        "image": prev_image_ref,
        "image_id": prev_image_id,
        "repo_digest": prev_digest,
        "local_tag": rollback_tag,
        "saved_at": int(time.time()),
    }
    (deploy_dir / "rollback.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return rollback_tag


def verify_telegram_e2e(
    base: list[str],
    *,
    attempts: int = 3,
    delay_s: float = 2.0,
    dc: int = 2,
    timeout_s: int = 8,
    fallback_probe_image: str | None = None,
) -> tuple[bool, str]:
    """Run an end-to-end Telegram probe (FakeTLS/MTV2 handshake + req_pq_multi -> resPQ) through the running proxy."""
    svc = compose_service(base)
    last_err = ""
    for idx in range(1, attempts + 1):
        proc = run(
            base
            + [
                "exec",
                "-T",
                svc,
                "mtevil",
                "probe-telegram",
                "--config",
                "/etc/mtevil/config.json",
                "--dc",
                str(dc),
                "--timeout-secs",
                str(timeout_s),
            ],
            check=False,
        )
        if proc.returncode == 0:
            detail = (proc.stdout or "").strip()
            try:
                info = json.loads(detail)
                rtt = info.get("rtt_ms")
                if rtt is not None:
                    return True, f"ответ Telegram DC {dc} получен за {rtt} мс"
            except Exception:
                pass
            return True, f"ответ Telegram DC {dc} получен"

        err_out = (proc.stderr or proc.stdout or "").strip()
        # If rolling back to an older image that does not yet have `probe-telegram`,
        # run the probe binary from `fallback_probe_image` inside the running container's network namespace.
        if (
            fallback_probe_image
            and ("unrecognized subcommand" in err_out.lower() or "unexpected argument" in err_out.lower())
        ):
            cid_proc = run(base + ["ps", "-q", svc], check=False)
            cid = cid_proc.stdout.strip() if cid_proc.returncode == 0 else ""
            if cid:
                deploy_dir = Path(base[-1]).parent.resolve()
                cfg_host = str((deploy_dir / "config.json").resolve())
                # Inspect the mounted state volume source from the running container so probe-telegram can read proxy-secret / egress-token.
                vol_args: list[str] = []
                insp = run(["docker", "inspect", cid], check=False)
                if insp.returncode == 0:
                    try:
                        mounts = json.loads(insp.stdout)[0].get("Mounts") or []
                        for m in mounts:
                            if m.get("Destination") in ("/var/lib/mtevil", "/var/lib/mtveil"):
                                src = m.get("Name") or m.get("Source")
                                if src:
                                    vol_args = ["-v", f"{src}:{m['Destination']}:ro"]
                                break
                    except Exception:
                        pass
                fb_proc = run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        f"--network=container:{cid}",
                        "-v",
                        f"{cfg_host}:/etc/mtevil/config.json:ro",
                        *vol_args,
                        fallback_probe_image,
                        "probe-telegram",
                        "--config",
                        "/etc/mtevil/config.json",
                        "--dc",
                        str(dc),
                        "--timeout-secs",
                        str(timeout_s),
                    ],
                    check=False,
                )
                if fb_proc.returncode == 0:
                    detail = (fb_proc.stdout or "").strip()
                    try:
                        info = json.loads(detail)
                        rtt = info.get("rtt_ms")
                        if rtt is not None:
                            return True, f"ответ Telegram DC {dc} получен за {rtt} мс"
                    except Exception:
                        pass
                    return True, f"ответ Telegram DC {dc} получен"
                err_out = (fb_proc.stderr or fb_proc.stdout or "").strip()

        last_err = err_out or f"код возврата {proc.returncode}"
        if idx < attempts:
            time.sleep(delay_s)
    return False, last_err


def perform_rollback(
    deploy_dir: Path,
    *,
    auto_from_failed_update: bool = False,
    verify_e2e: bool = True,
    probe_image_hint: str | None = None,
) -> int:
    rb_meta_file = deploy_dir / "rollback.json"
    if not rb_meta_file.is_file():
        print(err_text(f"Снимок для отката не найден в {deploy_dir} (нет rollback.json)."), file=sys.stderr)
        print("Дальше: откат доступен после хотя бы одного обновления через mtevilctl update.", file=sys.stderr)
        return 1

    for name in ("compose.yaml", ".env", "config.json"):
        if not (deploy_dir / f"{name}.rollback").is_file():
            print(err_text(f"Не найден файл снимка {name}.rollback в {deploy_dir}."), file=sys.stderr)
            return 1

    try:
        meta = json.loads(rb_meta_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(err_text(f"Не удалось прочитать rollback.json: {exc}"), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    project = str(meta.get("project") or saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    cur_image_cfg = str(saved.get("MTEVIL_IMAGE") or "")
    _, _, cur_version = inspect_current_deployment(deploy_dir, project, cur_image_cfg)

    target_version = str(meta.get("version") or meta.get("image") or "previous")
    local_tag = str(meta.get("local_tag") or f"mtevil:rollback-{project}")
    image_id = str(meta.get("image_id") or "").strip()

    # Verify the rollback image exists locally without touching the network.
    chosen_image = local_tag
    if run(["docker", "image", "inspect", local_tag], check=False).returncode != 0:
        if image_id and run(["docker", "image", "inspect", image_id], check=False).returncode == 0:
            run(["docker", "image", "tag", image_id, local_tag], check=False)
            chosen_image = local_tag
        else:
            orig_img = str(meta.get("image") or "").strip()
            if orig_img and run(["docker", "image", "inspect", orig_img], check=False).returncode == 0:
                chosen_image = orig_img
            else:
                print(err_text(f"Локальный образ для отката ({local_tag}) не найден в кэше Docker."), file=sys.stderr)
                return 1

    if not auto_from_failed_update:
        from_label = cur_version or cur_image_cfg or "текущая версия"
        print(heading(f"Откат mtevil: {from_label} -> {target_version}"))

    for name in ("compose.yaml", ".env", "config.json"):
        shutil.copyfile(deploy_dir / f"{name}.rollback", deploy_dir / name)

    try:
        stripped, backup_path = strip_me_block_for_legacy_version(
            deploy_dir / "config.json", target_version
        )
        if stripped and backup_path is not None:
            print(
                f"Блок 'me' не поддерживается в {target_version}: сохранён бэкап {backup_path.name} и удалён блок 'me' из config.json."
            )
    except Exception as exc:
        print(
            err_text(
                f"Не удалось подготовить config.json для отката на {target_version}: {exc}. Текущий контейнер не затронут."
            ),
            file=sys.stderr,
        )
        return 1

    env_path = deploy_dir / ".env"
    env_path.write_text(
        set_env_image(env_path.read_text(encoding="utf-8", errors="ignore"), chosen_image),
        encoding="utf-8",
    )

    base = compose_cmd(deploy_dir, project)
    up_proc = run(base + ["up", "-d", "--no-build", "--force-recreate", compose_service(base)], check=False)
    if up_proc.returncode != 0:
        detail = (up_proc.stderr or up_proc.stdout or "").strip()
        print(err_text(f"Не удалось запустить контейнер при откате: {detail}"), file=sys.stderr)
        return 1

    try:
        wait_healthy(base)
    except Exception as exc:
        print(err_text(f"Контейнер запущен при откате, но не подтвердил статус healthy: {exc}"), file=sys.stderr)
        return 1

    if verify_e2e and os.environ.get("MTEVIL_SKIP_E2E_PROBE") != "1":
        print("Сквозная проверка Telegram после отката...")
        e2e_ok, e2e_detail = verify_telegram_e2e(
            base,
            attempts=3,
            delay_s=2.0,
            fallback_probe_image=probe_image_hint or cur_image_cfg or None,
        )
        if not e2e_ok:
            print(err_text(f"Откат запущен (healthy), но сквозная проверка Telegram не прошла: {e2e_detail}"), file=sys.stderr)
            return 1
        print(ok_text(f"Сквозная проверка Telegram после отката пройдена ({e2e_detail})."))

    print(ok_text(f"Откат выполнен: работает версия {target_version}."))
    return 0


def resolve_allow_prerelease(flag: bool = False) -> bool:
    if flag:
        return True
    ch = (os.environ.get("MTEVIL_CHANNEL") or os.environ.get("MTVEIL_CHANNEL") or "stable").strip().lower()
    if ch in ("prerelease", "pre", "alpha", "beta", "rc"):
        return True
    if ch in ("", "stable"):
        return False
    fail(f"Неизвестный канал обновлений MTEVIL_CHANNEL='{ch}' (допустимо: stable или prerelease).")


def run_update_command(
    deploy_dir: Path,
    target_version_override: str | None = None,
    *,
    reexec: bool = False,
    allow_prerelease: bool = False,
) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        print("Дальше: укажите каталог через MTEVIL_DIR или выполните первичную установку.", file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    cur_image_ref = str(saved.get("MTEVIL_IMAGE") or "")
    cur_image_id, cur_digest, cur_version = inspect_current_deployment(deploy_dir, project, cur_image_ref)

    repo = os.environ.get("MTEVIL_REPO") or os.environ.get("MTVEIL_REPO") or "RsNest/mtevil"
    repo_lower = repo.lower()
    api_url = os.environ.get("MTEVIL_RELEASES_API_URL") or f"https://api.github.com/repos/{repo}/releases?per_page=30"
    release_base_url = os.environ.get("MTEVIL_RELEASE_BASE_URL") or f"https://github.com/{repo}/releases/download"

    requested_version = (
        target_version_override
        or os.environ.get("MTEVIL_VERSION")
        or os.environ.get("MTVEIL_VERSION")
        or ""
    ).strip()
    explicit_image = (os.environ.get("MTEVIL_UPDATE_IMAGE") or "").strip()
    use_prerelease = resolve_allow_prerelease(allow_prerelease)

    if requested_version:
        target_version = requested_version
    else:
        try:
            releases_data = fetch_json_url(api_url)
            if not isinstance(releases_data, list):
                raise ValueError("Ответ GitHub API не является списком релизов.")
            target_version = select_latest_release(releases_data, allow_prerelease=use_prerelease)
        except Exception as exc:
            print(err_text(f"Не удалось определить целевой релиз: {exc}"), file=sys.stderr)
            return 1

    if parse_semver_tag(target_version) is None:
        print(err_text(f"Недопустимый тег релиза: {target_version}"), file=sys.stderr)
        return 1

    target_image = explicit_image or f"ghcr.io/{repo_lower}:{target_version}"

    # Fast path if installed version already matches target_version (preserves existing rollback snapshot untouched).
    if not explicit_image and cur_version == target_version:
        print(ok_text(f"Уже установлена актуальная версия {target_version}. Перезапуск не требуется."))
        return 0

    # If downgrading to < v0.3.0 (e.g. v0.2.0), strip the `me` block BEFORE re-exec or restart
    # (saving a 0600 backup) so v0.2.0's strict deny_unknown_fields parser can start cleanly.
    try:
        stripped_me, me_backup = strip_me_block_for_legacy_version(cfg_file, target_version)
        if stripped_me and me_backup is not None:
            print(
                f"Блок 'me' не поддерживается в {target_version}: сохранён бэкап {me_backup.name} и удалён блок 'me' из config.json."
            )
    except Exception as exc:
        print(
            err_text(
                f"Переход на {target_version} отменён до остановки сервиса: ошибка обработки блока 'me' в config.json ({exc})."
            ),
            file=sys.stderr,
        )
        return 1

    # Download helper scripts from the target release and hand off execution (re-exec)
    # BEFORE mutating .env or recreating the container, so the target release's own update
    # and E2E verification logic runs for this very update.
    if not reexec and os.environ.get("MTEVIL_SKIP_ASSET_DOWNLOAD") != "1":
        new_setup = deploy_dir / "setup.py"
        new_ctl = deploy_dir / "mtevilctl"
        try:
            checksums = fetch_release_checksums(release_base_url, target_version)
            if checksums is None:
                print("SHA256SUMS отсутствует в старом релизе.", file=sys.stderr)
            elif not {"setup.py", "mtevilctl"}.issubset(checksums):
                raise ChecksumError("в SHA256SUMS отсутствует setup.py или mtevilctl")

            with tempfile.TemporaryDirectory(prefix=".release-", dir=deploy_dir) as staging_dir:
                staging = Path(staging_dir)
                for dest in (new_setup, new_ctl):
                    try:
                        download_url_atomic(
                            f"{release_base_url}/{target_version}/{dest.name}",
                            staging / dest.name,
                            mode=0o755,
                            expected_sha256=checksums[dest.name] if checksums is not None else None,
                        )
                    except urllib.error.HTTPError as exc:
                        if checksums is not None or dest != new_ctl or exc.code != 404:
                            raise

                candidate = staging / new_setup.name
                syntax_check = run([sys.executable, "-m", "py_compile", str(candidate)], check=False)
                if syntax_check.returncode:
                    raise ChecksumError("скачанный setup.py не проходит проверку синтаксиса")
                os.replace(candidate, new_setup)
                if (staging / new_ctl.name).is_file():
                    os.replace(staging / new_ctl.name, new_ctl)
        except (OSError, ChecksumError) as exc:
            print(err_text(f"Обновление отменено: {exc}. Текущий контейнер не затронут."), file=sys.stderr)
            return 1

        reexec_argv = [
            sys.executable,
            str(new_setup),
            "update",
            "--dir",
            str(deploy_dir),
            "--version",
            target_version,
            "--reexec",
        ]
        if explicit_image:
            reexec_argv.extend(["--image", explicit_image])
        try:
            os.execv(sys.executable, reexec_argv)
        except OSError as exc:
            print(
                err_text(
                    f"Не удалось запустить обновлённый setup.py ({target_version}): {exc}. Текущий контейнер не затронут."
                ),
                file=sys.stderr,
            )
            return 1

    from_label = cur_version or cur_image_ref or "unknown"
    print(heading(f"Обновление mtevil: {from_label} -> {target_version}"))

    ver_key = parse_semver_tag(target_version)
    if ver_key is None or ver_key[:3] >= (0, 4, 1) or explicit_image:
        try:
            pp_ok, _ = ensure_proxy_protocol_migration(
                deploy_dir,
                cfg_file,
                project=project,
                target_label=target_version,
            )
        except MigrationError as exc:
            print(
                err_text(f"Обновление отменено до скачивания образа и замены контейнера: {exc}."),
                file=sys.stderr,
            )
            return 1
        if not pp_ok:
            return 1
    else:
        try:
            json.loads(cfg_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(
                err_text(f"Обновление отменено до скачивания образа: повреждена конфигурация config.json ({exc})."),
                file=sys.stderr,
            )
            return 1

    print(f"Загрузка Docker-образа {target_image}...")
    pull_proc = run(["docker", "pull", target_image], check=False)
    if pull_proc.returncode != 0:
        detail = (pull_proc.stderr or pull_proc.stdout or "").strip()
        summary, action = diagnose_docker_error(detail, target_image)
        print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
        return 1

    new_image_id, _, new_image_ver = inspect_image_metadata(target_image)
    if cur_image_id and new_image_id and cur_image_id == new_image_id and (cur_version or new_image_ver) == target_version:
        print(ok_text(f"Уже установлена актуальная версия {target_version}. Перезапуск не требуется."))
        return 0

    # Validate existing config.json + state volume against the newly pulled image before touching live files or stopping the container.
    cand_env_file = deploy_dir / ".env.update_check"
    orig_env_text = env_file.read_text(encoding="utf-8", errors="ignore")
    try:
        cand_env_file.write_text(set_env_image(orig_env_text, target_image), encoding="utf-8")
        cand_base = compose_cmd(deploy_dir, project, "compose.yaml", ".env.update_check")
        cfg_check = run(
            cand_base + ["run", "--rm", "--no-deps", compose_service(cand_base), "--config", "/etc/mtevil/config.json", "--check-config"],
            check=False,
        )
    finally:
        if cand_env_file.exists():
            try:
                cand_env_file.unlink()
            except OSError:
                pass
    if cfg_check.returncode != 0:
        detail = (cfg_check.stderr or cfg_check.stdout or "").strip()
        print(err_text("Существующая конфигурация не прошла проверку на новом образе. Обновление отменено."), file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return 1

    # Validate migration plan BEFORE saving rollback or touching live files / stopping the running container.
    try:
        migrate_compose_and_replay_on_update(deploy_dir, cfg_file, compose_file, dry_run=True)
    except MigrationError as exc:
        print(
            err_text(f"Не удалось безопасно мигрировать compose.yaml/config.json: {exc}. Обновление отменено, текущий сервис не затронут."),
            file=sys.stderr,
        )
        return 1

    # Save rollback snapshot of the currently working version, image tag, and config before modifying anything.
    try:
        save_rollback_snapshot(
            deploy_dir,
            project,
            cur_version,
            cur_image_ref,
            cur_image_id,
            cur_digest,
        )
    except Exception as exc:
        print(err_text(str(exc)), file=sys.stderr)
        return 1

    strip_legacy_default_mss(cfg_file)
    migrated_v02 = migrate_compose_and_replay_on_update(deploy_dir, cfg_file, compose_file)
    orig_env_text = env_file.read_text(encoding="utf-8", errors="ignore")
    env_file.write_text(set_env_image(orig_env_text, target_image), encoding="utf-8")

    base = compose_cmd(deploy_dir, project)
    if migrated_v02:
        copy_legacy_replay_bin_to_replay_volume(base)
    up_proc = run(base + ["up", "-d", "--no-build", "--force-recreate", compose_service(base)], check=False)
    if up_proc.returncode != 0:
        detail = (up_proc.stderr or up_proc.stdout or "").strip()
        print(err_text(f"Не удалось запустить новый контейнер ({target_version}): {detail}"), file=sys.stderr)
        print(warn_text("Автоматический возврат предыдущей рабочей версии..."), file=sys.stderr)
        perform_rollback(deploy_dir, auto_from_failed_update=True, verify_e2e=True, probe_image_hint=target_image)
        return 1

    try:
        wait_healthy(base)
    except TimeoutError:
        print(err_text(f"Новый контейнер ({target_version}) не перешёл в статус healthy за 45 секунд."), file=sys.stderr)
        print_failed_container_logs(base)
        print(warn_text("Автоматический возврат предыдущей рабочей версии..."), file=sys.stderr)
        perform_rollback(deploy_dir, auto_from_failed_update=True, verify_e2e=True, probe_image_hint=target_image)
        return 1

    if os.environ.get("MTEVIL_SKIP_E2E_PROBE") != "1":
        print("Сквозная проверка прохождения запроса к Telegram через обновлённый прокси...")
        e2e_ok, e2e_detail = verify_telegram_e2e(base, attempts=3, delay_s=2.0, fallback_probe_image=target_image)
        if not e2e_ok:
            print(
                err_text(f"Сквозная проверка Telegram не прошла 3 раза подряд ({target_version}): {e2e_detail}"),
                file=sys.stderr,
            )
            print(warn_text("Автоматический возврат предыдущей рабочей версии..."), file=sys.stderr)
            perform_rollback(deploy_dir, auto_from_failed_update=True, verify_e2e=True, probe_image_hint=target_image)
            return 1
        print(ok_text(f"Сквозная проверка Telegram пройдена ({e2e_detail})."))

    print(ok_text(f"Обновление завершено: работает версия {target_version} (контейнер исправен)."))
    return 0


def format_bytes_ru(num_bytes: int | float | None) -> str:
    if num_bytes is None:
        return "нет данных"
    n = float(num_bytes)
    if n < 1024:
        return f"{int(n)} Б"
    for unit in ("КиБ", "МиБ", "ГиБ", "ТиБ"):
        n /= 1024.0
        if n < 1024.0 or unit == "ТиБ":
            return f"{n:.2f} {unit} ({int(num_bytes)} Б)"
    return f"{int(num_bytes)} Б"


def format_rate_ru(bytes_per_sec: float | None) -> str:
    if bytes_per_sec is None:
        return "нет данных"
    n = float(bytes_per_sec)
    if n < 1024:
        return f"{n:.0f} Б/с"
    for unit in ("КиБ/с", "МиБ/с", "ГиБ/с"):
        n /= 1024.0
        if n < 1024.0 or unit == "ГиБ/с":
            return f"{n:.2f} {unit}"
    return f"{bytes_per_sec:.0f} Б/с"


def format_duration_ru(seconds: int | float | None) -> str:
    if seconds is None or seconds < 0:
        return "нет данных"
    sec = int(seconds)
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts: list[str] = []
    if days > 0:
        parts.append(f"{days} д")
    if hours > 0 or days > 0:
        parts.append(f"{hours} ч")
    if mins > 0 or hours > 0 or days > 0:
        parts.append(f"{mins} мин")
    parts.append(f"{secs} с")
    return " ".join(parts)


def parse_iso_timestamp_to_epoch(iso_str: str) -> float | None:
    s = (iso_str or "").strip()
    if not s or s.startswith("0001-01-01"):
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}:\d{2})?$", s)
    if m:
        frac = (m.group(2) or "")[:6].ljust(6, "0")
        tz = m.group(3) or "+00:00"
        s = f"{m.group(1)}.{frac}{tz}" if frac else f"{m.group(1)}{tz}"
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def get_available_rollback_version(deploy_dir: Path, project: str) -> str:
    rb_file = deploy_dir / "rollback.json"
    if not rb_file.is_file():
        return "нет данных (откат ещё не сохранён)"
    try:
        meta = json.loads(rb_file.read_text(encoding="utf-8"))
    except Exception:
        return "нет данных"
    ver = str(meta.get("version") or meta.get("image") or "").strip()
    local_tag = str(meta.get("local_tag") or f"mtevil:rollback-{project}").strip()
    image_id = str(meta.get("image_id") or "").strip()
    has_local = (
        run(["docker", "image", "inspect", local_tag], check=False).returncode == 0
        or (bool(image_id) and run(["docker", "image", "inspect", image_id], check=False).returncode == 0)
    )
    if not ver:
        return "нет данных"
    return f"{ver} (образ доступен локально)" if has_local else f"{ver} (локальный образ отсутствует)"


def run_status_command(deploy_dir: Path) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    configured_image = str(saved.get("MTEVIL_IMAGE") or "")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)

    cid_proc = run(base + ["ps", "-q", svc], check=False)
    cid = cid_proc.stdout.strip() if cid_proc.returncode == 0 else ""
    running = False
    health_status = "остановлен"
    uptime_str = "нет данных"
    net_mode_label = "host (--network-host)" if "network_mode: host" in compose_file.read_text(encoding="utf-8", errors="ignore") else "bridge"

    if cid:
        c_proc = run(["docker", "inspect", cid], check=False)
        if c_proc.returncode == 0:
            try:
                c_info = json.loads(c_proc.stdout)[0]
                state = c_info.get("State") or {}
                running = bool(state.get("Running"))
                status_raw = str(state.get("Status") or "unknown")
                health_raw = str((state.get("Health") or {}).get("Status") or "")
                if running:
                    health_status = f"{health_raw} (работает)" if health_raw else f"{status_raw} (работает)"
                    started_epoch = parse_iso_timestamp_to_epoch(str(state.get("StartedAt") or ""))
                    if started_epoch is not None:
                        uptime_str = format_duration_ru(max(0.0, time.time() - started_epoch))
                else:
                    health_status = f"остановлен ({status_raw})"
            except Exception:
                pass

    _, _, cur_version = inspect_current_deployment(deploy_dir, project, configured_image)
    if not cur_version and running:
        ver_proc = run(base + ["exec", "-T", svc, "mtevil", "--version"], check=False)
        if ver_proc.returncode == 0 and ver_proc.stdout.strip():
            parts = ver_proc.stdout.strip().split()
            cur_version = parts[-1] if parts else ver_proc.stdout.strip()

    role_names = {
        "direct": "direct (один зарубежный сервер)",
        "edge": "edge (входной сервер -> egress)",
        "egress": "egress (зарубежный сервер выхода)",
    }
    rollback_ver = get_available_rollback_version(deploy_dir, project)
    port_val = str(saved.get("MTEVIL_PORT") or "")
    bind_val = str(saved.get("MTEVIL_BIND") or "")

    print(heading("Статус mtevil"))
    print(f"  Каталог установки: {deploy_dir}")
    print(f"  Версия:            {cur_version or configured_image or 'нет данных'}")
    print(f"  Роль:              {role_names.get(role, role)}")
    if bind_val and port_val:
        pub_port_env = str(saved.get("MTEVIL_PUBLIC_PORT") or "").strip()
        if pub_port_env and pub_port_env != port_val:
            print(
                f"  Порт и сеть:       внешний :{pub_port_env} -> {bind_val}:{port_val} "
                f"({net_mode_label}, PROXY protocol v2)"
            )
        else:
            print(f"  Порт и сеть:       {bind_val}:{port_val} ({net_mode_label})")
    if role in ("direct", "edge"):
        cur_sni = str(saved_cfg.get("sni") or "").strip()
        if cur_sni:
            extra_snis = [s for s in read_allowed_snis_from_volume(base) if s != cur_sni.lower()]
            sni_note = f" (также разрешены: {', '.join(extra_snis)})" if extra_snis else ""
            print(f"  Маскировка (SNI):  {cur_sni}{sni_note}")
        c_mss = saved_cfg.get("client_mss")
        b_mss = saved_cfg.get("client_mss_bulk")
        if c_mss is not None or b_mss is not None:
            print(f"  Профиль TCP MSS:   handshake={c_mss or 'авто'}, bulk={b_mss or 'авто'}")
    if role == "edge":
        raw_ups = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
        if raw_ups:
            redacted_ups = ", ".join(redact_egress_upstream(str(u)) for u in raw_ups)
            strat = str(saved_cfg.get("egress_strategy") or "round-robin")
            hedge_ms = int(saved_cfg.get("egress_hedge_ms", 400))
            print(f"  Узлы egress:       {redacted_ups} ({strat}, hedge={hedge_ms} мс)")
    print(f"  Состояние:         {health_status}")
    print(f"  Время работы:      {uptime_str}")
    print(f"  Версия для отката: {rollback_ver}")
    rstats = read_container_runtime_stats(base, svc) if running else None
    for me_line in format_me_status_lines(role, saved_cfg, rstats):
        print(me_line)
    for diag_line in format_handshake_diag_lines(role, rstats):
        print(diag_line)
    if saved.get("webproxy"):
        for wp_line in format_webproxy_status_lines(base, saved):
            print(wp_line)
    if (
        running
        and not (saved.get("webproxy") and bind_val in ("127.0.0.1", "::1"))
        and not bool(saved_cfg.get("proxy_protocol", False))
    ):
        for cov_line in format_cover_status_lines(role, saved_cfg, bind_val, port_val):
            print(cov_line)
    if role == "egress":
        accept_legacy = saved_cfg.get("egress_accept_legacy", True) is not False
        proto_mode = "MTV4 + MTV3 + legacy MTV2 (переходный)" if accept_legacy else "MTV4 + MTV3 (строгий)"
        print(f"  Протокол egress:   {proto_mode}")
        if saved_cfg.get("egress_ws_path"):
            print("  Транспорт WS/WSS:  включён (путь скрыт)")
        if isinstance(rstats, dict):
            mtv3_cnt = rstats.get("egress_mtv3_connections")
            legacy_cnt = rstats.get("egress_legacy_connections")
            if mtv3_cnt is not None or legacy_cnt is not None:
                print(
                    f"  Подключения:       MTV3={int(mtv3_cnt or 0)}, legacy MTV2={int(legacy_cnt or 0)}"
                )
        if accept_legacy:
            print(
                "  Подсказка MTV3:    после обновления всех edge выставите "
                '"egress_accept_legacy": false в config.json и перезапустите egress.'
            )
    if role == "edge" and running:
        alerts_text = ""
        for alerts_path in ("/var/lib/mtevil-replay/edge-alerts.jsonl", "/var/lib/mtevil/edge-alerts.jsonl"):
            alerts_proc = run(
                base + ["exec", "-T", svc, "/bin/cat", alerts_path],
                check=False,
            )
            if alerts_proc.returncode == 0 and alerts_proc.stdout.strip():
                alerts_text = alerts_proc.stdout.strip()
                break
        if alerts_text:
            lines = [ln.strip() for ln in alerts_text.splitlines() if ln.strip()]
            if lines:
                try:
                    last_ev = json.loads(lines[-1])
                    msg = str(last_ev.get("message") or last_ev.get("state") or "").strip()
                    if msg:
                        print(f"  Оповещение edge:   {msg}")
                except Exception:
                    pass
    return 0


def read_container_runtime_stats(base: list[str], svc: str) -> dict[str, object] | None:
    for path in ("/var/lib/mtevil-replay/runtime-stats.json", "/var/lib/mtevil/runtime-stats.json"):
        proc = run(
            base + ["exec", "-T", svc, "/bin/cat", path],
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
    return None


def direction_labels_for_role(role: str) -> tuple[str, str, str, str, str, str]:
    """Return (scope_note, down_rx_label, down_tx_label, up_tx_label, up_rx_label, leg_pair_names)."""
    if role == "edge":
        return (
            "только сокеты процесса mtevil (трафик других сервисов VPS исключён)",
            "Принято на участке клиент -> edge (вход прокси)",
            "Отправлено на участке edge -> клиент (ответ клиенту)",
            "Отправлено на участке edge -> egress (туннель к выходу)",
            "Принято на участке egress -> edge (ответ от выхода)",
            "клиент <-> edge / edge <-> egress",
        )
    if role == "egress":
        return (
            "только сокеты процесса mtevil (трафик других сервисов VPS исключён)",
            "Принято на участке edge -> egress (вход от edge)",
            "Отправлено на участке egress -> edge (ответ к edge)",
            "Отправлено на участке egress -> Telegram DC",
            "Принято на участке Telegram DC -> egress",
            "edge <-> egress / egress <-> Telegram DC",
        )
    return (
        "только сокеты процесса mtevil (трафик других сервисов VPS исключён)",
        "Принято на участке клиент -> прокси (загрузка от клиента)",
        "Отправлено на участке прокси -> клиент (отдача клиенту)",
        "Отправлено на участке прокси -> Telegram DC",
        "Принято на участке Telegram DC -> прокси",
        "клиент <-> прокси / прокси <-> Telegram DC",
    )


def format_period_covered(stats: dict[str, object] | None, container_started_epoch: float | None) -> str:
    if stats and isinstance(stats.get("started_unix_ms"), (int, float)) and int(stats["started_unix_ms"]) > 0:
        start_ts = float(stats["started_unix_ms"]) / 1000.0
        now_ts = (
            float(stats["ts_unix_ms"]) / 1000.0
            if isinstance(stats.get("ts_unix_ms"), (int, float)) and int(stats["ts_unix_ms"]) > 0
            else time.time()
        )
        dt_str = datetime.datetime.fromtimestamp(start_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"с запуска процесса mtevil ({dt_str}, длительность {format_duration_ru(max(0.0, now_ts - start_ts))})"
    if container_started_epoch is not None:
        dt_str = datetime.datetime.fromtimestamp(container_started_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"с запуска контейнера ({dt_str}, длительность {format_duration_ru(max(0.0, time.time() - container_started_epoch))})"
    return "нет данных"


def format_retrans_count(val: object, supported: bool) -> str:
    if not supported or not isinstance(val, (int, float)):
        return "нет данных"
    return f"{int(val)} сегм."


def render_traffic_snapshot(
    role: str,
    stats: dict[str, object] | None,
    container_started_epoch: float | None,
) -> str:
    scope_note, down_rx_lbl, down_tx_lbl, up_tx_lbl, up_rx_lbl, _ = direction_labels_for_role(role)
    period_str = format_period_covered(stats, container_started_epoch)
    lines: list[str] = [
        heading(f"Трафик mtevil (роль: {role})"),
        f"  Охват метрик:      {scope_note}",
        f"  Период счётчиков:  {period_str}",
    ]
    if stats is None:
        lines.extend([
            "  Активные сессии:   нет данных",
            "  Завершено сессий:  нет данных",
            f"  {down_rx_lbl}: нет данных",
            f"  {down_tx_lbl}: нет данных",
            f"  {up_tx_lbl}: нет данных",
            f"  {up_rx_lbl}: нет данных",
            "  Ретрансмиссии TCP: нет данных",
        ])
        return "\n".join(lines)

    active = stats.get("active_sessions")
    completed = stats.get("completed_sessions")
    failed = stats.get("failed_sessions")
    down_rx = stats.get("downstream_rx_bytes")
    down_tx = stats.get("downstream_tx_bytes")
    up_tx = stats.get("upstream_tx_bytes")
    up_rx = stats.get("upstream_rx_bytes")
    retrans_ok = bool(stats.get("retrans_supported"))
    down_retrans = stats.get("downstream_retrans_segs")
    up_retrans = stats.get("upstream_retrans_segs")

    active_str = str(int(active)) if isinstance(active, (int, float)) else "нет данных"
    if isinstance(completed, (int, float)) and isinstance(failed, (int, float)):
        total_closed = int(completed) + int(failed)
        closed_str = f"{total_closed} (успешно: {int(completed)}, с ошибкой: {int(failed)})"
    else:
        closed_str = "нет данных"

    down_leg_name = "edge -> клиент" if role == "edge" else ("egress -> edge" if role == "egress" else "прокси -> клиент")
    up_leg_name = "edge -> egress" if role == "edge" else ("egress -> Telegram DC" if role == "egress" else "прокси -> Telegram DC")

    lines.extend([
        f"  Активные сессии:   {active_str}",
        f"  Отключений всего:  {closed_str}",
        f"  {down_rx_lbl}: {format_bytes_ru(down_rx if isinstance(down_rx, (int, float)) else None)}",
        f"  {down_tx_lbl}: {format_bytes_ru(down_tx if isinstance(down_tx, (int, float)) else None)}",
        f"  {up_tx_lbl}: {format_bytes_ru(up_tx if isinstance(up_tx, (int, float)) else None)}",
        f"  {up_rx_lbl}: {format_bytes_ru(up_rx if isinstance(up_rx, (int, float)) else None)}",
        f"  Ретрансмиссии TCP ({down_leg_name}): {format_retrans_count(down_retrans, retrans_ok)}",
        f"  Ретрансмиссии TCP ({up_leg_name}): {format_retrans_count(up_retrans, retrans_ok)}",
    ])
    return "\n".join(lines)


def run_traffic_command(deploy_dir: Path, *, live: bool = False, max_iterations: int | None = None) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)

    cid_proc = run(base + ["ps", "-q", svc], check=False)
    cid = cid_proc.stdout.strip() if cid_proc.returncode == 0 else ""
    if not cid:
        print(err_text(f"Контейнер {svc} не запущен в {deploy_dir}."), file=sys.stderr)
        return 1

    container_started_epoch: float | None = None
    c_proc = run(["docker", "inspect", cid], check=False)
    if c_proc.returncode == 0:
        try:
            c_info = json.loads(c_proc.stdout)[0]
            state = c_info.get("State") or {}
            if not state.get("Running"):
                print(err_text(f"Контейнер {svc} остановлен."), file=sys.stderr)
                return 1
            container_started_epoch = parse_iso_timestamp_to_epoch(str(state.get("StartedAt") or ""))
        except Exception:
            pass

    if not live:
        stats = read_container_runtime_stats(base, svc)
        print(render_traffic_snapshot(role, stats, container_started_epoch))
        return 0

    prev_stats: dict[str, object] | None = None
    prev_ts: float | None = None
    iteration = 0
    down_leg_name = "edge -> клиент" if role == "edge" else ("egress -> edge" if role == "egress" else "прокси -> клиент")
    up_leg_name = "edge -> egress" if role == "edge" else ("egress -> Telegram DC" if role == "egress" else "прокси -> Telegram DC")
    in_leg_name = "клиент -> edge" if role == "edge" else ("edge -> egress" if role == "egress" else "клиент -> прокси")
    back_leg_name = "egress -> edge" if role == "edge" else ("Telegram DC -> egress" if role == "egress" else "Telegram DC -> прокси")

    try:
        while True:
            now_wall = time.monotonic()
            stats = read_container_runtime_stats(base, svc)
            dt = (now_wall - prev_ts) if (prev_ts is not None and now_wall > prev_ts) else 1.0

            def delta_metric(key: str) -> float | None:
                if stats is None or prev_stats is None:
                    return None
                cur_v = stats.get(key)
                old_v = prev_stats.get(key)
                if not isinstance(cur_v, (int, float)) or not isinstance(old_v, (int, float)):
                    return None
                if cur_v < old_v:
                    return None
                return float(cur_v - old_v)

            d_down_rx = delta_metric("downstream_rx_bytes")
            d_down_tx = delta_metric("downstream_tx_bytes")
            d_up_tx = delta_metric("upstream_tx_bytes")
            d_up_rx = delta_metric("upstream_rx_bytes")
            d_comp = delta_metric("completed_sessions")
            d_fail = delta_metric("failed_sessions")
            d_disc = (int(d_comp) + int(d_fail)) if (d_comp is not None and d_fail is not None) else None

            retrans_ok = bool(stats and stats.get("retrans_supported"))
            d_down_ret = delta_metric("downstream_retrans_segs") if retrans_ok else None
            d_up_ret = delta_metric("upstream_retrans_segs") if retrans_ok else None

            snap_text = render_traffic_snapshot(role, stats, container_started_epoch)
            rate_lines = [
                "",
                heading("Динамика за последнюю секунду (--live, нажмите Ctrl+C для выхода)"),
                f"  Скорость приёма ({in_leg_name}):   {format_rate_ru(d_down_rx / dt if d_down_rx is not None else None)}",
                f"  Скорость отдачи ({down_leg_name}): {format_rate_ru(d_down_tx / dt if d_down_tx is not None else None)}",
                f"  Скорость отправки ({up_leg_name}): {format_rate_ru(d_up_tx / dt if d_up_tx is not None else None)}",
                f"  Скорость ответа ({back_leg_name}): {format_rate_ru(d_up_rx / dt if d_up_rx is not None else None)}",
                f"  Отключения за 1 с:                 {f'{d_disc} сесс./с (всего завершено/ошибок)' if d_disc is not None else 'нет данных'}",
                f"  Ретрансмиссии TCP за 1 с ({down_leg_name}): {f'{int(d_down_ret)} сегм./с' if d_down_ret is not None else 'нет данных'}",
                f"  Ретрансмиссии TCP за 1 с ({up_leg_name}): {f'{int(d_up_ret)} сегм./с' if d_up_ret is not None else 'нет данных'}",
            ]

            if sys.stdout.isatty():
                sys.stdout.write("\033[2J\033[H")
            print(snap_text + "\n" + "\n".join(rate_lines), flush=True)

            prev_stats = stats
            prev_ts = now_wall
            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nМониторинг трафика остановлен.")
    return 0


def resolve_client_server_and_port(saved: dict[str, object]) -> tuple[str, int]:
    port_raw = str(saved.get("MTEVIL_PUBLIC_PORT") or saved.get("MTEVIL_PORT") or "443").strip()
    try:
        port = validate_port(port_raw)
    except Exception:
        port = 443
    host = str(saved.get("MTEVIL_PUBLIC_HOST") or "").strip()
    if not host:
        bind = str(saved.get("MTEVIL_BIND") or "").strip()
        if bind and bind not in ("0.0.0.0", "::"):
            host = bind
    if not host:
        host = detect_local_global_ipv4() or "127.0.0.1"
    return host, port


def probe_tproxy_readyz(admin_listen: str, timeout_s: float = 3.0) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(f"http://{admin_listen}/readyz", method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read(256).decode("utf-8", errors="replace").strip()
            if 200 <= status < 300:
                return True, body or f"HTTP {status}"
            return False, f"HTTP {status}"
    except Exception as exc:
        return False, str(exc)


def format_webproxy_status_lines(base: list[str], saved: dict[str, object]) -> list[str]:
    tp_cfg = saved.get("tproxy_config") if isinstance(saved.get("tproxy_config"), dict) else {}
    host = str(tp_cfg.get("public_hostname") or saved.get("MTEVIL_WEBPROXY_HOST") or "").strip()
    prefix = str(tp_cfg.get("base_path") or saved.get("MTEVIL_WEBPROXY_BASE_PATH") or "").strip()
    carrier = str(saved.get("MTEVIL_WEBPROXY_CARRIER") or "websocket").strip()
    admin_ep = str(tp_cfg.get("admin_listen") or saved.get("MTEVIL_TPROXY_ADMIN") or DEFAULT_TPROXY_ADMIN).strip()
    route_desc = f"{host}/{prefix}" if (host and prefix) else (host or "не задан")
    cid_proc = run(base + ["ps", "-q", "tproxy"], check=False)
    cid = cid_proc.stdout.strip() if cid_proc.returncode == 0 else ""
    if not cid:
        return [f"  WEB Proxy:         {err_text(f'tproxy остановлен ({route_desc}, carrier={carrier})')}"]
    ok, detail = probe_tproxy_readyz(admin_ep)
    if ok:
        listen_ep = tp_cfg.get("listen", DEFAULT_TPROXY_LISTEN)
        return [f"  WEB Proxy:         {ok_text(f'ready ({route_desc}, carrier={carrier}, listen={listen_ep})')}"]
    return [f"  WEB Proxy:         {warn_text(f'tproxy запущен, /readyz не готов ({detail})')}"]


def render_webproxy_links_output(
    base: list[str],
    saved: dict[str, object],
    *,
    user: str | None = None,
    all_users: bool = False,
) -> list[str]:
    tp_cfg = saved.get("tproxy_config") if isinstance(saved.get("tproxy_config"), dict) else {}
    host = str(tp_cfg.get("public_hostname") or saved.get("MTEVIL_WEBPROXY_HOST") or "").strip()
    prefix = str(tp_cfg.get("base_path") or saved.get("MTEVIL_WEBPROXY_BASE_PATH") or "").strip()
    if not host:
        raise ValueError("не найден public_hostname для WEB Proxy")
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    sec_path = str(saved_cfg.get("secret_file") or "/var/lib/mtevil/proxy-secret")
    users_path = str(saved_cfg.get("users_file") or "/var/lib/mtevil/users.json")
    default_sec = read_volume_secret(base, sec_path) if volume_file_exists(base, sec_path) else None
    users_map = read_users_map_from_volume(base, users_path)

    entries: list[tuple[str, str]] = []
    if user:
        if user == "default":
            if not default_sec:
                raise ValueError("основной секрет default отсутствует")
            entries.append(("default", default_sec))
        elif user in users_map:
            entries.append((user, users_map[user]))
        else:
            raise ValueError(f"пользователь '{user}' не найден")
    elif all_users:
        if default_sec:
            entries.append(("default", default_sec))
        for uname in sorted(users_map.keys()):
            entries.append((uname, users_map[uname]))
    else:
        if default_sec:
            entries.append(("default", default_sec))
        elif users_map:
            first_u = sorted(users_map.keys())[0]
            entries.append((first_u, users_map[first_u]))
    if not entries:
        raise ValueError("не найдено ни одного секрета для генерации ссылки WEB Proxy")

    lines: list[str] = []
    multi = len(entries) > 1 or bool(user) or all_users
    for uname, sec in entries:
        info = format_webproxy_links(host, prefix, sec)
        if multi:
            lines.append(f"[{uname}] {info['tme']}")
            lines.append(f"[{uname}] {info['tg']}")
        else:
            lines.append(info["tme"])
            lines.append(info["tg"])
    return lines


def run_link_command(
    deploy_dir: Path,
    *,
    sni_override: str | None = None,
    user: str | None = None,
    all_users: bool = False,
    dd: bool = False,
    webproxy_only: bool = False,
) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role == "egress":
        print(err_text("Команда link доступна только на сервере входа (direct или edge)."), file=sys.stderr)
        return 1

    if webproxy_only and not saved.get("webproxy"):
        print(err_text("Режим WEB Proxy не настроен для этой установки (запустите mtevilctl setup --webproxy)."), file=sys.stderr)
        return 1

    if sni_override is not None:
        try:
            sni_override = validate_sni(sni_override)
        except Exception as exc:
            print(err_text(f"Некорректный домен SNI: {exc}"), file=sys.stderr)
            return 1

    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
    bind_val = str(saved.get("MTEVIL_BIND") or "").strip()

    if saved.get("webproxy") and not dd and sni_override is None:
        try:
            wp_lines = render_webproxy_links_output(base, saved, user=user, all_users=all_users)
        except Exception as exc:
            print(err_text(f"Не удалось сформировать ссылку WEB Proxy: {exc}"), file=sys.stderr)
            return 1
        print("\n".join(wp_lines))
        if webproxy_only or bind_val in ("127.0.0.1", "::1"):
            return 0
        print()

    server_host, pub_port = resolve_client_server_and_port(saved)

    cid = run(base + ["ps", "-q", svc], check=False).stdout.strip()
    cmd_prefix = base + (["exec", "-T", svc] if cid else ["run", "--rm", "-T", "--no-deps", svc])
    write_prefix = base + ["run", "--rm", "-T", "--no-deps", compose_write_service(base)]
    link_args = [
        "mtevil",
        "link",
        "--config",
        "/etc/mtevil/config.json",
        "--server",
        server_host,
        "--port",
        str(pub_port),
    ]
    if dd:
        link_args.append("--dd")
    if user:
        link_args.extend(["--user", user])
    if all_users:
        link_args.append("--all")
    if sni_override:
        link_args.extend(["--sni", sni_override])

    proc = run(cmd_prefix + link_args, check=False)
    if proc.returncode != 0 and sni_override:
        # Backward compatibility if container runs an older binary (< v0.1.5) without `mtevil link --sni`:
        retry_args = [a for a in link_args if a not in ("--sni", sni_override)]
        retry_proc = run(cmd_prefix + retry_args, check=False)
        if retry_proc.returncode == 0:
            old_sni_hex = str(saved_cfg.get("sni") or "").encode("utf-8").hex()
            new_sni_hex = sni_override.encode("utf-8").hex()
            out_lines: list[str] = []
            for ln in retry_proc.stdout.strip().splitlines():
                if old_sni_hex and ln.endswith(old_sni_hex):
                    out_lines.append(ln[: -len(old_sni_hex)] + new_sni_hex)
                else:
                    out_lines.append(ln)
            print("\n".join(out_lines))
            return 0
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        print(err_text(f"Не удалось сформировать ссылку: {detail}"), file=sys.stderr)
        return 1
    print(proc.stdout.strip())
    return 0


def run_sni_command(deploy_dir: Path, new_sni_arg: str | None = None) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role == "egress":
        print(err_text("Команда sni доступна только на сервере входа (direct или edge)."), file=sys.stderr)
        return 1

    old_sni = str(saved_cfg.get("sni") or DEFAULT_SNI).strip()
    if new_sni_arg:
        try:
            new_sni = validate_sni(new_sni_arg)
        except Exception as exc:
            print(err_text(f"Некорректный домен SNI: {exc}"), file=sys.stderr)
            return 1
        warn_if_sni_suspicious(new_sni)
    else:
        new_sni = prompt_sni_choice(old_sni)

    new_cover = f"{new_sni}:443"
    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)

    print(f"Проверка HTTPS-cover ({new_cover}, SNI: {new_sni})...")
    cover_ok, cover_out = check_cover_from_container(base, new_cover, new_sni)
    if cover_ok:
        print(ok_text("HTTPS-сайт для маскировки доступен."))
    else:
        print(err_text(f"HTTPS-сайт для маскировки ({new_cover}, SNI {new_sni}) не прошёл проверку."), file=sys.stderr)
        if cover_out:
            print(f"Детали: {cover_out}", file=sys.stderr)
        if not sys.stdin.isatty() or not ask_yes_no("Всё равно применить этот SNI?", default=False):
            print("Отменено без изменений.")
            return 1

    merged_snis = record_allowed_snis_in_volume(base, [new_sni, old_sni])
    orig_cfg_text = cfg_file.read_text(encoding="utf-8")
    new_cfg = dict(saved_cfg)
    new_cfg["sni"] = new_sni
    new_cfg["cover"] = new_cover
    cfg_file.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")

    up_proc = run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
    if up_proc.returncode != 0:
        cfg_file.write_text(orig_cfg_text, encoding="utf-8")
        run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
        detail = (up_proc.stderr or up_proc.stdout or "").strip()
        print(err_text(f"Не удалось перезапустить контейнер с новым SNI: {detail}"), file=sys.stderr)
        return 1

    try:
        wait_healthy(base)
    except TimeoutError:
        print_failed_container_logs(base)
        cfg_file.write_text(orig_cfg_text, encoding="utf-8")
        run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
        print(err_text("Контейнер не перешёл в статус healthy; возвращён прежний SNI."), file=sys.stderr)
        return 1

    if os.environ.get("MTEVIL_SKIP_E2E_PROBE") != "1":
        probe_ok, probe_detail = verify_telegram_e2e(base, attempts=3, delay_s=2.0)
        if probe_ok:
            print(ok_text(f"Сквозная проверка Telegram пройдена ({probe_detail})."))
        else:
            print(warn_text(f"Предупреждение: сквозная проверка Telegram не подтверждена ({probe_detail})."), file=sys.stderr)

    print(ok_text(f"Основной SNI обновлён: {old_sni} -> {new_sni}"))
    extra = [s for s in merged_snis if s != new_sni.lower()]
    if extra:
        print(f"Прежние ссылки клиентов со старым SNI ({', '.join(extra)}) продолжают работать без перенастройки.")
    print("\n" + heading("Новая ссылка для подключения в Telegram"))
    run_link_command(deploy_dir)
    return 0


def run_user_command(deploy_dir: Path, action: str, name: str | None = None, sni_override: str | None = None) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role == "egress":
        print(err_text("Управление пользователями доступно только на сервере входа (direct или edge)."), file=sys.stderr)
        return 1

    users_file = str(saved_cfg.get("users_file") or "/var/lib/mtevil/users.json")
    if not saved_cfg.get("users_file"):
        new_cfg = dict(saved_cfg)
        new_cfg["users_file"] = users_file
        cfg_file.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")

    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
    cid = run(base + ["ps", "-q", svc], check=False).stdout.strip()
    cmd_prefix = base + (
        ["exec", "-T", svc, "/usr/local/bin/mtevil"]
        if cid
        else ["run", "--rm", "-T", "--no-deps", "--entrypoint", "/usr/local/bin/mtevil", svc]
    )
    write_prefix = base + [
        "run",
        "--rm",
        "-T",
        "--no-deps",
        "--entrypoint",
        "/usr/local/bin/mtevil",
        compose_write_service(base),
    ]

    act = (action or "list").strip().lower()
    if act in ("list", "ls"):
        proc = run(cmd_prefix + ["user-list", "--users-file", users_file], check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            print(err_text(f"Не удалось получить список пользователей: {detail}"), file=sys.stderr)
            return 1
        names = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if not names:
            print("Дополнительные пользователи не созданы (работает основной секрет default).")
        else:
            print(heading(f"Пользователи ({len(names)}):"))
            for n in names:
                print(f"  - {n}")
        return 0

    def _sync_tproxy_users_if_enabled() -> None:
        if not saved.get("webproxy"):
            return
        port_raw = str(saved.get("MTEVIL_PORT") or DEFAULT_TPROXY_BACKEND_PORT).strip()
        backend_ep = f"127.0.0.1:{port_raw}"
        carrier = str(saved.get("MTEVIL_WEBPROXY_CARRIER") or "websocket").strip()
        sec_path = str(saved_cfg.get("secret_file") or "/var/lib/mtevil/proxy-secret")
        sync_tproxy_profiles_in_volume(
            base,
            backend_ep,
            carrier,
            secret_path=sec_path,
            users_path=users_file,
        )
        tp_cid = run(base + ["ps", "-q", "tproxy"], check=False).stdout.strip()
        if tp_cid:
            run(base + ["restart", "tproxy"], check=False)

    if act == "add":
        if not name:
            print(err_text("Укажите имя пользователя: mtevilctl user add <имя>"), file=sys.stderr)
            return 1
        proc = run(write_prefix + ["user-add", "--users-file", users_file, "--name", name], check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            print(err_text(f"Не удалось добавить пользователя '{name}': {detail}"), file=sys.stderr)
            return 1
        _sync_tproxy_users_if_enabled()
        print(ok_text(f"Пользователь '{name}' добавлен (подхватится прокси автоматически без перезапуска)."))
        return run_link_command(deploy_dir, sni_override=sni_override, user=name)

    if act in ("del", "delete", "rm", "remove"):
        if not name:
            print(err_text("Укажите имя пользователя: mtevilctl user del <имя>"), file=sys.stderr)
            return 1
        proc = run(write_prefix + ["user-del", "--users-file", users_file, "--name", name], check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            print(err_text(f"Не удалось удалить пользователя '{name}': {detail}"), file=sys.stderr)
            return 1
        _sync_tproxy_users_if_enabled()
        print(ok_text(f"Пользователь '{name}' удалён (доступ отозван без перезапуска контейнера)."))
        return 0

    print(err_text(f"Неизвестное действие '{action}'. Используйте: list, add <имя> или del <имя>."), file=sys.stderr)
    return 1


AD_TAG_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")
DEFAULT_AD_TAG_PATH = "/var/lib/mtevil/ad-tag"


def validate_ad_tag_hex(raw: str) -> str:
    cleaned = (raw or "").strip()
    if not AD_TAG_HEX_RE.match(cleaned):
        raise ValueError("ad_tag должен содержать ровно 32 hex-символа (16 байт от @MTProxybot)")
    return cleaned.lower()


def mask_ad_tag(tag: str) -> str:
    cleaned = (tag or "").strip()
    if len(cleaned) < 8:
        return "***"
    return f"{cleaned[:4]}…{cleaned[-4:]}"


def format_me_status_lines(
    role: str,
    saved_cfg: dict[str, object],
    rstats: dict[str, object] | None,
) -> list[str]:
    me_cfg = saved_cfg.get("me") if isinstance(saved_cfg.get("me"), dict) else {}
    me_enabled = bool(me_cfg.get("enabled", False))
    if not me_enabled:
        return ["  Режим ME:          выключен (Direct)"]

    lines: list[str] = []
    me_stats = rstats.get("me") if isinstance(rstats, dict) and isinstance(rstats.get("me"), dict) else {}
    fallback_cfg = bool(me_cfg.get("fallback_to_direct", True))
    send_ip_cfg = bool(me_cfg.get("send_client_ip", True))

    if role == "edge":
        fb_total = int(me_stats.get("fallback_direct_total") or 0) if me_stats else 0
        if not me_stats and isinstance(rstats, dict):
            fb_total = int(rstats.get("me_fallback_direct_total") or 0)
        mode_lbl = (
            f"ME через egress (MTV4, fallback на Direct: {'вкл' if fallback_cfg else 'выкл'})"
        )
        lines.append(f"  Режим ME:          {mode_lbl}")
        lines.append(
            f"  Клиентский IP ME:  {'передаётся на egress (логика И)' if send_ip_cfg else 'не передаётся (0.0.0.0:0, экспериментально)'}"
        )
        if fb_total > 0:
            lines.append(f"  Fallback ME->Dir:  {fb_total}")
            lines.append(
                warn_text(
                    "  Предупреждение ME: зафиксирован fallback на Direct — проверьте, что узлы egress обновлены до v0.3+ и имеют me.enabled=true."
                )
            )
        return lines

    mode_raw = str(me_stats.get("mode") or "")
    if mode_raw == "me":
        mode_label = ok_text("ME активен")
    elif mode_raw == "me_degraded_fallback_direct":
        mode_label = warn_text("ME degraded -> fallback на Direct")
    elif mode_raw == "me_degraded_strict":
        mode_label = err_text("ME degraded (strict, без Direct fallback)")
    else:
        mode_label = "ME включён (ожидание runtime-stats)"
    lines.append(f"  Режим ME:          {mode_label}")
    if me_stats:
        alive = int(me_stats.get("alive_connections") or 0)
        slots = int(me_stats.get("total_slots") or 0)
        age = me_stats.get("config_age_secs")
        age_str = format_duration_ru(age) if isinstance(age, (int, float)) else "нет данных"
        fb_total = int(me_stats.get("fallback_direct_total") or 0)
        ref_err = int(me_stats.get("refresh_errors") or 0)
        bp_drops = int(me_stats.get("backpressure_drops") or 0)
        cl_drops = int(me_stats.get("dropped_close_ext") or 0)
        ad_status = "настроен" if me_stats.get("ad_tag") == "configured" else "не задан"
        lines.append(f"  Пул ME:            {alive}/{slots} живых, возраст конфига: {age_str}")
        lines.append(
            f"  Счётчики ME:       fallback={fb_total}, refresh_err={ref_err}, backpressure_drops={bp_drops}, dropped_close_ext={cl_drops}"
        )
        lines.append(f"  Рекламный тег:     {ad_status}")
    return lines


def format_handshake_diag_lines(
    role: str,
    rstats: dict[str, object] | None,
) -> list[str]:
    if role not in ("direct", "edge") or not isinstance(rstats, dict):
        return []
    if (
        "client_hello_incomplete_timeout" not in rstats
        and "client_hello_incomplete_close" not in rstats
        and "inner_header_incomplete" not in rstats
    ):
        return []
    ch_to = int(rstats.get("client_hello_incomplete_timeout") or 0)
    ch_cl = int(rstats.get("client_hello_incomplete_close") or 0)
    ih_inc = int(rstats.get("inner_header_incomplete") or 0)
    ch_inc = ch_to + ch_cl
    total_sessions = int(rstats.get("completed_sessions") or 0) + int(
        rstats.get("failed_sessions") or 0
    )
    uptime_ms_raw = rstats.get("uptime_ms")
    period_str = (
        format_duration_ru(float(uptime_ms_raw) / 1000.0)
        if isinstance(uptime_ms_raw, (int, float)) and uptime_ms_raw >= 0
        else None
    )
    lines = [
        f"  Сбои handshake:    таймаут ClientHello={ch_to}, закрытие сокета={ch_cl}, после ServerHello={ih_inc}"
    ]
    if total_sessions > 0:
        ch_pct = (ch_inc * 100.0) / total_sessions
        ih_pct = (ih_inc * 100.0) / total_sessions
        period_lbl = f"за {period_str}, сессий={total_sessions}" if period_str else f"сессий={total_sessions}"
        lines.append(
            f"  Доля обрывов:      client_hello_incomplete={ch_inc}/{total_sessions} ({ch_pct:.1f}%), "
            f"inner_header_incomplete={ih_inc}/{total_sessions} ({ih_pct:.1f}%) [{period_lbl}]"
        )
    elif period_str is not None:
        lines.append(
            f"  Доля обрывов:      client_hello_incomplete={ch_inc} (0.0%), inner_header_incomplete={ih_inc} (0.0%) [за {period_str}, сессий=0]"
        )
    if (ch_inc + ih_inc) > 0:
        lines.append(
            "  Подсказка:         зафиксированы обрывы handshake/TLS — смотрите ADR-005 (разделы про порт :443, размер ClientHello и WebProxy)."
        )
    sample = rstats.get("last_client_hello_incomplete")
    if ch_inc > 0 and isinstance(sample, dict):
        rx = int(sample.get("received_bytes") or 0)
        exp = int(sample.get("expected_bytes") or 0)
        reason_lbl = "таймаут" if sample.get("timeout") else "закрытие сокета"
        lines.append(f"  Последний обрыв:   ClientHello: получено {rx} из {exp} байт ({reason_lbl})")
    return lines


def format_cover_status_lines(
    role: str,
    saved_cfg: dict[str, object],
    bind_val: str,
    port_val: str,
) -> list[str]:
    if role not in ("direct", "edge"):
        return []
    sni = str(saved_cfg.get("sni") or "").strip()
    if not sni or not port_val:
        return []
    try:
        port = int(port_val)
    except ValueError:
        return []
    local_host = "127.0.0.1" if bind_val in ("", "0.0.0.0", "::", "127.0.0.1") else bind_val
    ok, detail, days_left = probe_cover_status(local_host, port, sni, timeout_s=3.0)
    if not ok:
        return [f"  Проверка cover:    {err_text(f'ошибка ({detail})')}"]
    cert_note = f", сертификат: {days_left} дн." if days_left is not None else ""
    lines = [f"  Проверка cover:    {ok_text(f'HTTPS GET OK ({detail}{cert_note})')}"]
    if days_left is not None and days_left < 14:
        lines.append(
            warn_text(
                f"  Предупреждение:    до окончания сертификата cover осталось {days_left} дн. (< 14) — проверьте автопродление."
            )
        )
    return lines


def prompt_me_config(
    role: str,
    *,
    network_host: bool,
    detected_public_ip: str | None,
    existing_me: dict[str, object] | None,
    cli_enabled: bool = False,
    cli_public_ipv4: str | None = None,
    cli_send_client_ip: bool | None = None,
    cli_fallback_to_direct: bool | None = None,
) -> dict[str, object] | None:
    prev = existing_me if isinstance(existing_me, dict) else {}
    prev_enabled = bool(prev.get("enabled", False))
    if cli_enabled:
        enabled = True
    else:
        print("\n" + heading("Режим Telegram Middle-End (ME / ad_tag)"))
        enabled = ask_yes_no(
            "Включить режим Telegram Middle-End (ME / рекламный тег ad_tag)?",
            default=prev_enabled,
        )
    if not enabled:
        return None

    print(
        warn_text(
            "Внимание (приватность): в режиме ME по умолчанию (send_client_ip=true) Telegram видит реальный IPv4 клиента, "
            "как в официальном MTProxy. Режим без передачи IP (0.0.0.0:0) является экспериментальным."
        )
    )
    prev_send_ip = bool(prev.get("send_client_ip", True))
    send_client_ip = (
        cli_send_client_ip
        if cli_send_client_ip is not None
        else ask_yes_no("Передавать реальный IPv4 клиента в Telegram (me.send_client_ip)?", default=prev_send_ip)
    )
    prev_fallback = bool(prev.get("fallback_to_direct", True))
    fallback_to_direct = (
        cli_fallback_to_direct
        if cli_fallback_to_direct is not None
        else ask_yes_no(
            "Включить автоматический fallback на Direct при недоступности ME (me.fallback_to_direct)?",
            default=prev_fallback,
        )
    )

    if role == "edge":
        print(
            "Подсказка (split): в схеме edge -> egress пул ME и файл ad_tag настраиваются на узлах egress; "
            "в @MTProxybot регистрируется публичный IP:PORT этого edge."
        )
        return {
            "enabled": True,
            "fallback_to_direct": fallback_to_direct,
            "send_client_ip": send_client_ip,
        }

    pub_ipv4: str | None = cli_public_ipv4
    if pub_ipv4 is None:
        prev_pub = str(prev.get("public_ipv4") or "").strip()
        default_pub = prev_pub or (detected_public_ip or "")
        if not network_host:
            print(
                "Подсказка (NAT/Docker bridge): без --network-host параметр me.public_ipv4 обязателен "
                "для совпадения KDF Telegram ME."
            )
            raw_pub = ask_validated("Публичный IPv4 сервера для KDF ME (me.public_ipv4)", validate_ip, default_pub or None)
            pub_ipv4 = raw_pub.strip()
        else:
            raw_pub = ask(
                "Публичный IPv4 для KDF ME (Enter = авто с локального интерфейса, обязательно за 1:1 NAT)",
                default_pub or "",
            ).strip()
            pub_ipv4 = validate_ip(raw_pub) if raw_pub else None

    me_block: dict[str, object] = {
        "enabled": True,
        "fallback_to_direct": fallback_to_direct,
        "send_client_ip": send_client_ip,
        "pool_size": int(prev.get("pool_size") or 2),
        "ad_tag_file": str(prev.get("ad_tag_file") or DEFAULT_AD_TAG_PATH),
    }
    if pub_ipv4:
        me_block["public_ipv4"] = pub_ipv4
    return me_block


def run_adtag_command(deploy_dir: Path, action: str, tag_value: str | None = None) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role == "edge":
        print(
            err_text(
                "Рекламный тег ad_tag хранится на сервере выхода (direct или egress). "
                "В @MTProxybot зарегистрируйте IP:PORT этого edge, а полученный ad_tag установите на узлах egress."
            ),
            file=sys.stderr,
        )
        return 1

    me_cfg = saved_cfg.get("me") if isinstance(saved_cfg.get("me"), dict) else {}
    ad_tag_path = str(me_cfg.get("ad_tag_file") or DEFAULT_AD_TAG_PATH)
    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
    write_svc = compose_write_service(base)
    cid = run(base + ["ps", "-q", svc], check=False).stdout.strip()

    act = (action or "show").strip().lower()
    if act in ("show", "status", "get"):
        read_cmd = base + (
            ["exec", "-T", svc, "/bin/sh", "-c", f'if [ -f "{ad_tag_path}" ]; then cat "{ad_tag_path}"; fi']
            if cid
            else ["run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh", svc, "-c", f'if [ -f "{ad_tag_path}" ]; then cat "{ad_tag_path}"; fi']
        )
        proc = run(read_cmd, check=False)
        if proc.returncode != 0:
            print(err_text("Не удалось прочитать файл ad_tag из тома state."), file=sys.stderr)
            return 1
        val = (proc.stdout or "").strip()
        if not val:
            print("Рекламный тег (ad_tag): не задан.")
        else:
            print(f"Рекламный тег (ad_tag): настроен ({mask_ad_tag(val)})")
        if not bool(me_cfg.get("enabled", False)):
            print(warn_text("Примечание: режим ME сейчас выключен в config.json (me.enabled=false)."))
        return 0

    if act == "set":
        raw_input = tag_value
        if not raw_input:
            try:
                if sys.stdin.isatty():
                    raw_input = getpass.getpass("Введите 32-hex ad_tag от @MTProxybot (ввод скрыт): ")
                else:
                    raw_input = sys.stdin.readline()
            except (EOFError, KeyboardInterrupt):
                print(err_text("Ввод ad_tag отменён."), file=sys.stderr)
                return 1
        if not (raw_input or "").strip():
            print(
                err_text("Не передан ad_tag. Используйте 'mtevilctl adtag set' (скрытый ввод) или stdin."),
                file=sys.stderr,
            )
            return 1
        try:
            clean_tag = validate_ad_tag_hex(raw_input)
        except ValueError as exc:
            print(err_text(str(exc)), file=sys.stderr)
            return 1

        # Pass ad_tag via stdin (not CLI args) into init service; atomic write with strict chmod 0600
        # and chown 10001:10001 (without ignoring errors via `|| true`).
        sh_script = (
            f'set -eu; umask 077; tmp="{ad_tag_path}.tmp.$$"; '
            f'trap \'rm -f "$tmp"\' EXIT; '
            f'cat > "$tmp"; '
            f'chmod 0600 "$tmp"; '
            f'if [ "$(id -u)" -eq 0 ]; then chown 10001:10001 "$tmp"; fi; '
            f'mv -f "$tmp" "{ad_tag_path}"; '
            f'trap - EXIT'
        )
        proc = subprocess.run(
            base + ["run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh", write_svc, "-c", sh_script],
            input=clean_tag + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            print(
                err_text(f"Не удалось записать файл ad_tag в том state ({detail or 'код ' + str(proc.returncode)})."),
                file=sys.stderr,
            )
            return 1

        # Verify actual owner/mode and readability strictly as UID 10001.
        verify_script = (
            f'set -eu; test -r "{ad_tag_path}"; '
            f'test "$(wc -c < "{ad_tag_path}")" -ge 32; '
            f'stat -c "%u:%g %a" "{ad_tag_path}"'
        )
        verify_cmd = base + (
            ["exec", "-T", "--user", "10001:10001", svc, "/bin/sh", "-c", verify_script]
            if cid
            else [
                "run",
                "--rm",
                "-T",
                "--no-deps",
                "--user",
                "10001:10001",
                "--entrypoint",
                "/bin/sh",
                svc,
                "-c",
                verify_script,
            ]
        )
        verify_proc = run(verify_cmd, check=False)
        if verify_proc.returncode != 0 or not (verify_proc.stdout or "").strip():
            detail = (verify_proc.stderr or verify_proc.stdout or "").strip()
            print(
                err_text(
                    f"Файл ad_tag записан, но проверка чтения от UID 10001 не прошла: {detail or 'нет доступа'}."
                ),
                file=sys.stderr,
            )
            return 1
        actual_meta = verify_proc.stdout.strip().splitlines()[-1].strip()
        meta_parts = actual_meta.split()
        actual_owner = meta_parts[0] if len(meta_parts) >= 1 else "unknown"
        actual_mode = meta_parts[1] if len(meta_parts) >= 2 else "unknown"
        if actual_mode != "600":
            print(
                err_text(
                    f"Небезопасные права на {ad_tag_path}: {actual_mode} (ожидалось 600, владелец {actual_owner})."
                ),
                file=sys.stderr,
            )
            return 1
        print(
            ok_text(
                f"Рекламный тег установлен ({mask_ad_tag(clean_tag)}, права 0{actual_mode}, владелец {actual_owner}, чтение от UID 10001 подтверждено)."
            )
        )
        print("Прокси подхватит новый тег автоматически в течение 2 секунд без перезапуска контейнера.")
        if not bool(me_cfg.get("enabled", False)):
            print(warn_text("Примечание: режим ME сейчас выключен в config.json (включите его через mtevilctl setup)."))
        return 0

    if act in ("clear", "del", "delete", "rm"):
        proc = run(
            base + ["run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh", write_svc, "-c", f'rm -f "{ad_tag_path}"'],
            check=False,
        )
        if proc.returncode != 0:
            print(err_text("Не удалось удалить файл ad_tag из тома state."), file=sys.stderr)
            return 1
        print(ok_text("Рекламный тег удалён (применится автоматически без перезапуска контейнера)."))
        return 0

    print(err_text(f"Неизвестное действие '{action}'. Используйте: show, set <32_hex> или clear."), file=sys.stderr)
    return 1


def _validate_mss_arg(raw: str | None) -> tuple[bool, int | None]:
    """Return (changed, new_value) for `--handshake-mss` / `--bulk-mss`."""
    if raw is None:
        return False, None
    v = raw.strip().lower()
    if v in ("off", "none", "auto", "clear", "0"):
        return True, None
    try:
        num = int(v)
    except ValueError as exc:
        raise ValueError("укажите число 88..1460 или 'off'") from exc
    if not (88 <= num <= 1460):
        raise ValueError("значение TCP MSS должно быть в диапазоне 88..1460 (или 'off' для сброса)")
    return True, num


def _apply_updated_config_safely(
    deploy_dir: Path,
    base: list[str],
    svc: str,
    cfg_file: Path,
    orig_cfg_text: str,
    new_cfg: dict[str, object],
) -> tuple[bool, str]:
    cand_cfg = deploy_dir / "config.cli-candidate.json"
    try:
        cand_cfg.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")
        abs_cand = str(cand_cfg.resolve())
        chk = run(
            base
            + [
                "run",
                "--rm",
                "-T",
                "--no-deps",
                "-v",
                f"{abs_cand}:/etc/mtevil/config.cli.json:ro",
                svc,
                "--config",
                "/etc/mtevil/config.cli.json",
                "--check-config",
            ],
            check=False,
        )
        if chk.returncode != 0:
            detail = (chk.stderr or chk.stdout or "").strip()
            return False, f"конфигурация не прошла проверку (--check-config): {detail}"
    finally:
        if cand_cfg.exists():
            cand_cfg.unlink()

    cfg_file.write_text(json.dumps(new_cfg, indent=2) + "\n", encoding="utf-8")
    cid = run(base + ["ps", "-q", svc], check=False).stdout.strip()
    if not cid:
        return True, "конфигурация обновлена (контейнер сейчас остановлен)"

    up_proc = run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
    if up_proc.returncode != 0:
        cfg_file.write_text(orig_cfg_text, encoding="utf-8")
        run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
        detail = (up_proc.stderr or up_proc.stdout or "").strip()
        return False, f"не удалось перезапустить контейнер: {detail}"
    try:
        wait_healthy(base)
    except TimeoutError:
        print_failed_container_logs(base)
        cfg_file.write_text(orig_cfg_text, encoding="utf-8")
        run(base + ["up", "-d", "--no-build", "--force-recreate", svc], check=False)
        return False, "контейнер не перешёл в статус healthy; возвращена прежняя конфигурация"
    return True, "контейнер перезапущен и исправен"


def run_egress_command(
    deploy_dir: Path,
    action: str = "list",
    target: str | None = None,
    *,
    force: bool = False,
) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role != "edge":
        print(
            err_text("Команда 'mtevilctl egress' предназначена для входного сервера (роль edge)."),
            file=sys.stderr,
        )
        return 1

    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
    orig_cfg_text = cfg_file.read_text(encoding="utf-8")
    upstreams = [str(u) for u in (saved_cfg.get("egress_upstreams") or []) if str(u).strip()]
    strategy = str(saved_cfg.get("egress_strategy") or "round-robin")
    hedge_ms = int(saved_cfg.get("egress_hedge_ms", 400))
    ws_pool_sz = int(saved_cfg.get("egress_ws_pool_size", 4))

    act = (action or "list").strip().lower()
    if act in ("list", "ls", "show", "status"):
        print(heading(f"Узлы egress ({len(upstreams)}):"))
        for idx, u in enumerate(upstreams, start=1):
            tag = " [основной]" if (strategy == "ordered" and idx == 1) else ""
            print(f"  {idx}. {redact_egress_upstream(u)}{tag}")
        print(f"  Стратегия:         {strategy}")
        print(f"  Хеджирование:      {hedge_ms} мс")
        if any(u.startswith(("ws://", "wss://")) for u in upstreams):
            print(f"  Тёплый пул WS/WSS: {ws_pool_sz} соед./узел")
        return 0

    if act == "check":
        proc = run(
            base + ["run", "--rm", "-T", "--no-deps", svc, "check-egress", "--config", "/etc/mtevil/config.json", "--dc", "2"],
            check=False,
        )
        if proc.stdout.strip():
            print(proc.stdout.strip())
        if proc.returncode != 0:
            if proc.stderr.strip():
                print(proc.stderr.strip(), file=sys.stderr)
            print(err_text("Один или несколько узлов egress не прошли проверку."), file=sys.stderr)
            return 1
        print(ok_text("Все узлы egress ответили успешно (DC 2)."))
        return 0

    if act == "add":
        if not target:
            print(err_text("Укажите адрес: mtevilctl egress add <IP:PORT | wss://host/ws/...>"), file=sys.stderr)
            return 1
        try:
            norm = validate_egress_upstream(target)
        except ValueError as exc:
            print(err_text(f"Некорректный адрес egress: {exc}"), file=sys.stderr)
            return 1
        if norm in upstreams:
            print(warn_text(f"Узел {redact_egress_upstream(norm)} уже присутствует в списке egress_upstreams."))
            return 0
        new_cfg = copy.deepcopy(saved_cfg)
        new_cfg["egress_upstreams"] = upstreams + [norm]
        if not force:
            probe_cfg = copy.deepcopy(saved_cfg)
            probe_cfg["egress_upstreams"] = [norm]
            cand_probe = deploy_dir / "config.egress-probe.json"
            try:
                cand_probe.write_text(json.dumps(probe_cfg, indent=2) + "\n", encoding="utf-8")
                abs_p = str(cand_probe.resolve())
                chk = run(
                    base
                    + [
                        "run",
                        "--rm",
                        "-T",
                        "--no-deps",
                        "-v",
                        f"{abs_p}:/etc/mtevil/config.probe.json:ro",
                        svc,
                        "check-egress",
                        "--config",
                        "/etc/mtevil/config.probe.json",
                        "--dc",
                        "2",
                    ],
                    check=False,
                )
                if chk.returncode != 0:
                    detail = (chk.stderr or chk.stdout or "").strip()
                    print(
                        err_text(
                            f"Проверка нового узла {redact_egress_upstream(norm)} не пройдена (используйте --force для принудительного добавления)."
                        ),
                        file=sys.stderr,
                    )
                    if detail:
                        print(detail, file=sys.stderr)
                    return 1
            finally:
                if cand_probe.exists():
                    cand_probe.unlink()
        ok, msg = _apply_updated_config_safely(deploy_dir, base, svc, cfg_file, orig_cfg_text, new_cfg)
        if not ok:
            print(err_text(f"Не удалось применить новый список egress: {msg}"), file=sys.stderr)
            return 1
        print(ok_text(f"Добавлен узел egress {redact_egress_upstream(norm)} ({msg})."))
        return 0

    if act in ("del", "delete", "rm", "remove"):
        if not target:
            print(err_text("Укажите адрес или номер узла: mtevilctl egress del <адрес|номер>"), file=sys.stderr)
            return 1
        idx_to_del: int | None = None
        if target.isdigit():
            pos = int(target) - 1
            if 0 <= pos < len(upstreams):
                idx_to_del = pos
        else:
            t_clean = target.strip()
            for i, u in enumerate(upstreams):
                if u == t_clean or redact_egress_upstream(u) == t_clean:
                    idx_to_del = i
                    break
            if idx_to_del is None:
                try:
                    t_norm = validate_egress_upstream(t_clean)
                    if t_norm in upstreams:
                        idx_to_del = upstreams.index(t_norm)
                except ValueError:
                    pass
        if idx_to_del is None:
            print(err_text(f"Узел '{target}' не найден в egress_upstreams."), file=sys.stderr)
            return 1
        if len(upstreams) <= 1:
            print(err_text("Нельзя удалить единственный узел egress на сервере с ролью edge."), file=sys.stderr)
            return 1
        removed = upstreams[idx_to_del]
        new_list = [u for i, u in enumerate(upstreams) if i != idx_to_del]
        new_cfg = copy.deepcopy(saved_cfg)
        new_cfg["egress_upstreams"] = new_list
        ok, msg = _apply_updated_config_safely(deploy_dir, base, svc, cfg_file, orig_cfg_text, new_cfg)
        if not ok:
            print(err_text(f"Не удалось обновить список egress: {msg}"), file=sys.stderr)
            return 1
        print(ok_text(f"Удалён узел egress {redact_egress_upstream(removed)} ({msg})."))
        return 0

    if act == "strategy":
        if target not in ("ordered", "round-robin"):
            print(err_text("Укажите стратегию: mtevilctl egress strategy <ordered|round-robin>"), file=sys.stderr)
            return 1
        new_cfg = copy.deepcopy(saved_cfg)
        new_cfg["egress_strategy"] = target
        ok, msg = _apply_updated_config_safely(deploy_dir, base, svc, cfg_file, orig_cfg_text, new_cfg)
        if not ok:
            print(err_text(f"Не удалось сменить стратегию egress: {msg}"), file=sys.stderr)
            return 1
        print(ok_text(f"Стратегия egress изменена на '{target}' ({msg})."))
        return 0

    if act == "hedge":
        if target is None:
            print(err_text("Укажите задержку в мс (0..30000): mtevilctl egress hedge <мс>"), file=sys.stderr)
            return 1
        try:
            ms = int(target.strip())
            if not (0 <= ms <= 30000):
                raise ValueError
        except ValueError:
            print(err_text("Задержка хеджирования должна быть целым числом от 0 до 30000 мс."), file=sys.stderr)
            return 1
        new_cfg = copy.deepcopy(saved_cfg)
        new_cfg["egress_hedge_ms"] = ms
        ok, msg = _apply_updated_config_safely(deploy_dir, base, svc, cfg_file, orig_cfg_text, new_cfg)
        if not ok:
            print(err_text(f"Не удалось обновить egress_hedge_ms: {msg}"), file=sys.stderr)
            return 1
        print(ok_text(f"Параметр egress_hedge_ms установлен в {ms} мс ({msg})."))
        return 0

    print(
        err_text(
            f"Неизвестное действие '{action}'. Используйте: list, add <адрес>, del <адрес>, strategy <ordered|round-robin>, hedge <мс> или check."
        ),
        file=sys.stderr,
    )
    return 1


def run_tuning_command(
    deploy_dir: Path,
    *,
    handshake_mss: str | None = None,
    bulk_mss: str | None = None,
) -> int:
    check_prerequisites()
    compose_file = deploy_dir / "compose.yaml"
    env_file = deploy_dir / ".env"
    cfg_file = deploy_dir / "config.json"
    if not compose_file.is_file() or not env_file.is_file() or not cfg_file.is_file():
        print(err_text(f"Существующая установка не найдена в {deploy_dir}."), file=sys.stderr)
        return 1

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    role = str(saved_cfg.get("role") or "direct")
    if role == "direct" and saved_cfg.get("egress_upstreams"):
        role = "edge"
    if role == "egress":
        print(err_text("Настройка клиентского TCP MSS применяется только на узлах входа (direct или edge)."), file=sys.stderr)
        return 1

    try:
        hs_changed, hs_val = _validate_mss_arg(handshake_mss)
        bk_changed, bk_val = _validate_mss_arg(bulk_mss)
    except ValueError as exc:
        print(err_text(str(exc)), file=sys.stderr)
        return 1

    if not hs_changed and not bk_changed:
        c_mss = saved_cfg.get("client_mss")
        b_mss = saved_cfg.get("client_mss_bulk")
        print(heading("Параметры TCP-фрагментации [experimental] (tuning)"))
        print(
            warn_text(
                "Статус [experimental]: профиль TCP MSS не подтверждён полевой матрицей H4; "
                "малый client_mss снижает размер сегментов отдачи клиента (upload) на всё время TCP-сессии."
            )
        )
        print(f"  client_mss (SYN-ACK):      {c_mss if c_mss is not None else 'выкл (системный MSS)'}")
        print(f"  client_mss_bulk (отдача):  {b_mss if b_mss is not None else 'выкл (системный MSS)'}")
        print("  Пример включения: mtevilctl tuning --handshake-mss 280 --bulk-mss 1400")
        print("  Пример сброса:    mtevilctl tuning --handshake-mss off --bulk-mss off")
        return 0

    orig_cfg_text = cfg_file.read_text(encoding="utf-8")
    new_cfg = copy.deepcopy(saved_cfg)
    if hs_changed:
        if hs_val is None:
            new_cfg.pop("client_mss", None)
        else:
            new_cfg["client_mss"] = hs_val
    if bk_changed:
        if bk_val is None:
            new_cfg.pop("client_mss_bulk", None)
        else:
            new_cfg["client_mss_bulk"] = bk_val

    if new_cfg.get("client_mss") is not None:
        print(
            warn_text(
                f"Примечание (RFC 9293): client_mss={new_cfg['client_mss']} объявляется в SYN-ACK и нарезает ClientHello, "
                "однако входящий поток от клиента (upload медиа) останется ограничен этим размером сегмента до конца сессии "
                "(client_mss_bulk поднимает размер сегмента только на скачивание сервер -> клиент)."
            )
        )

    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
    ok, msg = _apply_updated_config_safely(deploy_dir, base, svc, cfg_file, orig_cfg_text, new_cfg)
    if not ok:
        print(err_text(f"Не удалось применить настройки TCP MSS: {msg}"), file=sys.stderr)
        return 1
    print(
        ok_text(
            f"Настройки TCP MSS обновлены: handshake={new_cfg.get('client_mss') or 'off'}, "
            f"bulk={new_cfg.get('client_mss_bulk') or 'off'} ({msg})."
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interactive Docker Compose wizard and lifecycle tool for mtevil")
    parser.add_argument(
        "command",
        nargs="?",
        choices=(
            "wizard",
            "setup",
            "reconfigure",
            "status",
            "update",
            "rollback",
            "traffic",
            "traf",
            "link",
            "sni",
            "user",
            "adtag",
            "egress",
            "tuning",
        ),
        default="wizard",
        help="Action to perform: wizard (default), setup, status, update, rollback, traffic, link, sni, user, adtag, egress, tuning",
    )
    parser.add_argument("extra", nargs="*", help=argparse.SUPPRESS)
    parser.add_argument("--dir", type=Path, default=None, help="Target deployment directory (default: deploy/wizard)")
    parser.add_argument("--project", type=str, default=None, help="Docker Compose project name")
    parser.add_argument("--image", type=str, default=DEFAULT_IMAGE, help="Docker image tag")
    parser.add_argument("--no-build", action="store_true", help="Skip docker compose build")
    parser.add_argument(
        "--mode",
        choices=("simple", "advanced", "self-steal", "webproxy", "shared-443"),
        default=None,
        help="Wizard mode: simple, advanced, self-steal, webproxy, or shared-443",
    )
    parser.add_argument(
        "--self-steal",
        action="store_true",
        help="Configure mtevil in self-steal mode against an existing local HTTPS server (nginx/Caddy)",
    )
    parser.add_argument(
        "--webproxy",
        action="store_true",
        help="Configure Telegram WEB Proxy (tproxy-server sidecar behind Caddy/nginx) or print webproxy links",
    )
    parser.add_argument(
        "--shared-443",
        action="store_true",
        help="Configure mtevil on loopback behind an SNI router (Xray fallbacks / nginx stream) sharing external port 443 via PROXY protocol v2",
    )
    parser.add_argument(
        "--managed-caddy",
        action="store_true",
        help="[experimental] Include an automated Caddy TLS sidecar container in compose.yaml (for --webproxy when port 443 is free)",
    )
    parser.add_argument(
        "--cdn",
        action="store_true",
        help="[experimental] Generate Cloudflare/CDN reverse-proxy snippets and headers in --webproxy mode",
    )
    parser.add_argument(
        "--egress-ws",
        action="store_true",
        help="Enable RFC 6455 WebSocket listener path on egress (behind Caddy/nginx on :443 without SSH/VPN)",
    )
    parser.add_argument(
        "--egress-ws-path",
        type=str,
        default=None,
        help="Explicit secret HTTP path for WebSocket egress (e.g. /ws/9f3c...)",
    )
    parser.add_argument(
        "--egress-domain",
        type=str,
        default=None,
        help="Public domain name for generating WSS egress reverse-proxy snippets",
    )
    parser.add_argument(
        "--tproxy-image",
        type=str,
        default=None,
        help="Optional prebuilt Docker image for the tproxy-server sidecar",
    )
    parser.add_argument("--handshake-mss", type=str, default=None, help="Client SYN-ACK TCP MSS (88..1460 or off)")
    parser.add_argument("--bulk-mss", type=str, default=None, help="Post-handshake server->client TCP MSS (88..1460 or off)")
    parser.add_argument("--force", action="store_true", help="Skip live check-egress preflight in 'mtevilctl egress add'")
    parser.add_argument("--role", choices=("direct", "egress", "edge"), default=None, help="Deployment role (non-interactive override)")
    parser.add_argument(
        "--network-host",
        action="store_true",
        help="Use Docker host networking (for Linux hosts with policy-routed mesh/VPN egress)",
    )
    parser.add_argument("--version", type=str, default=None, help="Target release version override for update")
    parser.add_argument("--prerelease", action="store_true", help="Allow selecting alpha/beta/rc prereleases in update")
    parser.add_argument("--reexec", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--live", action="store_true", help="Refresh traffic statistics every second")
    parser.add_argument("--iterations", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--sni", type=str, default=None, help="Custom SNI domain for link generation")
    parser.add_argument("--user", type=str, default=None, help="Named user for link generation")
    parser.add_argument("--all", action="store_true", help="Print links for all configured users")
    parser.add_argument("--dd", action="store_true", help="Print dd-mode link instead of FakeTLS ee-link")
    parser.add_argument("--me-enabled", action="store_true", help="Enable Telegram Middle-End (ME) mode in wizard")
    parser.add_argument("--me-public-ipv4", type=str, default=None, help="Explicit public IPv4 for ME KDF (required behind NAT/bridge)")
    parser.add_argument("--me-send-client-ip", choices=("true", "false"), default=None, help="Whether to forward client IPv4 in ME RPC_PROXY_REQ")
    parser.add_argument("--me-fallback-to-direct", choices=("true", "false"), default=None, help="Whether to fall back to Direct when ME is degraded")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    if args.command in ("status", "update", "rollback", "traffic", "traf", "link", "sni", "user", "adtag", "egress", "tuning"):
        deploy_dir = (args.dir or default_deploy_dir(repo_root)).resolve()
        if args.command == "status":
            return run_status_command(deploy_dir)
        if args.command == "update":
            return run_update_command(
                deploy_dir,
                target_version_override=args.version,
                reexec=args.reexec,
                allow_prerelease=args.prerelease,
            )
        if args.command == "rollback":
            return perform_rollback(deploy_dir)
        if args.command == "link":
            return run_link_command(
                deploy_dir,
                sni_override=args.sni,
                user=args.user,
                all_users=args.all,
                dd=args.dd,
                webproxy_only=args.webproxy,
            )
        if args.command == "sni":
            target_sni = args.extra[0] if args.extra else args.sni
            return run_sni_command(deploy_dir, target_sni)
        if args.command == "user":
            sub_action = args.extra[0] if len(args.extra) >= 1 else "list"
            sub_name = args.extra[1] if len(args.extra) >= 2 else args.user
            return run_user_command(deploy_dir, sub_action, sub_name, sni_override=args.sni)
        if args.command == "adtag":
            sub_action = args.extra[0] if len(args.extra) >= 1 else "show"
            sub_val = args.extra[1] if len(args.extra) >= 2 else None
            return run_adtag_command(deploy_dir, sub_action, sub_val)
        if args.command == "egress":
            sub_action = args.extra[0] if len(args.extra) >= 1 else "list"
            sub_val = args.extra[1] if len(args.extra) >= 2 else None
            return run_egress_command(deploy_dir, sub_action, sub_val, force=args.force)
        if args.command == "tuning":
            return run_tuning_command(
                deploy_dir,
                handshake_mss=args.handshake_mss,
                bulk_mss=args.bulk_mss,
            )
        return run_traffic_command(deploy_dir, live=args.live, max_iterations=args.iterations)

    explicit_no_build = bool(args.no_build)
    if args.command in ("setup", "reconfigure"):
        deploy_dir = (args.dir or default_deploy_dir(repo_root)).resolve()
        saved_pre = load_existing_defaults(deploy_dir)
        saved_img = str(saved_pre.get("MTEVIL_IMAGE") or "").strip()
        if args.image == DEFAULT_IMAGE and saved_img:
            args.image = saved_img
        if not (repo_root / "Dockerfile").is_file():
            args.no_build = True
    else:
        deploy_dir = (args.dir or (repo_root / "deploy" / "wizard")).resolve()

    # Resolve conflicting CLI flags explicitly before prompting.
    mode_shorthands = sum([bool(args.self_steal), bool(args.webproxy), bool(args.shared_443)])
    if mode_shorthands > 1:
        print(
            err_text("Конфликт параметров: не сочетайте --self-steal, --webproxy и --shared-443 одновременно."),
            file=sys.stderr,
        )
        return 1
    if args.self_steal:
        if args.mode in ("simple", "advanced", "webproxy", "shared-443"):
            print(err_text("Конфликт параметров: не сочетайте --self-steal с другим --mode."), file=sys.stderr)
            return 1
        args.mode = "self-steal"
    if args.webproxy:
        if args.mode in ("simple", "advanced", "self-steal", "shared-443"):
            print(err_text("Конфликт параметров: не сочетайте --webproxy с другим --mode."), file=sys.stderr)
            return 1
        args.mode = "webproxy"
    if args.shared_443:
        if args.mode in ("simple", "advanced", "self-steal", "webproxy"):
            print(err_text("Конфликт параметров: не сочетайте --shared-443 с другим --mode."), file=sys.stderr)
            return 1
        args.mode = "shared-443"
    if args.mode in ("self-steal", "webproxy", "shared-443") and args.role == "egress":
        print(err_text(f"Конфликт параметров: режим {args.mode} несовместим с ролью egress."), file=sys.stderr)
        return 1
    if (args.managed_caddy or args.cdn) and args.mode not in (None, "webproxy"):
        print(err_text("Конфликт параметров: флаги --managed-caddy и --cdn применимы только к режиму --webproxy."), file=sys.stderr)
        return 1
    if args.managed_caddy and args.cdn:
        print(err_text("Конфликт параметров: не сочетайте --managed-caddy (прямой Let's Encrypt) и --cdn одновременно."), file=sys.stderr)
        return 1
    if args.mode == "simple" and args.role in ("edge", "egress"):
        print(
            err_text(
                f"Конфликт параметров: --mode simple поддерживает только роль direct (указана --role {args.role}). "
                f"Для {args.role} используйте --mode advanced --role {args.role}."
            ),
            file=sys.stderr,
        )
        return 1
    if args.mode == "simple" and args.network_host:
        print(
            err_text("Конфликт параметров: флаг --network-host доступен только в расширенном режиме (--mode advanced)."),
            file=sys.stderr,
        )
        return 1

    print_wizard_banner(args.image)

    check_prerequisites()

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    existing_cfg = deploy_dir / "config.json"
    existing_role = str(saved_cfg.get("role") or "")
    if existing_role == "direct" and saved_cfg.get("egress_upstreams"):
        existing_role = "edge"
    existing_network_host = bool(saved.get("network_host", False))

    if existing_cfg.exists():
        try:
            existing_parsed = json.loads(existing_cfg.read_text(encoding="utf-8"))
            if not isinstance(existing_parsed, dict):
                raise ValueError("config.json должен содержать JSON-объект")
        except (OSError, ValueError) as exc:
            print(
                err_text(
                    f"Повреждённая конфигурация {existing_cfg}: {exc}. Исправьте или удалите файл вручную перед запуском мастера."
                ),
                file=sys.stderr,
            )
            return 1
        print(f"\nНайдена существующая конфигурация в {deploy_dir}")
        if existing_role:
            cur_port = str(saved.get("MTEVIL_PORT") or "")
            cur_host = str(saved.get("MTEVIL_PUBLIC_HOST") or saved.get("MTEVIL_BIND") or "")
            cur_net = "host" if existing_network_host else "bridge"
            addr_part = f", {cur_host}:{cur_port}" if (cur_host and cur_port) else ""
            print(f"  Текущая установка: роль {existing_role}{addr_part}, сеть {cur_net}")
        if not ask_yes_no("Перенастроить её с сохранением текущих секретов, пользователей и токенов?", default=False):
            print("Отменено без изменений.")
            return 0
        if args.mode == "simple" and existing_role in ("edge", "egress") and args.role != "direct":
            print(
                err_text(
                    f"Текущая установка имеет роль {existing_role}. Для её перенастройки используйте --mode advanced "
                    "(или укажите --role direct для явной смены роли)."
                ),
                file=sys.stderr,
            )
            return 1

    if args.mode is not None:
        mode = args.mode
    elif args.egress_ws or args.egress_ws_path:
        mode = "advanced"
        args.role = args.role or "egress"
    elif args.role in ("edge", "egress") or args.network_host:
        mode = "advanced"
    elif args.role == "direct":
        mode = "simple"
    elif existing_cfg.exists() and saved.get("webproxy"):
        mode = choose_wizard_mode(default="webproxy")
    elif existing_cfg.exists() and saved.get("shared_443"):
        mode = choose_wizard_mode(default="shared-443")
    elif existing_cfg.exists() and is_local_cover_addr(str(saved_cfg.get("cover") or "")):
        mode = choose_wizard_mode(default="self-steal")
    elif existing_cfg.exists() and existing_role in ("edge", "egress"):
        mode = "advanced"
    else:
        mode = choose_wizard_mode(default="simple")

    tproxy_sidecar_cand: dict[str, object] | None = None
    tproxy_sidecar_live: dict[str, object] | None = None
    managed_caddy_cand: dict[str, object] | None = None
    managed_caddy_live: dict[str, object] | None = None
    managed_caddy_enabled = False
    egress_ws_domain: str | None = None
    egress_ws_path_val: str | None = None
    public_link_port_override: int | None = None
    tproxy_config_data: dict[str, object] | None = None
    webproxy_carrier = "websocket"
    webproxy_hostname = ""
    webproxy_base_path = ""
    tproxy_listen_ep = DEFAULT_TPROXY_LISTEN
    tproxy_admin_ep = DEFAULT_TPROXY_ADMIN
    tproxy_image_override = (
        args.tproxy_image
        or os.environ.get("MTEVIL_TPROXY_IMAGE")
        or str(saved.get("MTEVIL_TPROXY_IMAGE") or "")
    ).strip() or None

    default_bind = str(saved.get("MTEVIL_BIND") or "0.0.0.0")
    default_sni = str(saved_cfg.get("sni") or DEFAULT_SNI)
    default_cover = str(saved_cfg.get("cover") or f"{default_sni}:443")
    use_network_host = True if args.network_host else existing_network_host
    advanced_changed: list[str] = []
    carry_host: str | None = None
    carry_port: int | None = None
    dns_records: dict[str, list[str]] | None = None

    if mode == "simple":
        role = "direct"
        project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
        bind_ip = default_bind
        sni = default_sni
        cover = default_cover
        default_port = int(saved.get("MTEVIL_PORT") or 443)

        saved_host = str(saved.get("MTEVIL_PUBLIC_HOST") or "").strip()
        if saved_host:
            public_host = saved_host
            host_source = "из текущей конфигурации"
        else:
            detected_ip = detect_local_global_ipv4()
            if detected_ip:
                public_host = detected_ip
                host_source = "определён автоматически"
            else:
                print("\nНе удалось автоматически определить публичный IPv4-адрес этого сервера.")
                public_host, dns_records = prompt_client_address(None)
                host_source = "указан вручную"

        if deployment_owns_port(deploy_dir, project, bind_ip, default_port) or is_port_available(bind_ip, default_port):
            pub_port = default_port
        else:
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, default_port, show_link_note=True)

        while True:
            print()
            print(heading("Параметры простой установки (direct)"))
            print(f"  Публичный адрес:  {public_host} ({host_source})")
            print(f"  Порт:             {pub_port} (свободен)")
            if cover != f"{sni}:443":
                print(f"  Маскировка (SNI): {sni} (cover: {cover})")
            else:
                print(f"  Маскировка (SNI): {sni}")
            print(f"  Каталог:          {deploy_dir}")
            print()
            action = ask_simple_confirm()
            if action == "sni":
                sni = prompt_sni_choice(sni)
                cover = f"{sni}:443"
                continue
            break
        if action == "cancel":
            print("Отменено без изменений.")
            return 0
        if action == "advanced":
            mode = "advanced"
            carry_host = public_host
            carry_port = pub_port
            default_sni = sni
            default_cover = cover
        else:
            config_data = {
                "role": "direct",
                "listen": "0.0.0.0:24443",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "dc": DEFAULT_DCS,
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }

    if mode == "webproxy":
        role = args.role if args.role in ("direct", "edge") else (existing_role if existing_role in ("direct", "edge") else "direct")
        project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
        saved_tp = saved.get("tproxy_config") if isinstance(saved.get("tproxy_config"), dict) else {}
        print("\n" + heading("Настройка WEB Proxy (tproxy-server за Caddy/nginx)"))
        print("  Клиент Telegram подключается по настоящему HTTPS/WebSocket к вашему домену (порт 443 на Caddy/nginx),")
        print("  tproxy-server принимает мультиплексированные потоки на loopback и передаёт чистый dd-поток в mtevil.")

        host_seed_raw = str(
            saved_tp.get("public_hostname")
            or saved.get("MTEVIL_WEBPROXY_HOST")
            or (saved.get("MTEVIL_PUBLIC_HOST") if not is_ip_literal(str(saved.get("MTEVIL_PUBLIC_HOST") or "")) else "")
            or ""
        ).strip() or None
        webproxy_hostname = ask_validated(
            "Публичный домен сайта для WEB Proxy (без https:// и порта)",
            validate_webproxy_hostname,
            host_seed_raw,
        )
        warn_if_sni_suspicious(webproxy_hostname)
        base_seed = str(saved_tp.get("base_path") or saved.get("MTEVIL_WEBPROXY_BASE_PATH") or "").strip()
        webproxy_base_path = ask_validated(
            "Префикс пути base_path (пусто — корень домена /)",
            validate_webproxy_base_path,
            base_seed,
        )
        carrier_seed = str(saved.get("MTEVIL_WEBPROXY_CARRIER") or "websocket").strip()
        webproxy_carrier = ask_validated(
            "Режим транспорта (websocket / https / https-lanes / websocket-lanes)",
            validate_webproxy_carrier_mode,
            carrier_seed,
        )
        listen_seed = str(saved_tp.get("listen") or saved.get("MTEVIL_TPROXY_LISTEN") or DEFAULT_TPROXY_LISTEN).strip()
        admin_seed = str(saved_tp.get("admin_listen") or saved.get("MTEVIL_TPROXY_ADMIN") or DEFAULT_TPROXY_ADMIN).strip()
        while True:
            tproxy_listen_ep = ask_validated(
                "Локальный HTTP-адрес tproxy-server (за Caddy/nginx)",
                validate_loopback_endpoint,
                listen_seed,
            )
            tproxy_admin_ep = ask_validated(
                "Локальный admin-адрес tproxy-server (/healthz, /readyz)",
                validate_loopback_endpoint,
                admin_seed,
            )
            if tproxy_listen_ep == tproxy_admin_ep:
                print(err_text("Ошибка: адреса listen и admin_listen у tproxy-server должны различаться."))
                continue
            break

        existing_upstream = str(saved_tp.get("public_upstream") or "").strip()
        site_mode_default = "upstream" if existing_upstream else "static"
        while True:
            site_choice = ask(
                "Источник публичного сайта при обычном входе браузера (static — каталог ./site, upstream — локальный HTTP-сервер)",
                site_mode_default,
            ).strip().lower()
            if site_choice in ("static", "1", "dir", "site"):
                webproxy_public_upstream = None
                webproxy_site_mount = "./site"
                break
            if site_choice in ("upstream", "2", "http", "app"):
                webproxy_public_upstream = ask_validated(
                    "URL локального HTTP-приложения сайта",
                    validate_webproxy_upstream,
                    existing_upstream or "http://127.0.0.1:3000",
                )
                webproxy_site_mount = ""
                break
            print("Укажите static (каталог ./site) или upstream (http://127.0.0.1:PORT).")

        saved_bind_raw = str(saved.get("MTEVIL_BIND") or "").strip()
        wp_bind_default = saved_bind_raw if (saved.get("webproxy") and saved_bind_raw) else "127.0.0.1"
        saved_port_raw = str(saved.get("MTEVIL_PORT") or "").strip()
        wp_port_default = (
            saved_port_raw
            if (saved.get("webproxy") and saved_port_raw and saved_port_raw != "443")
            else str(DEFAULT_TPROXY_BACKEND_PORT)
        )
        bind_ip = ask_validated(
            "IP привязки mtevil (127.0.0.1 — только за tproxy-server; 0.0.0.0 — также внешний порт FakeTLS)",
            validate_ip,
            wp_bind_default,
        )
        pub_port = ask_validated("TCP-порт бэкенда mtevil", validate_port, wp_port_default)
        tp_listen_port = parse_cover_host_port(tproxy_listen_ep)[1]
        tp_admin_port = parse_cover_host_port(tproxy_admin_ep)[1]
        if pub_port in (tp_listen_port, tp_admin_port):
            print(err_text(f"Конфликт портов: порт mtevil ({pub_port}) совпадает с портом tproxy-server."), file=sys.stderr)
            return 1
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=False)
        use_network_host = True
        pub_port, use_network_host = resolve_network_host_port(
            deploy_dir,
            project,
            bind_ip,
            pub_port,
            True,
            explicit_network_host=True,
            show_link_note=False,
            allow_bridge_fallback=False,
        )

        public_host = webproxy_hostname
        sni = webproxy_hostname
        cover = default_cover if not is_local_cover_addr(default_cover) else f"{DEFAULT_SNI}:443"
        same_role_reconfigure = existing_cfg.exists() and existing_role == role
        if same_role_reconfigure:
            config_data = copy.deepcopy(saved_cfg)
            config_data["role"] = "direct" if role == "direct" else "edge"
            config_data.setdefault("secret_file", "/var/lib/mtevil/proxy-secret")
            config_data.setdefault("users_file", "/var/lib/mtevil/users.json")
            config_data.setdefault("replay_file", "/var/lib/mtevil-replay/replay.bin")
            config_data["sni"] = sni
            config_data["cover"] = cover
            config_data["enable_dd"] = True
        else:
            config_data = {
                "role": "direct" if role == "direct" else "edge",
                "listen": f"{bind_ip}:{pub_port}",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "enable_dd": True,
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }
            if role == "direct":
                config_data["dc"] = DEFAULT_DCS
        if role == "edge":
            saved_upstreams = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
            default_upstreams = ",".join(str(x) for x in saved_upstreams) if saved_upstreams else None
            upstreams = ask_egress_upstreams(default_upstreams)
            config_data["egress_upstreams"] = upstreams
            config_data.setdefault("egress_token_file", "/var/lib/mtevil/egress-token")

        tproxy_include_build = not explicit_no_build and tproxy_image_override is None
        tproxy_config_data = render_tproxy_config(
            webproxy_hostname,
            webproxy_base_path,
            tproxy_listen_ep,
            tproxy_admin_ep,
            public_dir="/srv/tproxy-site" if webproxy_site_mount else None,
            public_upstream=webproxy_public_upstream,
        )
        tproxy_sidecar_cand = {
            "config_name": "tproxy.candidate.json",
            "dockerfile_name": "tproxy.candidate.Dockerfile",
            "admin_listen": tproxy_admin_ep,
            "include_build": tproxy_include_build,
            "site_host_dir": webproxy_site_mount,
        }
        tproxy_sidecar_live = {
            "config_name": "tproxy.json",
            "dockerfile_name": "tproxy.Dockerfile",
            "admin_listen": tproxy_admin_ep,
            "include_build": tproxy_include_build,
            "site_host_dir": webproxy_site_mount,
        }
        if args.managed_caddy or (
            sys.stdin.isatty()
            and not args.cdn
            and ask_yes_no(
                "[experimental] Поднять встроенный контейнер Caddy (автоматический TLS Let's Encrypt на порту 443)?",
                default=bool(saved.get("managed_caddy", False)),
            )
        ):
            print(
                warn_text(
                    "Примечание [experimental]: --managed-caddy пока помечен как экспериментальный режим "
                    "(автоматический ACME не покрыт живыми E2E-тестами в CI)."
                )
            )
            managed_caddy_enabled = True
            managed_caddy_cand = {"caddyfile_name": "Caddyfile.candidate"}
            managed_caddy_live = {"caddyfile_name": "Caddyfile"}
        if args.cdn:
            print(
                warn_text(
                    "Примечание [experimental]: профиль --cdn помечен как экспериментальный "
                    "(требует ручной проверки Cloudflare SSL Full (Strict), WebSockets и полевой матрицы)."
                )
            )

    if mode == "self-steal":
        role = args.role if args.role in ("direct", "edge") else (existing_role if existing_role in ("direct", "edge") else "direct")
        project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
        print("\n" + heading("Настройка self-steal (маскировка под свой локальный HTTPS-сайт)"))
        print("  MTEvil примет клиентов на внешнем порту (обычно 443), а обычный HTTPS-трафик")
        print("  передаст уже работающему на сервере nginx/Caddy (например, на 127.0.0.1:8443).")

        sni_seed = default_sni if (is_local_cover_addr(default_cover) or default_sni not in ("mozilla.org", "example.com")) else None
        sni = ask_validated("Публичный домен сайта (SNI)", validate_sni, sni_seed)
        warn_if_sni_suspicious(sni)
        default_host = str(saved.get("MTEVIL_PUBLIC_HOST") or "") or sni
        public_host, dns_records = prompt_client_address(default_host)

        default_port_str = str(saved.get("MTEVIL_PORT") or "443")
        pub_port = ask_validated("Публичный TCP-порт входа mtevil", validate_port, default_port_str)
        bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, default_bind)
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=True)

        local_default = default_cover if is_local_cover_addr(default_cover) else "127.0.0.1:8443"
        while True:
            cover = ask("Адрес локального HTTPS-сайта (cover, host:port)", local_default).strip()
            parsed_cover = parse_cover_host_port(cover)
            if parsed_cover is None:
                print(warn_text("Укажите адрес в формате host:port (например, 127.0.0.1:8443)."))
                continue
            if cover_loops_to_public_entry(cover, bind_ip, pub_port, public_host, sni):
                print(
                    err_text(
                        f"Ошибка: cover {cover} указывает обратно на публичный вход mtevil ({bind_ip}:{pub_port}) — "
                        "обычный HTTPS-трафик зациклится. Укажите другой порт для бэкенда (например, 127.0.0.1:8443)."
                    )
                )
                continue
            break

        if is_loopback_cover_addr(cover):
            if not use_network_host:
                print(
                    "Для loopback-cover (127.0.0.1 / localhost) требуется сетевой режим Docker host "
                    "(в bridge 127.0.0.1 указывает внутрь контейнера)."
                )
            use_network_host = True
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                True,
                explicit_network_host=True,
                show_link_note=True,
                allow_bridge_fallback=False,
            )
        else:
            if not args.network_host:
                use_network_host = ask_yes_no("Использовать сетевой режим host (--network-host)?", default=existing_network_host)
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                use_network_host,
                explicit_network_host=args.network_host,
                show_link_note=True,
            )

        if dns_records is not None:
            check_domain_expected_ips(dns_records)

        same_role_reconfigure = existing_cfg.exists() and existing_role == role
        if same_role_reconfigure:
            config_data = copy.deepcopy(saved_cfg)
            config_data["role"] = "direct"
            config_data.setdefault("secret_file", "/var/lib/mtevil/proxy-secret")
            config_data.setdefault("users_file", "/var/lib/mtevil/users.json")
            config_data.setdefault("replay_file", "/var/lib/mtevil-replay/replay.bin")
            config_data["sni"] = sni
            config_data["cover"] = cover
            if not use_network_host:
                config_data["listen"] = "0.0.0.0:24443"
        else:
            config_data = {
                "role": "direct",
                "listen": "0.0.0.0:24443",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "dc": DEFAULT_DCS,
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }
        if role == "edge":
            saved_upstreams = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
            default_upstreams = ",".join(str(x) for x in saved_upstreams) if saved_upstreams else None
            upstreams = ask_egress_upstreams(default_upstreams)
            config_data["egress_upstreams"] = upstreams
            config_data.setdefault("egress_token_file", "/var/lib/mtevil/egress-token")

    if mode == "shared-443":
        role = args.role if args.role in ("direct", "edge") else (existing_role if existing_role in ("direct", "edge") else "direct")
        project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
        print("\n" + heading("Настройка shared-443 (деление внешнего порта 443 через SNI-роутер)"))
        print("  mtevil слушает локальный порт (127.0.0.1) с включённым PROXY protocol v2,")
        print("  а внешний порт 443 маршрутизируется по SNI через nginx stream или Xray fallbacks.")

        sni = ask_validated("Домен маскировки (SNI) для маршрутизации с :443", validate_sni, default_sni)
        warn_if_sni_suspicious(sni)
        cover_seed = default_cover if sni == default_sni else f"{sni}:443"
        cover = ask("Адрес HTTPS-cover при несовпадении секрета (host:port)", cover_seed).strip()
        default_host = str(saved.get("MTEVIL_PUBLIC_HOST") or "") or detect_local_global_ipv4() or sni
        public_host, dns_records = prompt_client_address(default_host)

        bind_ip = "127.0.0.1"
        saved_port_raw = str(saved.get("MTEVIL_PORT") or "").strip()
        local_port_seed = saved_port_raw if (saved_port_raw and saved_port_raw != "443") else "24443"
        pub_port = ask_validated("Локальный TCP-порт бэкенда mtevil (на 127.0.0.1)", validate_port, local_port_seed)
        if pub_port == 443:
            print(err_text("Ошибка: локальный порт бэкенда mtevil в режиме shared-443 не должен быть 443 (его занимает SNI-роутер)."), file=sys.stderr)
            return 1
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=False)
        use_network_host = True
        pub_port, use_network_host = resolve_network_host_port(
            deploy_dir,
            project,
            bind_ip,
            pub_port,
            True,
            explicit_network_host=True,
            show_link_note=False,
            allow_bridge_fallback=False,
        )
        public_link_port_override = 443
        if dns_records is not None:
            check_domain_expected_ips(dns_records)

        same_role_reconfigure = existing_cfg.exists() and existing_role == role
        if same_role_reconfigure:
            config_data = copy.deepcopy(saved_cfg)
            config_data["role"] = "direct" if role == "direct" else "edge"
            config_data.setdefault("secret_file", "/var/lib/mtevil/proxy-secret")
            config_data.setdefault("users_file", "/var/lib/mtevil/users.json")
            config_data.setdefault("replay_file", "/var/lib/mtevil-replay/replay.bin")
            config_data["sni"] = sni
            config_data["cover"] = cover
            config_data["proxy_protocol"] = True
        else:
            config_data = {
                "role": "direct" if role == "direct" else "edge",
                "listen": f"{bind_ip}:{pub_port}",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "proxy_protocol": True,
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }
            if role == "direct":
                config_data["dc"] = DEFAULT_DCS
        if role == "edge":
            saved_upstreams = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
            default_upstreams = ",".join(str(x) for x in saved_upstreams) if saved_upstreams else None
            upstreams = ask_egress_upstreams(default_upstreams)
            config_data["egress_upstreams"] = upstreams
            config_data.setdefault("egress_token_file", "/var/lib/mtevil/egress-token")

    if mode == "advanced":
        default_role = existing_role if existing_role in ("direct", "edge", "egress") else "direct"
        role = args.role or choose_advanced_role(default_role)
        project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")

        if role == "direct":
            print("\n" + heading("Шаг 2. Сеть и адрес"))
            default_host = carry_host or str(saved.get("MTEVIL_PUBLIC_HOST") or "") or detect_local_global_ipv4()
            public_host, dns_records = prompt_client_address(default_host)
            default_port_str = str(carry_port or saved.get("MTEVIL_PORT") or "443")
            pub_port = ask_validated("Публичный TCP-порт", validate_port, default_port_str)
            bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, default_bind)
            if not args.network_host:
                use_network_host = ask_yes_no("Использовать сетевой режим host (--network-host)?", default=existing_network_host)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=True)
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                use_network_host,
                explicit_network_host=args.network_host,
                show_link_note=True,
            )

            sni, cover = prompt_masking_config(default_sni, default_cover)
            if dns_records is not None:
                check_domain_expected_ips(dns_records)
            if bind_ip != "0.0.0.0":
                advanced_changed.append(f"IP привязки: {bind_ip}")
            if sni != DEFAULT_SNI or cover != f"{DEFAULT_SNI}:443":
                advanced_changed.append(f"HTTPS-cover: {cover} (SNI: {sni})")
            config_data = {
                "role": "direct",
                "listen": "0.0.0.0:24443",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "dc": DEFAULT_DCS,
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }
        elif role == "egress":
            print("\n" + heading("Шаг 2. Сеть и адрес выхода"))
            default_egress_port = str(saved.get("MTEVIL_PORT") or "29443")
            default_egress_bind = str(saved.get("MTEVIL_BIND") or ("127.0.0.1" if (args.egress_ws or args.egress_ws_path) else ""))
            print("Укажите приватный IP этого сервера (или 127.0.0.1 для режима WSS за Caddy/nginx; 0.0.0.0 запрещён).")
            bind_ip = ask_validated("Локальный IP туннеля / loopback", validate_egress_ip, default_egress_bind or None)
            pub_port = ask_validated("TCP-порт egress", validate_port, default_egress_port)
            if bind_ip in ("127.0.0.1", "::1") and (args.egress_ws or args.egress_ws_path):
                use_network_host = True
            elif not args.network_host:
                use_network_host = ask_yes_no("Использовать сетевой режим host (--network-host)?", default=existing_network_host)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=False)
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                use_network_host,
                explicit_network_host=bool(args.network_host or (bind_ip in ("127.0.0.1", "::1") and (args.egress_ws or args.egress_ws_path))),
                show_link_note=False,
            )
            public_host = bind_ip
            config_data = {
                "role": "egress",
                "listen": "0.0.0.0:29443",
                "egress_token_file": "/var/lib/mtevil/egress-token",
                "dc": DEFAULT_DCS,
                "max_connections": 512,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
            }
            prev_ws_path = str(saved_cfg.get("egress_ws_path") or "").strip()
            want_ws = bool(args.egress_ws or args.egress_ws_path)
            if not want_ws and sys.stdin.isatty():
                want_ws = ask_yes_no(
                    "Включить приём защищённых подключений wss:// (WebSocket за Caddy/nginx на :443 без SSH/VPN)?",
                    default=bool(prev_ws_path),
                )
            if want_ws:
                if args.egress_ws_path:
                    egress_ws_path_val = validate_egress_ws_path(args.egress_ws_path)
                elif prev_ws_path:
                    egress_ws_path_val = validate_egress_ws_path(prev_ws_path)
                else:
                    egress_ws_path_val = f"/ws/{secrets.token_hex(12)}"
                config_data["egress_ws_path"] = egress_ws_path_val
                print(
                    warn_text(
                        "Предупреждение безопасности (H2): секретный путь egress_ws_path является HTTP-аутентификатором. "
                        "В конфигурации nginx/Caddy обязательно отключите access_log для этого location "
                        "(`access_log off;` в nginx / `log_skip @mtevil_egress` в Caddy) или маскируйте URL в логах."
                    )
                )
                if args.egress_domain:
                    egress_ws_domain = validate_sni(args.egress_domain).lower()
                elif sys.stdin.isatty():
                    egress_ws_domain = ask_validated(
                        "Публичный домен этого узла egress для шаблона Caddy/nginx",
                        validate_sni,
                        str(saved.get("MTEVIL_EGRESS_DOMAIN") or "") or None,
                    ).lower()
                    warn_if_sni_suspicious(egress_ws_domain)
        else:  # edge
            print("\n" + heading("Шаг 2. Сеть и адрес"))
            default_host = carry_host or str(saved.get("MTEVIL_PUBLIC_HOST") or "") or detect_local_global_ipv4()
            public_host, dns_records = prompt_client_address(default_host)
            default_port_str = str(carry_port or saved.get("MTEVIL_PORT") or "443")
            pub_port = ask_validated("Публичный TCP-порт", validate_port, default_port_str)
            bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, default_bind)
            if not args.network_host:
                use_network_host = ask_yes_no("Использовать сетевой режим host (--network-host)?", default=existing_network_host)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=True)
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                use_network_host,
                explicit_network_host=args.network_host,
                show_link_note=True,
            )

            sni, cover = prompt_masking_config(default_sni, default_cover)
            if dns_records is not None:
                check_domain_expected_ips(dns_records)
            if bind_ip != "0.0.0.0":
                advanced_changed.append(f"IP привязки: {bind_ip}")
            if sni != DEFAULT_SNI or cover != f"{DEFAULT_SNI}:443":
                advanced_changed.append(f"HTTPS-cover: {cover} (SNI: {sni})")

            print("\n" + heading("Шаг 4. Узлы egress и отказоустойчивость"))
            saved_upstreams = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
            default_upstreams = ",".join(str(x) for x in saved_upstreams) if saved_upstreams else None
            upstreams = ask_egress_upstreams(default_upstreams)
            while ask_yes_no("Добавить резервный egress?", default=False):
                upstreams.append(
                    ask_validated("Резервный адрес egress (IP:port или wss://host/path)", validate_egress_upstream)
                )
            default_strat = "round-robin" if saved_cfg.get("egress_strategy") == "round-robin" else "ordered"
            strategy = choose_egress_strategy(default_strat)
            config_data = {
                "role": "edge",
                "listen": "0.0.0.0:24443",
                "secret_file": "/var/lib/mtevil/proxy-secret",
                "users_file": "/var/lib/mtevil/users.json",
                "replay_file": "/var/lib/mtevil-replay/replay.bin",
                "sni": sni,
                "cover": cover,
                "egress_upstreams": upstreams,
                "egress_strategy": strategy,
                "egress_token_file": "/var/lib/mtevil/egress-token",
                "max_connections": 256,
                "client_hello_timeout_secs": 5,
                "handshake_timeout_secs": 10,
                "idle_timeout_secs": 300,
                "drain_timeout_secs": 5,
                "fake_tls_cert_jitter": 16,
                "flight_shaping": True,
            }

        if args.me_enabled or sys.stdin.isatty() or os.environ.get("MTEVIL_PROMPT_ME") == "1":
            cli_send_ip = None if args.me_send_client_ip is None else (args.me_send_client_ip == "true")
            cli_fb = None if args.me_fallback_to_direct is None else (args.me_fallback_to_direct == "true")
            det_ip = detect_local_global_ipv4()
            if not det_ip and role == "direct":
                try:
                    det_ip = validate_ip(public_host)
                except Exception:
                    det_ip = None
            me_block = prompt_me_config(
                role,
                network_host=use_network_host,
                detected_public_ip=det_ip,
                existing_me=saved_cfg.get("me") if isinstance(saved_cfg.get("me"), dict) else None,
                cli_enabled=args.me_enabled,
                cli_public_ipv4=args.me_public_ipv4,
                cli_send_client_ip=cli_send_ip,
                cli_fallback_to_direct=cli_fb,
            )
            if me_block is not None:
                config_data["me"] = me_block
                advanced_changed.append("Режим ME: включён")

        print()
        print(heading("Параметры установки"))
        role_names = {
            "direct": "Один зарубежный сервер (direct)",
            "egress": "Зарубежный сервер выхода (egress)",
            "edge": "Входной сервер (edge)",
        }
        print(f"  Роль:              {role_names[role]}")
        if role in ("direct", "edge"):
            print(f"  Адрес для Telegram: {public_host}:{pub_port}")
            print(f"  IP привязки:       {bind_ip}")
            print(f"  HTTPS-cover:       {cover} (SNI: {sni})")
        else:
            print(f"  Адрес выхода:      {bind_ip}:{pub_port}")
        print(f"  Сетевой режим:     {'host' if use_network_host else 'bridge'}")
        if role == "edge":
            print(f"  Узлы egress:       {', '.join(upstreams)} ({strategy})")
        print(f"  Каталог:           {deploy_dir}")
        print()
        if not ask_yes_no("Применить конфигурацию и запустить контейнер?", default=True):
            print("Отменено без изменений.")
            return 0

    total_steps = 4 if role in ("direct", "edge") else 2
    print_step(1, total_steps, "Проверка конфигурации и HTTPS-cover")
    deploy_dir.mkdir(parents=True, exist_ok=True)
    if use_network_host:
        if bind_ip == "::":
            config_data["listen"] = f"[::]:{pub_port}"
            health_host = "::1"
        elif ":" in bind_ip:
            config_data["listen"] = f"[{bind_ip}]:{pub_port}"
            health_host = bind_ip
        else:
            config_data["listen"] = f"{bind_ip}:{pub_port}"
            health_host = "127.0.0.1" if bind_ip == "0.0.0.0" else bind_ip
    else:
        health_host = "127.0.0.1"

    try:
        pp_ok, config_data = ensure_proxy_protocol_migration(
            deploy_dir,
            deploy_dir / "config.json",
            project=project,
            target_label="текущая версия",
            apply_to_file=False,
            override_cfg=config_data,
            network_mode="host" if use_network_host else "bridge",
        )
    except MigrationError as exc:
        print(err_text(f"Некорректная конфигурация proxy_protocol: {exc}."), file=sys.stderr)
        return 1
    if not pp_ok:
        return 1

    cand_compose = deploy_dir / "compose.candidate.yaml"
    cand_env = deploy_dir / ".env.candidate"
    cand_config = deploy_dir / "config.candidate.json"
    cand_tproxy_cfg = deploy_dir / "tproxy.candidate.json"
    cand_tproxy_df = deploy_dir / "tproxy.candidate.Dockerfile"
    cand_caddyfile = deploy_dir / "Caddyfile.candidate"
    cand_tproxy_profiles = "/var/lib/mtevil/tproxy-profiles.candidate.json"
    pending_token: str | None = None
    previous_token: str | None = None
    cand_token_in_volume = False
    cand_tproxy_profiles_in_volume = False
    token_written_to_volume = False
    had_backup = False
    env_text = (
        f"MTEVIL_PROJECT={project}\n"
        f"MTEVIL_IMAGE={args.image}\n"
        f"MTEVIL_BIND={bind_ip}\n"
        f"MTEVIL_PORT={pub_port}\n"
        + (f"MTEVIL_PUBLIC_PORT={public_link_port_override}\n" if public_link_port_override else "")
        + (f"MTEVIL_PUBLIC_HOST={public_host}\n" if role in ("direct", "edge") else "")
    )
    if mode == "shared-443":
        env_text += "MTEVIL_SHARED_443=1\n"
    if egress_ws_domain:
        env_text += f"MTEVIL_EGRESS_DOMAIN={egress_ws_domain}\n"
    if mode == "webproxy":
        env_text += (
            "MTEVIL_WEBPROXY=1\n"
            + ("MTEVIL_MANAGED_CADDY=1\n" if managed_caddy_enabled else "")
            + ("MTEVIL_WEBPROXY_CDN=1\n" if args.cdn else "")
            + f"MTEVIL_WEBPROXY_HOST={webproxy_hostname}\n"
            f"MTEVIL_WEBPROXY_BASE_PATH={webproxy_base_path}\n"
            f"MTEVIL_WEBPROXY_CARRIER={webproxy_carrier}\n"
            f"MTEVIL_TPROXY_LISTEN={tproxy_listen_ep}\n"
            f"MTEVIL_TPROXY_ADMIN={tproxy_admin_ep}\n"
            + (f"MTEVIL_TPROXY_IMAGE={tproxy_image_override}\n" if tproxy_image_override else "")
        )
    cfg_text = json.dumps(config_data, indent=2) + "\n"

    cand_base = compose_cmd(deploy_dir, project, "compose.candidate.yaml", ".env.candidate")
    base = compose_cmd(deploy_dir, project)
    abs_env = str((deploy_dir / ".env").resolve())
    abs_compose = str((deploy_dir / "compose.yaml").resolve())
    compose_ref = f'--env-file "{abs_env}" -f "{abs_compose}"'
    include_build = not args.no_build and (repo_root / "Dockerfile").is_file()
    cover_val = str(config_data.get("cover") or "")
    effective_egress_token_file = str(config_data.get("egress_token_file") or "/var/lib/mtevil/egress-token")
    if role in ("edge", "egress"):
        config_data["egress_token_file"] = effective_egress_token_file
    cand_token_path = f"{effective_egress_token_file}.candidate"
    compose_extra_hosts = (
        ["host.docker.internal:host-gateway"]
        if (not use_network_host and "host.docker.internal" in cover_val.lower())
        else None
    )

    prev_image_id: str | None = None
    pinned_rollback_tag: str | None = None
    if existing_cfg.exists():
        prev_image_ref = str(saved.get("MTEVIL_IMAGE") or args.image).strip()
        try:
            prev_image_id, prev_digest, prev_version = inspect_current_deployment(
                deploy_dir, project, prev_image_ref
            )
            if prev_image_id:
                pinned_rollback_tag = save_rollback_snapshot(
                    deploy_dir,
                    project,
                    prev_version,
                    prev_image_ref,
                    prev_image_id,
                    prev_digest,
                )
        except Exception as exc:
            print(err_text(f"Не удалось зафиксировать текущий образ для отката: {exc}"), file=sys.stderr)
            return 1

    had_proxy_secret = False
    created_proxy_secret = False
    had_users_json = False
    created_users_json = False
    created_tproxy_token_key = False
    had_tproxy_profiles = False
    prev_tproxy_profiles_raw: str | None = None
    tproxy_profiles_modified = False
    created_site_dir = False
    created_site_index = False
    had_allowed_sni = False
    prev_allowed_snis: list[str] | None = None
    allowed_snis_modified = False
    preflight_passed = False
    try:
        if mode == "webproxy" and tproxy_config_data is not None:
            if tproxy_config_data.get("public_dir"):
                site_dir = deploy_dir / "site"
                if not site_dir.exists():
                    site_dir.mkdir(parents=True, exist_ok=True)
                    created_site_dir = True
                idx_file = site_dir / "index.html"
                if not idx_file.exists():
                    idx_file.write_text(
                        f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{webproxy_hostname}</title></head>"
                        f"<body><main><h1>{webproxy_hostname}</h1><p>Service online.</p></main></body></html>\n",
                        encoding="utf-8",
                    )
                    created_site_index = True
            cand_tproxy_df.write_text(render_tproxy_dockerfile(), encoding="utf-8")
            cand_tp_cfg = dict(tproxy_config_data)
            cand_tp_cfg["profiles_file"] = cand_tproxy_profiles
            cand_tproxy_cfg.write_text(json.dumps(cand_tp_cfg, indent=2) + "\n", encoding="utf-8")
            if managed_caddy_enabled:
                caddy_cand_txt, _ = render_webproxy_reverse_proxy_snippets(
                    webproxy_hostname,
                    webproxy_base_path,
                    tproxy_listen_ep,
                    cdn_mode=False,
                )
                cand_caddyfile.write_text(caddy_cand_txt, encoding="utf-8")

        max_conn_val = int(config_data.get("max_connections", 512 if role == "egress" else 256))
        cand_compose.write_text(
            render_compose(
                repo_root,
                deploy_dir,
                role,
                "config.candidate.json",
                network_host=use_network_host,
                health_host=health_host,
                health_port=pub_port,
                include_build=include_build,
                max_connections=max_conn_val,
                extra_hosts=compose_extra_hosts,
                tproxy_sidecar=tproxy_sidecar_cand,
                managed_caddy=managed_caddy_cand,
            ),
            encoding="utf-8",
        )
        cand_env.write_text(env_text, encoding="utf-8")
        cand_config.write_text(cfg_text, encoding="utf-8")

        run(cand_base + ["config", "--quiet"])
        need_tproxy_build = bool(mode == "webproxy" and tproxy_sidecar_cand and tproxy_sidecar_cand.get("include_build"))
        if not args.no_build or need_tproxy_build:
            build_targets = [] if not args.no_build else ["tproxy"]
            print("\nСборка Docker-образа...")
            build_proc = run(cand_base + ["build", *build_targets], capture=True, check=False)
            if build_proc.returncode != 0:
                detail = (build_proc.stderr or build_proc.stdout or "").strip()
                summary, action = diagnose_docker_error(detail, args.image)
                print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
                if detail:
                    print(f"Детали: {detail}", file=sys.stderr)
                return 1
            print(ok_text("Docker-образ собран"))

        # Ensure secrets / tokens in the state volume without overwriting existing ones.
        if role in ("direct", "edge"):
            if mode == "self-steal":
                print(f"Проверка локального HTTPS-сайта {cover_val} (SNI {sni}) из временного контейнера...")
                cov_ok, cov_out = check_cover_from_container(cand_base, cover_val, sni)
                if not cov_ok:
                    print(
                        err_text(
                            f"Проверка cover перед развёртыванием не пройдена: {cover_val} (SNI {sni})."
                        ),
                        file=sys.stderr,
                    )
                    if cov_out:
                        print(f"Детали: {cov_out}", file=sys.stderr)
                    print(
                        "Текущая конфигурация и allowed-sni.txt не затронуты. Проверьте, что nginx/Caddy запущен и отдаёт валидный сертификат для этого SNI.",
                        file=sys.stderr,
                    )
                    return 1
                print(ok_text(f"Сертификат и доступность {cover_val} из контейнера подтверждены."))
            try:
                had_proxy_secret = volume_file_exists(cand_base, "/var/lib/mtevil/proxy-secret")
                created_proxy_secret = ensure_generated_secret(cand_base, "/var/lib/mtevil/proxy-secret")
                had_users_json = volume_file_exists(cand_base, "/var/lib/mtevil/users.json")
                if not had_users_json:
                    write_volume_secret_stdin(cand_base, "/var/lib/mtevil/users.json", "{}")
                    created_users_json = True
            except RuntimeError as exc:
                summary, action = diagnose_docker_error(str(exc), args.image)
                print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
                return 1
            print(
                "Секрет клиента: создан в томе state."
                if created_proxy_secret
                else "Секрет клиента: сохранён прежний из тома state."
            )

        if role == "egress":
            has_egress_tok = volume_file_exists(cand_base, effective_egress_token_file)
            if has_egress_tok and ask_yes_no("Использовать существующий токен MTV2 из тома state?", default=True):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                if has_egress_tok:
                    previous_token = read_volume_secret(cand_base, effective_egress_token_file)
                is_first = ask_yes_no("Это первый узел egress (сгенерировать новый токен MTV2)?", default=True)
                if is_first:
                    pending_token = secrets.token_hex(16)
                    print("Токен MTV2 сгенерирован и подготовлен для проверки (0600).")
                    if ask_yes_no("Показать сгенерированный токен MTV2 для копирования на edge?", default=False):
                        print(f"Токен MTV2: {pending_token}")
                else:
                    pending_token = ask_hidden_token("Введите токен MTV2 с основного egress")
                    print("Токен MTV2 подготовлен для проверки (рабочий том state пока не изменён).")
        elif role == "edge":
            has_edge_tok = volume_file_exists(cand_base, effective_egress_token_file)
            if has_edge_tok and ask_yes_no(
                "Использовать существующий токен MTV2 из тома state?", default=True
            ):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                if has_edge_tok:
                    previous_token = read_volume_secret(cand_base, effective_egress_token_file)
                pending_token = ask_hidden_token("Введите общий токен MTV2")
                print("Токен MTV2 подготовлен для проверки (рабочий том state пока не изменён).")

        if pending_token is not None:
            write_volume_secret_stdin(cand_base, cand_token_path, pending_token)
            cand_token_in_volume = True
            cand_cfg_data = dict(config_data)
            cand_cfg_data["egress_token_file"] = cand_token_path
            cand_config.write_text(json.dumps(cand_cfg_data, indent=2) + "\n", encoding="utf-8")

        cfg_check = run(
            cand_base + ["run", "--rm", "--no-deps", compose_service(cand_base), "--config", "/etc/mtevil/config.json", "--check-config"],
            check=False,
        )
        if cfg_check.returncode != 0:
            detail = (cfg_check.stderr or cfg_check.stdout or "").strip()
            print(err_text("Конфигурация не прошла проверку."), file=sys.stderr)
            if detail:
                print(detail, file=sys.stderr)
            return 1
        print(ok_text("Конфигурация проверена"))

        if mode == "webproxy":
            try:
                created_tproxy_token_key = ensure_tproxy_token_key(cand_base)
                sync_tproxy_profiles_in_volume(
                    cand_base,
                    f"127.0.0.1:{pub_port}",
                    webproxy_carrier,
                    profiles_path=cand_tproxy_profiles,
                )
                cand_tproxy_profiles_in_volume = True
            except Exception as exc:
                print(err_text(f"Не удалось подготовить ключи/профили tproxy-server в томе state: {exc}"), file=sys.stderr)
                return 1
            tp_check = run(
                cand_base
                + [
                    "run",
                    "--rm",
                    "--no-deps",
                    "tproxy",
                    "-config",
                    "/etc/tproxy-server/config.json",
                    "-check",
                ],
                check=False,
            )
            if tp_check.returncode != 0:
                detail = (tp_check.stderr or tp_check.stdout or "").strip()
                print(err_text("Конфигурация tproxy-server не прошла проверку (-check)."), file=sys.stderr)
                if detail:
                    print(detail, file=sys.stderr)
                return 1
            print(ok_text("Конфигурация tproxy-server проверена"))

        if role in ("direct", "edge") and mode not in ("self-steal", "webproxy"):
            cover_ok, cover_out = check_cover_from_container(cand_base, cover, sni)
            if cover_ok:
                print(ok_text("HTTPS-сайт для маскировки доступен"))
            else:
                print(err_text(f"HTTPS-сайт для маскировки ({cover}, SNI {sni}) не прошёл проверку."), file=sys.stderr)
                print("Дальше: проверьте имя домена/сертификата в расширенных настройках или выберите другой HTTPS-сайт.", file=sys.stderr)
                if cover_out:
                    print(f"Детали: {cover_out}", file=sys.stderr)
                if not ask_yes_no("Всё равно применить конфиг и запустить контейнер?", default=False):
                    print("Прервано до применения изменений. Текущая конфигурация не затронута.")
                    return 1

        if role == "edge":
            print("\nПроверка узлов egress из сетевого контекста edge (DC 2)...")
            check_proc = run(
                cand_base + ["run", "--rm", "--no-deps", compose_service(cand_base), "check-egress", "--config", "/etc/mtevil/config.json", "--dc", "2"],
                check=False,
            )
            print(check_proc.stdout.strip())
            if check_proc.returncode != 0:
                if check_proc.stderr.strip():
                    print(check_proc.stderr.strip(), file=sys.stderr)
                if "tcp_connect_timeout" in check_proc.stdout and not use_network_host:
                    print(
                        "Подсказка: если egress доступен с хоста по приватному маршруту/туннелю, "
                        "но не отвечает из Docker bridge, перезапустите мастер с флагом --network-host.",
                        file=sys.stderr,
                    )
                else:
                    print("Дальше: проверьте, что egress запущен, порт открыт по туннелю и токен MTV2 совпадает.", file=sys.stderr)
                if not ask_yes_no("Один или несколько egress не прошли проверку. Всё равно запустить edge?", default=False):
                    print("Прервано до применения изменений. Текущая конфигурация не затронута.")
                    return 1

        live_compose = render_compose(
            repo_root,
            deploy_dir,
            role,
            "config.json",
            network_host=use_network_host,
            health_host=health_host,
            health_port=pub_port,
            include_build=include_build,
            max_connections=max_conn_val,
            extra_hosts=compose_extra_hosts,
            tproxy_sidecar=tproxy_sidecar_live,
            managed_caddy=managed_caddy_live,
        )
        preflight_passed = True
    finally:
        if cand_token_in_volume:
            remove_volume_file(cand_base, cand_token_path)
        if cand_tproxy_profiles_in_volume:
            remove_volume_file(cand_base, cand_tproxy_profiles)
        for p in (cand_compose, cand_env, cand_config, cand_tproxy_cfg, cand_tproxy_df, cand_caddyfile):
            if p.exists():
                p.unlink()
        if not preflight_passed:
            if created_tproxy_token_key:
                remove_volume_file(cand_base, "/var/lib/mtevil/tproxy-token.key")
                created_tproxy_token_key = False
            if created_proxy_secret:
                remove_volume_file(cand_base, "/var/lib/mtevil/proxy-secret")
                created_proxy_secret = False
            if created_users_json:
                remove_volume_file(cand_base, "/var/lib/mtevil/users.json")
                created_users_json = False
            if created_site_index:
                idx_p = deploy_dir / "site" / "index.html"
                if idx_p.exists():
                    idx_p.unlink()
                if created_site_dir:
                    try:
                        (deploy_dir / "site").rmdir()
                    except OSError:
                        pass
                created_site_index = False
                created_site_dir = False

    up_attempted = False
    up_succeeded = False
    deployment_committed = False
    backed_up_files: list[str] = []
    newly_created_host_files: list[str] = []
    try:
        # Back up existing deployment files before promoting validated candidate.
        managed_names = ["compose.yaml", ".env", "config.json"]
        if mode == "webproxy" or (deploy_dir / "tproxy.json").exists() or (deploy_dir / "tproxy.Dockerfile").exists():
            managed_names.extend(["tproxy.json", "tproxy.Dockerfile"])
        if managed_caddy_enabled or (deploy_dir / "Caddyfile").exists():
            managed_names.append("Caddyfile")
        for name in managed_names:
            live = deploy_dir / name
            if live.exists():
                live.replace(deploy_dir / f"{name}.bak")
                backed_up_files.append(name)
                had_backup = True
        (deploy_dir / "compose.yaml").write_text(live_compose, encoding="utf-8")
        (deploy_dir / ".env").write_text(env_text, encoding="utf-8")
        (deploy_dir / "config.json").write_text(cfg_text, encoding="utf-8")
        if mode == "webproxy" and tproxy_config_data is not None:
            for extra_name in ("tproxy.json", "tproxy.Dockerfile"):
                if extra_name not in backed_up_files:
                    newly_created_host_files.append(extra_name)
            (deploy_dir / "tproxy.json").write_text(json.dumps(tproxy_config_data, indent=2) + "\n", encoding="utf-8")
            (deploy_dir / "tproxy.Dockerfile").write_text(render_tproxy_dockerfile(), encoding="utf-8")
            if managed_caddy_enabled:
                if "Caddyfile" not in backed_up_files:
                    newly_created_host_files.append("Caddyfile")
                live_caddy_txt, _ = render_webproxy_reverse_proxy_snippets(
                    webproxy_hostname,
                    webproxy_base_path,
                    tproxy_listen_ep,
                    cdn_mode=False,
                )
                (deploy_dir / "Caddyfile").write_text(live_caddy_txt, encoding="utf-8")
            had_tproxy_profiles = volume_file_exists(base, "/var/lib/mtevil/tproxy-profiles.json")
            if had_tproxy_profiles:
                prev_tproxy_profiles_raw = read_volume_secret(base, "/var/lib/mtevil/tproxy-profiles.json")
            sync_tproxy_profiles_in_volume(
                base,
                f"127.0.0.1:{pub_port}",
                webproxy_carrier,
                profiles_path="/var/lib/mtevil/tproxy-profiles.json",
            )
            tproxy_profiles_modified = True
        if role in ("direct", "edge"):
            had_allowed_sni = volume_file_exists(base, "/var/lib/mtevil/allowed-sni.txt")
            prev_allowed_snis = read_allowed_snis_from_volume(base) if had_allowed_sni else []
            prev_sni = str(saved_cfg.get("sni") or "").strip()
            snis_to_record = [sni] + ([prev_sni] if prev_sni and prev_sni != sni else [])
            record_allowed_snis_in_volume(base, snis_to_record)
            allowed_snis_modified = True
        if pending_token is not None:
            write_volume_secret_stdin(base, effective_egress_token_file, pending_token)
            token_written_to_volume = True
            print("Токен MTV2 сохранён в томе state.")
        run(base + ["config", "--quiet"])

        print_step(2, total_steps, "Запуск контейнера")
        while True:
            up_args = ["up", "-d"]
            if had_backup:
                up_args.append("--force-recreate")
            up_args.append(compose_service(base))
            if mode == "webproxy":
                up_args.append("tproxy")
                if managed_caddy_enabled:
                    up_args.append("caddy")
            up_attempted = True
            up_proc = run(base + up_args, check=False)
            if up_proc.returncode == 0:
                up_succeeded = True
                break
            err_detail = (up_proc.stderr or up_proc.stdout or "").strip()
            if not is_port_conflict_error(err_detail):
                summary, action = diagnose_docker_error(err_detail, args.image)
                print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
                if err_detail:
                    print(f"Детали: {err_detail}", file=sys.stderr)
                return 1
            print(warn_text(f"\nПорт {pub_port} оказался занят при запуске контейнера."))
            try:
                retry = ask_yes_no("Выбрать другой порт и повторить запуск (настройки и секрет сохранятся)?", default=True)
            except EOFError:
                retry = False
            if not retry:
                return 1
            alt = find_free_port(bind_ip, pub_port)
            if alt is not None:
                if role in ("direct", "edge"):
                    print(f"Можно использовать {alt}. В ссылке Telegram порт подставится автоматически.")
                else:
                    print(f"Можно использовать {alt}.")
                pub_port = ask_validated("Другой порт", validate_port, str(alt))
            else:
                pub_port = ask_validated("Другой порт", validate_port)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=(role in ("direct", "edge")))
            (deploy_dir / ".env").write_text(
                f"MTEVIL_PROJECT={project}\nMTEVIL_IMAGE={args.image}\nMTEVIL_BIND={bind_ip}\nMTEVIL_PORT={pub_port}\n"
                + (f"MTEVIL_PUBLIC_HOST={public_host}\n" if role in ("direct", "edge") else ""),
                encoding="utf-8",
            )
            if use_network_host:
                listen_addr, health_host = compute_listen_and_health(bind_ip, pub_port, True)
                config_data["listen"] = listen_addr
                (deploy_dir / "config.json").write_text(json.dumps(config_data, indent=2) + "\n", encoding="utf-8")
                (deploy_dir / "compose.yaml").write_text(
                    render_compose(
                        repo_root,
                        deploy_dir,
                        role,
                        "config.json",
                        network_host=True,
                        health_host=health_host,
                        health_port=pub_port,
                        include_build=include_build,
                        max_connections=max_conn_val,
                        extra_hosts=compose_extra_hosts,
                    ),
                    encoding="utf-8",
                )

        print(ok_text("Контейнер запущен"))
        try:
            wait_healthy(base)
            if mode == "webproxy":
                wait_service_healthy(base, "tproxy")
        except TimeoutError as exc:
            print(err_text(f"Сервис не перешёл в статус healthy за 45 секунд ({exc})."), file=sys.stderr)
            print_failed_container_logs(base)
            print(f"Проверьте логи этой установки: docker compose {compose_ref} logs --tail=100", file=sys.stderr)
            return 1

        self_steal_probe_ok: bool | None = None
        self_steal_probe_detail = ""
        self_steal_local_https_detail = ""
        webproxy_probe_ok: bool | None = None
        webproxy_probe_detail = ""
        if mode == "self-steal":
            local_https_host = "127.0.0.1" if bind_ip in ("0.0.0.0", "::", "127.0.0.1") else bind_ip
            https_ok, https_detail = probe_local_https_get(local_https_host, int(pub_port), sni)
            if not https_ok:
                print(
                    err_text(
                        f"Проверка локального HTTPS GET через вход mtevil ({local_https_host}:{pub_port}, SNI {sni}) не пройдена: {https_detail}"
                    ),
                    file=sys.stderr,
                )
                return 1
            self_steal_local_https_detail = https_detail
            print(ok_text(f"Локальный HTTPS GET через вход mtevil ({local_https_host}:{pub_port}): {https_detail}."))

            self_steal_probe_ok, self_steal_probe_detail = verify_telegram_e2e(base, attempts=3, delay_s=2.0)
            if not self_steal_probe_ok:
                print(
                    err_text(
                        f"Сквозная проверка Telegram через self-steal не пройдена: {self_steal_probe_detail or 'нет ответа'}"
                    ),
                    file=sys.stderr,
                )
                return 1
            print(ok_text(f"Локальная проверка Telegram: {self_steal_probe_detail}."))
        elif mode == "webproxy":
            rd_ok, rd_detail = probe_tproxy_readyz(tproxy_admin_ep)
            if not rd_ok:
                print(
                    err_text(
                        f"Проверка готовности tproxy-server (/readyz на {tproxy_admin_ep}) не пройдена: {rd_detail}"
                    ),
                    file=sys.stderr,
                )
                return 1
            print(ok_text(f"tproxy-server готов (/readyz: {rd_detail}, listen={tproxy_listen_ep})."))
            webproxy_probe_ok, webproxy_probe_detail = verify_telegram_e2e(base, attempts=3, delay_s=2.0)
            if not webproxy_probe_ok:
                print(
                    err_text(
                        f"Сквозная проверка Telegram через бэкенд mtevil не пройдена: {webproxy_probe_detail or 'нет ответа'}"
                    ),
                    file=sys.stderr,
                )
                return 1
            print(ok_text(f"Локальная проверка связи с Telegram: {webproxy_probe_detail}."))
            caddy_snip, nginx_snip = render_webproxy_reverse_proxy_snippets(
                webproxy_hostname,
                webproxy_base_path,
                tproxy_listen_ep,
                cdn_mode=bool(args.cdn),
            )
            (deploy_dir / "Caddyfile.webproxy.example").write_text(caddy_snip, encoding="utf-8")
            (deploy_dir / "nginx.webproxy.example").write_text(nginx_snip, encoding="utf-8")
        elif mode == "shared-443":
            xray_snip, nginx_stream_snip = render_shared_443_snippets(sni, f"127.0.0.1:{pub_port}")
            (deploy_dir / "xray.shared443.example.json").write_text(xray_snip, encoding="utf-8")
            (deploy_dir / "nginx.stream443.example.conf").write_text(nginx_stream_snip, encoding="utf-8")
        elif role == "egress" and egress_ws_path_val:
            eg_host_for_snip = egress_ws_domain or "egress.example.com"
            eg_loopback = f"{bind_ip}:{pub_port}" if bind_ip in ("127.0.0.1", "::1") else f"127.0.0.1:{pub_port}"
            eg_caddy, eg_nginx = render_egress_ws_reverse_proxy_snippets(
                eg_host_for_snip,
                egress_ws_path_val,
                eg_loopback,
            )
            (deploy_dir / "Caddyfile.egress.example").write_text(eg_caddy, encoding="utf-8")
            (deploy_dir / "nginx.egress.example").write_text(eg_nginx, encoding="utf-8")

        deployment_committed = True
    finally:
        if not deployment_committed:
            if mode == "webproxy" and up_attempted and "tproxy.json" not in backed_up_files:
                for extra_svc in (["caddy", "tproxy"] if managed_caddy_enabled else ["tproxy"]):
                    run(base + ["stop", extra_svc], check=False)
                    run(base + ["rm", "-f", extra_svc], check=False)
            for extra_f in newly_created_host_files:
                p_ex = deploy_dir / extra_f
                if p_ex.exists():
                    p_ex.unlink()
            if backed_up_files:
                restore_backup_files(deploy_dir, backed_up_files)
                print("Прежние файлы конфигурации восстановлены.", file=sys.stderr)
            if pinned_rollback_tag and (deploy_dir / ".env.rollback").is_file():
                try:
                    shutil.copyfile(deploy_dir / ".env.rollback", deploy_dir / ".env")
                except OSError:
                    pass
            if token_written_to_volume:
                try:
                    if previous_token is not None:
                        write_volume_secret_stdin(base, effective_egress_token_file, previous_token)
                    else:
                        remove_volume_file(base, effective_egress_token_file)
                except Exception as exc:
                    print(err_text(f"Не удалось вернуть прежний токен MTV2 в том state: {exc}"), file=sys.stderr)
            if tproxy_profiles_modified:
                try:
                    if had_tproxy_profiles and prev_tproxy_profiles_raw is not None:
                        write_volume_secret_stdin(base, "/var/lib/mtevil/tproxy-profiles.json", prev_tproxy_profiles_raw)
                    elif not had_tproxy_profiles:
                        remove_volume_file(base, "/var/lib/mtevil/tproxy-profiles.json")
                except Exception as exc:
                    print(err_text(f"Не удалось восстановить tproxy-profiles.json в томе state: {exc}"), file=sys.stderr)
            if created_tproxy_token_key:
                remove_volume_file(base, "/var/lib/mtevil/tproxy-token.key")
            if created_site_index:
                idx_p = deploy_dir / "site" / "index.html"
                if idx_p.exists():
                    idx_p.unlink()
                if created_site_dir:
                    try:
                        (deploy_dir / "site").rmdir()
                    except OSError:
                        pass
            if allowed_snis_modified:
                try:
                    if had_allowed_sni and prev_allowed_snis:
                        write_volume_secret_stdin(base, "/var/lib/mtevil/allowed-sni.txt", "\n".join(prev_allowed_snis))
                    elif not had_allowed_sni:
                        remove_volume_file(base, "/var/lib/mtevil/allowed-sni.txt")
                except Exception as exc:
                    print(err_text(f"Не удалось восстановить allowed-sni.txt в томе state: {exc}"), file=sys.stderr)
            if created_proxy_secret:
                remove_volume_file(base, "/var/lib/mtevil/proxy-secret")
            if created_users_json:
                remove_volume_file(base, "/var/lib/mtevil/users.json")
            if had_backup and up_attempted:
                rb_services = [compose_service(base)]
                if "tproxy.json" in backed_up_files:
                    rb_services.append("tproxy")
                rb_up = run(base + ["up", "-d", "--force-recreate", *rb_services], check=False)
                if rb_up.returncode == 0:
                    try:
                        wait_healthy(base)
                        if "tproxy" in rb_services:
                            wait_service_healthy(base, "tproxy")
                        if prev_image_id:
                            restored_ref = pinned_rollback_tag or str(saved.get("MTEVIL_IMAGE") or args.image)
                            restored_id, _, _ = inspect_current_deployment(deploy_dir, project, restored_ref)
                            if restored_id and restored_id != prev_image_id:
                                print(
                                    err_text(
                                        f"Откат перезапустил контейнер с другим image ID ({restored_id} вместо {prev_image_id})."
                                    ),
                                    file=sys.stderr,
                                )
                            else:
                                print("Прежний контейнер снова работает.", file=sys.stderr)
                        else:
                            print("Прежний контейнер снова работает.", file=sys.stderr)
                    except Exception as exc:
                        print(err_text(f"Прежний контейнер запущен, но не подтвердил статус healthy: {exc}"), file=sys.stderr)
                else:
                    rb_err = (rb_up.stderr or rb_up.stdout or "").strip()
                    print(err_text(f"Не удалось перезапустить прежний контейнер после отката: {rb_err}"), file=sys.stderr)
            elif not had_backup and up_attempted:
                for svc_name in ([compose_service(base), "tproxy"] if mode == "webproxy" else [compose_service(base)]):
                    run(base + ["stop", svc_name], check=False)
                    run(base + ["rm", "-f", svc_name], check=False)
                print("Неудачный кандидат остановлен.", file=sys.stderr)

    print(ok_text("Контейнер исправен (Docker healthcheck: локальный порт отвечает)"))
    status_cmd = format_status_command(deploy_dir)

    probe_ok: bool | None = None
    probe_detail = ""
    port_status = "skipped"
    port_detail = ""
    if role in ("direct", "edge"):
        if mode == "self-steal":
            probe_ok = self_steal_probe_ok
            probe_detail = self_steal_probe_detail
            print_step(3, total_steps, "Проверка self-steal (локально подтверждено, публичный адрес — справочно)")
            print(ok_text(f"Локальный вход: HTTPS GET ({self_steal_local_https_detail}) и Telegram ({probe_detail}) работают."))
            pub_target = f"{public_host}:{pub_port}"
            pub_https_ok, pub_https_detail = probe_local_https_get(public_host, int(pub_port), sni)
            if pub_https_ok:
                print(ok_text(f"Публичный HTTPS GET ({pub_target}): {pub_https_detail}."))
            else:
                print(
                    warn_text(
                        f"Публичный HTTPS GET ({pub_target}) с самого сервера не подтверждён (справочно, откат не требуется): {pub_https_detail}."
                    ),
                    file=sys.stderr,
                )
        elif mode == "webproxy":
            probe_ok = webproxy_probe_ok
            probe_detail = webproxy_probe_detail
            print_step(3, total_steps, "Проверка WEB Proxy (tproxy-server + mtevil локально готовы)")
            print(ok_text(f"tproxy-server ({tproxy_listen_ep}) и mtevil ({probe_detail}) проверены."))
            pub_https_ok, pub_https_detail = probe_local_https_get(webproxy_hostname, 443, webproxy_hostname)
            if pub_https_ok:
                print(ok_text(f"Публичный HTTPS {webproxy_hostname}:443 уже отвечает ({pub_https_detail})."))
            else:
                caddy_ex = deploy_dir / "Caddyfile.webproxy.example"
                nginx_ex = deploy_dir / "nginx.webproxy.example"
                print(
                    warn_text(
                        f"Публичный HTTPS {webproxy_hostname}:443 пока не настроен ({pub_https_detail}). "
                        f"Подключите проксирование в Caddy/nginx по шаблону {caddy_ex} или {nginx_ex}."
                    )
                )
        else:
            print_step(3, total_steps, "Сквозная проверка связи с Telegram")
            probe_ok, probe_detail = verify_telegram_e2e(base, attempts=3, delay_s=2.0)
            if probe_ok:
                print(ok_text(f"Проверено: прокси отвечает как Telegram ({probe_detail})."))
            else:
                print(warn_text("Не удалось получить ответ Telegram через прокси."), file=sys.stderr)
                if probe_detail:
                    print(f"  Причина: {probe_detail}", file=sys.stderr)
                print(
                    "  Прокси запущен, но доступ к Telegram DC с этого сервера не подтверждён. "
                    "Проверьте исходящий доступ к Telegram и логи контейнера (см. deploy/README.md).",
                    file=sys.stderr,
                )
        if mode == "webproxy" and bind_ip in ("127.0.0.1", "::1"):
            print_step(4, total_steps, "Проверка внешнего порта (Caddy/nginx 443)")
            port_status, port_detail = check_public_port_reachable(webproxy_hostname, 443)
            if port_status == "ok":
                print(ok_text(f"Порт 443 отвечает по адресу {webproxy_hostname}."))
            else:
                print(f"Внешний порт 443 ({webproxy_hostname}): {port_detail} (включается вашим Caddy/nginx).")
        elif mode == "shared-443":
            print_step(4, total_steps, "Проверка внешнего порта (SNI-роутер 443)")
            port_status, port_detail = check_public_port_reachable(public_host, 443)
            if port_status == "ok":
                print(ok_text(f"Внешний порт 443 отвечает по адресу {public_host}."))
            else:
                print(f"Внешний порт 443 ({public_host}): {port_detail} (обслуживается вашим Xray/nginx SNI-роутером).")
        else:
            print_step(4, total_steps, "Проверка порта на публичном адресе")
            port_status, port_detail = check_public_port_reachable(public_host, int(pub_port))
            if port_status == "ok":
                print(ok_text(f"Порт {pub_port} отвечает по адресу {public_host} (проверено с самого сервера)."))
                print("  Доступность из Интернета так не проверяется: убедитесь, что порт открыт в firewall провайдера и сервера.")
            elif port_status == "unreachable":
                print(warn_text(f"Не удалось подключиться к {public_host}:{pub_port} с самого сервера ({port_detail})."))
                print(
                    f"  Откройте порт {pub_port}/tcp в панели провайдера и в firewall сервера "
                    "(например, ufw allow {0}/tcp). Если сервер за NAT, проверьте проброс порта.".format(pub_port)
                )
            else:
                print(f"Проверка порта пропущена ({port_detail}).")

    if role in ("direct", "edge"):
        if mode == "webproxy":
            saved_post = load_existing_defaults(deploy_dir)
            wp_out = render_webproxy_links_output(base, saved_post)
            print("\n" + heading("Ссылки WEB Proxy для подключения в Telegram"))
            print("\n".join(wp_out))
            if bind_ip not in ("127.0.0.1", "::1"):
                ee_link = run(
                    base
                    + [
                        "exec",
                        "-T",
                        compose_service(base),
                        "mtevil",
                        "link",
                        "--config",
                        "/etc/mtevil/config.json",
                        "--server",
                        public_host,
                        "--port",
                        str(pub_port),
                    ]
                ).stdout.strip()
                print("\n" + heading("Резервная ссылка FakeTLS (tg://proxy)"))
                print(ee_link)
            print()
            caddy_ex = deploy_dir / "Caddyfile.webproxy.example"
            nginx_ex = deploy_dir / "nginx.webproxy.example"
            site_idx_ex = deploy_dir / "site" / "index.html"
            print(f"Каталог установки: {deploy_dir}")
            print(f"Шаблон Caddy:      {caddy_ex}")
            print(f"Шаблон nginx:      {nginx_ex}")
            if created_site_index:
                print(
                    warn_text(
                        f"Важно: замените заглушку {site_idx_ex} на уникальный контент вашего сайта и выполните docker compose {compose_ref} restart tproxy."
                    )
                )
            print(f"Проверка статуса:  {status_cmd}")
            print("Показать ссылку:   mtevilctl link")
            print("Перенастроить:     mtevilctl setup --webproxy")
        else:
            effective_link_port = public_link_port_override or pub_port
            link = run(
                base
                + [
                    "exec",
                    "-T",
                    compose_service(base),
                    "mtevil",
                    "link",
                    "--config",
                    "/etc/mtevil/config.json",
                    "--server",
                    public_host,
                    "--port",
                    str(effective_link_port),
                ]
            ).stdout.strip()
            print("\n" + heading("Ссылка для подключения в Telegram"))
            print(link)
            print()
            print(f"Каталог установки: {deploy_dir}")
            if mode == "shared-443":
                print(f"Шаблон Xray:       {deploy_dir / 'xray.shared443.example.json'}")
                print(f"Шаблон nginx L4:   {deploy_dir / 'nginx.stream443.example.conf'}")
            print(f"Проверка статуса:  {status_cmd}")
            print("Показать ссылку:   mtevilctl link")
            print("Сменить SNI:       mtevilctl sni <домен>  (старые ссылки продолжат работать)")
            print("Перенастроить:     mtevilctl setup" + (" --shared-443" if mode == "shared-443" else ""))
            if mode == "simple":
                print("\nОткройте ссылку в Telegram, нажмите «Подключить прокси» и проверьте отправку сообщения.")
                print("Справочник по диагностике, обновлению и откату: deploy/README.md")
            else:
                print("\nДальше:")
                if mode == "shared-443":
                    print(f"  1. Добавьте маршрут SNI '{sni}' -> 127.0.0.1:{pub_port} (PROXY protocol v2) в ваш Xray или nginx stream по шаблону выше.")
                    print("  2. Откройте ссылку в Telegram (порт 443) и нажмите «Подключить прокси».")
                else:
                    print("  1. Откройте ссылку в Telegram и нажмите «Подключить прокси» (сквозная связь проверяется клиентом).")
                    print("  2. Ссылка даёт доступ к прокси — передавайте её только тем, кому доверяете.")
                    print("  3. Дополнительная диагностика и команды управления описаны в deploy/README.md.")
    else:
        print("\n" + heading("Что указать на входном сервере (edge)"))
        if egress_ws_path_val:
            eg_dom_disp = egress_ws_domain or "<ваш-домен-egress>"
            print(f"  Адрес выхода (WSS без SSH/VPN): wss://{eg_dom_disp}{egress_ws_path_val}")
            print(f"  Добавить на edge одной командой: mtevilctl egress add \"wss://{eg_dom_disp}{egress_ws_path_val}\"")
            print(f"  Шаблон Caddy:      {deploy_dir / 'Caddyfile.egress.example'}")
            print(f"  Шаблон nginx:      {deploy_dir / 'nginx.egress.example'}")
            print(
                warn_text(
                    "  Важно (H2): не логируйте секретный путь egress_ws_path в access_log nginx/Caddy "
                    "(используйте `access_log off;` внутри `location = ...` / `log_skip @mtevil_egress` или маскирование пути)."
                )
            )
        else:
            print(f"  Адрес выхода: {bind_ip}:{pub_port}")
        print("  Режим в мастере на edge: 2 (Расширенная настройка) -> 2 (edge)")
        print(f"  Получить токен безопасно: docker compose {compose_ref} exec -T {compose_service(base)} cat {effective_egress_token_file}")
        print("  Миграция на MTV3: сначала обновите egress, затем все edge; после этого выставите \"egress_accept_legacy\": false в config.json egress.")
        print()
        print(f"Каталог установки: {deploy_dir}")
        print(f"Проверка статуса:  {status_cmd}")
        print("Перенастроить:     mtevilctl setup")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nОтменено пользователем.")
        raise SystemExit(130)
