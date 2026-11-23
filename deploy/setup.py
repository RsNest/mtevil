#!/usr/bin/env python3
"""Interactive Docker Compose setup wizard for mtevil (Direct, Egress, Edge)."""
import argparse
import datetime
import errno
import getpass
import hashlib
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
import urllib.request

DEFAULT_IMAGE = "mtevil:local"
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
            return pub_port
        print(warn_text(f"\nПорт {pub_port} уже занят на этом сервере."))
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
    extra_vol_lines = "".join(f"\n      - {v}" for v in (extra_volumes or []))
    return f"""name: ${{MTEVIL_PROJECT:-mtevil-{role}}}

x-image: &image
  image: ${{MTEVIL_IMAGE:-{DEFAULT_IMAGE}}}{build_block}

services:
  {deployment_service(deploy_dir)}:
    <<: *image
    init: true
    restart: unless-stopped
{net_block}
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
"""


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


def wait_healthy(base: list[str], timeout_s: int = 45) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cid = run(base + ["ps", "-q", compose_service(base)]).stdout.strip()
        if cid:
            raw = run(["docker", "inspect", cid]).stdout
            info = json.loads(raw)[0]
            status = info.get("State", {}).get("Health", {}).get("Status")
            if status == "healthy":
                return
        time.sleep(1.0)
    raise TimeoutError("mtevil container did not become healthy within 45s")


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
    default_num = "2" if default == "advanced" else "1"
    print()
    print(heading("Выберите режим установки"))
    print("  1. Простая установка · один VPS [по умолчанию]")
    print("  2. Расширенная настройка · ручные параметры и несколько серверов")
    print()
    while True:
        choice = ask("Ваш выбор", default_num).lower()
        if choice in ("1", "simple", "s", "простая"):
            return "simple"
        if choice in ("2", "advanced", "a", "adv", "расширенная"):
            return "advanced"
        print("Некорректный выбор: введите 1 (простая установка) или 2 (расширенная настройка).")


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


def probe_cover_reachable(cover: str, sni: str, timeout_s: float = 4.0) -> tuple[bool, str]:
    """Quickly verify TLS reachability of `cover` from this VPS before writing config."""
    import ssl

    host, _, port_str = cover.rpartition(":")
    if not host:
        host, port = cover, 443
    else:
        host = host.strip("[]")
        try:
            port = int(port_str)
        except ValueError:
            return False, f"некорректный порт в адресе cover: {cover}"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                ver = tls_sock.version() or "TLS"
                return True, ver
    except Exception as exc:
        return False, str(exc)


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
        raw_list = ask("Основной (или список через запятую) адрес egress (IP:port)", default_upstreams)
        try:
            upstreams = [validate_endpoint(item) for item in raw_list.split(",") if item.strip()]
            if not upstreams:
                raise ValueError("укажите хотя бы один адрес IP:port")
            return upstreams
        except ValueError as exc:
            print(f"Некорректный адрес egress: {exc}. Формат: IP:PORT (например, 10.203.0.9:29443).")


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
        print(f"  Порт и сеть:       {bind_val}:{port_val} ({net_mode_label})")
    if role in ("direct", "edge"):
        cur_sni = str(saved_cfg.get("sni") or "").strip()
        if cur_sni:
            extra_snis = [s for s in read_allowed_snis_from_volume(base) if s != cur_sni.lower()]
            sni_note = f" (также разрешены: {', '.join(extra_snis)})" if extra_snis else ""
            print(f"  Маскировка (SNI):  {cur_sni}{sni_note}")
    print(f"  Состояние:         {health_status}")
    print(f"  Время работы:      {uptime_str}")
    print(f"  Версия для отката: {rollback_ver}")
    rstats = read_container_runtime_stats(base, svc) if running else None
    for me_line in format_me_status_lines(role, saved_cfg, rstats):
        print(me_line)
    if role == "egress":
        accept_legacy = saved_cfg.get("egress_accept_legacy", True) is not False
        proto_mode = "MTV4 + MTV3 + legacy MTV2 (переходный)" if accept_legacy else "MTV4 + MTV3 (строгий)"
        print(f"  Протокол egress:   {proto_mode}")
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
    port_raw = str(saved.get("MTEVIL_PORT") or "443").strip()
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


def run_link_command(
    deploy_dir: Path,
    *,
    sni_override: str | None = None,
    user: str | None = None,
    all_users: bool = False,
    dd: bool = False,
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

    if sni_override is not None:
        try:
            sni_override = validate_sni(sni_override)
        except Exception as exc:
            print(err_text(f"Некорректный домен SNI: {exc}"), file=sys.stderr)
            return 1

    project = str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")
    base = compose_cmd(deploy_dir, project)
    svc = compose_service(base)
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

    if act == "add":
        if not name:
            print(err_text("Укажите имя пользователя: mtevilctl user add <имя>"), file=sys.stderr)
            return 1
        proc = run(write_prefix + ["user-add", "--users-file", users_file, "--name", name], check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            print(err_text(f"Не удалось добавить пользователя '{name}': {detail}"), file=sys.stderr)
            return 1
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interactive Docker Compose wizard and lifecycle tool for mtevil")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("wizard", "setup", "reconfigure", "status", "update", "rollback", "traffic", "traf", "link", "sni", "user", "adtag"),
        default="wizard",
        help="Action to perform: wizard (default), setup, status, update, rollback, traffic, link, sni, user, adtag",
    )
    parser.add_argument("extra", nargs="*", help=argparse.SUPPRESS)
    parser.add_argument("--dir", type=Path, default=None, help="Target deployment directory (default: deploy/wizard)")
    parser.add_argument("--project", type=str, default=None, help="Docker Compose project name")
    parser.add_argument("--image", type=str, default=DEFAULT_IMAGE, help="Docker image tag")
    parser.add_argument("--no-build", action="store_true", help="Skip docker compose build")
    parser.add_argument(
        "--mode",
        choices=("simple", "advanced"),
        default=None,
        help="Wizard mode: simple (single VPS direct) or advanced (manual settings & edge/egress)",
    )
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
    if args.command in ("status", "update", "rollback", "traffic", "traf", "link", "sni", "user", "adtag"):
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
        return run_traffic_command(deploy_dir, live=args.live, max_iterations=args.iterations)

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
    elif args.role in ("edge", "egress") or args.network_host:
        mode = "advanced"
    elif args.role == "direct":
        mode = "simple"
    elif existing_cfg.exists() and existing_role in ("edge", "egress"):
        mode = "advanced"
    else:
        mode = choose_wizard_mode(default="simple")

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

            print("\n" + heading("Шаг 3. Маскировка (HTTPS-cover)"))
            print("Подсказка: после настройки можно уточнить fake_tls_cert_bytes в config.json под размер цепочки сертификата выбранного домена.")
            sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, default_sni)
            cover_default = default_cover if sni == default_sni else f"{sni}:443"
            cover = ask("Адрес HTTPS-cover (host:port)", cover_default)
            cover_ok_host, cover_detail_host = probe_cover_reachable(cover, sni)
            if not cover_ok_host:
                print(f"Предупреждение: cover {cover} (SNI {sni}) не отвечает с этого VPS ({cover_detail_host}).")
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
            default_egress_bind = str(saved.get("MTEVIL_BIND") or "")
            print("Укажите приватный IP этого сервера, по которому до него дотянется edge (0.0.0.0 запрещён).")
            bind_ip = ask_validated("Локальный IP туннеля", validate_egress_ip, default_egress_bind or None)
            pub_port = ask_validated("TCP-порт egress", validate_port, default_egress_port)
            if not args.network_host:
                use_network_host = ask_yes_no("Использовать сетевой режим host (--network-host)?", default=existing_network_host)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=False)
            pub_port, use_network_host = resolve_network_host_port(
                deploy_dir,
                project,
                bind_ip,
                pub_port,
                use_network_host,
                explicit_network_host=args.network_host,
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

            print("\n" + heading("Шаг 3. Маскировка (HTTPS-cover)"))
            print("Подсказка: после настройки можно уточнить fake_tls_cert_bytes в config.json под размер цепочки сертификата выбранного домена.")
            sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, default_sni)
            cover_default = default_cover if sni == default_sni else f"{sni}:443"
            cover = ask("Адрес HTTPS-cover (host:port)", cover_default)
            cover_ok_host, cover_detail_host = probe_cover_reachable(cover, sni)
            if not cover_ok_host:
                print(f"Предупреждение: cover {cover} (SNI {sni}) не отвечает с этого VPS ({cover_detail_host}).")
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
                upstreams.append(ask_validated("Резервный адрес egress (IP:port)", validate_endpoint))
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

    cand_compose = deploy_dir / "compose.candidate.yaml"
    cand_env = deploy_dir / ".env.candidate"
    cand_config = deploy_dir / "config.candidate.json"
    pending_token: str | None = None
    previous_token: str | None = None
    cand_token_in_volume = False
    token_written_to_volume = False
    had_backup = False
    env_text = (
        f"MTEVIL_PROJECT={project}\n"
        f"MTEVIL_IMAGE={args.image}\n"
        f"MTEVIL_BIND={bind_ip}\n"
        f"MTEVIL_PORT={pub_port}\n"
        + (f"MTEVIL_PUBLIC_HOST={public_host}\n" if role in ("direct", "edge") else "")
    )
    cfg_text = json.dumps(config_data, indent=2) + "\n"

    cand_base = compose_cmd(deploy_dir, project, "compose.candidate.yaml", ".env.candidate")
    base = compose_cmd(deploy_dir, project)
    abs_env = str((deploy_dir / ".env").resolve())
    abs_compose = str((deploy_dir / "compose.yaml").resolve())
    compose_ref = f'--env-file "{abs_env}" -f "{abs_compose}"'
    include_build = not args.no_build and (repo_root / "Dockerfile").is_file()
    try:
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
            ),
            encoding="utf-8",
        )
        cand_env.write_text(env_text, encoding="utf-8")
        cand_config.write_text(cfg_text, encoding="utf-8")

        run(cand_base + ["config", "--quiet"])
        if not args.no_build:
            print("\nСборка Docker-образа mtevil...")
            build_proc = run(cand_base + ["build"], capture=True, check=False)
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
            try:
                created = ensure_generated_secret(cand_base, "/var/lib/mtevil/proxy-secret")
                if not volume_file_exists(cand_base, "/var/lib/mtevil/users.json"):
                    write_volume_secret_stdin(cand_base, "/var/lib/mtevil/users.json", "{}")
                prev_sni = str(saved_cfg.get("sni") or "").strip()
                snis_to_record = [sni] + ([prev_sni] if prev_sni and prev_sni != sni else [])
                record_allowed_snis_in_volume(cand_base, snis_to_record)
            except RuntimeError as exc:
                summary, action = diagnose_docker_error(str(exc), args.image)
                print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
                return 1
            print("Секрет клиента: создан в томе state." if created else "Секрет клиента: сохранён прежний из тома state.")

        if role == "egress":
            has_egress_tok = volume_file_exists(cand_base, "/var/lib/mtevil/egress-token")
            if has_egress_tok and ask_yes_no("Использовать существующий токен MTV2 из тома state?", default=True):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                if has_egress_tok:
                    previous_token = read_volume_secret(cand_base, "/var/lib/mtevil/egress-token")
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
            has_edge_tok = volume_file_exists(cand_base, "/var/lib/mtevil/egress-token")
            if has_edge_tok and ask_yes_no(
                "Использовать существующий токен MTV2 из тома state?", default=True
            ):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                if has_edge_tok:
                    previous_token = read_volume_secret(cand_base, "/var/lib/mtevil/egress-token")
                pending_token = ask_hidden_token("Введите общий токен MTV2")
                print("Токен MTV2 подготовлен для проверки (рабочий том state пока не изменён).")

        if pending_token is not None:
            write_volume_secret_stdin(cand_base, "/var/lib/mtevil/egress-token.candidate", pending_token)
            cand_token_in_volume = True
            cand_cfg_data = dict(config_data)
            cand_cfg_data["egress_token_file"] = "/var/lib/mtevil/egress-token.candidate"
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

        if role in ("direct", "edge"):
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
        )
    finally:
        if cand_token_in_volume:
            try:
                run(
                    cand_base
                    + [
                        "run",
                        "--rm",
                        "--no-deps",
                        "--entrypoint",
                        "/bin/rm",
                        compose_write_service(cand_base),
                        "-f",
                        "/var/lib/mtevil/egress-token.candidate",
                    ],
                    check=False,
                )
            except Exception:
                pass
        for p in (cand_compose, cand_env, cand_config):
            if p.exists():
                p.unlink()

    up_attempted = False
    up_succeeded = False
    deployment_committed = False
    backed_up_files: list[str] = []
    try:
        # Back up existing deployment files before promoting validated candidate.
        for name in ("compose.yaml", ".env", "config.json"):
            live = deploy_dir / name
            if live.exists():
                live.replace(deploy_dir / f"{name}.bak")
                backed_up_files.append(name)
                had_backup = True
        (deploy_dir / "compose.yaml").write_text(live_compose, encoding="utf-8")
        (deploy_dir / ".env").write_text(env_text, encoding="utf-8")
        (deploy_dir / "config.json").write_text(cfg_text, encoding="utf-8")
        if pending_token is not None:
            write_volume_secret_stdin(base, "/var/lib/mtevil/egress-token", pending_token)
            token_written_to_volume = True
            print("Токен MTV2 сохранён в томе state.")
        run(base + ["config", "--quiet"])

        print_step(2, total_steps, "Запуск контейнера")
        while True:
            up_args = ["up", "-d"]
            if had_backup:
                up_args.append("--force-recreate")
            up_args.append(compose_service(base))
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
                    ),
                    encoding="utf-8",
                )

        print(ok_text("Контейнер запущен"))
        try:
            wait_healthy(base)
        except TimeoutError:
            print(err_text("Контейнер не перешёл в статус healthy за 45 секунд."), file=sys.stderr)
            print_failed_container_logs(base)
            print(f"Проверьте логи этой установки: docker compose {compose_ref} logs --tail=100 {compose_service(base)}", file=sys.stderr)
            return 1
        deployment_committed = True
    finally:
        if not deployment_committed:
            if backed_up_files:
                restore_backup_files(deploy_dir, backed_up_files)
                print("Прежние файлы конфигурации восстановлены.", file=sys.stderr)
            if token_written_to_volume and previous_token is not None:
                try:
                    write_volume_secret_stdin(base, "/var/lib/mtevil/egress-token", previous_token)
                except Exception as exc:
                    print(err_text(f"Не удалось вернуть прежний токен MTV2 в том state: {exc}"), file=sys.stderr)
            if had_backup and up_attempted:
                rb_up = run(base + ["up", "-d", "--force-recreate", compose_service(base)], check=False)
                if rb_up.returncode == 0:
                    try:
                        wait_healthy(base)
                        print("Прежний контейнер снова работает.", file=sys.stderr)
                    except Exception as exc:
                        print(err_text(f"Прежний контейнер запущен, но не подтвердил статус healthy: {exc}"), file=sys.stderr)
                else:
                    rb_err = (rb_up.stderr or rb_up.stdout or "").strip()
                    print(err_text(f"Не удалось перезапустить прежний контейнер после отката: {rb_err}"), file=sys.stderr)

    print(ok_text("Контейнер исправен (Docker healthcheck: локальный порт отвечает)"))
    status_cmd = format_status_command(deploy_dir)

    probe_ok: bool | None = None
    probe_detail = ""
    port_status = "skipped"
    port_detail = ""
    if role in ("direct", "edge"):
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
                str(pub_port),
            ]
        ).stdout.strip()
        print("\n" + heading("Ссылка для подключения в Telegram"))
        print(link)
        print()
        print(f"Каталог установки: {deploy_dir}")
        print(f"Проверка статуса:  {status_cmd}")
        print("Показать ссылку:   mtevilctl link")
        print("Сменить SNI:       mtevilctl sni <домен>  (старые ссылки продолжат работать)")
        print("Перенастроить:     mtevilctl setup")
        if mode == "simple":
            print("\nОткройте ссылку в Telegram, нажмите «Подключить прокси» и проверьте отправку сообщения.")
            print("Справочник по диагностике, обновлению и откату: deploy/README.md")
        else:
            print("\nДальше:")
            print("  1. Откройте ссылку в Telegram и нажмите «Подключить прокси» (сквозная связь проверяется клиентом).")
            print("  2. Ссылка даёт доступ к прокси — передавайте её только тем, кому доверяете.")
            print("  3. Дополнительная диагностика и команды управления описаны в deploy/README.md.")
    else:
        print("\n" + heading("Что указать на входном сервере (edge)"))
        print(f"  Адрес выхода: {bind_ip}:{pub_port}")
        print("  Режим в мастере на edge: 2 (Расширенная настройка) -> 2 (edge)")
        print(f"  Получить токен безопасно: docker compose {compose_ref} exec -T {compose_service(base)} cat /var/lib/mtevil/egress-token")
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
