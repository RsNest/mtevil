#!/usr/bin/env python3
"""Interactive Docker Compose setup wizard for mtevil (Direct, Egress, Edge)."""
import argparse
import datetime
import errno
import getpass
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


def select_latest_release(releases: list[dict[str, object]]) -> str:
    if not isinstance(releases, list) or not releases:
        raise ValueError("no releases found")
    candidates: list[tuple[tuple[int, int, int, int, int], str]] = []
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
        if {"install.sh", "setup.py"}.issubset(ready_names):
            candidates.append((key, tag))
    if not candidates:
        raise ValueError("no eligible published release with install.sh and setup.py assets")
    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


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
HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SNI_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def fail(msg: str) -> "NoReturn":
    print(f"Ошибка: {msg}", file=sys.stderr)
    raise SystemExit(1)


def use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


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
) -> str:
    try:
        rel_context = os.path.relpath(repo_root, deploy_dir).replace("\\", "/")
    except ValueError:
        rel_context = str(repo_root).replace("\\", "/")
    internal_port = 29443 if role == "egress" else 24443
    hc_port = health_port if (network_host and health_port is not None) else internal_port
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
      - state:/var/lib/mtevil{extra_vol_lines}
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    memswap_limit: 256m
    cpus: "0.50"
    pids_limit: 128
    ulimits:
      nofile:
        soft: 4096
        hard: 4096
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

volumes:
  state:
"""


def deployment_service(deploy_dir: Path) -> str:
    # Compose identifies an existing container by project and service.
    compose = deploy_dir / "compose.yaml"
    if compose.is_file() and "\n  mtveil:\n" in compose.read_text(encoding="utf-8"):
        return "mtveil"
    return "mtevil"


def compose_service(base: list[str]) -> str:
    return deployment_service(Path(base[-1]).parent)


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
            compose_service(base),
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
            compose_service(base),
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


def configure_role() -> str:
    print()
    print(heading("Настройка прокси для Telegram"))
    print("\nКак вы хотите подключаться?")
    print("  1. Через один зарубежный сервер — подойдёт для первой установки")
    print("  2. Через несколько серверов — отдельный вход и зарубежный выход")
    print()
    choice = ask("Ваш выбор", "1").lower()
    while choice not in ("1", "2", "direct", "egress", "edge"):
        choice = ask("Введите 1 или 2", "1").lower()
    if choice in ("1", "direct"):
        return "direct"
    if choice in ("egress", "edge"):
        return choice

    print("\nЧто вы настраиваете на этом сервере?")
    print("  1. Зарубежный сервер выхода (egress) — принимает трафик от входного сервера и отправляет в Telegram. Настраивается первым.")
    print("  2. Входной сервер (edge) — принимает подключения Telegram и передаёт их на один или несколько egress.")
    print()
    sub = ask("Ваш выбор", "1").lower()
    mapping = {"1": "egress", "egress": "egress", "2": "edge", "edge": "edge"}
    while sub not in mapping:
        sub = ask("Введите 1 (egress) или 2 (edge)", "1").lower()
    return mapping[sub]


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


def download_url_atomic(url: str, dest: Path, mode: int | None = None) -> None:
    tmp = dest.with_name(f".{dest.name}.tmp.{os.getpid()}")
    req = urllib.request.Request(url, headers={"User-Agent": "mtevilctl"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
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


def run_update_command(deploy_dir: Path, target_version_override: str | None = None) -> int:
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

    if requested_version:
        target_version = requested_version
    else:
        try:
            releases_data = fetch_json_url(api_url)
            if not isinstance(releases_data, list):
                raise ValueError("Ответ GitHub API не является списком релизов.")
            target_version = select_latest_release(releases_data)
        except Exception as exc:
            print(err_text(f"Не удалось определить свежий релиз из GitHub API ({api_url}): {exc}"), file=sys.stderr)
            print("Дальше: проверьте доступ к api.github.com или задайте версию через MTEVIL_VERSION.", file=sys.stderr)
            return 1

    target_image = explicit_image or f"ghcr.io/{repo_lower}:{target_version}"

    # Fast path if installed version already matches target_version (preserves existing rollback snapshot untouched).
    if not explicit_image and cur_version == target_version:
        print(ok_text(f"Уже установлена актуальная версия {target_version}. Перезапуск не требуется."))
        return 0

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

    # Update helper scripts from the release if available (non-fatal if offline/custom image).
    if os.environ.get("MTEVIL_SKIP_ASSET_DOWNLOAD") != "1":
        for asset_name, mode in (("setup.py", 0o755), ("mtevilctl", 0o755)):
            asset_url = f"{release_base_url}/{target_version}/{asset_name}"
            try:
                download_url_atomic(asset_url, deploy_dir / asset_name, mode=mode)
            except Exception:
                pass

    orig_env_text = env_file.read_text(encoding="utf-8", errors="ignore")
    env_file.write_text(set_env_image(orig_env_text, target_image), encoding="utf-8")

    base = compose_cmd(deploy_dir, project)
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
    print(f"  Состояние:         {health_status}")
    print(f"  Время работы:      {uptime_str}")
    print(f"  Версия для отката: {rollback_ver}")
    if role == "edge" and running:
        alerts_proc = run(
            base + ["exec", "-T", svc, "/bin/cat", "/var/lib/mtevil/edge-alerts.jsonl"],
            check=False,
        )
        if alerts_proc.returncode == 0 and alerts_proc.stdout.strip():
            lines = [ln.strip() for ln in alerts_proc.stdout.splitlines() if ln.strip()]
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
    proc = run(
        base + ["exec", "-T", svc, "/bin/cat", "/var/lib/mtevil/runtime-stats.json"],
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
        return data if isinstance(data, dict) else None
    except Exception:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interactive Docker Compose wizard and lifecycle tool for mtevil")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("wizard", "status", "update", "rollback", "traffic", "traf"),
        default="wizard",
        help="Action to perform: wizard (default), status, update, rollback, traffic (or traf)",
    )
    parser.add_argument("--dir", type=Path, default=None, help="Target deployment directory (default: deploy/wizard)")
    parser.add_argument("--project", type=str, default=None, help="Docker Compose project name")
    parser.add_argument("--image", type=str, default=DEFAULT_IMAGE, help="Docker image tag")
    parser.add_argument("--no-build", action="store_true", help="Skip docker compose build")
    parser.add_argument("--role", choices=("direct", "egress", "edge"), default=None, help="Deployment role (non-interactive override)")
    parser.add_argument(
        "--network-host",
        action="store_true",
        help="Use Docker host networking (for Linux hosts with policy-routed mesh/VPN egress)",
    )
    parser.add_argument("--version", type=str, default=None, help="Target release version override for update")
    parser.add_argument("--live", action="store_true", help="Refresh traffic statistics every second")
    parser.add_argument("--iterations", type=int, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    if args.command in ("status", "update", "rollback", "traffic", "traf"):
        deploy_dir = (args.dir or default_deploy_dir(repo_root)).resolve()
        if args.command == "status":
            return run_status_command(deploy_dir)
        if args.command == "update":
            return run_update_command(deploy_dir, target_version_override=args.version)
        if args.command == "rollback":
            return perform_rollback(deploy_dir)
        return run_traffic_command(deploy_dir, live=args.live, max_iterations=args.iterations)

    deploy_dir = (args.dir or (repo_root / "deploy" / "wizard")).resolve()

    check_prerequisites()

    saved = load_existing_defaults(deploy_dir)
    saved_cfg = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    existing_cfg = deploy_dir / "config.json"
    if existing_cfg.exists():
        print(f"\nНайдена существующая конфигурация в {deploy_dir}")
        if not ask_yes_no("Перенастроить её с сохранением текущих секретов/токенов?", default=False):
            print("Отменено без изменений.")
            return 0

    role = args.role or configure_role()
    project = args.project or str(saved.get("MTEVIL_PROJECT") or f"mtevil-{role}")

    default_bind = str(saved.get("MTEVIL_BIND") or "0.0.0.0")
    default_sni = str(saved_cfg.get("sni") or "example.com")
    default_cover = str(saved_cfg.get("cover") or f"{default_sni}:443")
    advanced_changed: list[str] = []

    if role == "direct":
        default_port = str(saved.get("MTEVIL_PORT") or "443")
        default_host = str(saved.get("MTEVIL_PUBLIC_HOST") or "") or detect_local_global_ipv4()
        public_host, dns_records = prompt_client_address(default_host)
        print(f"\nНа каком TCP-порту принимать подключения?")
        print(f"Нажмите Enter, чтобы использовать {default_port}.")
        pub_port = ask_validated("Порт", validate_port, default_port)
        bind_ip = default_bind
        sni = default_sni
        cover = default_cover
        print("\nРасширенные настройки (по умолчанию):")
        print(f"  IP прослушивания: {bind_ip}")
        print(f"  Маскировка (HTTPS-cover): {cover} (SNI: {sni})")
        if ask_yes_no("Изменить расширенные настройки?", default=False):
            bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, default_bind)
            sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, default_sni)
            cover = ask("Адрес HTTPS-cover (host:port)", f"{sni}:443")
            if dns_records is not None:
                check_domain_expected_ips(dns_records)
            if bind_ip != default_bind:
                advanced_changed.append(f"IP привязки: {bind_ip}")
            if sni != default_sni or cover != default_cover:
                advanced_changed.append(f"HTTPS-cover: {cover} (SNI: {sni})")
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=True)
        config_data = {
            "role": "direct",
            "listen": "0.0.0.0:24443",
            "secret_file": "/var/lib/mtevil/proxy-secret",
            "users_file": "/var/lib/mtevil/users.json",
            "replay_file": "/var/lib/mtevil/replay.bin",
            "sni": sni,
            "cover": cover,
            "dc": DEFAULT_DCS,
            "max_connections": 256,
            "client_hello_timeout_secs": 5,
            "handshake_timeout_secs": 10,
            "idle_timeout_secs": 300,
            "drain_timeout_secs": 5,
            "fake_tls_cert_bytes": 2878,
            "fake_tls_cert_jitter": 256,
            "flight_shaping": True,
            "client_mss": 100,
            "client_mss_bulk": 1380,
        }
    elif role == "egress":
        default_egress_port = str(saved.get("MTEVIL_PORT") or "29443")
        default_egress_bind = str(saved.get("MTEVIL_BIND") or "")
        print("\nУкажите приватный IP этого сервера, по которому до него сможет дотянуться входной сервер (edge).")
        print("(Например, адрес интерфейса WireGuard, AmneziaWG или SharX; 0.0.0.0 запрещён.)")
        bind_ip = ask_validated("Локальный IP туннеля", validate_egress_ip, default_egress_bind or None)
        pub_port = ask_validated("TCP-порт egress", validate_port, default_egress_port)
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=False)
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
        default_port = str(saved.get("MTEVIL_PORT") or "443")
        default_host = str(saved.get("MTEVIL_PUBLIC_HOST") or "") or detect_local_global_ipv4()
        public_host, dns_records = prompt_client_address(default_host)
        print(f"\nНа каком TCP-порту принимать подключения?")
        print(f"Нажмите Enter, чтобы использовать {default_port}.")
        pub_port = ask_validated("Порт", validate_port, default_port)
        bind_ip = default_bind
        sni = default_sni
        cover = default_cover
        print("\nРасширенные настройки (по умолчанию):")
        print(f"  IP прослушивания: {bind_ip}")
        print(f"  Маскировка (HTTPS-cover): {cover} (SNI: {sni})")
        if ask_yes_no("Изменить расширенные настройки?", default=False):
            bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, default_bind)
            sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, default_sni)
            cover = ask("Адрес HTTPS-cover (host:port)", f"{sni}:443")
            if dns_records is not None:
                check_domain_expected_ips(dns_records)
            if bind_ip != default_bind:
                advanced_changed.append(f"IP привязки: {bind_ip}")
            if sni != default_sni or cover != default_cover:
                advanced_changed.append(f"HTTPS-cover: {cover} (SNI: {sni})")
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, show_link_note=True)
        print("\nУкажите один или несколько адресов egress (IP:port) в порядке приоритета (через запятую или по одному).")
        saved_upstreams = saved_cfg.get("egress_upstreams") if isinstance(saved_cfg.get("egress_upstreams"), list) else []
        default_upstreams = ",".join(str(x) for x in saved_upstreams) if saved_upstreams else None
        upstreams: list[str] = []
        raw_list = ask("Основной (или список через запятую) адрес egress (IP:port)", default_upstreams)
        for item in raw_list.split(","):
            upstreams.append(validate_endpoint(item))
        while ask_yes_no("Добавить резервный egress?", default=False):
            upstreams.append(ask_validated("Резервный адрес egress (IP:port)", validate_endpoint))
        print("\nКак распределять новые подключения между узлами egress:")
        print("  1. ordered     — новые подключения идут на основной egress; при его сбое — на резервные по порядку")
        print("  2. round-robin — новые подключения распределяются по кругу между всеми egress")
        default_strat = "2" if saved_cfg.get("egress_strategy") == "round-robin" else "1"
        strat_choice = ask("Стратегия [1/2]", default_strat).lower()
        strategy = "ordered" if strat_choice in ("1", "ordered") else "round-robin"
        config_data = {
            "role": "edge",
            "listen": "0.0.0.0:24443",
            "secret_file": "/var/lib/mtevil/proxy-secret",
            "users_file": "/var/lib/mtevil/users.json",
            "replay_file": "/var/lib/mtevil/replay.bin",
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
            "fake_tls_cert_bytes": 2878,
            "fake_tls_cert_jitter": 256,
            "flight_shaping": True,
            "client_mss": 100,
            "client_mss_bulk": 1380,
        }

    print()
    print(heading("Параметры установки"))
    role_names = {
        "direct": "Один зарубежный сервер (direct)",
        "egress": "Зарубежный сервер выхода (egress)",
        "edge": "Входной сервер (edge)",
    }
    print(f"  Режим: {role_names[role]}")
    if role in ("direct", "edge"):
        print(f"  Адрес для Telegram: {public_host}:{pub_port}")
    else:
        print(f"  Адрес выхода: {bind_ip}:{pub_port}")
    if role == "edge":
        print(f"  Узлы egress: {', '.join(upstreams)} ({strategy})")
    if advanced_changed:
        for item in advanced_changed:
            print(f"  {item}")
    elif role in ("direct", "edge"):
        print("  Расширенные настройки: по умолчанию")

    deploy_dir.mkdir(parents=True, exist_ok=True)
    if args.network_host:
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
        cand_compose.write_text(
            render_compose(
                repo_root,
                deploy_dir,
                role,
                "config.candidate.json",
                network_host=args.network_host,
                health_host=health_host,
                health_port=pub_port,
                include_build=include_build,
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
                if "tcp_connect_timeout" in check_proc.stdout and not args.network_host:
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
            network_host=args.network_host,
            health_host=health_host,
            health_port=pub_port,
            include_build=include_build,
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
                        compose_service(cand_base),
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
            if args.network_host:
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
                    ),
                    encoding="utf-8",
                )

        print(ok_text("Контейнер запущен"))
        try:
            wait_healthy(base)
        except TimeoutError:
            print(err_text("Контейнер не перешёл в статус healthy за 45 секунд."), file=sys.stderr)
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

    print(ok_text("Контейнер исправен"))

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
        print(f"  {link}\n")
        print("Дальше:")
        print("  1. Откройте ссылку на телефоне или компьютере и нажмите «Подключить прокси».")
        print("  2. Ссылка даёт доступ к прокси — передавайте её только тем, кому доверяете.")
        print("  3. Для проверки откройте любой чат и загрузите фото или видео (включая мобильную сеть).")
    else:
        print("\n" + heading("Что указать на входном сервере (edge)"))
        print(f"  Адрес выхода: {bind_ip}:{pub_port}")
        print(f"  Режим в мастере на edge: 2 (несколько серверов) -> 2 (Входной сервер (edge))")
        print(f"  Получить токен MTV2 безопасно: docker compose {compose_ref} exec -T {compose_service(base)} cat /var/lib/mtevil/egress-token")

    print("\nУправление и диагностика:")
    ctl_path = deploy_dir / "mtevilctl"
    ctl_cmd = "mtevilctl" if ctl_path.is_file() else f'python3 "{(deploy_dir / "setup.py").resolve()}"'
    print(f"  {ctl_cmd} status")
    print(f"  {ctl_cmd} traffic --live")
    print(f"  {ctl_cmd} update")
    print(f"  {ctl_cmd} rollback")
    print(f"  docker compose {compose_ref} ps")
    print(f"  docker compose {compose_ref} logs --tail=100 {compose_service(base)}")
    if role == "edge":
        print(f"  docker compose {compose_ref} exec {compose_service(base)} mtevil check-egress --config /etc/mtevil/config.json --dc 2")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nОтменено пользователем.")
        raise SystemExit(130)
