#!/usr/bin/env python3
"""Interactive Docker Compose setup wizard for mtevil (Direct, Egress, Edge)."""
import argparse
import errno
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

DEFAULT_IMAGE = "mtevil:0.1.0-alpha.1"
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


def restore_backup_files(deploy_dir: Path) -> bool:
    restored = False
    for name in ("compose.yaml", ".env", "config.json"):
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Docker Compose wizard for mtevil")
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
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
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
    cand_token = deploy_dir / ".egress-token.candidate"
    pending_edge_token: str | None = None
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
            except RuntimeError as exc:
                summary, action = diagnose_docker_error(str(exc), args.image)
                print(f"{err_text(summary)}\nДальше: {action}", file=sys.stderr)
                return 1
            print("Секрет клиента: создан в томе state." if created else "Секрет клиента: сохранён прежний из тома state.")

        if role == "egress":
            if volume_file_exists(cand_base, "/var/lib/mtevil/egress-token"):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                is_first = ask_yes_no("Это первый узел egress (сгенерировать новый токен MTV2)?", default=True)
                if is_first:
                    ensure_generated_secret(cand_base, "/var/lib/mtevil/egress-token")
                    print("Токен MTV2 сгенерирован и сохранён в томе state (0600).")
                    if ask_yes_no("Показать сгенерированный токен MTV2 для копирования на edge?", default=False):
                        tok = read_volume_secret(cand_base, "/var/lib/mtevil/egress-token")
                        print(f"Токен MTV2: {tok}")
                else:
                    tok = ask_hidden_token("Введите токен MTV2 с основного egress")
                    write_volume_secret_stdin(cand_base, "/var/lib/mtevil/egress-token", tok)
                    print("Токен MTV2 импортирован в том state.")
        elif role == "edge":
            if volume_file_exists(cand_base, "/var/lib/mtevil/egress-token") and ask_yes_no(
                "Использовать существующий токен MTV2 из тома state?", default=True
            ):
                print("Токен MTV2: сохранён прежний из тома state.")
            else:
                pending_edge_token = ask_hidden_token("Введите общий токен MTV2")
                cand_token.write_text(pending_edge_token + "\n", encoding="utf-8")
                try:
                    os.chmod(cand_token, 0o600)
                except OSError:
                    pass
                cand_cfg_data = dict(config_data)
                cand_cfg_data["egress_token_file"] = "/etc/mtevil/egress-token.candidate"
                cand_config.write_text(json.dumps(cand_cfg_data, indent=2) + "\n", encoding="utf-8")
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
                        extra_volumes=["./.egress-token.candidate:/etc/mtevil/egress-token.candidate:ro"],
                    ),
                    encoding="utf-8",
                )
                print("Токен MTV2 подготовлен для проверки (рабочий том state пока не изменён).")

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
        # Back up existing deployment files before promoting validated candidate.
        had_backup = False
        for name in ("compose.yaml", ".env", "config.json"):
            live = deploy_dir / name
            if live.exists():
                live.replace(deploy_dir / f"{name}.bak")
                had_backup = True
        (deploy_dir / "compose.yaml").write_text(live_compose, encoding="utf-8")
        os.replace(cand_env, deploy_dir / ".env")
        os.replace(cand_config, deploy_dir / "config.json")
        if pending_edge_token is not None:
            (deploy_dir / "config.json").write_text(cfg_text, encoding="utf-8")
            write_volume_secret_stdin(base, "/var/lib/mtevil/egress-token", pending_edge_token)
            print("Токен MTV2 сохранён в томе state.")
        run(base + ["config", "--quiet"])
    finally:
        for p in (cand_compose, cand_env, cand_config, cand_token):
            if p.exists():
                p.unlink()

    up_succeeded = False
    try:
        while True:
            up_proc = run(base + ["up", "-d", compose_service(base)], check=False)
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
    finally:
        if not up_succeeded and had_backup:
            restore_backup_files(deploy_dir)
            print("Прежние файлы конфигурации восстановлены.", file=sys.stderr)

    print(ok_text("Контейнер запущен"))
    try:
        wait_healthy(base)
    except TimeoutError:
        print(err_text("Контейнер не перешёл в статус healthy за 45 секунд."), file=sys.stderr)
        print(f"Проверьте логи этой установки: docker compose {compose_ref} logs --tail=100 {compose_service(base)}", file=sys.stderr)
        return 1
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
