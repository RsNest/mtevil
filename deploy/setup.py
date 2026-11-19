#!/usr/bin/env python3
"""Interactive Docker Compose setup wizard for mtveil (Direct, Egress, Edge)."""
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

DEFAULT_IMAGE = "mtveil:0.1.0-alpha.1"
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
    print(f"Error: {msg}", file=sys.stderr)
    raise SystemExit(1)


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
        fail(f"Требуется запущенный Docker Engine ({exc})")
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
        if raw in ("y", "yes", "д", "да"):
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


def prompt_client_host_and_dns(prompt: str) -> str:
    host = ask_validated(prompt, validate_host)
    if not is_ip_literal(host):
        records = resolve_domain_records(host)
        while True:
            raw_exp = input("Ожидаемые публичные IPv4/IPv6-адреса (через запятую, Enter — пропустить проверку): ").strip()
            expected: list[str] = []
            if not raw_exp:
                break
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
        print("  Примечание: DNS-проверка не проверяет доступность порта снаружи; проверьте порт с телефона или другого хоста.")
        if not ok and not ask_yes_no("Проверка DNS обнаружила расхождение или отсутствие записи. Продолжить?", default=False):
            raise SystemExit(1)
    return host


def check_cover_from_container(base: list[str], cover: str, sni: str) -> tuple[bool, str]:
    proc = run(
        base
        + [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "openssl",
            "mtveil",
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
    proc = run(base + ["ps", "-q", "mtveil"], check=False)
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


def ensure_available_port(deploy_dir: Path, project: str, bind_ip: str, pub_port: int, prompt: str) -> int:
    while True:
        if deployment_owns_port(deploy_dir, project, bind_ip, pub_port) or is_port_available(bind_ip, pub_port):
            return pub_port
        print(f"Порт {pub_port} на {bind_ip} уже занят другим сервисом.")
        pub_port = ask_validated(prompt, validate_port)


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
        else f'    ports:\n      - "${{MTVEIL_BIND:-127.0.0.1}}:${{MTVEIL_PORT:-{internal_port}}}:{internal_port}/tcp"'
    )
    return f"""name: ${{MTVEIL_PROJECT:-mtveil-{role}}}

x-image: &image
  image: ${{MTVEIL_IMAGE:-{DEFAULT_IMAGE}}}{build_block}

services:
  mtveil:
    <<: *image
    init: true
    restart: unless-stopped
{net_block}
    volumes:
      - ./{config_name}:/etc/mtveil/config.json:ro
      - state:/var/lib/mtveil
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
      test: [CMD, /usr/local/bin/mtveil, health, --address, "{health_host}:{hc_port}"]
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
            "mtveil",
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
            "/usr/local/bin/mtveil",
            "mtveil",
            "secret",
            "--output",
            path_in_container,
        ],
        capture=False,
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
            "mtveil",
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
            "mtveil",
            path_in_container,
        ]
    ).stdout.strip()


def wait_healthy(base: list[str], timeout_s: int = 45) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cid = run(base + ["ps", "-q", "mtveil"]).stdout.strip()
        if cid:
            raw = run(["docker", "inspect", cid]).stdout
            info = json.loads(raw)[0]
            status = info.get("State", {}).get("Health", {}).get("Status")
            if status == "healthy":
                return
        time.sleep(1.0)
    raise TimeoutError("mtveil container did not become healthy within 45s")


def configure_role() -> str:
    print("\nВыберите режим установки:")
    print("  1) direct (по умолчанию) — один зарубежный VPS")
    print("  2) egress                — зарубежный узел-ретранслятор (настраивается до edge)")
    print("  3) edge                  — входной VPS (например, в РФ), пересылающий трафик на egress")
    choice = ask("Режим [1/2/3]", "1").lower()
    mapping = {"1": "direct", "direct": "direct", "2": "egress", "egress": "egress", "3": "edge", "edge": "edge"}
    while choice not in mapping:
        choice = ask("Выберите 1 (direct), 2 (egress) или 3 (edge)", "1").lower()
    return mapping[choice]


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Docker Compose wizard for mtveil")
    parser.add_argument("--dir", type=Path, default=None, help="Target deployment directory (default: deploy/wizard)")
    parser.add_argument("--project", type=str, default=None, help="Docker Compose project name")
    parser.add_argument("--image", type=str, default=DEFAULT_IMAGE, help="Docker image tag")
    parser.add_argument("--no-build", action="store_true", help="Skip docker compose build")
    parser.add_argument(
        "--network-host",
        action="store_true",
        help="Use Docker host networking (for Linux hosts with policy-routed mesh/VPN egress)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    deploy_dir = (args.dir or (repo_root / "deploy" / "wizard")).resolve()

    check_prerequisites()

    existing_cfg = deploy_dir / "config.json"
    if existing_cfg.exists():
        print(f"\nНайдена существующая конфигурация в {deploy_dir}")
        if not ask_yes_no("Перенастроить её с сохранением текущих секретов/токенов?", default=False):
            print("Отменено без изменений.")
            return 0

    role = configure_role()
    project = args.project or f"mtveil-{role}"

    if role == "direct":
        public_host = prompt_client_host_and_dns("Публичный домен или IP для ссылки Telegram")
        pub_port = ask_validated("Публичный TCP-порт", validate_port, "443")
        bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, "0.0.0.0")
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, "Укажите другой публичный TCP-порт")
        sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, "example.com")
        cover = ask("Адрес HTTPS-cover (host:port)", f"{sni}:443")
        config_data = {
            "role": "direct",
            "listen": "0.0.0.0:24443",
            "secret_file": "/var/lib/mtveil/proxy-secret",
            "replay_file": "/var/lib/mtveil/replay.bin",
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
        print("\nПримечание: укажите приватный туннельный IP (SharX, WireGuard или AmneziaWG), доступный с edge.")
        bind_ip = ask_validated("Локальный IP туннеля для прослушивания egress", validate_egress_ip)
        pub_port = ask_validated("TCP-порт egress", validate_port, "29443")
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, "Укажите другой TCP-порт egress")
        public_host = bind_ip
        config_data = {
            "role": "egress",
            "listen": "0.0.0.0:29443",
            "egress_token_file": "/var/lib/mtveil/egress-token",
            "dc": DEFAULT_DCS,
            "max_connections": 512,
            "handshake_timeout_secs": 10,
            "idle_timeout_secs": 300,
            "drain_timeout_secs": 5,
        }
    else:  # edge
        public_host = prompt_client_host_and_dns("Публичный домен или IP для ссылки Telegram")
        pub_port = ask_validated("Публичный TCP-порт для клиентов", validate_port, "443")
        bind_ip = ask_validated("IP интерфейса для привязки на хосте", validate_ip, "0.0.0.0")
        pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, "Укажите другой публичный TCP-порт")
        sni = ask_validated("Домен для HTTPS-маскировки (SNI)", validate_sni, "example.com")
        cover = ask("Адрес HTTPS-cover (host:port)", f"{sni}:443")
        print("\nУкажите один или несколько адресов egress (IP:port) в порядке приоритета (через запятую или по одному).")
        upstreams: list[str] = []
        raw_list = ask("Основной (или список через запятую) адрес egress (IP:port)")
        for item in raw_list.split(","):
            upstreams.append(validate_endpoint(item))
        while ask_yes_no("Добавить резервный egress?", default=False):
            upstreams.append(ask_validated("Резервный адрес egress (IP:port)", validate_endpoint))
        strat_choice = ask("Стратегия выбора egress: 1) ordered (основной, затем резервные), 2) round-robin", "1").lower()
        strategy = "ordered" if strat_choice in ("1", "ordered") else "round-robin"
        config_data = {
            "role": "edge",
            "listen": "0.0.0.0:24443",
            "secret_file": "/var/lib/mtveil/proxy-secret",
            "replay_file": "/var/lib/mtveil/replay.bin",
            "sni": sni,
            "cover": cover,
            "egress_upstreams": upstreams,
            "egress_strategy": strategy,
            "egress_token_file": "/var/lib/mtveil/egress-token",
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
    env_text = f"MTVEIL_PROJECT={project}\nMTVEIL_IMAGE={args.image}\nMTVEIL_BIND={bind_ip}\nMTVEIL_PORT={pub_port}\n"
    cfg_text = json.dumps(config_data, indent=2) + "\n"

    cand_base = compose_cmd(deploy_dir, project, "compose.candidate.yaml", ".env.candidate")
    base = compose_cmd(deploy_dir, project)
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
            print("\nСборка Docker-образа mtveil...")
            run(cand_base + ["build"], capture=False)

        # Ensure secrets / tokens in the state volume without overwriting existing ones.
        if role in ("direct", "edge"):
            created = ensure_generated_secret(cand_base, "/var/lib/mtveil/proxy-secret")
            print("Клиентский секрет: сгенерирован в томе state." if created else "Клиентский секрет: сохранён существующий из тома state.")

        if role == "egress":
            if volume_file_exists(cand_base, "/var/lib/mtveil/egress-token"):
                print("Токен MTV2: сохранён существующий из тома state.")
            else:
                is_first = ask_yes_no("Это первый узел egress (сгенерировать новый токен MTV2)?", default=True)
                if is_first:
                    ensure_generated_secret(cand_base, "/var/lib/mtveil/egress-token")
                    print("Токен MTV2 сгенерирован и сохранён в томе state (0600).")
                    if ask_yes_no("Показать сгенерированный токен MTV2 для копирования на другие узлы?", default=False):
                        tok = read_volume_secret(cand_base, "/var/lib/mtveil/egress-token")
                        print(f"Токен MTV2: {tok}")
                else:
                    tok = ask_hidden_token("Введите токен MTV2 с основного egress")
                    write_volume_secret_stdin(cand_base, "/var/lib/mtveil/egress-token", tok)
                    print("Токен MTV2 импортирован в том state.")
        elif role == "edge":
            if volume_file_exists(cand_base, "/var/lib/mtveil/egress-token") and ask_yes_no(
                "Использовать существующий токен MTV2 из тома state?", default=True
            ):
                print("Токен MTV2: сохранён существующий из тома state.")
            else:
                tok = ask_hidden_token("Введите общий токен MTV2")
                write_volume_secret_stdin(cand_base, "/var/lib/mtveil/egress-token", tok)
                print("Токен MTV2 сохранён в томе state.")

        print("\nПроверка конфигурации через mtveil...")
        run(cand_base + ["run", "--rm", "--no-deps", "mtveil", "--config", "/etc/mtveil/config.json", "--check-config"], capture=False)

        if role in ("direct", "edge"):
            print(f"\nПроверка HTTPS-cover {cover} (SNI {sni}) изнутри контейнера...")
            cover_ok, cover_out = check_cover_from_container(cand_base, cover, sni)
            if cover_ok:
                print("Проверка HTTPS-cover: OK (DNS, TCP, TLS и имя в сертификате подтверждены).")
            else:
                print(f"Проверка HTTPS-cover НЕ ПРОШЛА:\n{cover_out}", file=sys.stderr)
                if not ask_yes_no("Проверка HTTPS-cover не прошла. Всё равно применить конфиг и запустить контейнер?", default=False):
                    print("Прервано до применения изменений. Текущая конфигурация не затронута.")
                    return 1

        if role == "edge":
            print("\nПроверка узлов egress из сетевого контекста edge (DC 2)...")
            check_proc = run(
                cand_base + ["run", "--rm", "--no-deps", "mtveil", "check-egress", "--config", "/etc/mtveil/config.json", "--dc", "2"],
                check=False,
            )
            print(check_proc.stdout)
            if check_proc.returncode != 0:
                print(check_proc.stderr.strip(), file=sys.stderr)
                if "tcp_connect_timeout" in check_proc.stdout and not args.network_host:
                    print(
                        "Подсказка: если egress доступен с хоста по mesh/VPN-туннелю (SharX/WireGuard), "
                        "но не отвечает из Docker bridge, перезапустите мастер с флагом --network-host.",
                        file=sys.stderr,
                    )
                if not ask_yes_no("Один или несколько egress не прошли проверку. Всё равно применить конфиг и запустить edge?", default=False):
                    print("Прервано до применения изменений. Текущая конфигурация не затронута.")
                    return 1

        # Back up existing deployment files before promoting validated candidate.
        had_backup = False
        for name in ("compose.yaml", ".env", "config.json"):
            live = deploy_dir / name
            if live.exists():
                live.replace(deploy_dir / f"{name}.bak")
                had_backup = True
        (deploy_dir / "compose.yaml").write_text(
            render_compose(
                repo_root,
                deploy_dir,
                role,
                "config.json",
                network_host=args.network_host,
                health_host=health_host,
                health_port=pub_port,
                include_build=include_build,
            ),
            encoding="utf-8",
        )
        os.replace(cand_env, deploy_dir / ".env")
        os.replace(cand_config, deploy_dir / "config.json")
        run(base + ["config", "--quiet"])
    finally:
        for p in (cand_compose, cand_env, cand_config):
            if p.exists():
                p.unlink()

    print("\nЗапуск сервиса mtveil...")
    up_succeeded = False
    try:
        while True:
            up_proc = run(base + ["up", "-d", "mtveil"], check=False)
            if up_proc.returncode == 0:
                up_succeeded = True
                break
            err_detail = (up_proc.stderr or up_proc.stdout or "").strip()
            print(f"Не удалось запустить контейнер на {bind_ip}:{pub_port}.\n{err_detail}", file=sys.stderr)
            try:
                retry = ask_yes_no("Указать другой порт и повторить запуск (настройки и секрет сохранятся)?", default=True)
            except EOFError:
                retry = False
            if not retry:
                return 1
            pub_port = ask_validated("Укажите другой TCP-порт", validate_port)
            pub_port = ensure_available_port(deploy_dir, project, bind_ip, pub_port, "Укажите другой TCP-порт")
            (deploy_dir / ".env").write_text(
                f"MTVEIL_PROJECT={project}\nMTVEIL_IMAGE={args.image}\nMTVEIL_BIND={bind_ip}\nMTVEIL_PORT={pub_port}\n",
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
            print("Предыдущая рабочая конфигурация восстановлена.", file=sys.stderr)
    wait_healthy(base)
    print("Статус контейнера: healthy (порт открыт; проверьте передачу данных в Telegram, отправив или загрузив фото).")

    if role in ("direct", "edge"):
        link = run(
            base
            + [
                "exec",
                "-T",
                "mtveil",
                "mtveil",
                "link",
                "--config",
                "/etc/mtveil/config.json",
                "--server",
                public_host,
                "--port",
                str(pub_port),
            ]
        ).stdout.strip()
        print(f"\nСсылка для Telegram:\n{link}\n")
    else:
        print(f"\nАдрес egress для ввода на узле edge:\n{bind_ip}:{pub_port}\n")

    try:
        rel_dir = os.path.relpath(deploy_dir, repo_root).replace("\\", "/")
    except ValueError:
        rel_dir = str(deploy_dir)
    compose_ref = f"--env-file {rel_dir}/.env -f {rel_dir}/compose.yaml"
    print("Полезные команды:")
    print(f"  docker compose {compose_ref} ps")
    print(f"  docker compose {compose_ref} logs --tail=100 mtveil")
    if role == "edge":
        print(f"  docker compose {compose_ref} exec mtveil mtveil check-egress --config /etc/mtveil/config.json --dc 2")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nОтменено пользователем.")
        raise SystemExit(130)
