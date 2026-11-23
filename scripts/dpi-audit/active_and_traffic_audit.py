#!/usr/bin/env python3
"""
Active probes (part 4), post-handshake traffic profile (part 5), and IP-SNI ASN check (part 6).
Runs against an isolated local mtevil test instance and compares with the real cover domain.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import statistics
import struct
import subprocess
import time
from typing import Any

from tls_audit import build_faketls_client_hello, recv_tls_records


def run_openssl_probe(host: str, port: int, sni: str, extra_args: list[str]) -> dict[str, Any]:
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", sni,
        *extra_args,
    ]
    t0 = time.monotonic()
    proc = subprocess.run(cmd, input=b"GET / HTTP/1.1\r\nHost: " + sni.encode() + b"\r\nConnection: close\r\n\r\n", capture_output=True, timeout=15)
    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    combined = out + "\n" + err
    proto = None
    cipher = None
    alpn = None
    subject = None
    issuer = None
    alert = None
    http_status = None
    for line in combined.splitlines():
        s = line.strip()
        if s.startswith("Protocol  :") or s.startswith("Protocol:"):
            proto = s.split(":", 1)[1].strip()
        elif s.startswith("Cipher    :") or s.startswith("Cipher:"):
            cipher = s.split(":", 1)[1].strip()
        elif "ALPN protocol:" in s:
            alpn = s.split(":", 1)[1].strip()
        elif s.startswith("subject="):
            subject = s
        elif s.startswith("issuer="):
            issuer = s
        elif "alert" in s.lower() and ("fatal" in s.lower() or "warning" in s.lower()):
            alert = s
        elif s.startswith("HTTP/"):
            http_status = s
    return {
        "rc": proc.returncode,
        "elapsed_ms": elapsed_ms,
        "protocol": proto,
        "cipher": cipher,
        "alpn": alpn,
        "subject": subject,
        "issuer": issuer,
        "alert": alert,
        "http_status": http_status,
        "verify_line": next((l.strip() for l in combined.splitlines() if "Verification:" in l or "Verify return code:" in l), None),
    }


def run_curl_probe(host: str, port: int, sni: str, is_local: bool) -> dict[str, Any]:
    cmd = ["curl", "-sS", "-i", "--http2", "--max-time", "12"]
    if is_local:
        cmd.extend(["--resolve", f"{sni}:{port}:{host}"])
        url = f"https://{sni}:{port}/"
    else:
        url = f"https://{sni}/"
    cmd.extend(["-w", "\n__TIMING__:%{http_version}|%{http_code}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{size_download}\n", url])
    proc = subprocess.run(cmd, capture_output=True, timeout=15)
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    timing_line = None
    for line in out.splitlines():
        if line.startswith("__TIMING__:"):
            timing_line = line.split(":", 1)[1]
    return {
        "rc": proc.returncode,
        "timing": timing_line,
        "stderr": err.strip()[:300],
    }


def raw_tcp_probe(host: str, port: int, payload: bytes, wait_s: float = 3.0) -> dict[str, Any]:
    t0 = time.monotonic()
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(wait_s)
    if payload:
        s.sendall(payload)
    first_ms = None
    chunks = []
    close_kind = "timeout"
    try:
        while True:
            d = s.recv(65536)
            if not d:
                close_kind = "fin"
                break
            if first_ms is None:
                first_ms = round((time.monotonic() - t0) * 1000.0, 2)
            chunks.append(d)
            if sum(len(x) for x in chunks) > 16384:
                break
    except socket.timeout:
        close_kind = "timeout"
    except ConnectionResetError:
        close_kind = "rst"
    finally:
        s.close()
    raw = b"".join(chunks)
    tls_types = []
    off = 0
    while off + 5 <= len(raw) and raw[off] in (0x14, 0x15, 0x16, 0x17):
        rlen = (raw[off + 3] << 8) | raw[off + 4]
        tls_types.append(f"0x{raw[off]:02x}({rlen})")
        off += 5 + rlen
    return {
        "first_byte_ms": first_ms,
        "rx_bytes": len(raw),
        "close_kind": close_kind,
        "tls_records": tls_types[:10],
        "head_ascii": raw[:120].decode("ascii", errors="replace") if not tls_types else None,
    }


def probe_post_handshake_idle(host: str, port: int, sni: str, secret: bytes) -> dict[str, Any]:
    """Connect via FakeTLS, send obfuscated2 init + req_pq_multi, read resPQ, then stay idle 12s."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    ch = build_faketls_client_hello(sni, secret=secret)
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(ch)
    recs, fb_ms, _ = recv_tls_records(s, timeout_s=1.5)
    assert len(recs) == 3

    while True:
        plain = bytearray(os.urandom(64))
        if plain[0] != 0xEF and plain[4:8] != b"\x00\x00\x00\x00" and bytes(plain[:4]) not in (b"HEAD", b"POST", b"GET ", b"PVrG", b"\xee"*4, b"\xdd"*4, b"\x16\x03\x01\x02"):
            break
    plain[56:60] = b"\xdd\xdd\xdd\xdd"
    plain[60:62] = struct.pack("<h", 2)
    enc_key = hashlib.sha256(bytes(plain[8:40]) + secret).digest()
    enc_iv = bytes(plain[40:56])
    rev = bytes(plain[8:56])[::-1]
    dec_key = hashlib.sha256(rev[:32] + secret).digest()
    dec_iv = rev[32:48]
    enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    dec = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()
    wire_init = bytes(plain[:56]) + enc.update(bytes(plain))[56:64]

    nonce = os.urandom(16)
    msg_id = (int(time.time()) << 32) & ~3
    req_body = struct.pack("<I", 0xBE7E8EF1) + nonce
    req = struct.pack("<qqI", 0, msg_id, len(req_body)) + req_body
    framed = struct.pack("<I", len(req)) + req

    def tls_app(d: bytes) -> bytes:
        return b"\x17\x03\x03" + struct.pack(">H", len(d)) + d

    s.sendall(tls_app(wire_init) + tls_app(enc.update(framed)))
    resp_recs, resp_ms, _ = recv_tls_records(s, timeout_s=2.0)

    # Stay completely idle for 12s to check if mtevil or DC emits periodic keepalives/pings
    s.settimeout(12.0)
    idle_events = []
    t_idle = time.monotonic()
    try:
        while time.monotonic() - t_idle < 12.0:
            d = s.recv(4096)
            if not d:
                idle_events.append(("eof", round(time.monotonic() - t_idle, 2)))
                break
            idle_events.append(("data", len(d), round(time.monotonic() - t_idle, 2)))
    except socket.timeout:
        idle_events.append(("quiet_12s", 12.0))
    s.close()
    return {
        "req_pq_records": [{"payload_len": r["payload_len"], "arrived_ms": r["arrived_ms"]} for r in resp_recs],
        "idle_12s_events": idle_events,
    }


def lookup_asn(ip: str) -> dict[str, Any]:
    try:
        import urllib.request
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=6) as resp:
            d = json.loads(resp.read().decode("utf-8"))
            return {"org": d.get("org"), "country": d.get("country"), "city": d.get("city")}
    except Exception as exc:
        return {"error": str(exc)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=24470)
    ap.add_argument("--sni", default="example.com")
    ap.add_argument("--secret-hex", required=True)
    ap.add_argument("--vps-public-ip", default="")
    ap.add_argument("--domains", nargs="*", default=["example.com", "ya.ru", "vk.com", "ozon.ru", "habr.com", "github.com", "google.com"])
    args = ap.parse_args()

    secret = bytes.fromhex(args.secret_hex)
    out: dict[str, Any] = {"active_probes": {}, "post_handshake": {}, "asn_check": {}}

    # Active probes: ours vs real domain
    for label, host, port, is_local in [
        ("mtevil_cover", args.target_host, args.target_port, True),
        ("real_origin", args.sni, 443, False),
    ]:
        p: dict[str, Any] = {}
        p["no_secret_openssl_tls13"] = run_openssl_probe(host, port, args.sni, ["-tls1_3", "-alpn", "h2,http/1.1"])
        p["tls12_only"] = run_openssl_probe(host, port, args.sni, ["-tls1_2", "-alpn", "http/1.1"])
        p["bad_ciphers_legacy"] = run_openssl_probe(host, port, args.sni, ["-tls1_2", "-cipher", "AES128-SHA256"])
        p["curl_http2"] = run_curl_probe(host, port, args.sni, is_local)
        p["plain_http_on_443"] = raw_tcp_probe(host, port, f"GET / HTTP/1.1\r\nHost: {args.sni}\r\nConnection: close\r\n\r\n".encode(), wait_s=3.0)
        p["garbage_10b"] = raw_tcp_probe(host, port, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", wait_s=3.0)
        p["truncated_ch_header"] = raw_tcp_probe(host, port, b"\x16\x03\x01\x01\x00\x01\x00\x00\xfc", wait_s=12.0)
        out["active_probes"][label] = p

    # Wrong secret & replay probes on mtevil
    wrong_ch = build_faketls_client_hello(args.sni, secret=b"\xff" * 16)
    out["active_probes"]["mtevil_wrong_secret"] = raw_tcp_probe(args.target_host, args.target_port, wrong_ch, wait_s=3.0)

    valid_ch = build_faketls_client_hello(args.sni, secret=secret)
    out["active_probes"]["mtevil_replay_1st"] = raw_tcp_probe(args.target_host, args.target_port, valid_ch, wait_s=1.5)
    out["active_probes"]["mtevil_replay_2nd"] = raw_tcp_probe(args.target_host, args.target_port, valid_ch, wait_s=3.0)

    # Post-handshake idle test
    out["post_handshake"]["idle_test"] = probe_post_handshake_idle(args.target_host, args.target_port, args.sni, secret)

    # ASN comparison (VPS vs domains; do not print VPS IP)
    if args.vps_public_ip:
        out["asn_check"]["vps_host"] = lookup_asn(args.vps_public_ip)
    for dom in args.domains:
        try:
            ip = socket.gethostbyname(dom)
            info = lookup_asn(ip)
            info["resolved_prefix_24"] = ".".join(ip.split(".")[:3]) + ".0/24"
            out["asn_check"][dom] = info
        except Exception as exc:
            out["asn_check"][dom] = {"error": str(exc)}

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
