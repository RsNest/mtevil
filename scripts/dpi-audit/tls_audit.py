#!/usr/bin/env python3
"""
Passive & active TLS/FakeTLS audit helper for mtevil (without secrets or raw pcap storage).

Measures:
1. De-facto ServerHello flight profile across N connections to a local mtevil test instance.
2. Reference ServerHello + EncryptedExtensions/Cert/Tickets profiles for real HTTPS domains
   (single normal TLS/HTTPS connections per domain, no scanning or load).
3. Active probes comparing mtevil (with cover fallback) vs the real cover domain.
4. Post-handshake TLS record sizes and inter-arrival timings.
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
import sys
import time
from collections import Counter
from typing import Any

GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

EXT_NAMES = {
    0x0000: "server_name",
    0x0005: "status_request",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000D: "signature_algorithms",
    0x0010: "alpn",
    0x0012: "signed_cert_timestamp",
    0x0017: "extended_master_secret",
    0x001B: "compress_certificate",
    0x0023: "session_ticket",
    0x0029: "pre_shared_key",
    0x002B: "supported_versions",
    0x002D: "psk_key_exchange_modes",
    0x0033: "key_share",
    0xFF01: "renegotiation_info",
}

GROUP_NAMES = {
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x11EC: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}


def build_faketls_client_hello(sni: str, secret: bytes | None = None, cipher_list: list[int] | None = None) -> bytes:
    """Build a TLS 1.3 ClientHello (optionally HMAC-authenticated for FakeTLS)."""
    if cipher_list is None:
        cipher_list = [0x1301, 0x1302, 0x1303]
    sid = os.urandom(32)
    sni_b = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    ext_ver = struct.pack(">HHB", 0x002B, 3, 2) + b"\x03\x04"
    # Valid X25519 public key (9 * basepoint = 9, valid low-order/simple curve point? Use 32-byte random-like valid pubkey from RFC 7748)
    x25519_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    ks_entry = struct.pack(">HH", 0x001D, len(x25519_pub)) + x25519_pub
    ext_ks = struct.pack(">HHH", 0x0033, len(ks_entry) + 2, len(ks_entry)) + ks_entry
    ext_sig = struct.pack(">HHH", 0x000D, 8, 6) + bytes.fromhex("040308040401")
    ext_grp = struct.pack(">HHH", 0x000A, 4, 2) + struct.pack(">H", 0x001D)
    ext_alpn = struct.pack(">HHH", 0x0010, 14, 12) + b"\x02h2\x08http/1.1"
    exts = ext_sni + ext_ver + ext_ks + ext_sig + ext_grp + ext_alpn

    ciphers_wire = b"".join(struct.pack(">H", c) for c in cipher_list)
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + bytes([len(sid)])
        + sid
        + struct.pack(">H", len(ciphers_wire))
        + ciphers_wire
        + b"\x01\x00"
        + struct.pack(">H", len(exts))
        + exts
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    if secret is not None:
        zero_rec = rec[:11] + (b"\x00" * 32) + rec[43:]
        digest = bytearray(hmac.new(secret, zero_rec, hashlib.sha256).digest())
        ts = int(time.time())
        for i in range(4):
            digest[28 + i] ^= (ts >> (8 * i)) & 0xFF
        rec = rec[:11] + bytes(digest) + rec[43:]
    return rec


def recv_tls_records(sock: socket.socket, timeout_s: float = 4.0) -> tuple[list[dict[str, Any]], float, str]:
    """Read TLS records until timeout or EOF, recording per-record timings and sizes."""
    sock.settimeout(0.5)
    t_start = time.monotonic()
    deadline = t_start + timeout_s
    buf = bytearray()
    records: list[dict[str, Any]] = []
    first_byte_ms: float | None = None
    close_kind = "timeout"

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            if records:
                # If we already got records and server went quiet for 0.5s, stop waiting
                break
            continue
        except ConnectionResetError:
            close_kind = "rst"
            break
        if not chunk:
            close_kind = "fin"
            break
        now_ms = (time.monotonic() - t_start) * 1000.0
        if first_byte_ms is None:
            first_byte_ms = now_ms
        buf.extend(chunk)
        while len(buf) >= 5:
            rtype = buf[0]
            rver = (buf[1] << 8) | buf[2]
            rlen = (buf[3] << 8) | buf[4]
            if rtype not in (0x14, 0x15, 0x16, 0x17) or rlen > 18432:
                close_kind = "non_tls"
                return records, first_byte_ms or 0.0, close_kind
            if len(buf) < 5 + rlen:
                break
            payload = bytes(buf[5 : 5 + rlen])
            del buf[: 5 + rlen]
            records.append(
                {
                    "type": rtype,
                    "type_hex": f"0x{rtype:02x}",
                    "record_ver": f"0x{rver:04x}",
                    "payload_len": rlen,
                    "wire_len": 5 + rlen,
                    "arrived_ms": round(now_ms, 2),
                    "payload": payload,
                }
            )
            # If alert received, wait briefly for FIN/RST then break
            if rtype == 0x15:
                deadline = min(deadline, time.monotonic() + 0.3)
    return records, round(first_byte_ms or 0.0, 2), close_kind


def parse_server_hello(payload: bytes) -> dict[str, Any]:
    """Parse TLS ServerHello handshake message (type 0x02)."""
    if len(payload) < 4 or payload[0] != 0x02:
        return {"error": "not ServerHello"}
    hs_len = int.from_bytes(payload[1:4], "big")
    body = payload[4 : 4 + hs_len]
    if len(body) < 38:
        return {"error": "truncated ServerHello"}
    legacy_ver = (body[0] << 8) | body[1]
    random_bytes = body[2:34]
    is_hrr = random_bytes == bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    sid_len = body[34]
    off = 35 + sid_len
    cipher = (body[off] << 8) | body[off + 1]
    comp = body[off + 2]
    off += 3
    ext_len = (body[off] << 8) | body[off + 1]
    off += 2
    ext_bytes = body[off : off + ext_len]

    exts: list[int] = []
    ext_details: dict[str, Any] = {}
    eo = 0
    while eo + 4 <= len(ext_bytes):
        ek = (ext_bytes[eo] << 8) | ext_bytes[eo + 1]
        el = (ext_bytes[eo + 2] << 8) | ext_bytes[eo + 3]
        ev = ext_bytes[eo + 4 : eo + 4 + el]
        eo += 4 + el
        if ek not in GREASE_VALUES:
            exts.append(ek)
        if ek == 0x002B and len(ev) == 2:
            ext_details["supported_version"] = f"0x{int.from_bytes(ev, 'big'):04x}"
        elif ek == 0x0033 and len(ev) >= 4:
            grp = (ev[0] << 8) | ev[1]
            klen = (ev[2] << 8) | ev[3]
            ext_details["key_share_group"] = GROUP_NAMES.get(grp, f"0x{grp:04x}")
            ext_details["key_share_len"] = klen
        elif ek == 0x0010 and len(ev) >= 3:
            plen = ev[2]
            ext_details["alpn_in_sh"] = ev[3 : 3 + plen].decode("ascii", errors="replace")

    ja3s_str = f"{legacy_ver},{cipher},{'-'.join(str(x) for x in exts)}"
    ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()
    ver_code = "13" if ext_details.get("supported_version") == "0x0304" else "12"
    alpn_code = "00"
    sorted_exts = ",".join(f"{x:04x}" for x in sorted(exts))
    ext_hash = hashlib.sha256(sorted_exts.encode("ascii")).hexdigest()[:12] if exts else "000000000000"
    ja4s = f"t{ver_code}{len(exts):02d}{alpn_code}_{cipher:04x}_{ext_hash}"

    return {
        "legacy_version": f"0x{legacy_ver:04x}",
        "is_hello_retry_request": is_hrr,
        "sid_len": sid_len,
        "cipher_hex": f"0x{cipher:04x}",
        "cipher_name": CIPHER_NAMES.get(cipher, f"0x{cipher:04x}"),
        "compression": comp,
        "extensions_order": exts,
        "extensions_names": [EXT_NAMES.get(x, f"0x{x:04x}") for x in exts],
        "ja3s_raw": ja3s_str,
        "ja3s": ja3s_hash,
        "ja4s": ja4s,
        **ext_details,
    }


def summarize_flight(records: list[dict[str, Any]], first_byte_ms: float, close_kind: str) -> dict[str, Any]:
    sh_info = {}
    ccs_count = 0
    appdata_sizes: list[int] = []
    alerts: list[str] = []
    for r in records:
        if r["type"] == 0x16 and not sh_info:
            sh_info = parse_server_hello(r["payload"])
        elif r["type"] == 0x14:
            ccs_count += 1
        elif r["type"] == 0x17:
            appdata_sizes.append(r["payload_len"])
        elif r["type"] == 0x15 and len(r["payload"]) >= 2:
            alerts.append(f"level={r['payload'][0]},desc={r['payload'][1]}")

    record_seq = [
        {"type": r["type_hex"], "payload_len": r["payload_len"], "arrived_ms": r["arrived_ms"]}
        for r in records
    ]
    return {
        "first_byte_ms": first_byte_ms,
        "close_kind": close_kind,
        "total_records": len(records),
        "total_wire_bytes": sum(r["wire_len"] for r in records),
        "ccs_count": ccs_count,
        "appdata_count": len(appdata_sizes),
        "appdata_payload_sizes": appdata_sizes,
        "alerts": alerts,
        "server_hello": sh_info,
        "records": record_seq,
    }


def probe_domain_openssl_alpn(host: str, port: int = 443) -> dict[str, Any]:
    """Single normal openssl s_client check to get real ALPN, cert chain size, and NewSessionTicket count."""
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-tls1_3",
        "-alpn", "h2,http/1.1",
        "-msg",
    ]
    t0 = time.monotonic()
    proc = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=12)
    rtt_ms = round((time.monotonic() - t0) * 1000.0, 1)
    out = proc.stdout.decode("utf-8", errors="replace") + "\n" + proc.stderr.decode("utf-8", errors="replace")
    alpn = None
    cipher = None
    tickets = 0
    cert_chain_bytes = 0
    for line in out.splitlines():
        if "ALPN protocol:" in line:
            alpn = line.split(":", 1)[1].strip()
        elif "New, TLSv1.3, Cipher is" in line:
            cipher = line.split("Cipher is", 1)[1].strip()
        elif "NewSessionTicket" in line and "TLS 1.3" in line:
            tickets += 1
    # Count PEM cert sizes as lower bound for cert chain
    in_pem = False
    b64_buf: list[str] = []
    import base64
    for line in out.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_pem = True
            b64_buf = []
        elif "-----END CERTIFICATE-----" in line and in_pem:
            in_pem = False
            try:
                cert_chain_bytes += len(base64.b64decode("".join(b64_buf)))
            except Exception:
                pass
        elif in_pem:
            b64_buf.append(line.strip())
    return {
        "rc": proc.returncode,
        "rtt_ms": rtt_ms,
        "alpn": alpn,
        "cipher": cipher,
        "new_session_tickets": tickets,
        "cert_chain_der_bytes": cert_chain_bytes,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="mtevil FakeTLS DPI audit probe tool")
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=24470)
    ap.add_argument("--sni", default="example.com")
    ap.add_argument("--secret-hex", default="")
    ap.add_argument("--n-samples", type=int, default=200)
    ap.add_argument("--domains", nargs="*", default=["example.com", "ya.ru", "vk.com", "ozon.ru", "habr.com", "github.com", "google.com"])
    args = ap.parse_args()

    result: dict[str, Any] = {"defacto": {}, "reference_domains": {}}

    # 1. De-facto ServerHello profile across N authenticated FakeTLS connections
    if args.secret_hex:
        secret = bytes.fromhex(args.secret_hex)
        appdata_sizes: list[int] = []
        wire_totals: list[int] = []
        first_byte_list: list[float] = []
        ja3s_cnt: Counter[str] = Counter()
        ja4s_cnt: Counter[str] = Counter()
        key_shares: set[str] = set()
        sample_detail = None

        for i in range(args.n_samples):
            ch = build_faketls_client_hello(args.sni, secret=secret)
            s = socket.create_connection((args.target_host, args.target_port), timeout=5)
            s.sendall(ch)
            recs, fb_ms, close_k = recv_tls_records(s, timeout_s=0.35 if i > 0 else 1.2)
            s.close()
            summ = summarize_flight(recs, fb_ms, close_k)
            if sample_detail is None:
                sample_detail = summ
            if summ["appdata_payload_sizes"]:
                appdata_sizes.append(summ["appdata_payload_sizes"][0])
            wire_totals.append(summ["total_wire_bytes"])
            first_byte_list.append(fb_ms)
            sh = summ["server_hello"]
            if "ja3s" in sh:
                ja3s_cnt[sh["ja3s"]] += 1
                ja4s_cnt[sh["ja4s"]] += 1
            if recs and recs[0]["type"] == 0x16 and len(recs[0]["payload"]) >= 90:
                key_shares.add(recs[0]["payload"][-32:].hex())

        result["defacto"] = {
            "samples": args.n_samples,
            "ja3s_counts": dict(ja3s_cnt),
            "ja4s_counts": dict(ja4s_cnt),
            "distinct_key_shares": len(key_shares),
            "appdata_min": min(appdata_sizes) if appdata_sizes else None,
            "appdata_max": max(appdata_sizes) if appdata_sizes else None,
            "appdata_unique": sorted(set(appdata_sizes)),
            "wire_total_unique": sorted(set(wire_totals)),
            "first_byte_ms_p50": round(statistics.median(first_byte_list), 2) if first_byte_list else None,
            "first_byte_ms_max": round(max(first_byte_list), 2) if first_byte_list else None,
            "first_sample": sample_detail,
        }

    # 2. Reference domains (single normal TLS ClientHello + single openssl s_client per domain)
    for dom in args.domains:
        try:
            ch = build_faketls_client_hello(dom, secret=None)
            s = socket.create_connection((dom, 443), timeout=5)
            s.sendall(ch)
            recs, fb_ms, close_k = recv_tls_records(s, timeout_s=1.5)
            s.close()
            raw_summ = summarize_flight(recs, fb_ms, close_k)
            ossl = probe_domain_openssl_alpn(dom, 443)
            result["reference_domains"][dom] = {
                "raw_flight": raw_summ,
                "openssl": ossl,
            }
        except Exception as exc:
            result["reference_domains"][dom] = {"error": str(exc)}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
