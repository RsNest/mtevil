#!/usr/bin/env python3
"""FakeTLS MTProto-proxy client for connectivity/protocol smoke tests.

Protocol reference (wire-exact): mtg v2 (github.com/9seconds/mtg, MIT license,
verified 2026-11-17) — mtglib/internal/tls/fake/{client_side,server_side,utils}.go,
mtglib/obfuscation/{obfuscator,handshake_frame}.go, mtglib/internal/tls/{conn,utils}.go.
Uses only stdlib + `cryptography` (AES-CTR). Phase 0 client test tooling;
this is not the mtveil data plane or a stock Telegram client.

Flow (ee-secret FakeTLS):
  1. ClientHello: random(32) hidden as HMAC certificate, session_id(32) carries
     the obfuscation frame tail (iv/tag/dc); canonical single-record form.
  2. ServerHello: verify HMAC-SHA256(secret, client_random || packet-with-zeros)
     in packet[11:43], verify session_id echo.
  3. TLS record layer (0x17/03 03) carries the obfuscated MTProto stream:
     first 64 bytes = obfuscation frame (tag dddddddd, dc), then padded
     intermediate MTProto packets. Inner MTProto: plaintext req_pq_multi ->
     resPQ from a Telegram DC (real handshake with the DC through the proxy).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TLS_03_01 = b"\x16\x03\x01"
TLS_03_03 = b"\x16\x03\x03"


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _ctr(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack(">H", etype) + _u16(len(body)) + body


def build_client_hello(secret: bytes, sni: str, now: int):
    """Returns (record, frame64, ks_send, ks_recv, session32)."""
    iv = os.urandom(16)
    # session_id = frame[32:64]: key tail (8) + iv (16) + tag dddddddd (4) + dc LE (2) + zeros (2)
    session32 = os.urandom(8) + iv + b"\xdd\xdd\xdd\xdd" + struct.pack("<H", 2) + b"\x00\x00"
    # Chrome-like cipher suite list (non-GREASE)
    ciphers = bytes.fromhex(
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a"
    )
    sni_entry = b"\x00" + _u16(len(sni)) + sni.encode()
    sni_ext = _ext(0x0000, _u16(len(sni_entry)) + sni_entry)
    key_share = _ext(0x0033, _u16(36) + _u16(0x001D) + _u16(32) + os.urandom(32))
    exts = b"".join([
        sni_ext,
        _ext(0x0017, b""),                                                    # extended_master_secret
        _ext(0xFF01, b"\x00"),                                                # renegotiation_info
        _ext(0x000A, _u16(8) + bytes.fromhex("001d001700180019")),            # supported_groups
        _ext(0x000B, b"\x01\x00"),                                            # ec_point_formats
        _ext(0x0023, b""),                                                    # session_ticket
        _ext(0x0010, _u16(12) + b"\x02h2\x08http/1.1"),                       # ALPN
        _ext(0x0005, b"\x01\x00\x00\x00\x00"),                                # status_request
        key_share,                                                            # key_share (x25519)
        _ext(0x000D, _u16(14) + bytes.fromhex("0804080508060401050106010201")),  # sig_algs
        _ext(0x002B, b"\x04\x03\x04\x03\x03"),                                # supported_versions
        _ext(0x002D, b"\x01\x01"),                                            # psk_key_exchange_modes
        _ext(0x001B, b"\x02\x01\x02"),                                        # compress_certificate
    ])
    ext_block = _u16(len(exts)) + exts
    body = (
        b"\x03\x03"                      # client version TLS1.2
        + b"\x00" * 32                   # random slot (certificate placeholder)
        + b"\x20" + session32            # session_id = frame tail
        + _u16(len(ciphers)) + ciphers
        + b"\x01\x00"                    # compression: len 1, null
        + ext_block
    )
    hs = b"\x01" + _u24(len(body)) + body
    record = bytearray(TLS_03_01 + _u16(len(hs)) + hs)
    # canonical copy: zeros in random slot [11:43]
    zeroed = bytes(record[0:11]) + b"\x00" * 32 + bytes(record[43:])
    digest = hmac.new(secret, zeroed, hashlib.sha256).digest()
    ts = struct.pack("<I", now & 0xFFFFFFFF)
    random32 = bytearray(digest[0:28] + bytes(a ^ b for a, b in zip(digest[28:32], ts)))
    record[11:43] = random32
    record = bytes(record)

    frame = bytes(random32) + session32
    key32, ivf = frame[8:40], frame[40:56]
    ks_send = _ctr(hashlib.sha256(key32 + secret).digest(), ivf)
    rev48 = frame[8:56][::-1]
    ks_recv = _ctr(hashlib.sha256(rev48[0:32] + secret).digest(), rev48[32:48])
    return record, frame, ks_send, ks_recv, session32


class RecordReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_record(self):
        hdr = self._read_exact(5)
        rtype, ver = hdr[0], hdr[1:3]
        length = int.from_bytes(hdr[3:5], "big")
        if ver != b"\x03\x03":
            raise ValueError(f"bad record version {ver.hex()}")
        payload = self._read_exact(length)
        return rtype, payload


def read_server_flight(rr: RecordReader):
    """Reads SH record + ChangeCipherSpec + first application-data (noise) record.
    The FakeTLS certificate HMAC covers the ENTIRE packet (mtg SendServerHello
    hashes client_random || whole_packet). Returns (packet, session_echo)."""
    packet = b""
    seen = {"sh": False, "ccs": False, "noise": False}
    session_echo = None
    while not (seen["sh"] and seen["ccs"] and seen["noise"]):
        rtype, payload = rr.read_record()
        packet += bytes([rtype, 0x03, 0x03]) + _u16(len(payload)) + payload
        if rtype == 0x16 and not seen["sh"]:
            seen["sh"] = True
            if payload[0] != 0x02:
                raise ValueError(f"expected handshake 0x02, got {payload[0]:#x}")
            session_echo = payload[39:71]
        elif rtype == 0x14 and not seen["ccs"]:
            seen["ccs"] = True
        elif rtype == 0x17 and not seen["noise"]:
            seen["noise"] = True
        else:
            raise ValueError(f"unexpected record {rtype:#x} in server flight")
    return packet, session_echo


def verify_server_hello(packet: bytes, secret: bytes, my_random: bytes, my_session: bytes):
    if packet[11:43] == b"\x00" * 32:
        raise ValueError("ServerHello without certificate")
    zeroed = packet[0:11] + b"\x00" * 32 + packet[43:]
    expected = hmac.new(secret, my_random + zeroed, hashlib.sha256).digest()
    got = packet[11:43]
    if not hmac.compare_digest(expected, got):
        raise ValueError("ServerHello HMAC mismatch")
    # session echo: SH payload random at packet[11:43], sess_len at [43], session at [44:76]
    if packet[43] != 0x20 or packet[44:76] != my_session:
        raise ValueError("ServerHello session_id echo mismatch")
    return True


def padded_packet(payload: bytes) -> bytes:
    pad = os.urandom(int.from_bytes(os.urandom(1), "big") % 16)
    return struct.pack("<I", len(payload) + len(pad)) + payload + pad


def mtproto_plain_message(body: bytes, msg_counter: list) -> bytes:
    # MTProto client ids are increasing, time-based and divisible by four.
    msg_id = max((time.time_ns() * (1 << 32) // 1_000_000_000) & ~3,
                 msg_counter[0] + 4)
    msg_counter[0] = msg_id
    return b"\x00" * 8 + struct.pack("<Q", msg_id) + struct.pack("<I", len(body)) + body


def run(host: str, port: int, ee_secret_hex: str, timeout: float = 25.0):
    if not ee_secret_hex.startswith("ee"):
        raise ValueError("secret must be ee-prefixed hex")
    sni_hex = ee_secret_hex[2 + 32:]
    secret = bytes.fromhex(ee_secret_hex[2:2 + 32])
    sni = bytes.fromhex(sni_hex).decode()
    events = []

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    rr = RecordReader(sock)
    now = int(time.time())
    record, frame, ks_send, ks_recv, session32 = build_client_hello(secret, sni, now)
    sock.sendall(record)
    events.append({"kind": "ch_sent", "bytes": len(record), "sni": sni})

    packet, session_echo = read_server_flight(rr)
    verify_server_hello(packet, secret, frame[0:32], session32)
    events.append({
        "kind": "sh_hmac_verified",
        "packet_bytes": len(packet),
        "session_echo_ok": session_echo == session32,
    })

    # obfuscation frame: encrypt with send cipher, then restore plaintext
    # key+iv into positions [8:56] (mtg SendHandshake semantics: the server
    # derives the decryptor from the WIRE bytes at [8:56]).
    frame_ct = bytearray(ks_send.update(frame))
    frame_ct[8:56] = frame[8:56]
    sock.sendall(b"\x17\x03\x03" + _u16(len(frame_ct)) + bytes(frame_ct))
    events.append({"kind": "obf_frame_sent"})

    # req_pq_multi -> DC through the proxy
    nonce = os.urandom(16)
    req = b"\xf1\x8e\x7e\xbe" + nonce  # req_pq_multi#be7e8ef1
    pkt = padded_packet(mtproto_plain_message(req, [0]))
    pkt_ct = ks_send.update(pkt)
    sock.sendall(b"\x17\x03\x03" + _u16(len(pkt_ct)) + pkt_ct)
    events.append({"kind": "req_pq_multi_sent", "nonce": nonce.hex()})

    # read resPQ
    stream = b""
    deadline = time.monotonic() + timeout
    res = None
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        rtype, payload = rr.read_record()
        if rtype != 0x17:
            raise ValueError(f"unexpected transport record {rtype:#x}")
        stream += ks_recv.update(payload)
        while True:
            if len(stream) < 4:
                break
            plen = struct.unpack("<I", stream[:4])[0]
            if plen == 0 or plen > 4096:
                raise ValueError(f"invalid transport frame length {plen}")
            if len(stream) < 4 + plen:
                break
            data, stream = stream[4:4 + plen], stream[4 + plen:]
            if len(data) < 20:
                raise ValueError("truncated MTProto message")
            auth_key_id, msg_id, mlen = struct.unpack("<QQI", data[0:20])
            if mlen < 4 or mlen > len(data) - 20:
                raise ValueError("invalid MTProto body length")
            body = data[20:20 + mlen]
            if body[0:4] == b"\x63\x24\x16\x05":  # resPQ#0x05162463
                if len(body) < 37 or body[4:20] != nonce or auth_key_id != 0:
                    raise ValueError("resPQ nonce/auth_key_id/length mismatch")
                res = {
                    "kind": "resPQ_received",
                    "nonce_ok": body[4:20] == nonce,
                    "server_nonce": body[20:36].hex(),
                    "pq_len": body[36],
                    "pq_hex": body[37:37 + body[36]].hex(),
                    "auth_key_id_zero": auth_key_id == 0,
                }
                events.append(res)
                sock.close()
                return events, res
            events.append({"kind": "unknown_body", "ctor": body[0:4].hex(), "len": mlen})
    raise TimeoutError("no resPQ within timeout")


if __name__ == "__main__":
    host, port, secret = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ev, res = run(host, port, secret)
    for e in ev:
        print(e, flush=True)
