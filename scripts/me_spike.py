#!/usr/bin/env python3
"""Phase 0.3 standalone spike for Telegram Middle-End (ME) protocol.

NOT part of the production data-plane. Implemented cleanly from the public
ME wire specification (without copying GPL code).

Steps performed when run:
  1. Fetches `proxy-secret` and `proxy-multi.conf` from core.telegram.org.
  2. Connects to one DC-2 middle-end server from `proxy-multi.conf`.
  3. Performs `RPC_NONCE` + AES-256-CBC key derivation + `RPC_HANDSHAKE`.
  4. Sends `RPC_PROXY_REQ` carrying an unencrypted MTProto `req_pq_multi`
     (optionally with `--ad-tag <32-hex>` if supplied) and validates `RPC_PROXY_ANS` (`resPQ`).
"""
import argparse
import hashlib
import ipaddress
import os
import re
import socket
import struct
import sys
import time
import urllib.request
import zlib

# Wire opcodes (little-endian uint32 on the wire)
RPC_NONCE = 0x7ACB87AA
RPC_HANDSHAKE = 0x7682EEF5
RPC_PROXY_REQ = 0x36CEF1EE
RPC_PROXY_ANS = 0x4403DA0D
RPC_SIMPLE_ACK = 0x3BAC409B
RPC_CLOSE_EXT = 0x5EB634A2
CRYPTO_AES = 1

# RPC_PROXY_REQ flags
FLAG_ENCRYPTED = 0x01
FLAG_MAGIC = 0x1000
FLAG_EXTMODE2 = 0x20000
FLAG_PAD = 0x8000000
FLAG_HAS_AD_TAG = 0x08

PROXY_CONF_LINE_RE = re.compile(r"^proxy_for\s+(-?\d+)\s+([0-9.]+):(\d+)\s*;")


class _Aes256Block:
    """Minimal pure-Python AES-256 block cipher (encrypt + decrypt) for spike use."""

    _SBOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
    _INV_SBOX = tuple(
        idx for _, idx in sorted((val, i) for i, val in enumerate(_SBOX))
    )
    _RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

    def __init__(self, key: bytes) -> None:
        assert len(key) == 32
        w = [list(key[i : i + 4]) for i in range(0, 32, 4)]
        for i in range(8, 60):
            t = list(w[i - 1])
            if i % 8 == 0:
                t = [self._SBOX[b] for b in t[1:] + t[:1]]
                t[0] ^= self._RCON[i // 8 - 1]
            elif i % 8 == 4:
                t = [self._SBOX[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - 8], t)])
        self._rkeys = [bytes(sum(w[r * 4 : (r + 1) * 4], [])) for r in range(15)]

    @staticmethod
    def _xtime(a: int) -> int:
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

    @classmethod
    def _mul(cls, a: int, b: int) -> int:
        res = 0
        for _ in range(8):
            if b & 1:
                res ^= a
            a = cls._xtime(a)
            b >>= 1
        return res

    def encrypt_block(self, block: bytes) -> bytes:
        s = [a ^ b for a, b in zip(block, self._rkeys[0])]
        sb = self._SBOX
        xt = self._xtime
        for r in range(1, 15):
            s = [sb[b] for b in s]
            s = [
                s[0], s[5], s[10], s[15],
                s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7],
                s[12], s[1], s[6], s[11],
            ]
            if r < 14:
                for c in range(0, 16, 4):
                    a0, a1, a2, a3 = s[c : c + 4]
                    t = a0 ^ a1 ^ a2 ^ a3
                    s[c] ^= t ^ xt(a0 ^ a1)
                    s[c + 1] ^= t ^ xt(a1 ^ a2)
                    s[c + 2] ^= t ^ xt(a2 ^ a3)
                    s[c + 3] ^= t ^ xt(a3 ^ a0)
            rk = self._rkeys[r]
            s = [a ^ b for a, b in zip(s, rk)]
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = [a ^ b for a, b in zip(block, self._rkeys[14])]
        isb = self._INV_SBOX
        mul = self._mul
        for r in range(13, -1, -1):
            s = [
                s[0], s[13], s[10], s[7],
                s[4], s[1], s[14], s[11],
                s[8], s[5], s[2], s[15],
                s[12], s[9], s[6], s[3],
            ]
            s = [isb[b] for b in s]
            rk = self._rkeys[r]
            s = [a ^ b for a, b in zip(s, rk)]
            if r > 0:
                for c in range(0, 16, 4):
                    a0, a1, a2, a3 = s[c : c + 4]
                    s[c] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9)
                    s[c + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13)
                    s[c + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11)
                    s[c + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14)
        return bytes(s)


class _Aes256Cbc:
    def __init__(self, key: bytes, iv: bytes) -> None:
        self._blk = _Aes256Block(key)
        self._iv = bytearray(iv)

    def encrypt(self, data: bytes) -> bytes:
        assert len(data) % 16 == 0
        out = bytearray(len(data))
        for off in range(0, len(data), 16):
            xored = bytes(a ^ b for a, b in zip(data[off : off + 16], self._iv))
            enc = self._blk.encrypt_block(xored)
            out[off : off + 16] = enc
            self._iv[:] = enc
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        assert len(data) % 16 == 0
        out = bytearray(len(data))
        for off in range(0, len(data), 16):
            ct = data[off : off + 16]
            pt = self._blk.decrypt_block(ct)
            out[off : off + 16] = bytes(a ^ b for a, b in zip(pt, self._iv))
            self._iv[:] = ct
        return bytes(out)


def derive_me_aes_key_iv(
    srv_nonce: bytes,
    clt_nonce: bytes,
    clt_ts: int,
    srv_ip: str,
    clt_port: int,
    purpose: bytes,
    clt_ip: str,
    srv_port: int,
    proxy_secret: bytes,
) -> tuple[bytes, bytes]:
    srv_ip_le = struct.pack("<I", int(ipaddress.IPv4Address(srv_ip)))
    clt_ip_le = struct.pack("<I", int(ipaddress.IPv4Address(clt_ip)))
    s = (
        srv_nonce
        + clt_nonce
        + struct.pack("<I", clt_ts)
        + srv_ip_le
        + struct.pack("<H", clt_port)
        + purpose
        + clt_ip_le
        + struct.pack("<H", srv_port)
        + proxy_secret
        + srv_nonce
        + clt_nonce
    )
    key = hashlib.md5(s[1:]).digest()[:12] + hashlib.sha1(s).digest()
    iv = hashlib.md5(s[2:]).digest()
    return key, iv


def pack_rpc_frame(seq_no: int, payload: bytes, *, pad_to_16: bool = False) -> bytes:
    total_len = 12 + len(payload)
    body = struct.pack("<Ii", total_len, seq_no) + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    frame = body + struct.pack("<I", crc)
    if pad_to_16:
        rem = len(frame) % 16
        if rem:
            # 4-byte 0x00000004 padding words appended after CRC32 to align to 16 bytes
            pad_len = 16 - rem
            assert pad_len % 4 == 0
            frame += b"\x04\x00\x00\x00" * (pad_len // 4)
    return frame


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"EOF after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def read_plain_rpc_frame(sock: socket.socket) -> tuple[int, bytes]:
    hdr = recv_exact(sock, 8)
    total_len, seq_no = struct.unpack("<Ii", hdr)
    if total_len < 12 or total_len > 65536:
        raise ValueError(f"invalid plain RPC frame length: {total_len}")
    rest = recv_exact(sock, total_len - 8)
    payload, crc_bytes = rest[:-4], rest[-4:]
    (crc_got,) = struct.unpack("<I", crc_bytes)
    crc_exp = zlib.crc32(hdr + payload) & 0xFFFFFFFF
    if crc_got != crc_exp:
        raise ValueError(f"CRC32 mismatch: got={crc_got:#x} exp={crc_exp:#x}")
    return seq_no, payload


class EncryptedRpcReader:
    def __init__(self, sock: socket.socket, dec: _Aes256Cbc) -> None:
        self._sock = sock
        self._dec = dec
        self._buf = bytearray()

    def _fill(self, need: int) -> None:
        while len(self._buf) < need:
            # Read 16-byte AES-CBC blocks
            ct = recv_exact(self._sock, 16)
            self._buf.extend(self._dec.decrypt(ct))

    def read_frame(self) -> tuple[int, bytes]:
        while True:
            self._fill(4)
            (first_word,) = struct.unpack("<I", self._buf[:4])
            if first_word == 4:
                # 4-byte padding word (0x00000004)
                del self._buf[:4]
                continue
            total_len = first_word
            if total_len < 12 or total_len > 1024 * 1024:
                raise ValueError(f"invalid encrypted RPC frame length: {total_len:#x}")
            self._fill(total_len)
            raw = bytes(self._buf[:total_len])
            del self._buf[:total_len]
            seq_no = struct.unpack("<i", raw[4:8])[0]
            payload = raw[8:-4]
            (crc_got,) = struct.unpack("<I", raw[-4:])
            crc_exp = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
            if crc_got != crc_exp:
                raise ValueError(f"encrypted CRC32 mismatch: got={crc_got:#x} exp={crc_exp:#x}")
            return seq_no, payload


def tl_encode_bytes(data: bytes) -> bytes:
    n = len(data)
    if n < 254:
        out = bytes([n]) + data
    else:
        out = bytes([254, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF]) + data
    pad = (-len(out)) % 4
    return out + (b"\x00" * pad)


def ipv4_mapped_16(ip: str) -> bytes:
    return b"\x00" * 10 + b"\xff\xff" + ipaddress.IPv4Address(ip).packed


def build_req_pq_multi(nonce: bytes) -> bytes:
    now_secs = int(time.time())
    msg_id = (now_secs << 32) & ~3
    return (
        b"\x00" * 8
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", 20)
        + b"\xf1\x8e\x7e\xbe"
        + nonce
    )


def parse_proxy_config(text: str) -> dict[int, list[tuple[str, int]]]:
    dcs: dict[int, list[tuple[str, int]]] = {}
    for line in text.splitlines():
        m = PROXY_CONF_LINE_RE.match(line.strip())
        if m:
            dc_id = int(m.group(1))
            dcs.setdefault(dc_id, []).append((m.group(2), int(m.group(3))))
    return dcs


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 0.3 ME protocol spike")
    ap.add_argument("--dc", type=int, default=2, help="DC id from proxy-multi.conf (default: 2)")
    ap.add_argument("--ad-tag", default="", help="Optional 32-hex ad_tag (16 bytes) from @MTProxybot")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    print("[1/4] Fetching proxy-secret and proxy-multi.conf from core.telegram.org...")
    proxy_secret = urllib.request.urlopen("https://core.telegram.org/getProxySecret", timeout=args.timeout).read()
    proxy_conf_text = urllib.request.urlopen("https://core.telegram.org/getProxyConfig", timeout=args.timeout).read().decode("utf-8")
    dcs = parse_proxy_config(proxy_conf_text)
    print(f"      proxy-secret: {len(proxy_secret)} bytes, key_selector={proxy_secret[:4].hex()}")
    print(f"      proxy-multi.conf: {len(dcs)} DCs parsed, DC {args.dc} endpoints: {len(dcs.get(args.dc, []))}")
    if args.dc not in dcs or not dcs[args.dc]:
        print(f"ERROR: DC {args.dc} not found in proxy-multi.conf", file=sys.stderr)
        return 1

    srv_ip, srv_port = dcs[args.dc][0]
    print(f"[2/4] Connecting to ME server (DC {args.dc}, port {srv_port})...")
    sock = socket.create_connection((srv_ip, srv_port), timeout=args.timeout)
    try:
        clt_ip, clt_port = sock.getsockname()
        clt_nonce = os.urandom(16)
        clt_ts = int(time.time()) & 0xFFFFFFFF
        nonce_payload = (
            struct.pack("<I", RPC_NONCE)
            + proxy_secret[:4]
            + struct.pack("<I", CRYPTO_AES)
            + struct.pack("<I", clt_ts)
            + clt_nonce
        )
        sock.sendall(pack_rpc_frame(-2, nonce_payload))
        seq_srv, srv_payload = read_plain_rpc_frame(sock)
        if seq_srv != -2 or len(srv_payload) < 32:
            raise ValueError(f"unexpected RPC_NONCE reply: seq={seq_srv} len={len(srv_payload)}")
        srv_op, srv_ksel, srv_schema, srv_ts = struct.unpack("<I4sII", srv_payload[:16])
        srv_nonce = srv_payload[16:32]
        if srv_op != RPC_NONCE or srv_schema != CRYPTO_AES or srv_ksel != proxy_secret[:4]:
            raise ValueError(f"RPC_NONCE mismatch: op={srv_op:#x} schema={srv_schema} ksel={srv_ksel.hex()}")
        print(f"      RPC_NONCE OK (server_ts={srv_ts})")

        # Derive AES-256-CBC keys
        enc_key, enc_iv = derive_me_aes_key_iv(
            srv_nonce, clt_nonce, clt_ts, srv_ip, clt_port, b"CLIENT", clt_ip, srv_port, proxy_secret
        )
        dec_key, dec_iv = derive_me_aes_key_iv(
            srv_nonce, clt_nonce, clt_ts, srv_ip, clt_port, b"SERVER", clt_ip, srv_port, proxy_secret
        )
        enc = _Aes256Cbc(enc_key, enc_iv)
        dec = _Aes256Cbc(dec_key, dec_iv)
        reader = EncryptedRpcReader(sock, dec)

        # RPC_HANDSHAKE (seq_no = -1): op(4) + flags(4) + sender_pid(12) + peer_pid(12) = 32 bytes
        sender_pid = b"IPIPPRPDTIME"
        peer_pid = b"\x00" * 12
        hs_payload = struct.pack("<II", RPC_HANDSHAKE, 0) + sender_pid + peer_pid
        sock.sendall(enc.encrypt(pack_rpc_frame(-1, hs_payload, pad_to_16=True)))
        hs_seq, hs_resp = reader.read_frame()
        if hs_seq != -1 or len(hs_resp) < 32:
            raise ValueError(f"unexpected RPC_HANDSHAKE reply: seq={hs_seq} len={len(hs_resp)}")
        (hs_op,) = struct.unpack("<I", hs_resp[:4])
        if hs_op != RPC_HANDSHAKE:
            raise ValueError(f"RPC_HANDSHAKE op mismatch: {hs_op:#x}")
        print("[3/4] RPC_HANDSHAKE OK (AES-256-CBC encrypted channel verified)")

        # RPC_PROXY_REQ (seq_no = 0) with unencrypted req_pq_multi
        pq_nonce = os.urandom(16)
        req_pq = build_req_pq_multi(pq_nonce)
        conn_id = int.from_bytes(os.urandom(8), "little")
        flags = FLAG_EXTMODE2 | FLAG_MAGIC
        extra = b""
        if args.ad_tag:
            tag_bytes = bytes.fromhex(args.ad_tag.strip())
            if len(tag_bytes) != 16:
                raise ValueError("--ad-tag must be 32 hex chars (16 bytes)")
            flags |= FLAG_HAS_AD_TAG
            # TL extra bytes containing proxy_tag (16 bytes)
            extra = tl_encode_bytes(tag_bytes)

        proxy_req = (
            struct.pack("<IIQ", RPC_PROXY_REQ, flags, conn_id)
            + ipv4_mapped_16("192.0.2.1")
            + struct.pack("<I", 12345)
            + ipv4_mapped_16(clt_ip)
            + struct.pack("<I", clt_port)
            + extra
            + req_pq
        )
        t0 = time.monotonic()
        sock.sendall(enc.encrypt(pack_rpc_frame(0, proxy_req, pad_to_16=True)))

        # Wait for RPC_PROXY_ANS matching our conn_id
        for _ in range(10):
            rseq, rpayload = reader.read_frame()
            (rop,) = struct.unpack("<I", rpayload[:4])
            if rop == RPC_SIMPLE_ACK:
                continue
            if rop == RPC_PROXY_ANS and len(rpayload) >= 16:
                ans_flags, ans_conn_id = struct.unpack("<IQ", rpayload[4:16])
                ans_body = rpayload[16:]
                if ans_conn_id == conn_id and len(ans_body) >= 40:
                    if ans_body[0:8] == b"\x00" * 8 and ans_body[20:24] == b"\x63\x24\x16\x05" and ans_body[24:40] == pq_nonce:
                        rtt_ms = (time.monotonic() - t0) * 1000.0
                        print(f"[4/4] RPC_PROXY_ANS OK! Received valid resPQ#05162463 ({len(ans_body)} bytes, RTT={rtt_ms:.1f} ms)")
                        return 0
                raise ValueError(f"RPC_PROXY_ANS payload validation failed: conn_id_match={ans_conn_id==conn_id} body_len={len(ans_body)} head={ans_body[:24].hex()}")
            raise ValueError(f"unexpected RPC response op={rop:#x} seq={rseq} len={len(rpayload)}")
        raise TimeoutError("no RPC_PROXY_ANS received")
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
