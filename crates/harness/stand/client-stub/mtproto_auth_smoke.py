"""Full unauthenticated-account MTProto key exchange + encrypted ping over FakeTLS.

Uses Telethon's RSA/DH verification and MTProto sender; no API id, login,
user session or authorization key is persisted. The channel factory must open
an SSH direct-tcpip tunnel to the isolated test DUT, never a production proxy.
"""
import asyncio
from collections import defaultdict
import logging
import os
import struct
import time

import faketls_client as ft


class TunnelConnection:
    def __init__(self, factory, secret, sni):
        self.factory, self.secret, self.sni = factory, secret, sni
        self._connected = False
        self.channel = None
        self.buffer = b''

    def _open(self):
        self.channel = self.factory()
        self.channel.settimeout(20)
        self.reader = ft.RecordReader(self.channel)
        hello, frame, self.enc, self.dec, session = ft.build_client_hello(
            self.secret, self.sni, int(time.time()))
        self.channel.sendall(hello)
        packet, _ = ft.read_server_flight(self.reader)
        ft.verify_server_hello(packet, self.secret, frame[:32], session)
        encoded = bytearray(self.enc.update(frame))
        encoded[8:56] = frame[8:56]
        self.channel.sendall(b'\x17\x03\x03' + ft._u16(len(encoded)) + encoded)
        self._connected = True

    async def connect(self, timeout=None):
        await asyncio.to_thread(self._open)

    async def disconnect(self):
        self._connected = False
        if self.channel:
            self.channel.close()

    def _send(self, data):
        # Match Telethon's randomized intermediate codec: 0..3 padding bytes.
        padding = os.urandom(os.urandom(1)[0] % 4)
        packet = struct.pack('<I', len(data) + len(padding)) + data + padding
        cipher = self.enc.update(packet)
        for i in range(0, len(cipher), 16000):
            chunk = cipher[i:i + 16000]
            self.channel.sendall(b'\x17\x03\x03' + ft._u16(len(chunk)) + chunk)

    async def send(self, data):
        await asyncio.to_thread(self._send, data)

    def _recv(self):
        while True:
            if len(self.buffer) >= 4:
                size = struct.unpack('<I', self.buffer[:4])[0]
                if size == 0 or size > 1024 * 1024:
                    raise ValueError('invalid intermediate packet size')
                if len(self.buffer) >= size + 4:
                    packet, self.buffer = self.buffer[4:4 + size], self.buffer[4 + size:]
                    return packet[:len(packet) & ~3]
            kind, payload = self.reader.read_record()
            if kind != 0x17:
                raise ValueError('unexpected FakeTLS record')
            self.buffer += self.dec.update(payload)

    async def recv(self):
        return await asyncio.to_thread(self._recv)

    def __str__(self):
        return 'isolated FakeTLS DUT through SSH'


async def run(factory, secret, sni):
    from telethon.network.mtprotosender import MTProtoSender
    from telethon.tl.functions import PingRequest
    loggers = defaultdict(lambda: logging.getLogger('mtevil.auth-smoke'))
    connection = TunnelConnection(factory, secret, sni)
    sender = MTProtoSender(None, loggers=loggers, retries=1, auto_reconnect=False,
                          connect_timeout=20)
    start = time.monotonic()
    try:
        await asyncio.wait_for(sender.connect(connection), timeout=75)
        key_seconds = time.monotonic() - start
        if not sender.auth_key or len(sender.auth_key.key) != 256:
            raise ValueError('2048-bit authorization key was not generated')
        ping_id = int.from_bytes(os.urandom(8), 'little', signed=True)
        pong = await asyncio.wait_for(sender.send(PingRequest(ping_id)), timeout=20)
        if getattr(pong, 'ping_id', None) != ping_id:
            raise ValueError('encrypted pong ping_id mismatch')
        return {'status': 'PASS', 'auth_key_bits': 2048,
                'server_authentication': 'Telethon RSA/DH checks completed',
                'encrypted_ping_pong': True, 'pong_type': type(pong).__name__,
                'key_exchange_seconds': round(key_seconds, 3),
                'total_seconds': round(time.monotonic() - start, 3),
                'account_login': False, 'session_persisted': False}
    finally:
        await sender.disconnect()
        await connection.disconnect()
