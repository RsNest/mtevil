#!/usr/bin/env python3
"""Account-free P09: FakeTLS, authenticated MTProto key exchange, encrypted ping."""
import argparse
import asyncio
import json
import socket
from pathlib import Path

import mtproto_auth_smoke


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--secret-file', type=Path, required=True)
    parser.add_argument('--sni', required=True)
    args = parser.parse_args()
    secret = bytes.fromhex(args.secret_file.read_text(encoding='utf-8').strip())
    if len(secret) != 16:
        raise ValueError('secret file must contain 32 hex characters')

    def factory():
        return socket.create_connection((args.host, args.port), timeout=20)

    result = asyncio.run(mtproto_auth_smoke.run(factory, secret, args.sni))
    print(json.dumps({'probe': 'P09', **result}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Do not emit secret values, local credentials or payloads in failure output.
        print(json.dumps({'probe': 'P09', 'status': 'FAIL', 'error': type(exc).__name__}))
        raise SystemExit(1) from None
