"""Transparent TCP ingress for an isolated mtveil test."""
import asyncio
import json
import os
import time

LISTEN = os.environ['MTVEIL_LISTEN']
BACKEND = os.environ['MTVEIL_BACKEND']
stats = dict(active=0, accepted=0, rejected=0, errors=0, uploaded=0, downloaded=0)


async def pump(source, destination, counter, flow):
    while chunk := await asyncio.wait_for(source.read(32768), timeout=360):
        flow['read_bytes'] += len(chunk)
        destination.write(chunk)
        await asyncio.wait_for(destination.drain(), timeout=20)
        stats[counter] += len(chunk)
        flow['forwarded_bytes'] += len(chunk)
    destination.write_eof()


async def handle(reader, writer):
    remote_writer = None
    if stats['active'] >= 32:
        stats['rejected'] += 1
        writer.close()
        return
    stats['active'] += 1
    stats['accepted'] += 1
    session = stats['accepted']
    started = time.monotonic()
    start_unix_ms = time.time_ns() // 1_000_000
    connected_ms = None
    outcome = 'connecting'
    initiator = None
    error = None
    upload = dict(read_bytes=0, forwarded_bytes=0)
    download = dict(read_bytes=0, forwarded_bytes=0)
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(BACKEND, 29444), timeout=4
        )
        connected_ms = round((time.monotonic() - started) * 1000, 1)
        outcome = 'relay'
        up = asyncio.create_task(pump(reader, remote_writer, 'uploaded', upload))
        down = asyncio.create_task(pump(remote_reader, writer, 'downloaded', download))
        try:
            finished, _ = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
            initiator = 'both' if len(finished) == 2 else 'backend' if down in finished else 'client'
            for task in (up, down):
                if task in finished:
                    task.result()
            if down not in finished:
                outcome = 'drain'
                await asyncio.wait_for(down, timeout=8)
            outcome = 'eof'
        finally:
            for task in (up, down):
                task.cancel()
            await asyncio.gather(up, down, return_exceptions=True)
    except (OSError, TimeoutError) as exc:
        stats['errors'] += 1
        error = type(exc).__name__
    finally:
        writer.close()
        if remote_writer:
            remote_writer.close()
        stats['active'] -= 1
        print(json.dumps({
            'event': 'ingress_close',
            'session': session,
            'start_unix_ms': start_unix_ms,
            'backend_connected_ms': connected_ms,
            'duration_ms': round((time.monotonic() - started) * 1000, 1),
            'initiator': initiator,
            'outcome': outcome,
            'error': error,
            'upload': upload,
            'download': download,
        }), flush=True)


async def diagnostics(reader, writer):
    try:
        await asyncio.wait_for(reader.readline(), timeout=1)
        body = json.dumps(stats).encode()
        writer.write(
            f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()
            + body
        )
        await asyncio.wait_for(writer.drain(), timeout=1)
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def main():
    ingress = await asyncio.start_server(handle, LISTEN, 19444, backlog=64)
    async with ingress:
        health = await asyncio.start_server(diagnostics, '127.0.0.1', 39444, limit=1024)
        async with health:
            await asyncio.gather(ingress.serve_forever(), health.serve_forever())


if __name__ == '__main__':
    asyncio.run(main())
