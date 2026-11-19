#!/usr/bin/env python3
"""Linux-only, bounded loopback smoke. No Telegram DC, netem or live-node changes."""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import selectors
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


class Cover(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        with server.lock:
            server.active += 1
            server.peak = max(server.active, server.peak)
        try:
            self.request.settimeout(2)
            while self.request.recv(4096):
                pass
        except OSError:
            pass
        finally:
            with server.lock:
                server.active -= 1


class CoverServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    active = 0
    peak = 0
    lock = threading.Lock()


def snapshot(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    rss = re.search(r'^VmRSS:\s+(\d+)', status, flags=re.M)
    return {'fd': len(list(Path(f'/proc/{pid}/fd').iterdir())),
            'rss_kib': int(rss[1]) if rss else None}


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--binary', type=Path, required=True)
    args.add_argument('--out', type=Path, required=True)
    params = args.parse_args()
    if os.name != 'posix' or not Path('/proc/self/fd').is_dir():
        raise RuntimeError('resource smoke requires Linux /proc')
    params.out.mkdir(parents=True, exist_ok=True)
    samples = []
    logs = []
    ready = queue.Queue()
    peers = []
    process = None
    result = {'status': 'FAIL', 'scope': '12 slow loopback clients, limit 4; not a load benchmark'}
    with CoverServer(('127.0.0.1', 0), Cover) as cover, tempfile.TemporaryDirectory(prefix='mtveil-smoke-') as temp:
        worker = threading.Thread(target=cover.serve_forever, daemon=True)
        worker.start()
        secret = Path(temp) / 'secret'
        secret.write_text('000102030405060708090a0b0c0d0e0f')
        secret.chmod(0o600)
        command = [str(params.binary.resolve()), '--listen', '127.0.0.1:0',
                   '--secret-file', str(secret), '--sni', 'example.com',
                   '--cover', f'127.0.0.1:{cover.server_address[1]}',
                   '--dc', '2=127.0.0.1:9', '--max-connections', '4',
                   '--handshake-timeout-secs', '1', '--idle-timeout-secs', '1',
                   '--drain-timeout-secs', '1']
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            def collect():
                for line in process.stderr:
                    logs.append(line)
                    match = re.search(r'listening=127\.0\.0\.1:(\d+)', line)
                    if not match:
                        try:
                            event=json.loads(line)
                            if event.get('event')=='startup':
                                ready.put(int(event['details']['listen'].rsplit(':',1)[1]))
                        except (ValueError,KeyError):
                            pass
                    if match:
                        ready.put(int(match[1]))
            threading.Thread(target=collect, daemon=True).start()
            port = ready.get(timeout=5)
            before = snapshot(process.pid)
            start = time.monotonic()
            closed = 0
            with selectors.DefaultSelector() as poll:
                for _ in range(12):
                    peer = socket.create_connection(('127.0.0.1', port), timeout=2)
                    peer.setblocking(False)
                    peers.append(peer)
                    poll.register(peer, selectors.EVENT_READ)
                while closed < len(peers) and time.monotonic() - start < 10:
                    samples.append(snapshot(process.pid))
                    for event, _ in poll.select(timeout=0.1):
                        try:
                            data = event.fileobj.recv(4096)
                        except ConnectionResetError:
                            data = b''
                        if not data:
                            poll.unregister(event.fileobj)
                            event.fileobj.close()
                            closed += 1
                if closed != 12:
                    raise RuntimeError(f'only {closed}/12 slow clients released within 10s')
            after = snapshot(process.pid)
            peak_fd = max(x['fd'] for x in samples)
            if after['fd'] > before['fd'] + 1:
                raise RuntimeError('FD count did not return to baseline')
            if peak_fd > before['fd'] + 4 * 2 + 2 or cover.peak > 4:
                raise RuntimeError('admission FD/cover bound exceeded')
            elapsed = time.monotonic() - start
            process.send_signal(signal.SIGTERM)
            code = process.wait(timeout=3)
            if code != 0:
                raise RuntimeError(f'shutdown returned {code}')
            result.update(status='PASS', clients=12, released=closed, max_connections=4,
                          before=before, after=after, peak_fd=peak_fd,
                          peak_rss_kib=max(x['rss_kib'] for x in samples),
                          peak_cover_connections=cover.peak, release_seconds=round(elapsed, 3),
                          shutdown_signal='SIGTERM', shutdown_exit=code)
        except Exception as exc:
            result['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            for peer in peers:
                peer.close()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            cover.shutdown()
            (params.out / 'resource-smoke.json').write_text(json.dumps(result, indent=2))
            (params.out / 'samples.json').write_text(json.dumps(samples))
            (params.out / 'dut.log').write_text(''.join(logs))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
