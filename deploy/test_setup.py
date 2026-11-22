#!/usr/bin/env python3
"""Unit and container tests for deploy/setup.py DNS and HTTPS-cover checks."""
import contextlib
import importlib.util
import io
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SETUP_PATH = Path(__file__).resolve().parent / "setup.py"
SPEC = importlib.util.spec_from_file_location("mtevil_setup", SETUP_PATH)
setup = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(setup)


class _Aes256Ctr:
    """Minimal pure-Python AES-256-CTR (128-bit big-endian counter) for mock DC tests."""

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
    _RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

    def __init__(self, key: bytes, iv: bytes) -> None:
        assert len(key) == 32 and len(iv) == 16
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
        self._ctr = int.from_bytes(iv, "big")
        self._buf = b""

    @staticmethod
    def _xtime(a: int) -> int:
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

    def _encrypt_block(self, block: bytes) -> bytes:
        s = [a ^ b for a, b in zip(block, self._rkeys[0])]
        sb = self._SBOX
        xt = self._xtime
        for r in range(1, 15):
            s = [sb[b] for b in s]
            # ShiftRows (column-major)
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

    def xor(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        pos = 0
        while pos < len(data):
            if not self._buf:
                blk = self._ctr.to_bytes(16, "big")
                self._ctr = (self._ctr + 1) & ((1 << 128) - 1)
                self._buf = self._encrypt_block(blk)
            take = min(len(data) - pos, len(self._buf))
            for i in range(take):
                out[pos + i] = data[pos + i] ^ self._buf[i]
            self._buf = self._buf[take:]
            pos += take
        return bytes(out)


class _MockTelegramDcServer:
    """Distinguishable local MTProto DC mock that separates background probes from real client req_pq_multi."""

    def __init__(self) -> None:
        import threading

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.probe_connections = 0
        self.client_nonces: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _handle(self, conn: socket.socket) -> None:
        import struct
        import time

        try:
            conn.settimeout(2.0)
            hdr = self._recv_exact(conn, 64)
            if hdr is None:
                return
            frame_enc = self._recv_exact(conn, 44)
            if frame_enc is None:
                # Background probe / check-egress closes right after 64-byte DC header.
                with self._lock:
                    self.probe_connections += 1
                return
            dec = _Aes256Ctr(hdr[8:40], hdr[40:56])
            dec.xor(bytes(64))  # advance past 64-byte obfuscated2 init header
            frame = dec.xor(frame_enc)
            if (
                len(frame) == 44
                and frame[0:4] == struct.pack("<I", 40)
                and frame[4:12] == b"\x00" * 8
                and frame[24:28] == b"\xf1\x8e\x7e\xbe"
            ):
                nonce = frame[28:44]
                with self._lock:
                    self.client_nonces.append(nonce)
                msg_id = ((int(time.time()) << 32) & ~3) + 1
                resp = (
                    struct.pack("<I", 40)
                    + (b"\x00" * 8)
                    + struct.pack("<Q", msg_id)
                    + struct.pack("<I", 20)
                    + b"\x63\x24\x16\x05"
                    + nonce
                )
                rev = hdr[8:56][::-1]
                enc = _Aes256Ctr(rev[:32], rev[32:48])
                conn.sendall(enc.xor(resp))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve(self) -> None:
        import threading

        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)


class SetupValidationTests(unittest.TestCase):
    def test_ipv4_and_ipv6_literals(self) -> None:
        self.assertEqual(setup.validate_host("192.0.2.10"), "192.0.2.10")
        self.assertEqual(setup.validate_host("2001:db8::1"), "2001:db8::1")
        self.assertEqual(setup.validate_host("[2001:db8::1]"), "2001:db8::1")
        self.assertTrue(setup.is_ip_literal("192.0.2.10"))
        self.assertTrue(setup.is_ip_literal("2001:db8::1"))
        self.assertFalse(setup.is_ip_literal("proxy.example.com"))

    def test_host_and_egress_reject_invalid_inputs(self) -> None:
        for bad in ("https://example.com", "example.com:443", "example.com/path", ""):
            with self.assertRaises(ValueError):
                setup.validate_host(bad)
        for bad_egress in ("0.0.0.0", "::"):
            with self.assertRaises(ValueError):
                setup.validate_egress_ip(bad_egress)
        self.assertEqual(setup.validate_egress_ip("10.203.0.9"), "10.203.0.9")

    def test_a_and_aaaa_match(self) -> None:
        rec = {"a": ["192.0.2.10"], "aaaa": ["2001:db8::1"], "cnames": []}
        ok, lines = setup.compare_dns_records(rec, ["192.0.2.10", "2001:db8::1"])
        self.assertTrue(ok)
        self.assertTrue(any("A records: OK" in l for l in lines))
        self.assertTrue(any("AAAA records: OK" in l for l in lines))

    def test_cname_chain_and_missing_domain(self) -> None:
        rec = {"a": ["192.0.2.10"], "aaaa": [], "cnames": ["edge.example.net"]}
        ok, lines = setup.compare_dns_records(rec, ["192.0.2.10"])
        self.assertTrue(ok)
        self.assertTrue(any("CNAME chain: edge.example.net" in l for l in lines))

        missing = {"a": [], "aaaa": [], "cnames": []}
        ok_m, lines_m = setup.compare_dns_records(missing, ["192.0.2.10"])
        self.assertFalse(ok_m)
        self.assertTrue(any("neither A nor AAAA" in l for l in lines_m))

    def test_right_a_with_stale_aaaa_reports_separate_divergence(self) -> None:
        rec = {"a": ["192.0.2.10"], "aaaa": ["2001:db8::99"], "cnames": []}
        ok, lines = setup.compare_dns_records(rec, ["192.0.2.10", "2001:db8::1"])
        self.assertFalse(ok)
        self.assertTrue(any("A records: OK" in l for l in lines))
        self.assertTrue(any("AAAA records: MISMATCH" in l for l in lines))

        ok2, lines2 = setup.compare_dns_records(rec, ["192.0.2.10"])
        self.assertFalse(ok2)
        self.assertTrue(any("A records: OK" in l for l in lines2))
        self.assertTrue(any("unexpected AAAA" in l for l in lines2))

    def test_cover_cert_hostname_mismatch_from_container(self) -> None:
        image = self._local_image()
        if image is None:
            self.skipTest("no local mtevil image available")
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text(setup.render_compose(repo, d, "direct"), encoding="utf-8")
            (d / ".env").write_text(f"MTEVIL_PROJECT=mtevil-cov-test\nMTEVIL_IMAGE={image}\nMTEVIL_BIND=127.0.0.1\nMTEVIL_PORT=26449\n", encoding="utf-8")
            (d / "config.json").write_text("{}\n", encoding="utf-8")
            base = setup.compose_cmd(d, "mtevil-cov-test")
            ok_good, out_good = setup.check_cover_from_container(base, "example.com:443", "example.com")
            self.assertTrue(ok_good, out_good)
            ok_bad, _ = setup.check_cover_from_container(base, "example.com:443", "wrong-host.invalid")
            self.assertFalse(ok_bad)

    def test_render_compose_network_host(self):
        repo_root = Path(__file__).resolve().parent.parent
        yaml_text = setup.render_compose(
            repo_root,
            repo_root / "deploy" / "wizard",
            "edge",
            network_host=True,
            health_host="127.0.0.1",
            health_port=27443,
        )
        self.assertIn("network_mode: host", yaml_text)
        self.assertNotIn("ports:", yaml_text)
        self.assertIn("127.0.0.1:27443", yaml_text)

    def test_render_compose_without_build(self):
        repo_root = Path(__file__).resolve().parent.parent
        yaml_text = setup.render_compose(
            repo_root,
            repo_root / "deploy" / "wizard",
            "direct",
            include_build=False,
        )
        self.assertNotIn("build:", yaml_text)
        self.assertIn("image:", yaml_text)
        self.assertIn("- state:/var/lib/mtevil:ro", yaml_text)
        self.assertIn("- replay:/var/lib/mtevil-replay", yaml_text)
        self.assertIn("\n  init:\n", yaml_text)
        self.assertIn("soft: 4096", yaml_text)
        self.assertIn("hard: 4096", yaml_text)
        self.assertEqual(setup.compute_compose_nofile(256), 4096)
        self.assertEqual(setup.compute_compose_nofile(2048), 4608)
        self.assertEqual(setup.compute_compose_nofile(4096), 8704)
        yaml_high = setup.render_compose(
            repo_root,
            repo_root / "deploy" / "wizard",
            "direct",
            include_build=False,
            max_connections=4096,
        )
        self.assertIn("soft: 8704", yaml_high)
        self.assertIn("hard: 8704", yaml_high)

    def test_is_port_available_and_restore_backup(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        busy_port = sock.getsockname()[1]
        try:
            self.assertFalse(setup.is_port_available("127.0.0.1", busy_port))
        finally:
            sock.close()
        self.assertTrue(setup.is_port_available("127.0.0.1", busy_port))

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml.bak").write_text("old-compose", encoding="utf-8")
            (d / ".env.bak").write_text("stale-env-from-previous-run", encoding="utf-8")
            (d / "config.json.bak").write_text("stale-cfg-from-previous-run", encoding="utf-8")
            (d / "compose.yaml").write_text("new-compose", encoding="utf-8")
            (d / ".env").write_text("current-env", encoding="utf-8")
            (d / "config.json").write_text("current-cfg", encoding="utf-8")
            self.assertTrue(setup.restore_backup_files(d, ["compose.yaml"]))
            self.assertEqual((d / "compose.yaml").read_text(encoding="utf-8"), "old-compose")
            self.assertEqual((d / ".env").read_text(encoding="utf-8"), "current-env")
            self.assertEqual((d / "config.json").read_text(encoding="utf-8"), "current-cfg")

    def _local_image(self):
        env_img = setup.os.environ.get("MTEVIL_TEST_IMAGE")
        candidates = ([env_img] if env_img else []) + ["mtevil:wizard-test", "ghcr.io/rsnest/mtevil:v0.1.0-alpha.5"]
        for candidate in candidates:
            if subprocess.run(["docker", "image", "inspect", candidate], capture_output=True).returncode == 0:
                return candidate
        return None

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_short_direct_path_defaults_non_tty_no_ansi(self):
        image = self._local_image()
        if image is None:
            self.skipTest("no local mtevil image available")
        free_port = self._free_port()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            project = f"mtevil-short-test-{free_port}"
            # Fresh Simple mode when public IPv4 is detected and default port (443) is free:
            # ONLY 2 prompts (mode selection + final confirmation)!
            # Here we test free port via is_port_available mock for 443 OR fallback to free_port.
            stdin_data = f"1\n{free_port}\ny\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            try:
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", project, "--image", image, "--no-build"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                    mock.patch.object(sys, "stdout", out_buf),
                    mock.patch.object(sys, "stderr", err_buf),
                    mock.patch.object(setup, "detect_local_global_ipv4", return_value="127.0.0.1"),
                    mock.patch.object(setup, "is_port_available", side_effect=lambda _ip, port: port != 443),
                ):
                    rc = setup.main()
                out = out_buf.getvalue()
                self.assertEqual(rc, 0, out + err_buf.getvalue())
                self.assertNotIn("\x1b[", out)
                self.assertIn("Конфигурация проверена", out)
                self.assertIn("HTTPS-сайт для маскировки доступен", out)
                self.assertIn("Контейнер запущен", out)
                self.assertIn("Контейнер исправен", out)
                self.assertIn("Docker healthcheck", out)
                self.assertIn(f"Каталог установки: {d.resolve()}", out)
                self.assertIn("Проверка статуса:", out)
                # Telegram link must appear on its own line.
                link_lines = [ln for ln in out.splitlines() if ln.startswith(f"https://t.me/proxy?server=127.0.0.1&port={free_port}&secret=")]
                self.assertEqual(len(link_lines), 1, out)
            finally:
                base = setup.compose_cmd(d, project)
                if (d / "compose.yaml").exists():
                    subprocess.run(base + ["down", "-v"], capture_output=True)

    def test_busy_443_prompts_new_port_and_starts_container(self):
        image = self._local_image()
        if image is None:
            self.skipTest("no local mtevil image available")
        free_port = self._free_port()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            project = f"mtevil-port-test-{free_port}"
            # Simple mode: 1 -> IP detected -> 443 busy -> enter free_port -> confirm y
            stdin_data = f"1\n{free_port}\ny\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            try:
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", project, "--image", image, "--no-build"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                    mock.patch.object(sys, "stdout", out_buf),
                    mock.patch.object(sys, "stderr", err_buf),
                    mock.patch.object(setup, "detect_local_global_ipv4", return_value="127.0.0.1"),
                    mock.patch.object(setup, "is_port_available", side_effect=lambda _ip, port: port != 443),
                ):
                    rc = setup.main()
                out = out_buf.getvalue()
                self.assertEqual(rc, 0, out + err_buf.getvalue())
                self.assertNotIn("\x1b[", out)
                self.assertIn("Порт 443 уже занят на этом сервере.", out)
                self.assertIn(f"https://t.me/proxy?server=127.0.0.1&port={free_port}&secret=", out)
            finally:
                base = setup.compose_cmd(d, project)
                if (d / "compose.yaml").exists():
                    subprocess.run(base + ["down", "-v"], capture_output=True)

    def test_advanced_settings_and_unrelated_docker_error_no_port_prompt(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text("old-compose", encoding="utf-8")
            (d / ".env").write_text("MTEVIL_PORT=24443\n", encoding="utf-8")
            (d / "config.json").write_text('{"sni":"example.com","cover":"example.com:443"}\n', encoding="utf-8")

            def fake_run(argv, **_kwargs):
                cmd = " ".join(argv)
                if "up -d" in cmd:
                    return subprocess.CompletedProcess(
                        argv,
                        1,
                        stdout="",
                        stderr="permission denied while trying to connect to the docker API at unix:///var/run/docker.sock",
                    )
                if "link" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="https://t.me/proxy?server=127.0.0.1&port=25443&secret=ee00\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            # Existing config confirm y -> mode 2 (advanced) -> role 1 (direct) -> host 127.0.0.1 ->
            # port 25443 -> bind 127.0.0.1 -> network-host n -> sni example.com -> cover example.com:443 -> apply y
            stdin_data = "y\n2\n1\n127.0.0.1\n25443\n127.0.0.1\nn\nexample.com\nexample.com:443\ny\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtevil-err-test", "--image", "mtevil:test", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                mock.patch.object(sys, "stdout", out_buf),
                mock.patch.object(sys, "stderr", err_buf),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "run", side_effect=fake_run),
            ):
                rc = setup.main()
            out = out_buf.getvalue()
            err = err_buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("IP привязки:       127.0.0.1", out)
            self.assertNotIn("Выбрать другой порт", out)
            self.assertIn("docker.sock", err)
            self.assertIn("Прежние файлы конфигурации восстановлены.", err)
            self.assertEqual((d / "compose.yaml").read_text(encoding="utf-8"), "old-compose")

    def test_detect_local_global_ipv4_and_cyrillic_yes(self):
        class FakeSock:
            def __init__(self, ip: str):
                self._ip = ip
            def connect(self, _addr):
                pass
            def getsockname(self):
                return (self._ip, 12345)
            def close(self):
                pass

        for priv in ("192.168.1.10", "10.203.0.9", "100.64.0.1"):
            with mock.patch.object(setup.socket, "socket", return_value=FakeSock(priv)):
                self.assertIsNone(setup.detect_local_global_ipv4())

        with mock.patch.object(setup.socket, "socket", return_value=FakeSock("93.184.216.34")):
            self.assertEqual(setup.detect_local_global_ipv4(), "93.184.216.34")

        with mock.patch.object(sys, "stdin", io.StringIO("у\n")), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertTrue(setup.ask_yes_no("Продолжить?", default=False))

        with mock.patch.object(sys, "stdin", io.StringIO("\n")), mock.patch.object(sys, "stdout", io.StringIO()):
            host, recs = setup.prompt_client_address("93.184.216.34")
            self.assertEqual(host, "93.184.216.34")
            self.assertIsNone(recs)

    def test_edge_failed_check_preserves_live_token_and_wait_healthy_timeout_has_abs_logs(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text("old-compose", encoding="utf-8")
            (d / ".env").write_text("MTEVIL_PORT=443\n", encoding="utf-8")
            (d / "config.json").write_text('{"role":"edge"}\n', encoding="utf-8")

            def fake_check_egress_fail(argv, **_kwargs):
                cmd = " ".join(argv)
                if "check-egress" in cmd:
                    return subprocess.CompletedProcess(argv, 1, stdout='[{"status":"fail"}]', stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            # Existing edge config auto-enters advanced mode:
            # confirm y -> role 2 (edge) -> host 203.0.113.10 -> port 443 -> bind default ->
            # network-host n -> sni default -> cover default -> upstream 10.203.0.9:29443 ->
            # backup n -> strategy 1 -> apply y -> reuse token n -> enter new token -> abort after check-egress fail n
            stdin_data = (
                "y\n2\n203.0.113.10\n443\n\nn\n\n\n10.203.0.9:29443\nn\n1\ny\nn\n"
                + ("a" * 32)
                + "\nn\n"
            )
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtevil-edge-tok", "--image", "mtevil:test", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                mock.patch.object(sys, "stdout", out_buf),
                mock.patch.object(sys, "stderr", err_buf),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "read_volume_secret", return_value="0" * 32),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "write_volume_secret_stdin") as mock_write_tok,
                mock.patch.object(setup, "run", side_effect=fake_check_egress_fail),
            ):
                rc = setup.main()
            self.assertEqual(rc, 1)
            for call in mock_write_tok.call_args_list:
                self.assertNotEqual(call.args[1], "/var/lib/mtevil/egress-token")

        with tempfile.TemporaryDirectory() as td2:
            d2 = Path(td2)
            out2 = io.StringIO()
            err2 = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d2), "--project", "mtevil-hc-test", "--image", "mtevil:test", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO("1\ny\n")),
                mock.patch.object(sys, "stdout", out2),
                mock.patch.object(sys, "stderr", err2),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value="203.0.113.10"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", side_effect=TimeoutError("timeout")),
                mock.patch.object(setup, "run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")),
            ):
                rc2 = setup.main()
            self.assertEqual(rc2, 1)
            err_text = err2.getvalue()
            self.assertIn("healthy", err_text)
            self.assertIn(f'"{(d2 / ".env").resolve()}"', err_text)
            self.assertIn(f'"{(d2 / "compose.yaml").resolve()}"', err_text)

    def test_token_rollback_after_check_egress_passes_and_up_or_health_fails(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text("working-compose", encoding="utf-8")
            (d / ".env").write_text("MTEVIL_PORT=443\n", encoding="utf-8")
            (d / "config.json").write_text('{"role":"edge","egress_upstreams":["10.203.0.9:29443"]}\n', encoding="utf-8")

            old_tok = "1" * 32
            new_tok = "2" * 32
            volume_store = {
                "/var/lib/mtevil/proxy-secret": "0" * 32,
                "/var/lib/mtevil/users.json": "{}",
                "/var/lib/mtevil/egress-token": old_tok,
            }

            def fake_vol_exists(_base, path):
                return path in volume_store

            def fake_read_secret(_base, path):
                return volume_store[path]

            def fake_write_secret(_base, path, val):
                volume_store[path] = val

            def fake_run_ok(argv, **_kwargs):
                cmd = " ".join(argv)
                if "check-egress" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout='[{"status":"ok"}]', stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            stdin_data = f"y\n2\n203.0.113.10\n443\n\nn\n\n\n10.203.0.9:29443\nn\n1\ny\nn\n{new_tok}\n"
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtevil-edge-rb", "--image", "mtevil:test", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "volume_file_exists", side_effect=fake_vol_exists),
                mock.patch.object(setup, "read_volume_secret", side_effect=fake_read_secret),
                mock.patch.object(setup, "write_volume_secret_stdin", side_effect=fake_write_secret),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", side_effect=TimeoutError("unhealthy")),
                mock.patch.object(setup, "run", side_effect=fake_run_ok),
            ):
                rc = setup.main()
            self.assertEqual(rc, 1)
            # Verify both config files AND the live token in state volume rolled back to old_tok!
            self.assertEqual(volume_store["/var/lib/mtevil/egress-token"], old_tok)
            self.assertEqual((d / "compose.yaml").read_text(encoding="utf-8"), "working-compose")

    def test_real_container_token_rotation_rollback_reconnects_edge_to_egress(self):
        image = self._local_image()
        if image is None:
            self.skipTest("no local mtevil image available")

        eg1_port = self._free_port()
        eg2_port = self._free_port()
        edge_port = self._free_port()
        old_tok = "11111111111111111111111111111111"
        new_tok = "22222222222222222222222222222222"
        dc_eg1 = _MockTelegramDcServer()
        dc_eg2 = _MockTelegramDcServer()

        with (
            tempfile.TemporaryDirectory() as td_eg1,
            tempfile.TemporaryDirectory() as td_eg2,
            tempfile.TemporaryDirectory() as td_edge,
        ):
            d_eg1 = Path(td_eg1)
            d_eg2 = Path(td_eg2)
            d_edge = Path(td_edge)
            p_eg1 = f"mtevil-eg1-{eg1_port}"
            p_eg2 = f"mtevil-eg2-{eg2_port}"
            p_edge = f"mtevil-edge-{edge_port}"
            try:
                # 1. Start real Egress 1 with old_tok and point its DCs to distinguishable mock DC 1.
                stdin_eg1 = f"3\n127.0.0.1\n{eg1_port}\ny\nn\n{old_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_eg1), "--project", p_eg1, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_eg1)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)
                eg1_cfg = setup.json.loads((d_eg1 / "config.json").read_text(encoding="utf-8"))
                eg1_cfg["dc"] = [f"{i}=127.0.0.1:{dc_eg1.port}" for i in range(1, 6)]
                (d_eg1 / "config.json").write_text(setup.json.dumps(eg1_cfg, indent=2) + "\n", encoding="utf-8")
                eg1_base = setup.compose_cmd(d_eg1, p_eg1)
                setup.run(eg1_base + ["up", "-d", "--force-recreate", setup.compose_service(eg1_base)])
                setup.wait_healthy(eg1_base)

                # 2. Start real Egress 2 with new_tok and point its DCs to distinguishable mock DC 2.
                stdin_eg2 = f"3\n127.0.0.1\n{eg2_port}\ny\nn\n{new_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_eg2), "--project", p_eg2, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_eg2)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)
                eg2_cfg = setup.json.loads((d_eg2 / "config.json").read_text(encoding="utf-8"))
                eg2_cfg["dc"] = [f"{i}=127.0.0.1:{dc_eg2.port}" for i in range(1, 6)]
                (d_eg2 / "config.json").write_text(setup.json.dumps(eg2_cfg, indent=2) + "\n", encoding="utf-8")
                eg2_base = setup.compose_cmd(d_eg2, p_eg2)
                setup.run(eg2_base + ["up", "-d", "--force-recreate", setup.compose_service(eg2_base)])
                setup.wait_healthy(eg2_base)

                # 3. Start real Edge connected to Egress 1 with old_tok (background probes remain enabled).
                stdin_edge1 = f"2\n127.0.0.1\n{edge_port}\n\n\n\n127.0.0.1:{eg1_port}\nn\n1\ny\n{old_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_edge), "--project", p_edge, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_edge1)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)

                edge_base = setup.compose_cmd(d_edge, p_edge)
                self.assertEqual(setup.read_volume_secret(edge_base, "/var/lib/mtevil/egress-token"), old_tok)

                # 4. Reconfigure Edge to rotate to Egress 2 + new_tok:
                #    check-egress passes against real Egress 2, new_tok is written to real Docker volume,
                #    up -d --force-recreate runs (loading new_tok), and then wait_healthy raises TimeoutError
                #    on that 1st wait_healthy call -> setup.py's rollback restores old_tok + config and
                #    recreates the original Edge container itself (calling real wait_healthy on the 2nd call)!
                orig_wait_healthy = setup.wait_healthy
                wait_calls = 0

                def fail_first_wait_healthy(base, timeout_s=45):
                    nonlocal wait_calls
                    wait_calls += 1
                    if wait_calls == 1:
                        raise TimeoutError("simulated health timeout on rotated container")
                    return orig_wait_healthy(base, timeout_s)

                stdin_edge2 = f"y\n2\n127.0.0.1\n{edge_port}\n\n\n\n127.0.0.1:{eg2_port}\nn\n1\ny\nn\n{new_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_edge), "--project", p_edge, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_edge2)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                    mock.patch.object(setup, "wait_healthy", side_effect=fail_first_wait_healthy),
                ):
                    self.assertEqual(setup.main(), 1)
                self.assertEqual(wait_calls, 2)

                # 5. Without restarting Edge in the test, send a real end-to-end client request
                #    (FakeTLS + obfuscated2 + MTProto req_pq_multi) through Edge's listening port
                #    and verify the client-specific payload reached Egress 1's DC and NOT Egress 2's DC!
                self.assertEqual(setup.read_volume_secret(edge_base, "/var/lib/mtevil/egress-token"), old_tok)
                with dc_eg1._lock:
                    dc_eg1.client_nonces.clear()
                with dc_eg2._lock:
                    dc_eg2.client_nonces.clear()

                probe_proc = setup.run(
                    edge_base
                    + [
                        "exec",
                        "-T",
                        setup.compose_service(edge_base),
                        "/usr/local/bin/mtevil",
                        "probe-telegram",
                        "--config",
                        "/etc/mtevil/config.json",
                        "--address",
                        f"127.0.0.1:{edge_port}",
                        "--dc",
                        "2",
                    ],
                    check=False,
                )
                self.assertEqual(probe_proc.returncode, 0, probe_proc.stdout + probe_proc.stderr)

                with dc_eg1._lock:
                    eg1_nonces = list(dc_eg1.client_nonces)
                with dc_eg2._lock:
                    eg2_nonces = list(dc_eg2.client_nonces)
                self.assertEqual(
                    len(eg1_nonces),
                    1,
                    f"Expected client req_pq_multi payload to traverse Egress 1 (got eg1={len(eg1_nonces)}, eg2={len(eg2_nonces)})",
                )
                self.assertEqual(
                    len(eg2_nonces),
                    0,
                    f"Client req_pq_multi payload must NOT traverse Egress 2 after rollback (got eg2={len(eg2_nonces)})",
                )
            finally:
                dc_eg1.close()
                dc_eg2.close()
                for d_path, proj in ((d_edge, p_edge), (d_eg2, p_eg2), (d_eg1, p_eg1)):
                    if (d_path / "compose.yaml").exists():
                        subprocess.run(setup.compose_cmd(d_path, proj) + ["down", "-v"], capture_output=True)

    def test_version_selection_and_commit_tag_allocation(self):
        def rel(tag: str, *, draft: bool = False, assets=("install.sh", "setup.py")):
            return {
                "tag_name": tag,
                "draft": draft,
                "assets": [
                    {"name": name, "state": "uploaded", "browser_download_url": f"https://example.invalid/{tag}/{name}"}
                    for name in assets
                ],
            }

        releases = [
            rel("v0.1.0-alpha.5"),
            rel("v0.1.0-alpha.9"),
            rel("v0.1.0-alpha.10"),
            rel("v0.1.0-alpha.11", draft=True),
            rel("v0.1.0-alpha.12", assets=("install.sh",)),
        ]
        # Prerelease-only repository: default (stable channel) must fail with clear guidance.
        with self.assertRaises(ValueError) as pre_err:
            setup.select_latest_release(releases)
        self.assertIn("MTEVIL_CHANNEL=prerelease", str(pre_err.exception))
        self.assertIn("MTEVIL_VERSION=v0.1.0-alpha.10", str(pre_err.exception))

        # Explicit prerelease opt-in selects the newest valid prerelease.
        self.assertEqual(setup.select_latest_release(releases, allow_prerelease=True), "v0.1.0-alpha.10")

        releases_with_beta = releases + [rel("v0.1.0-beta.1")]
        self.assertEqual(setup.select_latest_release(releases_with_beta, allow_prerelease=True), "v0.1.0-beta.1")

        # Newer prerelease alongside older stable release (even if GitHub marks prerelease=False for Latest):
        # default stable channel must pick the stable tag, while prerelease opt-in picks the newer RC.
        mixed_releases = releases_with_beta + [
            rel("v0.1.0"),
            dict(rel("v0.2.0-rc.1"), prerelease=False),
        ]
        self.assertEqual(setup.select_latest_release(mixed_releases), "v0.1.0")
        self.assertEqual(setup.select_latest_release(mixed_releases, allow_prerelease=True), "v0.2.0-rc.1")

        with self.assertRaises(ValueError):
            setup.select_latest_release([])
        with self.assertRaises(ValueError):
            setup.select_latest_release([rel("v0.1.0-alpha.6", draft=True)], allow_prerelease=True)

        # Rerun for an already tagged commit SHA must reuse its tag without incrementing.
        tag, is_new = setup.resolve_commit_release_tag(
            ["v0.1.0-alpha.6"],
            ["v0.1.0-alpha.4", "v0.1.0-alpha.5", "v0.1.0-alpha.6"],
        )
        self.assertEqual((tag, is_new), ("v0.1.0-alpha.6", False))

        # Deliberate beta tag on the commit is reused without creating a duplicate alpha tag.
        tag_b, is_new_b = setup.resolve_commit_release_tag(
            ["v0.1.0-beta.1"],
            ["v0.1.0-alpha.5", "v0.1.0-alpha.6", "v0.1.0-beta.1"],
        )
        self.assertEqual((tag_b, is_new_b), ("v0.1.0-beta.1", False))

        # New untagged commit after alpha.5 allocates v0.1.0-alpha.6.
        tag_next, is_new_next = setup.resolve_commit_release_tag(
            [],
            ["v0.1.0-alpha.2", "v0.1.0-alpha.3", "v0.1.0-alpha.4", "v0.1.0-alpha.5"],
        )
        self.assertEqual((tag_next, is_new_next), ("v0.1.0-alpha.6", True))

    def test_pinned_install_sh_ignores_midway_newer_release(self):
        # Verify that a release-pinned copy of install.sh (MTEVIL_PINNED_VERSION="v0.1.0-alpha.6")
        # keeps v0.1.0-alpha.6 for setup.py and image even if v0.1.0-alpha.7 is published before setup.py downloads.
        install_text = (Path(__file__).resolve().parent / "install.sh").read_text(encoding="utf-8")
        self.assertIn('MTEVIL_PINNED_VERSION="__AUTO__"', install_text)
        pinned_alpha6 = install_text.replace(
            'MTEVIL_PINNED_VERSION="__AUTO__"',
            'MTEVIL_PINNED_VERSION="v0.1.0-alpha.6"',
            1,
        )
        self.assertIn('MTEVIL_PINNED_VERSION="v0.1.0-alpha.6"', pinned_alpha6)

        import http.server
        import threading

        requested_paths: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requested_paths.append(self.path)
                if self.path == "/releases":
                    # Midway through installation, the API already advertises alpha.7 as latest!
                    body = setup.json.dumps([
                        {
                            "tag_name": "v0.1.0-alpha.6",
                            "draft": False,
                            "assets": [
                                {"name": "install.sh", "state": "uploaded", "browser_download_url": "http://127.0.0.1/a6/install.sh"},
                                {"name": "setup.py", "state": "uploaded", "browser_download_url": "http://127.0.0.1/a6/setup.py"},
                            ],
                        },
                        {
                            "tag_name": "v0.1.0-alpha.7",
                            "draft": False,
                            "assets": [
                                {"name": "install.sh", "state": "uploaded", "browser_download_url": "http://127.0.0.1/a7/install.sh"},
                                {"name": "setup.py", "state": "uploaded", "browser_download_url": "http://127.0.0.1/a7/setup.py"},
                            ],
                        },
                    ]).encode("utf-8")
                elif self.path == "/download/v0.1.0-alpha.6/setup.py":
                    body = b"import sys\nprint('SETUP_ARGS:', ' '.join(sys.argv[1:]))\n"
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_port
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                pinned_path = d / "install.alpha6.sh"
                pinned_path.write_text(pinned_alpha6, encoding="utf-8", newline="\n")
                fake_bin = d / "bin"
                fake_bin.mkdir()
                pulled_file = d / "pulled.txt"
                fake_docker = fake_bin / "docker"
                fake_docker.write_text(
                    "#!/usr/bin/env bash\n"
                    'if [ "$1" = "pull" ]; then echo "${@: -1}" > "' + str(pulled_file).replace("\\", "/") + '"; exit 0; fi\n'
                    "exit 0\n",
                    encoding="utf-8",
                    newline="\n",
                )
                try:
                    setup.os.chmod(fake_docker, 0o755)
                except OSError:
                    pass
                bash_bin = "/bin/bash" if Path("/bin/bash").is_file() else None
                if bash_bin is not None:
                    env = dict(setup.os.environ)
                    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
                    env["MTEVIL_DIR"] = str(d / "install_dir")
                    env["MTEVIL_RELEASES_API_URL"] = f"http://127.0.0.1:{port}/releases"
                    env["MTEVIL_RELEASE_BASE_URL"] = f"http://127.0.0.1:{port}/download"
                    proc = subprocess.run([bash_bin, str(pinned_path)], env=env, capture_output=True, text=True)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("/download/v0.1.0-alpha.6/setup.py", requested_paths)
                    self.assertNotIn("/releases", requested_paths)
                    self.assertEqual(pulled_file.read_text(encoding="utf-8").strip(), "ghcr.io/rsnest/mtevil:v0.1.0-alpha.6")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_traffic_snapshot_rendering_and_unavailable_metrics(self):
        # 1. When runtime stats are unavailable, all metrics render as "нет данных".
        out_none = setup.render_traffic_snapshot("edge", None, None)
        self.assertIn("клиент -> edge", out_none)
        self.assertIn("edge -> egress", out_none)
        self.assertIn("нет данных", out_none)
        self.assertNotIn("%", out_none)

        # 2. On edge, distinguish client -> edge from edge -> egress and never show retransmissions as packet-loss %.
        sample_stats = {
            "role": "edge",
            "started_unix_ms": 1700000000000,
            "ts_unix_ms": 1700000065000,
            "uptime_ms": 65000,
            "active_sessions": 3,
            "completed_sessions": 12,
            "failed_sessions": 2,
            "downstream_rx_bytes": 2048,
            "downstream_tx_bytes": 4096,
            "upstream_tx_bytes": 1536,
            "upstream_rx_bytes": 3584,
            "downstream_retrans_segs": 4,
            "upstream_retrans_segs": 1,
            "retrans_supported": True,
        }
        out_edge = setup.render_traffic_snapshot("edge", sample_stats, None)
        self.assertIn("только сокеты процесса mtevil", out_edge)
        self.assertIn("клиент -> edge", out_edge)
        self.assertIn("edge -> клиент", out_edge)
        self.assertIn("edge -> egress", out_edge)
        self.assertIn("egress -> edge", out_edge)
        self.assertIn("Активные сессии:   3", out_edge)
        self.assertIn("14 (успешно: 12, с ошибкой: 2)", out_edge)
        self.assertIn("4 сегм.", out_edge)
        self.assertIn("1 сегм.", out_edge)
        self.assertNotIn("%", out_edge)

        # 3. When retrans_supported is False, retransmissions show "нет данных".
        sample_no_retrans = dict(sample_stats, retrans_supported=False, downstream_retrans_segs=None, upstream_retrans_segs=None)
        out_no_ret = setup.render_traffic_snapshot("direct", sample_no_retrans, None)
        self.assertIn("Ретрансмиссии TCP (прокси -> клиент): нет данных", out_no_ret)
        self.assertIn("Ретрансмиссии TCP (прокси -> Telegram DC): нет данных", out_no_ret)

    def test_mtevilctl_status_update_rollback_and_traffic_commands(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text("services:\n  mtevil:\n    image: ${MTEVIL_IMAGE}\n", encoding="utf-8")
            (d / ".env").write_text(
                "MTEVIL_PROJECT=mtevil-direct\n"
                "MTEVIL_IMAGE=ghcr.io/rsnest/mtevil:v0.1.0-alpha.5\n"
                "MTEVIL_BIND=0.0.0.0\n"
                "MTEVIL_PORT=24443\n"
                "MTEVIL_PUBLIC_HOST=198.51.100.10\n",
                encoding="utf-8",
            )
            (d / "config.json").write_text(
                setup.json.dumps({"role": "direct", "listen": "0.0.0.0:24443", "sni": "example.com"}) + "\n",
                encoding="utf-8",
            )

            current_img = {"version": "v0.1.0-alpha.5", "id": "sha256:aaaa5555", "fail_healthy": False, "fail_e2e": False}
            pulled_images: list[str] = []
            tagged_images: list[tuple[str, str]] = []
            recreated_count = {"n": 0}
            probe_calls: list[str] = []

            def fake_run(argv, **kwargs):
                cmd = " ".join(argv)
                if "docker info" in cmd or "docker compose version" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "ok", "")
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "cid123\n", "")
                if argv[:2] == ["docker", "inspect"] and argv[2] == "cid123":
                    health = "starting" if current_img["fail_healthy"] else "healthy"
                    info = [{
                        "Image": current_img["id"],
                        "State": {
                            "Running": True,
                            "Status": "running",
                            "StartedAt": "2026-11-20T00:00:00Z",
                            "Health": {"Status": health},
                        },
                    }]
                    return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                if argv[:3] == ["docker", "image", "inspect"]:
                    target = argv[3]
                    if target in (current_img["id"], "ghcr.io/rsnest/mtevil:v0.1.0-alpha.5", "mtevil:rollback-mtevil-direct"):
                        ver = "v0.1.0-alpha.5" if "5555" in target or "alpha.5" in target or "rollback" in target else current_img["version"]
                        img_id = "sha256:aaaa5555" if ver == "v0.1.0-alpha.5" else "sha256:bbbb6666"
                        info = [{
                            "Id": img_id,
                            "RepoDigests": [f"ghcr.io/rsnest/mtevil@{img_id}"],
                            "Config": {"Labels": {"org.opencontainers.image.version": ver}},
                        }]
                        return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                    if "alpha.6" in target or target == "sha256:bbbb6666":
                        info = [{
                            "Id": "sha256:bbbb6666",
                            "RepoDigests": ["ghcr.io/rsnest/mtevil@sha256:bbbb6666"],
                            "Config": {"Labels": {"org.opencontainers.image.version": "v0.1.0-alpha.6"}},
                        }]
                        return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                    if "alpha.7" in target:
                        info = [{
                            "Id": "sha256:cccc7777",
                            "RepoDigests": ["ghcr.io/rsnest/mtevil@sha256:cccc7777"],
                            "Config": {"Labels": {"org.opencontainers.image.version": "v0.1.0-alpha.7"}},
                        }]
                        return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                    return subprocess.CompletedProcess(argv, 1, "", "not found")
                if argv[:2] == ["docker", "pull"]:
                    pulled_images.append(argv[2])
                    return subprocess.CompletedProcess(argv, 0, "pulled", "")
                if argv[:3] == ["docker", "image", "tag"]:
                    tagged_images.append((argv[3], argv[4]))
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "--check-config" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "configuration valid\n", "")
                if "up -d" in cmd:
                    recreated_count["n"] += 1
                    env_txt = (d / ".env").read_text(encoding="utf-8")
                    if "alpha.6" in env_txt:
                        current_img["version"] = "v0.1.0-alpha.6"
                        current_img["id"] = "sha256:bbbb6666"
                    elif "alpha.7" in env_txt:
                        current_img["version"] = "v0.1.0-alpha.7"
                        current_img["id"] = "sha256:cccc7777"
                        current_img["fail_healthy"] = True
                    elif "rollback" in env_txt or "alpha.5" in env_txt:
                        current_img["version"] = "v0.1.0-alpha.5"
                        current_img["id"] = "sha256:aaaa5555"
                        current_img["fail_healthy"] = False
                        current_img["fail_e2e"] = False
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "probe-telegram" in cmd:
                    probe_calls.append(current_img["version"])
                    if current_img["fail_e2e"]:
                        return subprocess.CompletedProcess(argv, 1, "", "probe_telegram_timeout")
                    return subprocess.CompletedProcess(argv, 0, '{"status":"ok","dc":2,"rtt_ms":42}\n', "")
                if "/var/lib/mtevil/runtime-stats.json" in cmd:
                    stats_json = setup.json.dumps({
                        "role": "direct",
                        "started_unix_ms": 1700000000000,
                        "ts_unix_ms": 1700000030000,
                        "uptime_ms": 30000,
                        "active_sessions": 2,
                        "completed_sessions": 5,
                        "failed_sessions": 0,
                        "downstream_rx_bytes": 10240,
                        "downstream_tx_bytes": 20480,
                        "upstream_tx_bytes": 9800,
                        "upstream_rx_bytes": 19900,
                        "downstream_retrans_segs": 0,
                        "upstream_retrans_segs": 0,
                        "retrans_supported": True,
                    })
                    return subprocess.CompletedProcess(argv, 0, stats_json, "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            fake_releases = [
                {
                    "tag_name": "v0.1.0-alpha.6",
                    "draft": False,
                    "assets": [
                        {"name": "install.sh", "state": "uploaded", "browser_download_url": "https://example.invalid/install.sh"},
                        {"name": "setup.py", "state": "uploaded", "browser_download_url": "https://example.invalid/setup.py"},
                    ],
                }
            ]

            with (
                mock.patch.object(setup, "run", side_effect=fake_run),
                mock.patch.object(setup, "fetch_json_url", return_value=fake_releases),
                mock.patch.dict(setup.os.environ, {"MTEVIL_SKIP_ASSET_DOWNLOAD": "1"}),
            ):
                # 0. Default stable channel refuses prerelease-only feed with clear opt-in hint.
                err_stable = io.StringIO()
                with contextlib.redirect_stderr(err_stable):
                    rc_stable = setup.main(["update", "--dir", str(d)])
                self.assertEqual(rc_stable, 1)
                self.assertIn("MTEVIL_CHANNEL=prerelease", err_stable.getvalue())
                self.assertIn("v0.1.0-alpha.6", err_stable.getvalue())

                # 1. Update with --prerelease from alpha.5 -> alpha.6 succeeds and saves alpha.5 rollback snapshot.
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = setup.main(["update", "--prerelease", "--dir", str(d)])
                self.assertEqual(rc, 0)
                self.assertIn("v0.1.0-alpha.5 -> v0.1.0-alpha.6", buf.getvalue())
                self.assertTrue((d / "rollback.json").is_file())
                rb_meta = setup.json.loads((d / "rollback.json").read_text(encoding="utf-8"))
                self.assertEqual(rb_meta["version"], "v0.1.0-alpha.5")
                self.assertEqual(recreated_count["n"], 1)

                # 2. Running update again when already on alpha.6 skips restart and preserves alpha.5 rollback!
                buf2 = io.StringIO()
                with contextlib.redirect_stdout(buf2):
                    rc2 = setup.main(["update", "--prerelease", "--dir", str(d)])
                self.assertEqual(rc2, 0)
                self.assertIn("Уже установлена актуальная версия v0.1.0-alpha.6", buf2.getvalue())
                self.assertEqual(recreated_count["n"], 1)
                rb_meta_after = setup.json.loads((d / "rollback.json").read_text(encoding="utf-8"))
                self.assertEqual(rb_meta_after["version"], "v0.1.0-alpha.5")

                # 3. Status shows running version v0.1.0-alpha.6, healthy, and rollback v0.1.0-alpha.5.
                buf_st = io.StringIO()
                with contextlib.redirect_stdout(buf_st):
                    rc_st = setup.main(["status", "--dir", str(d)])
                self.assertEqual(rc_st, 0)
                st_out = buf_st.getvalue()
                self.assertIn("v0.1.0-alpha.6", st_out)
                self.assertIn("healthy", st_out)
                self.assertIn("v0.1.0-alpha.5", st_out)

                # 4. Traffic and traf --live (2 iterations) show labeled metrics.
                buf_tr = io.StringIO()
                with contextlib.redirect_stdout(buf_tr):
                    rc_tr = setup.main(["traffic", "--dir", str(d)])
                self.assertEqual(rc_tr, 0)
                self.assertIn("Активные сессии:   2", buf_tr.getvalue())
                self.assertIn("клиент -> прокси", buf_tr.getvalue())

                buf_live = io.StringIO()
                with (
                    contextlib.redirect_stdout(buf_live),
                    mock.patch.object(setup.time, "sleep", return_value=None),
                ):
                    rc_live = setup.main(["traf", "--live", "--iterations", "2", "--dir", str(d)])
                self.assertEqual(rc_live, 0)
                self.assertIn("Динамика за последнюю секунду", buf_live.getvalue())

                # 5. Rollback restores v0.1.0-alpha.5 offline without calling fetch_json_url or docker pull.
                pulls_before = len(pulled_images)
                buf_rb = io.StringIO()
                with (
                    contextlib.redirect_stdout(buf_rb),
                    mock.patch.object(setup, "fetch_json_url", side_effect=AssertionError("rollback must be offline")),
                ):
                    rc_rb = setup.main(["rollback", "--dir", str(d)])
                self.assertEqual(rc_rb, 0)
                self.assertEqual(len(pulled_images), pulls_before)
                self.assertIn("Откат выполнен: работает версия v0.1.0-alpha.5", buf_rb.getvalue())
                self.assertEqual(current_img["version"], "v0.1.0-alpha.5")

                # 6. Failed update (alpha.7 fails wait_healthy) automatically rolls back to alpha.5!
                def fail_wait_healthy(_base, timeout_s=45):
                    if current_img["fail_healthy"]:
                        raise TimeoutError("not healthy")

                buf_fail = io.StringIO()
                err_fail = io.StringIO()
                with (
                    contextlib.redirect_stdout(buf_fail),
                    contextlib.redirect_stderr(err_fail),
                    mock.patch.object(setup, "wait_healthy", side_effect=fail_wait_healthy),
                    mock.patch.object(setup.time, "sleep", return_value=None),
                ):
                    rc_fail = setup.main(["update", "--version", "v0.1.0-alpha.7", "--dir", str(d)])
                self.assertEqual(rc_fail, 1)
                self.assertIn("Автоматический возврат предыдущей рабочей версии", err_fail.getvalue())
                self.assertEqual(current_img["version"], "v0.1.0-alpha.5")

                # 7. Healthy container that fails end-to-end Telegram probe 3 times triggers rollback and verifies restored container via E2E probe!
                current_img["fail_healthy"] = False
                probe_calls.clear()

                def up_with_e2e_failure(argv, **kwargs):
                    res = fake_run(argv, **kwargs)
                    if "up -d" in " ".join(argv) and current_img["version"] == "v0.1.0-alpha.7":
                        current_img["fail_healthy"] = False
                        current_img["fail_e2e"] = True
                    return res

                buf_e2e = io.StringIO()
                err_e2e = io.StringIO()
                with (
                    contextlib.redirect_stdout(buf_e2e),
                    contextlib.redirect_stderr(err_e2e),
                    mock.patch.object(setup, "run", side_effect=up_with_e2e_failure),
                    mock.patch.object(setup.time, "sleep", return_value=None),
                ):
                    rc_e2e = setup.main(["update", "--version", "v0.1.0-alpha.7", "--dir", str(d)])
                self.assertEqual(rc_e2e, 1)
                self.assertIn("Сквозная проверка Telegram не прошла 3 раза подряд", err_e2e.getvalue())
                self.assertIn("Сквозная проверка Telegram после отката пройдена", buf_e2e.getvalue())
                self.assertEqual(current_img["version"], "v0.1.0-alpha.5")
                self.assertEqual(probe_calls, ["v0.1.0-alpha.7", "v0.1.0-alpha.7", "v0.1.0-alpha.7", "v0.1.0-alpha.5"])

    def test_update_reexec_passes_version_and_aborts_safely_on_launch_failure(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            orig_env = (
                "MTEVIL_PROJECT=mtevil-direct\n"
                "MTEVIL_IMAGE=ghcr.io/rsnest/mtevil:v0.1.0-alpha.9\n"
                "MTEVIL_BIND=0.0.0.0\n"
                "MTEVIL_PORT=24443\n"
            )
            (d / "compose.yaml").write_text("services:\n  mtevil:\n    image: ${MTEVIL_IMAGE}\n", encoding="utf-8")
            (d / ".env").write_text(orig_env, encoding="utf-8")
            (d / "config.json").write_text(setup.json.dumps({"role": "direct"}) + "\n", encoding="utf-8")

            up_called = {"n": 0}
            exec_calls: list[tuple[str, list[str]]] = []

            def fake_run(argv, **kwargs):
                cmd = " ".join(argv)
                if "docker info" in cmd or "docker compose version" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "ok", "")
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "cid123\n", "")
                if argv[:2] == ["docker", "inspect"] and argv[2] == "cid123":
                    info = [{"Image": "sha256:9999", "State": {"Running": True, "Health": {"Status": "healthy"}}}]
                    return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                if argv[:3] == ["docker", "image", "inspect"]:
                    info = [{
                        "Id": "sha256:9999",
                        "RepoDigests": ["ghcr.io/rsnest/mtevil@sha256:9999"],
                        "Config": {"Labels": {"org.opencontainers.image.version": "v0.1.0-alpha.9"}},
                    }]
                    return subprocess.CompletedProcess(argv, 0, setup.json.dumps(info), "")
                if "py_compile" in cmd:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "up -d" in cmd:
                    up_called["n"] += 1
                return subprocess.CompletedProcess(argv, 0, "", "")

            fake_releases = [
                {
                    "tag_name": "v0.1.0-alpha.11",
                    "draft": False,
                    "assets": [
                        {"name": "install.sh", "state": "uploaded", "browser_download_url": "https://example.invalid/install.sh"},
                        {"name": "setup.py", "state": "uploaded", "browser_download_url": "https://example.invalid/setup.py"},
                    ],
                }
            ]

            def fake_download(url, dest, mode=None, expected_sha256=None):
                dest.write_text("#!/usr/bin/env python3\nprint('new setup')\n", encoding="utf-8")

            def fake_execv_fail(executable, argv):
                exec_calls.append((executable, list(argv)))
                raise OSError("exec failed")

            err = io.StringIO()
            with (
                mock.patch.object(setup, "run", side_effect=fake_run),
                mock.patch.object(setup, "fetch_json_url", return_value=fake_releases),
                mock.patch.object(setup, "fetch_release_checksums", return_value={"setup.py": "a" * 64, "mtevilctl": "b" * 64}),
                mock.patch.object(setup, "download_url_atomic", side_effect=fake_download),
                mock.patch.object(setup.os, "execv", side_effect=fake_execv_fail),
                contextlib.redirect_stderr(err),
            ):
                rc = setup.main(["update", "--prerelease", "--dir", str(d)])

            # 1. Must abort with rc=1, pass --version v0.1.0-alpha.11 and --reexec,
            #    and leave .env and running container completely untouched!
            self.assertEqual(rc, 1)
            self.assertEqual(len(exec_calls), 1)
            _, passed_argv = exec_calls[0]
            self.assertIn("--version", passed_argv)
            self.assertIn("v0.1.0-alpha.11", passed_argv)
            self.assertIn("--reexec", passed_argv)
            self.assertEqual(up_called["n"], 0)
            self.assertEqual((d / ".env").read_text(encoding="utf-8"), orig_env)
            self.assertIn("Текущий контейнер не затронут", err.getvalue())

            before = (d / "setup.py").read_bytes()
            with (
                mock.patch.object(setup, "run", side_effect=fake_run),
                mock.patch.object(setup, "fetch_json_url", return_value=fake_releases),
                mock.patch.object(setup, "fetch_release_checksums", return_value={"setup.py": "a" * 64, "mtevilctl": "b" * 64}),
                mock.patch.object(setup, "download_url_atomic", side_effect=setup.ChecksumError("контрольная сумма не совпала")),
                mock.patch.object(setup.os, "execv", side_effect=AssertionError("must not execute unverified setup.py")),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(setup.main(["update", "--prerelease", "--dir", str(d)]), 1)
            self.assertEqual((d / "setup.py").read_bytes(), before)
            self.assertEqual((d / ".env").read_text(encoding="utf-8"), orig_env)
            self.assertEqual(up_called["n"], 0)

            # 2. If --reexec is already set, it must NOT call os.execv again (no loop).
            exec_calls.clear()
            with (
                mock.patch.object(setup, "run", side_effect=fake_run),
                mock.patch.object(setup, "download_url_atomic", side_effect=AssertionError("must not download again on --reexec")),
                mock.patch.object(setup.os, "execv", side_effect=AssertionError("must not execv again on --reexec")),
                mock.patch.object(setup, "verify_telegram_e2e", return_value=(True, "ok")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
            ):
                rc2 = setup.main(["update", "--dir", str(d), "--version", "v0.1.0-alpha.11", "--reexec"])
            self.assertEqual(rc2, 0)
            self.assertEqual(up_called["n"], 1)

    def test_install_sh_release_channel_and_explicit_pin(self):
        bash_bin = "/bin/bash" if Path("/bin/bash").is_file() else None
        if bash_bin is None:
            self.skipTest("/bin/bash not available")

        install_text = (Path(__file__).resolve().parent / "install.sh").read_text(encoding="utf-8")

        import http.server
        import threading

        state = {"releases": []}

        def make_rel(tag: str) -> dict:
            return {
                "tag_name": tag,
                "draft": False,
                "prerelease": False,
                "assets": [
                    {"name": "install.sh", "state": "uploaded", "browser_download_url": f"http://127.0.0.1/{tag}/install.sh"},
                    {"name": "setup.py", "state": "uploaded", "browser_download_url": f"http://127.0.0.1/{tag}/setup.py"},
                ],
            }

        def release_assets(tag):
            return {
                "install.sh": install_text.replace(
                    'MTEVIL_PINNED_VERSION="__AUTO__"',
                    f'MTEVIL_PINNED_VERSION="{tag}"',
                    1,
                ).encode("utf-8"),
                "setup.py": f"import sys\nprint('SELECTED_TAG={tag}', 'ARGS=' + ' '.join(sys.argv[1:]))\n".encode("utf-8"),
                "mtevilctl": b"#!/bin/sh\n",
            }

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/releases":
                    body = setup.json.dumps(state["releases"]).encode("utf-8")
                else:
                    _, _, tag, name = self.path.split("/")
                    files = release_assets(tag)
                    if name == "SHA256SUMS":
                        if state.get("missing_manifest"):
                            self.send_error(404)
                            return
                        body = "".join(
                            f"{setup.hashlib.sha256(data).hexdigest()}  {asset}\n"
                            for asset, data in files.items()
                        ).encode("utf-8")
                    else:
                        body = files[name]
                        if state.get("tamper") == name:
                            body += b"tampered"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_port
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                inst = d / "install.sh"
                inst.write_text(install_text, encoding="utf-8", newline="\n")
                fake_bin = d / "bin"
                fake_bin.mkdir()
                pulled_file = d / "pulled.txt"
                fake_docker = fake_bin / "docker"
                fake_docker.write_text(
                    "#!/usr/bin/env bash\n"
                    'if [ "$1" = "pull" ]; then echo "${@: -1}" > "' + str(pulled_file).replace("\\", "/") + '"; exit 0; fi\n'
                    "exit 0\n",
                    encoding="utf-8",
                    newline="\n",
                )
                setup.os.chmod(fake_docker, 0o755)

                base_env = dict(setup.os.environ)
                base_env["PATH"] = f"{fake_bin}:{base_env.get('PATH', '')}"
                base_env["MTEVIL_RELEASES_API_URL"] = f"http://127.0.0.1:{port}/releases"
                base_env["MTEVIL_RELEASE_BASE_URL"] = f"http://127.0.0.1:{port}/download"
                for k in ("MTEVIL_VERSION", "MTVEIL_VERSION", "MTEVIL_CHANNEL", "MTVEIL_CHANNEL"):
                    base_env.pop(k, None)

                # Case 1: Newer prerelease alongside older stable -> default picks stable, channel=prerelease picks RC.
                state["releases"] = [make_rel("v0.1.0"), make_rel("v0.2.0-rc.1")]
                env1 = dict(base_env, MTEVIL_DIR=str(d / "case1"))
                p1 = subprocess.run([bash_bin, str(inst)], env=env1, capture_output=True, text=True)
                self.assertEqual(p1.returncode, 0, p1.stdout + p1.stderr)
                self.assertIn("SELECTED_TAG=v0.1.0", p1.stdout)
                self.assertEqual(pulled_file.read_text(encoding="utf-8").strip(), "ghcr.io/rsnest/mtevil:v0.1.0")

                env1b = dict(base_env, MTEVIL_DIR=str(d / "case1b"), MTEVIL_CHANNEL="prerelease")
                p1b = subprocess.run([bash_bin, str(inst)], env=env1b, capture_output=True, text=True)
                self.assertEqual(p1b.returncode, 0, p1b.stdout + p1b.stderr)
                self.assertIn("SELECTED_TAG=v0.2.0-rc.1", p1b.stdout)
                self.assertEqual(pulled_file.read_text(encoding="utf-8").strip(), "ghcr.io/rsnest/mtevil:v0.2.0-rc.1")

                # Reject a bad second asset before overwriting the installed helpers.
                installed = d / "case1b"
                before = (installed / "setup.py").read_bytes()
                state["tamper"] = "mtevilctl"
                p_bad = subprocess.run([bash_bin, str(inst)], env=env1b, capture_output=True, text=True)
                self.assertNotEqual(p_bad.returncode, 0)
                self.assertIn("контрольная сумма mtevilctl", p_bad.stderr)
                self.assertNotIn("SELECTED_TAG", p_bad.stdout)
                self.assertEqual((installed / "setup.py").read_bytes(), before)
                state.pop("tamper")

                state["missing_manifest"] = True
                p_missing = subprocess.run([bash_bin, str(inst)], env=env1b, capture_output=True, text=True)
                self.assertNotEqual(p_missing.returncode, 0)
                self.assertIn("HTTP Error 404", p_missing.stderr)
                self.assertNotIn("SELECTED_TAG", p_missing.stdout)
                state.pop("missing_manifest")

                # Case 2: Prerelease-only repository -> default fails clearly; --prerelease succeeds.
                state["releases"] = [make_rel("v0.1.0-alpha.11"), make_rel("v0.1.0-rc.1")]
                env2 = dict(base_env, MTEVIL_DIR=str(d / "case2"))
                p2 = subprocess.run([bash_bin, str(inst)], env=env2, capture_output=True, text=True)
                self.assertEqual(p2.returncode, 1)
                self.assertIn("MTEVIL_CHANNEL=prerelease", p2.stderr)
                self.assertIn("MTEVIL_VERSION=v0.1.0-rc.1", p2.stderr)

                env2b = dict(base_env, MTEVIL_DIR=str(d / "case2b"))
                p2b = subprocess.run([bash_bin, str(inst), "--prerelease"], env=env2b, capture_output=True, text=True)
                self.assertEqual(p2b.returncode, 0, p2b.stdout + p2b.stderr)
                self.assertIn("SELECTED_TAG=v0.1.0-rc.1", p2b.stdout)

                # Case 3: Explicit version pin works even on stable channel.
                env3 = dict(base_env, MTEVIL_DIR=str(d / "case3"), MTEVIL_VERSION="v0.1.0-alpha.11")
                p3 = subprocess.run([bash_bin, str(inst)], env=env3, capture_output=True, text=True)
                self.assertEqual(p3.returncode, 0, p3.stdout + p3.stderr)
                self.assertIn("SELECTED_TAG=v0.1.0-alpha.11", p3.stdout)
                self.assertEqual(pulled_file.read_text(encoding="utf-8").strip(), "ghcr.io/rsnest/mtevil:v0.1.0-alpha.11")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_simple_fresh_install_two_prompts_and_output_contract(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            prompts_seen: list[str] = []
            answers = iter(["", ""])  # Prompt 1: Enter (Simple [1]), Prompt 2: Enter (Confirm [Y/a/n])

            def fake_input(prompt=""):
                prompts_seen.append(prompt)
                return next(answers)

            def fake_run(argv, **_kwargs):
                cmd = " ".join(argv)
                if "link" in cmd:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="https://t.me/proxy?server=203.0.113.10&port=443&secret=ee11223344556677889900aabbccddeeff6578616d706c652e636f6d\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtevil-simple-2p", "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch("builtins.input", side_effect=fake_input),
                mock.patch.object(sys, "stdout", out_buf),
                mock.patch.object(sys, "stderr", err_buf),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value="203.0.113.10"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "ensure_generated_secret", return_value=True),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
                mock.patch.object(setup, "run", side_effect=fake_run),
            ):
                rc = setup.main()
            out = out_buf.getvalue()
            self.assertEqual(rc, 0, out + err_buf.getvalue())
            # Fresh simple install with detected IPv4 and free port 443 uses strictly 2 prompts!
            self.assertEqual(len(prompts_seen), 2, prompts_seen)
            self.assertNotIn("IP интерфейса", out)
            self.assertNotIn("Адрес HTTPS-cover (host:port)", out)
            self.assertNotIn("network-host", out)
            self.assertIn("203.0.113.10 (определён автоматически)", out)
            self.assertIn("443 (свободен)", out)
            self.assertIn("Docker healthcheck", out)
            self.assertIn("[1/4] Проверка конфигурации и HTTPS-cover", out)
            self.assertIn("[2/4] Запуск контейнера", out)
            self.assertIn("[3/4] Сквозная проверка связи с Telegram", out)
            self.assertIn("[4/4] Проверка порта на публичном адресе", out)
            self.assertIn("Проверено: прокси отвечает как Telegram", out)
            self.assertIn("Проверка порта пропущена (адрес не публичный)", out)
            self.assertIn(f"Каталог установки: {d.resolve()}", out)
            self.assertIn("Проверка статуса:", out)
            self.assertIn(
                "https://t.me/proxy?server=203.0.113.10&port=443&secret=ee11223344556677889900aabbccddeeff6578616d706c652e636f6d",
                out.splitlines(),
            )

    def test_public_port_check_states_and_nonfatal_telegram_probe_failure(self):
        # skipped: private/documentation and unresolved hosts never trigger a network connection.
        with mock.patch.object(setup.socket, "create_connection", side_effect=AssertionError("must not connect")):
            self.assertEqual(setup.check_public_port_reachable("10.0.0.5", 443)[0], "skipped")
            self.assertEqual(setup.check_public_port_reachable("203.0.113.10", 443)[0], "skipped")
        # ok / unreachable for a global address.
        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with mock.patch.object(setup.socket, "create_connection", return_value=_Conn()):
            self.assertEqual(setup.check_public_port_reachable("93.184.216.34", 443), ("ok", ""))
        with mock.patch.object(setup.socket, "create_connection", side_effect=OSError("timed out")):
            st, detail = setup.check_public_port_reachable("93.184.216.34", 443)
            self.assertEqual(st, "unreachable")
            self.assertIn("timed out", detail)

        # Wizard: failed Telegram probe and unreachable public port are warnings, not install failures,
        # and the Telegram link is still printed.
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)

            def fake_run(argv, **_kwargs):
                if "link" in " ".join(argv):
                    return subprocess.CompletedProcess(argv, 0, stdout="https://t.me/proxy?server=93.184.216.34&port=443&secret=ee00\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtevil-warn", "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO("1\ny\n")),
                mock.patch.object(sys, "stdout", out_buf),
                mock.patch.object(sys, "stderr", err_buf),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value="93.184.216.34"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "ensure_generated_secret", return_value=True),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
                mock.patch.object(setup, "verify_telegram_e2e", return_value=(False, "probe_telegram_timeout")),
                mock.patch.object(setup, "check_public_port_reachable", return_value=("unreachable", "timed out")),
                mock.patch.object(setup, "run", side_effect=fake_run),
            ):
                rc = setup.main()
            self.assertEqual(rc, 0, out_buf.getvalue() + err_buf.getvalue())
            self.assertIn("Не удалось получить ответ Telegram через прокси.", err_buf.getvalue())
            self.assertIn("probe_telegram_timeout", err_buf.getvalue())
            self.assertIn("Не удалось подключиться к 93.184.216.34:443 с самого сервера", out_buf.getvalue())
            self.assertIn("ufw allow 443/tcp", out_buf.getvalue())
            self.assertIn("https://t.me/proxy?server=93.184.216.34&port=443&secret=ee00", out_buf.getvalue().splitlines())

    def test_simple_missing_ip_occupied_port_invalid_input_switch_and_cancel(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            # 1. Invalid mode choice -> 1 (simple) -> missing IPv4 -> enter 198.51.100.5 ->
            #    port 443 busy -> accept suggested 25443 -> invalid confirm 'zzz' -> cancel 'n'.
            stdin_cancel = "99\n1\n198.51.100.5\n25443\nzzz\nn\n"
            out_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_cancel)),
                mock.patch.object(sys, "stdout", out_buf),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value=None),
                mock.patch.object(setup, "is_port_available", side_effect=lambda _ip, port: port != 443),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
            ):
                rc = setup.main()
            out = out_buf.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn("Некорректный выбор: введите 1", out)
            self.assertIn("Не удалось автоматически определить публичный IPv4", out)
            self.assertIn("Порт 443 уже занят на этом сервере.", out)
            self.assertIn("Некорректный выбор: введите y", out)
            self.assertIn("Отменено без изменений.", out)
            self.assertFalse((d / "config.json").exists())

            # 2. Switch from Simple confirmation ('a') to Advanced, verify detected IP/port carried over, then cancel at final confirm.
            # Mode 1 -> Simple confirm 'a' -> Advanced role 1 -> accept host/port/bind -> net-host n -> accept sni/cover -> cancel n.
            stdin_switch = "1\na\n1\n\n\n\nn\n\n\nn\n"
            out_sw = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_switch)),
                mock.patch.object(sys, "stdout", out_sw),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value="203.0.113.20"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
            ):
                rc_sw = setup.main()
            self.assertEqual(rc_sw, 0)
            self.assertIn("Шаг 1. Роль сервера", out_sw.getvalue())
            self.assertIn("203.0.113.20:443", out_sw.getvalue())
            self.assertFalse((d / "config.json").exists())

    def test_advanced_edge_egress_rerun_preservation_and_flag_conflicts(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            # 1. Conflicting --mode simple with --role edge or --network-host fails explicitly.
            err1 = io.StringIO()
            with mock.patch.object(sys, "stderr", err1):
                rc1 = setup.main(["--dir", str(d), "--mode", "simple", "--role", "edge"])
            self.assertEqual(rc1, 1)
            self.assertIn("Конфликт параметров", err1.getvalue())

            err2 = io.StringIO()
            with mock.patch.object(sys, "stderr", err2):
                rc2 = setup.main(["--dir", str(d), "--mode", "simple", "--network-host"])
            self.assertEqual(rc2, 1)
            self.assertIn("Конфликт параметров", err2.getvalue())

            # 2. Existing installation with network_mode: host + custom SNI/cover/bind:
            #    declining reconfigure leaves everything intact; accepting in Simple mode preserves all existing settings!
            (d / "compose.yaml").write_text("services:\n  mtevil:\n    network_mode: host\n", encoding="utf-8")
            (d / ".env").write_text(
                "MTEVIL_PROJECT=mtevil-keep\nMTEVIL_IMAGE=mtevil:v0.1.0\nMTEVIL_BIND=10.0.0.5\nMTEVIL_PORT=8443\nMTEVIL_PUBLIC_HOST=198.51.100.77\n",
                encoding="utf-8",
            )
            (d / "config.json").write_text(
                setup.json.dumps({"role": "direct", "sni": "cdn.example.org", "cover": "cdn.example.org:443"}) + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO("n\n")),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
            ):
                self.assertEqual(setup.main(), 0)

            def fake_run_ok(argv, **_kwargs):
                if "link" in " ".join(argv):
                    return subprocess.CompletedProcess(argv, 0, stdout="https://t.me/proxy?server=198.51.100.77&port=8443&secret=ee00\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            # Confirm reconfigure (y) -> mode 1 (simple) -> confirm (y): preserves host networking, bind, SNI, cover, port, public host!
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO("y\n1\ny\n")),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=True),
                mock.patch.object(setup, "ensure_generated_secret", return_value=False),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
                mock.patch.object(setup, "run", side_effect=fake_run_ok),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("network_mode: host", (d / "compose.yaml").read_text(encoding="utf-8"))
            new_cfg = setup.json.loads((d / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(new_cfg["sni"], "cdn.example.org")
            self.assertEqual(new_cfg["listen"], "10.0.0.5:8443")

            # 3. Legacy --role egress skips mode & role prompts and validates invalid inputs with retry.
            d_eg = Path(td) / "egress"
            # invalid IP 0.0.0.0 -> valid 10.203.0.5 -> port 29443 -> net-host n -> confirm n (cancel cleanly)
            stdin_eg = "0.0.0.0\n10.203.0.5\n29443\nn\nn\n"
            out_eg = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_eg), "--role", "egress", "--image", "mtevil:v0.1.0", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO(stdin_eg)),
                mock.patch.object(sys, "stdout", out_eg),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("Шаг 2. Сеть и адрес выхода", out_eg.getvalue())
            self.assertIn("10.203.0.5:29443", out_eg.getvalue())

    def test_banner_tty_no_color_dumb_ascii_and_install_sh_bootstrap_once(self):
        # Unit checks for banner formatting, NO_COLOR, TERM=dumb, ASCII fallback, and non-TTY silence.
        b_color = setup.render_banner("v0.1.0", color=True, unicode_ok=True)
        self.assertIn("\033[1;32m", b_color)
        self.assertIn("mtevil", b_color)
        self.assertIn("v0.1.0", b_color)

        b_ascii = setup.render_banner("v0.1.0", color=False, unicode_ok=False)
        self.assertNotIn("\x1b[", b_ascii)
        self.assertTrue(b_ascii.isascii())
        self.assertIn("mtevil v0.1.0", b_ascii)

        non_tty_buf = io.StringIO()
        with mock.patch.object(sys, "stdout", non_tty_buf), mock.patch.dict(setup.os.environ, {}, clear=False):
            setup.os.environ.pop("MTEVIL_BANNER_SHOWN", None)
            setup.print_wizard_banner("ghcr.io/rsnest/mtevil:v0.1.0")
        self.assertEqual(non_tty_buf.getvalue(), "")

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        with mock.patch.object(sys, "stdout", FakeTTY()), mock.patch.dict(setup.os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(setup.use_color())
        with mock.patch.object(sys, "stdout", FakeTTY()), mock.patch.dict(setup.os.environ, {"TERM": "dumb"}):
            setup.os.environ.pop("NO_COLOR", None)
            self.assertFalse(setup.use_color())

        # On Linux with /bin/bash and pty: verify banner prints ONCE across bootstrap -> pinned install.sh -> setup.py,
        # --mode simple is forwarded, NO_COLOR omits ANSI, and non-TTY omits banner.
        bash_bin = "/bin/bash" if Path("/bin/bash").is_file() else None
        if bash_bin is None:
            return

        import http.server
        import pty
        import select
        import threading

        install_text = (Path(__file__).resolve().parent / "install.sh").read_text(encoding="utf-8")

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/releases":
                    body = setup.json.dumps([{
                        "tag_name": "v0.1.0",
                        "draft": False,
                        "prerelease": False,
                        "assets": [
                            {"name": "install.sh", "state": "uploaded", "browser_download_url": "http://127.0.0.1/v0.1.0/install.sh"},
                            {"name": "setup.py", "state": "uploaded", "browser_download_url": "http://127.0.0.1/v0.1.0/setup.py"},
                        ],
                    }]).encode("utf-8")
                elif self.path == "/download/v0.1.0/install.sh":
                    body = install_text.replace(
                        'MTEVIL_PINNED_VERSION="__AUTO__"',
                        'MTEVIL_PINNED_VERSION="v0.1.0"',
                        1,
                    ).encode("utf-8")
                elif self.path == "/download/v0.1.0/setup.py":
                    body = (
                        "import os, sys\n"
                        "print('BANNER_SHOWN=' + os.environ.get('MTEVIL_BANNER_SHOWN', ''))\n"
                        "print('SETUP_ARGS=' + ' '.join(sys.argv[1:]))\n"
                    ).encode("utf-8")
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_port
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                inst = d / "install.sh"
                inst.write_text(install_text, encoding="utf-8", newline="\n")
                fake_bin = d / "bin"
                fake_bin.mkdir()
                fake_docker = fake_bin / "docker"
                fake_docker.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
                setup.os.chmod(fake_docker, 0o755)

                base_env = dict(setup.os.environ)
                base_env["PATH"] = f"{fake_bin}:{base_env.get('PATH', '')}"
                base_env["MTEVIL_DIR"] = str(d / "inst_dir")
                base_env["MTEVIL_RELEASES_API_URL"] = f"http://127.0.0.1:{port}/releases"
                base_env["MTEVIL_RELEASE_BASE_URL"] = f"http://127.0.0.1:{port}/download"
                for k in ("MTEVIL_VERSION", "MTVEIL_VERSION", "MTEVIL_CHANNEL", "MTVEIL_CHANNEL", "MTEVIL_BANNER_SHOWN", "NO_COLOR"):
                    base_env.pop(k, None)

                def run_in_pty(extra_env: dict[str, str], extra_args: list[str]) -> str:
                    master_fd, slave_fd = pty.openpty()
                    env = dict(base_env, **extra_env)
                    proc = subprocess.Popen(
                        [bash_bin, str(inst)] + extra_args,
                        env=env,
                        stdin=slave_fd,
                        stdout=slave_fd,
                        stderr=slave_fd,
                        close_fds=True,
                    )
                    setup.os.close(slave_fd)
                    chunks: list[bytes] = []
                    try:
                        while True:
                            r, _, _ = select.select([master_fd], [], [], 0.2)
                            if r:
                                try:
                                    data = setup.os.read(master_fd, 4096)
                                    if not data:
                                        break
                                    chunks.append(data)
                                except OSError:
                                    break
                            elif proc.poll() is not None:
                                break
                    finally:
                        setup.os.close(master_fd)
                    proc.wait(timeout=10)
                    self.assertEqual(proc.returncode, 0, b"".join(chunks).decode("utf-8", errors="ignore"))
                    return b"".join(chunks).decode("utf-8", errors="ignore")

                # 1. Interactive TTY with NO_COLOR=1 across bootstrap -> pinned exec: banner printed ONCE, zero ANSI, --mode forwarded.
                out_nc = run_in_pty({"NO_COLOR": "1", "LANG": "C.UTF-8"}, ["--mode", "simple"])
                self.assertEqual(out_nc.count("mtevil v0.1.0"), 1, out_nc)
                self.assertNotIn("\x1b[", out_nc)
                self.assertIn("BANNER_SHOWN=1", out_nc)
                self.assertIn("--mode simple", out_nc)

                # 2. Non-TTY call omits decorative banner completely.
                p_nontty = subprocess.run([bash_bin, str(inst), "--mode", "advanced"], env=base_env, capture_output=True, text=True)
                self.assertEqual(p_nontty.returncode, 0, p_nontty.stdout + p_nontty.stderr)
                self.assertNotIn("▄▄▄▄▄", p_nontty.stdout)
                self.assertNotIn("__ __", p_nontty.stdout)
                self.assertIn("--mode advanced", p_nontty.stdout)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_network_host_unprivileged_port_check_and_failed_logs_before_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            # 1. Missing / unreadable ip_unprivileged_port_start: warns cleanly and keeps host mode.
            out_none = io.StringIO()
            with (
                contextlib.redirect_stdout(out_none),
                mock.patch.object(setup, "read_unprivileged_port_start", return_value=None),
            ):
                p, nh = setup.resolve_network_host_port(d, "mtevil-direct", "0.0.0.0", 443, True)
            self.assertEqual((p, nh), (443, True))
            self.assertIn("ip_unprivileged_port_start", out_none.getvalue())

            # 2. Port 443 < 1024 without --network-host: choice 1 switches to bridge keeping port 443.
            out_br = io.StringIO()
            with (
                contextlib.redirect_stdout(out_br),
                mock.patch.object(sys, "stdin", io.StringIO("1\n")),
                mock.patch.object(setup, "read_unprivileged_port_start", return_value=1024),
            ):
                p, nh = setup.resolve_network_host_port(d, "mtevil-direct", "0.0.0.0", 443, True, explicit_network_host=False)
            self.assertEqual((p, nh), (443, False))
            self.assertIn("ip_unprivileged_port_start = 1024", out_br.getvalue())

            # 3. Explicit --network-host: declining bridge confirmation, then choice 2 rejects 80 (< 1024) and accepts 25443.
            out_exp = io.StringIO()
            with (
                contextlib.redirect_stdout(out_exp),
                mock.patch.object(sys, "stdin", io.StringIO("1\nn\n2\n80\n25443\n")),
                mock.patch.object(setup, "read_unprivileged_port_start", return_value=1024),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
            ):
                p, nh = setup.resolve_network_host_port(d, "mtevil-direct", "0.0.0.0", 443, True, explicit_network_host=True)
            self.assertEqual((p, nh), (25443, True))
            self.assertIn("Флаг --network-host задан явно", out_exp.getvalue())
            self.assertIn("для режима host требуется порт >= 1024", out_exp.getvalue())

            # 4. print_failed_container_logs handles OSError cleanly without blocking rollback,
            #    and prints tail=30 logs when available.
            err_os = io.StringIO()
            with (
                contextlib.redirect_stderr(err_os),
                mock.patch.object(setup, "run", side_effect=OSError("docker unavailable")),
            ):
                setup.print_failed_container_logs(["docker", "compose", "-f", str(d / "compose.yaml")])
            self.assertIn("Не удалось прочитать логи нового контейнера", err_os.getvalue())

            err_ok = io.StringIO()
            with (
                contextlib.redirect_stderr(err_ok),
                mock.patch.object(setup, "run", return_value=subprocess.CompletedProcess([], 0, stdout="bind 0.0.0.0:443 permission denied\n", stderr="")) as mock_run,
            ):
                setup.print_failed_container_logs(["docker", "compose", "-f", str(d / "compose.yaml")])
            self.assertIn("bind 0.0.0.0:443 permission denied", err_ok.getvalue())
            called_argv = mock_run.call_args.args[0]
            self.assertIn("--no-color", called_argv)
            self.assertIn("--tail=30", called_argv)

            # 5. Simple mode 's' shortcut changes SNI/cover inline and omits legacy client_mss=100;
            #    strip_legacy_default_mss removes legacy 100/1380 on update while keeping custom values.
            d_sni = d / "simple_sni"
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_sni), "--image", "mtevil:v0.1.4", "--no-build"]),
                mock.patch.object(sys, "stdin", io.StringIO("1\ns\nya.ru\ny\n")),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(sys, "stderr", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "detect_local_global_ipv4", return_value="203.0.113.55"),
                mock.patch.object(setup, "is_port_available", return_value=True),
                mock.patch.object(setup, "deployment_owns_port", return_value=False),
                mock.patch.object(setup, "ensure_generated_secret", return_value=True),
                mock.patch.object(setup, "volume_file_exists", return_value=True),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
                mock.patch.object(setup, "verify_telegram_e2e", return_value=(True, "ok")),
                mock.patch.object(setup, "run", return_value=subprocess.CompletedProcess([], 0, stdout="https://t.me/proxy?server=203.0.113.55&port=443&secret=ee00\n", stderr="")),
            ):
                self.assertEqual(setup.main(), 0)
            sni_cfg = setup.json.loads((d_sni / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(sni_cfg["sni"], "ya.ru")
            self.assertEqual(sni_cfg["cover"], "ya.ru:443")
            self.assertNotIn("client_mss", sni_cfg)
            self.assertNotIn("client_mss_bulk", sni_cfg)

            legacy_cfg = d / "legacy_cfg.json"
            legacy_cfg.write_text('{"role":"direct","client_mss":100,"client_mss_bulk":1380}\n', encoding="utf-8")
            self.assertTrue(setup.strip_legacy_default_mss(legacy_cfg))
            cleaned = setup.json.loads(legacy_cfg.read_text(encoding="utf-8"))
            self.assertNotIn("client_mss", cleaned)
            self.assertNotIn("client_mss_bulk", cleaned)

    def test_mtevilctl_link_sni_user_and_setup_commands(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text("services:\n  mtevil:\n    image: mtevil:v0.1.5\n", encoding="utf-8")
            (d / ".env").write_text(
                "MTEVIL_PROJECT=mtevil-direct\nMTEVIL_IMAGE=mtevil:v0.1.5\nMTEVIL_BIND=0.0.0.0\nMTEVIL_PORT=443\nMTEVIL_PUBLIC_HOST=203.0.113.77\n",
                encoding="utf-8",
            )
            (d / "config.json").write_text(
                '{"role":"direct","sni":"example.com","cover":"example.com:443","users_file":"/var/lib/mtevil/users.json"}\n',
                encoding="utf-8",
            )

            # 1. prompt_sni_choice supports numbered quick-pick (1 -> ya.ru, 2 -> vk.com) and custom hostname.
            with mock.patch.object(sys, "stdin", io.StringIO("1\n")), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(setup.prompt_sni_choice("example.com"), "ya.ru")
            with mock.patch.object(sys, "stdin", io.StringIO("2\n")), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(setup.prompt_sni_choice("example.com"), "vk.com")
            with mock.patch.object(sys, "stdin", io.StringIO("custom.example.org\n")), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(setup.prompt_sni_choice("example.com"), "custom.example.org")

            # 2. mtevilctl link (--sni ya.ru) passes --sni to mtevil link and prints the link.
            out_link = io.StringIO()
            def fake_link_run(argv, **_kw):
                cmd = " ".join(argv)
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="cid123\n", stderr="")
                if "mtevil link" in cmd:
                    self.assertIn("--sni ya.ru", cmd)
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="https://t.me/proxy?server=203.0.113.77&port=443&secret=ee00112233445566778899aabbccddeeff79612e7275\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with (
                mock.patch.object(sys, "argv", ["setup.py", "link", "--dir", str(d), "--sni", "ya.ru"]),
                mock.patch.object(sys, "stdout", out_link),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_link_run),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("79612e7275", out_link.getvalue())

            # 3. mtevilctl sni ya.ru saves both new_sni (ya.ru) and old_sni (example.com) in allowed-sni.txt,
            #    updates config.json with single hostname "ya.ru" (preserving 100% rollback compatibility),
            #    recreates container, and prints the new link + note that old links keep working.
            recorded_volume: dict[str, str] = {}
            def fake_sni_run(argv, **kw):
                cmd = " ".join(argv)
                if "test -s /var/lib/mtevil/allowed-sni.txt" in cmd:
                    return subprocess.CompletedProcess(argv, 0 if "allowed-sni.txt" in recorded_volume else 1, stdout="", stderr="")
                if "/bin/cat /var/lib/mtevil/allowed-sni.txt" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout=recorded_volume.get("allowed-sni.txt", ""), stderr="")
                if "cat > /var/lib/mtevil/allowed-sni.txt" in cmd:
                    recorded_volume["allowed-sni.txt"] = kw.get("input_text") or ""
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="cid123\n", stderr="")
                if "mtevil link" in cmd:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="https://t.me/proxy?server=203.0.113.77&port=443&secret=ee00112233445566778899aabbccddeeff79612e7275\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            out_sni = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "sni", "ya.ru", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", out_sni),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "check_cover_from_container", return_value=(True, "")),
                mock.patch.object(setup, "wait_healthy", return_value=None),
                mock.patch.object(setup, "verify_telegram_e2e", return_value=(True, "DC 2 RTT 8ms")),
                mock.patch.object(setup, "run", side_effect=fake_sni_run),
            ):
                self.assertEqual(setup.main(), 0)
            updated_cfg = setup.json.loads((d / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(updated_cfg["sni"], "ya.ru")
            self.assertEqual(updated_cfg["cover"], "ya.ru:443")
            self.assertIn("ya.ru", recorded_volume.get("allowed-sni.txt", ""))
            self.assertIn("example.com", recorded_volume.get("allowed-sni.txt", ""))
            self.assertIn("Прежние ссылки клиентов со старым SNI (example.com) продолжают работать", out_sni.getvalue())

            # 4. mtevilctl user add/list/del
            out_user = io.StringIO()
            def fake_user_run(argv, **_kw):
                cmd = " ".join(argv)
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="cid123\n", stderr="")
                if "user-add" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="user 'phone' added\n", stderr="")
                if "mtevil link" in cmd:
                    self.assertIn("--user phone", cmd)
                    return subprocess.CompletedProcess(argv, 0, stdout="phone: https://t.me/proxy?server=203.0.113.77&port=443&secret=eeaa\n", stderr="")
                if "user-list" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="phone\n", stderr="")
                if "user-del" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="user 'phone' deleted\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with (
                mock.patch.object(sys, "argv", ["setup.py", "user", "add", "phone", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", out_user),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_user_run),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("Пользователь 'phone' добавлен", out_user.getvalue())
            self.assertIn("phone: https://t.me/proxy", out_user.getvalue())

            out_list = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "user", "list", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", out_list),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_user_run),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("- phone", out_list.getvalue())

            out_del = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "user", "del", "phone", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", out_del),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_user_run),
            ):
                self.assertEqual(setup.main(), 0)
            self.assertIn("Пользователь 'phone' удалён", out_del.getvalue())

    def test_state_ro_user_and_sni_use_init_service_and_replay_stats_paths(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            repo_root = Path(__file__).resolve().parent.parent
            compose_text = setup.render_compose(repo_root, d, "direct", include_build=False)
            (d / "compose.yaml").write_text(compose_text, encoding="utf-8")
            (d / ".env").write_text(
                "MTEVIL_PROJECT=mtevil-ro\nMTEVIL_IMAGE=mtevil:v0.2.0-rc.1\nMTEVIL_BIND=0.0.0.0\nMTEVIL_PORT=443\nMTEVIL_PUBLIC_HOST=203.0.113.77\n",
                encoding="utf-8",
            )
            (d / "config.json").write_text(
                '{"role":"direct","sni":"example.com","cover":"example.com:443","users_file":"/var/lib/mtevil/users.json","replay_file":"/var/lib/mtevil-replay/replay.bin"}\n',
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run(argv, **_kw):
                calls.append(list(argv))
                cmd = " ".join(argv)
                if "ps -q" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="cid999\n", stderr="")
                if "user-add" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")
                if "mtevil link" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="alice: https://t.me/proxy?server=203.0.113.77&port=443&secret=eeaa\n", stderr="")
                if "user-del" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with (
                mock.patch.object(sys, "argv", ["setup.py", "user", "add", "alice", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_run),
            ):
                self.assertEqual(setup.main(), 0)
            add_cmds = [" ".join(c) for c in calls if "user-add" in " ".join(c)]
            self.assertEqual(len(add_cmds), 1)
            self.assertIn(" run --rm -T --no-deps --entrypoint /usr/local/bin/mtevil init user-add ", add_cmds[0])

            calls.clear()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "user", "del", "alice", "--dir", str(d)]),
                mock.patch.object(sys, "stdout", io.StringIO()),
                mock.patch.object(setup, "check_prerequisites"),
                mock.patch.object(setup, "run", side_effect=fake_run),
            ):
                self.assertEqual(setup.main(), 0)
            del_cmds = [" ".join(c) for c in calls if "user-del" in " ".join(c)]
            self.assertEqual(len(del_cmds), 1)
            self.assertIn(" run --rm -T --no-deps --entrypoint /usr/local/bin/mtevil init user-del ", del_cmds[0])

            # Verify v0.1.5 -> v0.2.0 migration across:
            # 1) standard compose, 2) customized compose (+ .pre-v0.2 backup preservation on retry),
            # 3) host-network edge compose, 4) corrupted compose (fails before touching files or stopping container).
            d_std = d / "mig_std"
            d_std.mkdir()
            std_compose = (
                "name: ${MTEVIL_PROJECT:-mtevil-direct}\n\n"
                "services:\n"
                "  mtevil:\n"
                "    image: ${MTEVIL_IMAGE:-ghcr.io/rsnest/mtevil:v0.1.5}\n"
                "    ports:\n"
                '      - "0.0.0.0:443:24443/tcp"\n'
                "    volumes:\n"
                "      - ./config.json:/etc/mtevil/config.json:ro\n"
                "      - state:/var/lib/mtevil\n\n"
                "volumes:\n"
                "  state:\n"
            )
            std_cfg = setup.json.dumps({"role": "direct", "listen": "0.0.0.0:24443", "replay_file": "/var/lib/mtevil/replay.bin"}) + "\n"
            (d_std / "compose.yaml").write_text(std_compose, encoding="utf-8")
            (d_std / "config.json").write_text(std_cfg, encoding="utf-8")
            self.assertTrue(setup.migrate_compose_and_replay_on_update(d_std, d_std / "config.json", d_std / "compose.yaml"))
            self.assertEqual((d_std / "compose.yaml.pre-v0.2").read_text(encoding="utf-8"), std_compose)
            self.assertEqual((d_std / "config.json.pre-v0.2").read_text(encoding="utf-8"), std_cfg)
            std_after = (d_std / "compose.yaml").read_text(encoding="utf-8")
            self.assertIn("state:/var/lib/mtevil:ro", std_after)
            self.assertIn("replay:/var/lib/mtevil-replay", std_after)
            self.assertIn("\n  init:\n", std_after)
            self.assertIn("\n  replay:\n", std_after)
            self.assertEqual(setup.json.loads((d_std / "config.json").read_text(encoding="utf-8"))["replay_file"], "/var/lib/mtevil-replay/replay.bin")
            self.assertFalse(setup.migrate_compose_and_replay_on_update(d_std, d_std / "config.json", d_std / "compose.yaml"))

            # 2) Custom compose: ports, environment, extra volumes, ulimits, labels, cpus/mem, extra service preserved!
            d_cust = d / "mig_custom"
            d_cust.mkdir()
            cust_compose = (
                "name: ${MTEVIL_PROJECT:-mtevil-custom}\n\n"
                "services:\n"
                "  mtevil:\n"
                "    image: ${MTEVIL_IMAGE:-ghcr.io/rsnest/mtevil:v0.1.5}\n"
                "    ports:\n"
                '      - "127.0.0.1:8443:24443/tcp"\n'
                "    environment:\n"
                "      - CUSTOM_ENV=keep_me\n"
                "    labels:\n"
                '      com.example.role: "custom-proxy"\n'
                "    cpus: \"1.50\"\n"
                "    mem_limit: 512m\n"
                "    ulimits:\n"
                "      nofile:\n"
                "        soft: 16384\n"
                "        hard: 16384\n"
                "    volumes:\n"
                "      - ./config.json:/etc/mtevil/config.json:ro\n"
                "      - state:/var/lib/mtevil\n"
                "      - ./extra-certs:/etc/extra:ro\n"
                "  sidecar:\n"
                "    image: alpine:3.20\n"
                '    command: ["sleep", "infinity"]\n\n'
                "volumes:\n"
                "  state:\n"
                "  custom_vol:\n"
            )
            (d_cust / "compose.yaml").write_text(cust_compose, encoding="utf-8")
            (d_cust / "config.json").write_text(std_cfg, encoding="utf-8")
            self.assertTrue(setup.migrate_compose_and_replay_on_update(d_cust, d_cust / "config.json", d_cust / "compose.yaml"))
            cust_after = (d_cust / "compose.yaml").read_text(encoding="utf-8")
            for must_keep in (
                '127.0.0.1:8443:24443/tcp',
                'CUSTOM_ENV=keep_me',
                'com.example.role: "custom-proxy"',
                'cpus: "1.50"',
                'mem_limit: 512m',
                'soft: 16384',
                './extra-certs:/etc/extra:ro',
                '  sidecar:',
                '  custom_vol:',
                'state:/var/lib/mtevil:ro',
                'replay:/var/lib/mtevil-replay',
                '  init:',
                '  replay:',
            ):
                self.assertIn(must_keep, cust_after)
            # Retry after modifying compose.yaml must NOT overwrite existing .pre-v0.2 backup!
            (d_cust / "compose.yaml").write_text(cust_compose.replace("CUSTOM_ENV=keep_me", "CUSTOM_ENV=retry"), encoding="utf-8")
            self.assertTrue(setup.migrate_compose_and_replay_on_update(d_cust, d_cust / "config.json", d_cust / "compose.yaml"))
            self.assertIn("CUSTOM_ENV=keep_me", (d_cust / "compose.yaml.pre-v0.2").read_text(encoding="utf-8"))

            # 3) Host-network edge compose
            d_edge = d / "mig_edge"
            d_edge.mkdir()
            edge_compose = (
                "services:\n"
                "  mtevil:\n"
                "    image: ${MTEVIL_IMAGE}\n"
                "    network_mode: host\n"
                "    volumes:\n"
                "      - ./config.json:/etc/mtevil/config.json:ro\n"
                "      - state:/var/lib/mtevil\n"
                "    healthcheck:\n"
                '      test: [CMD, /usr/local/bin/mtevil, health, --address, "127.0.0.1:443"]\n'
                "volumes:\n"
                "  state:\n"
            )
            (d_edge / "compose.yaml").write_text(edge_compose, encoding="utf-8")
            (d_edge / "config.json").write_text(
                setup.json.dumps({"role": "edge", "listen": "0.0.0.0:443", "replay_file": "/var/lib/mtevil/replay.bin"}) + "\n",
                encoding="utf-8",
            )
            self.assertTrue(setup.migrate_compose_and_replay_on_update(d_edge, d_edge / "config.json", d_edge / "compose.yaml"))
            edge_after = (d_edge / "compose.yaml").read_text(encoding="utf-8")
            self.assertIn("network_mode: host", edge_after)
            self.assertIn('"127.0.0.1:443"', edge_after)
            self.assertIn("state:/var/lib/mtevil:ro", edge_after)
            self.assertIn("replay:/var/lib/mtevil-replay", edge_after)

            # 4) Corrupted compose (tab indentation / missing volumes section) -> MigrationError without touching files!
            for bad_name, bad_yaml in (
                ("bad_tab", "services:\n\tmtevil:\n\t\tvolumes:\n\t\t\t- state:/var/lib/mtevil\nvolumes:\n  state:\n"),
                ("bad_no_vols", "services:\n  mtevil:\n    volumes:\n      - state:/var/lib/mtevil\n"),
            ):
                d_bad = d / bad_name
                d_bad.mkdir()
                (d_bad / "compose.yaml").write_text(bad_yaml, encoding="utf-8")
                (d_bad / "config.json").write_text(std_cfg, encoding="utf-8")
                with self.assertRaises(setup.MigrationError):
                    setup.migrate_compose_and_replay_on_update(d_bad, d_bad / "config.json", d_bad / "compose.yaml")
                self.assertEqual((d_bad / "compose.yaml").read_text(encoding="utf-8"), bad_yaml)
                self.assertEqual((d_bad / "config.json").read_text(encoding="utf-8"), std_cfg)
                self.assertFalse((d_bad / "compose.yaml.pre-v0.2").exists())

    def test_release_publish_flags_and_updater_channel_selection(self):
        # 1. Verify compute_release_publish_flags across prereleases, newer stable, older stable, and draft handling.
        existing = [
            {"tagName": "v0.1.5", "isDraft": False, "isPrerelease": False},
        ]
        # Prereleases (RC, alpha, beta) MUST publish as prerelease and explicitly NOT Latest.
        self.assertEqual(
            setup.compute_release_publish_flags("v0.2.0-rc.1", existing),
            ("--prerelease=true", "--latest=false"),
        )
        self.assertEqual(
            setup.compute_release_publish_flags("v0.1.0-alpha.6", existing),
            ("--prerelease=true", "--latest=false"),
        )
        self.assertEqual(
            setup.compute_release_publish_flags("v0.2.0-alpha.1", existing),
            ("--prerelease=true", "--latest=false"),
        )
        self.assertEqual(
            setup.compute_release_publish_flags("v0.2.0-beta.1", existing),
            ("--prerelease=true", "--latest=false"),
        )
        # Newer stable v0.2.0 becomes Latest (even when v0.2.0-rc.1 is already published).
        existing_with_rc = existing + [
            {"tagName": "v0.2.0-rc.1", "isDraft": False, "isPrerelease": True},
        ]
        self.assertEqual(
            setup.compute_release_publish_flags("v0.2.0", existing_with_rc),
            ("--prerelease=false", "--latest"),
        )
        # Newer patch stable v0.1.6 becomes Latest despite v0.2.0-rc.1 prerelease.
        self.assertEqual(
            setup.compute_release_publish_flags("v0.1.6", existing_with_rc),
            ("--prerelease=false", "--latest"),
        )
        # Older stable tag v0.1.4 MUST NOT steal Latest from v0.1.5.
        self.assertEqual(
            setup.compute_release_publish_flags("v0.1.4", existing_with_rc),
            ("--prerelease=false", "--latest=false"),
        )

        # 2. Verify default updater (stable channel) vs opt-in prerelease channel against the same release set.
        def gh_rel(tag: str, *, prerelease: bool = False, draft: bool = False) -> dict:
            return {
                "tag_name": tag,
                "draft": draft,
                "prerelease": prerelease,
                "assets": [
                    {"name": "install.sh", "state": "uploaded", "browser_download_url": f"https://example.invalid/{tag}/install.sh"},
                    {"name": "setup.py", "state": "uploaded", "browser_download_url": f"https://example.invalid/{tag}/setup.py"},
                ],
            }

        rels_with_pre = [
            gh_rel("v0.1.4", prerelease=False),
            gh_rel("v0.1.5", prerelease=False),
            gh_rel("v0.2.0-alpha.1", prerelease=True),
            gh_rel("v0.2.0-beta.1", prerelease=True),
            gh_rel("v0.2.0-rc.1", prerelease=True),
        ]
        self.assertEqual(setup.select_latest_release(rels_with_pre, allow_prerelease=False), "v0.1.5")
        self.assertEqual(setup.select_latest_release(rels_with_pre, allow_prerelease=True), "v0.2.0-rc.1")

        rels_with_v020 = rels_with_pre + [gh_rel("v0.2.0", prerelease=False)]
        self.assertEqual(setup.select_latest_release(rels_with_v020, allow_prerelease=False), "v0.2.0")
        self.assertEqual(setup.select_latest_release(rels_with_v020, allow_prerelease=True), "v0.2.0")

        # 3. Verify .github/workflows/release.yml wires compute_release_publish_flags and passes both flags
        #    for both new releases and existing drafts, and test offline with a mocked `gh` CLI when bash is available.
        repo_root = Path(__file__).resolve().parent.parent
        wf_text = (repo_root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("setup.compute_release_publish_flags(tag, published)", wf_text)
        self.assertNotIn("--prerelease=false ${latest_flag}", wf_text)
        self.assertNotIn("branches:\n      - main", wf_text)
        self.assertIn('tags:\n      - "v*"', wf_text)
        self.assertIn('docs/releases/${tag}.md', wf_text)
        self.assertEqual(wf_text.count('gh release edit "${tag}" --draft=false "${prerelease_flag}" "${latest_flag}"'), 2)

        bash_bin = "/bin/bash" if Path("/bin/bash").is_file() else None
        if bash_bin is not None:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                fake_bin = d / "bin"
                fake_bin.mkdir()
                gh_log = d / "gh_calls.log"
                gh_state = d / "gh_state.json"
                fake_gh = fake_bin / "gh"
                fake_gh.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json, os, sys\n"
                    "args = sys.argv[1:]\n"
                    "with open(os.environ['GH_LOG'], 'a', encoding='utf-8') as f:\n"
                    "    f.write(' '.join(args) + '\\n')\n"
                    "st = json.loads(open(os.environ['GH_STATE'], encoding='utf-8').read())\n"
                    "if args[:2] == ['release', 'list']:\n"
                    "    print(json.dumps(st['published']))\n"
                    "    raise SystemExit(0)\n"
                    "if args[:2] == ['release', 'view']:\n"
                    "    if not st.get('exists'):\n"
                    "        raise SystemExit(1)\n"
                    "    if 'isDraft' in args:\n"
                    "        print('true' if st.get('is_draft') else 'false')\n"
                    "    elif 'assets' in args:\n"
                    "        print('')\n"
                    "    raise SystemExit(0)\n"
                    "raise SystemExit(0)\n",
                    encoding="utf-8",
                    newline="\n",
                )
                setup.os.chmod(fake_gh, 0o755)

                publish_script = (
                    'set -euo pipefail\n'
                    'tag="$1"\n'
                    'read -r prerelease_flag latest_flag < <(python3 - "${tag}" <<\'PY\'\n'
                    'import json, subprocess, sys\n'
                    'sys.path.insert(0, "deploy")\n'
                    'import setup\n'
                    'tag = sys.argv[1]\n'
                    'raw = subprocess.check_output(["gh", "release", "list", "--limit", "100", "--json", "tagName,isDraft,isPrerelease"], text=True)\n'
                    'pre_flag, lat_flag = setup.compute_release_publish_flags(tag, json.loads(raw))\n'
                    'print(pre_flag, lat_flag)\n'
                    'PY\n'
                    ')\n'
                    'if gh release view "${tag}" >/dev/null 2>&1; then\n'
                    '  is_draft="$(gh release view "${tag}" --json isDraft -q .isDraft)"\n'
                    '  if [ "${is_draft}" = "true" ]; then\n'
                    '    gh release edit "${tag}" --draft=false "${prerelease_flag}" "${latest_flag}"\n'
                    '  fi\n'
                    'else\n'
                    '  gh release create "${tag}" --draft\n'
                    '  gh release edit "${tag}" --draft=false "${prerelease_flag}" "${latest_flag}"\n'
                    'fi\n'
                )
                script_path = d / "pub.sh"
                script_path.write_text(publish_script, encoding="utf-8", newline="\n")

                cases = [
                    ("v0.2.0-rc.1", False, False, "--prerelease=true --latest=false"),
                    ("v0.2.0-rc.1", True, True, "--prerelease=true --latest=false"),
                    ("v0.1.0-alpha.6", False, False, "--prerelease=true --latest=false"),
                    ("v0.2.0-beta.1", False, False, "--prerelease=true --latest=false"),
                    ("v0.2.0", False, False, "--prerelease=false --latest"),
                    ("v0.1.4", False, False, "--prerelease=false --latest=false"),
                ]
                for tag_name, exists, is_draft, expected_flags in cases:
                    gh_log.write_text("", encoding="utf-8")
                    gh_state.write_text(
                        setup.json.dumps({"published": existing, "exists": exists, "is_draft": is_draft}),
                        encoding="utf-8",
                    )
                    env = dict(setup.os.environ)
                    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
                    env["GH_LOG"] = str(gh_log)
                    env["GH_STATE"] = str(gh_state)
                    p = subprocess.run([bash_bin, str(script_path), tag_name], cwd=str(repo_root), env=env, capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    edit_lines = [l for l in gh_log.read_text(encoding="utf-8").splitlines() if l.startswith("release edit ")]
                    self.assertEqual(len(edit_lines), 1, f"{tag_name} ({exists=}, {is_draft=}): {edit_lines}")
                    self.assertEqual(edit_lines[0], f"release edit {tag_name} --draft=false {expected_flags}")


if __name__ == "__main__":
    prog = unittest.main(verbosity=2, exit=False)
    if setup.os.environ.get("MTEVIL_REQUIRE_ALL_TESTS") == "1" and prog.result.skipped:
        print(f"ERROR: MTEVIL_REQUIRE_ALL_TESTS=1 but {len(prog.result.skipped)} test(s) were skipped", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0 if prog.result.wasSuccessful() else 1)
