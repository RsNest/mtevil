#!/usr/bin/env python3
"""Unit and container tests for deploy/setup.py DNS and HTTPS-cover checks."""
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
SPEC = importlib.util.spec_from_file_location("mtveil_setup", SETUP_PATH)
setup = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(setup)


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
        # Requires local image mtveil:wizard-test with openssl + ca-certificates.
        if subprocess.run(["docker", "image", "inspect", "mtveil:wizard-test"], capture_output=True).returncode != 0:
            self.skipTest("mtveil:wizard-test image not built")
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "compose.yaml").write_text(setup.render_compose(repo, d, "direct"), encoding="utf-8")
            (d / ".env").write_text("MTVEIL_PROJECT=mtveil-cov-test\nMTVEIL_IMAGE=mtveil:wizard-test\nMTVEIL_BIND=127.0.0.1\nMTVEIL_PORT=26449\n", encoding="utf-8")
            (d / "config.json").write_text("{}\n", encoding="utf-8")
            base = setup.compose_cmd(d, "mtveil-cov-test")
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
            (d / ".env.bak").write_text("old-env", encoding="utf-8")
            (d / "config.json.bak").write_text("old-cfg", encoding="utf-8")
            (d / "compose.yaml").write_text("new-compose", encoding="utf-8")
            self.assertTrue(setup.restore_backup_files(d))
            self.assertEqual((d / "compose.yaml").read_text(encoding="utf-8"), "old-compose")
            self.assertEqual((d / ".env").read_text(encoding="utf-8"), "old-env")
            self.assertEqual((d / "config.json").read_text(encoding="utf-8"), "old-cfg")

    def _local_image(self):
        for candidate in ("ghcr.io/rsnest/mtevil:v0.1.0-alpha.3", "mtveil:wizard-test"):
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
            self.skipTest("no local mtveil image available")
        free_port = self._free_port()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            project = f"mtveil-short-test-{free_port}"
            stdin_data = f"1\n127.0.0.1\n{free_port}\nn\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            try:
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", project, "--image", image, "--no-build"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                    mock.patch.object(sys, "stdout", out_buf),
                    mock.patch.object(sys, "stderr", err_buf),
                ):
                    rc = setup.main()
                out = out_buf.getvalue()
                self.assertEqual(rc, 0, out + err_buf.getvalue())
                self.assertNotIn("\x1b[", out)
                self.assertIn("Конфигурация проверена", out)
                self.assertIn("HTTPS-сайт для маскировки доступен", out)
                self.assertIn("Контейнер запущен", out)
                self.assertIn("Контейнер исправен", out)
                self.assertIn(f"https://t.me/proxy?server=127.0.0.1&port={free_port}&secret=", out)
            finally:
                base = setup.compose_cmd(d, project)
                if (d / "compose.yaml").exists():
                    subprocess.run(base + ["down", "-v"], capture_output=True)

    def test_busy_443_prompts_new_port_and_starts_container(self):
        image = self._local_image()
        if image is None:
            self.skipTest("no local mtveil image available")
        free_port = self._free_port()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            project = f"mtveil-port-test-{free_port}"
            stdin_data = f"1\n127.0.0.1\n443\nn\n{free_port}\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            try:
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", project, "--image", image, "--no-build"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_data)),
                    mock.patch.object(sys, "stdout", out_buf),
                    mock.patch.object(sys, "stderr", err_buf),
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
            (d / ".env").write_text("MTVEIL_PORT=24443\n", encoding="utf-8")
            (d / "config.json").write_text('{"sni":"example.com","cover":"example.com:443"}\n', encoding="utf-8")

            def fake_run(argv, **_kwargs):
                cmd = " ".join(argv)
                if "up -d mtveil" in cmd:
                    return subprocess.CompletedProcess(
                        argv,
                        1,
                        stdout="",
                        stderr="permission denied while trying to connect to the docker API at unix:///var/run/docker.sock",
                    )
                if "link" in cmd:
                    return subprocess.CompletedProcess(argv, 0, stdout="https://t.me/proxy?server=127.0.0.1&port=25443&secret=ee00\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            stdin_data = "y\n1\n127.0.0.1\n25443\ny\n127.0.0.1\nexample.com\nexample.com:443\n"
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d), "--project", "mtveil-err-test", "--image", "mtveil:test", "--no-build"]),
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
            self.assertIn("IP привязки: 127.0.0.1", out)
            self.assertNotIn("Выбрать другой порт", out)
            self.assertIn("docker.sock", err)
            self.assertIn("Прежние файлы конфигурации восстановлены.", err)
            self.assertEqual((d / "compose.yaml").read_text(encoding="utf-8"), "old-compose")


if __name__ == "__main__":
    unittest.main(verbosity=2)
