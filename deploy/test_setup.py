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
SPEC = importlib.util.spec_from_file_location("mtevil_setup", SETUP_PATH)
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
            self.skipTest("no local mtevil image available")
        free_port = self._free_port()
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            project = f"mtevil-port-test-{free_port}"
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

            stdin_data = "y\n1\n127.0.0.1\n25443\ny\n127.0.0.1\nexample.com\nexample.com:443\n"
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
            self.assertIn("IP привязки: 127.0.0.1", out)
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

            # Role 2 (edge) -> 2, address 203.0.113.10, port 443, adv n, upstream 10.203.0.9:29443,
            # backup n, strategy 1, reuse existing token n, enter new token, confirm abort n.
            stdin_data = (
                "y\n2\n2\n203.0.113.10\n443\nn\n10.203.0.9:29443\nn\n1\nn\n"
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
                mock.patch.object(sys, "stdin", io.StringIO("1\n203.0.113.10\n25443\nn\n")),
                mock.patch.object(sys, "stdout", out2),
                mock.patch.object(sys, "stderr", err2),
                mock.patch.object(setup, "check_prerequisites"),
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

            stdin_data = f"y\n2\n2\n203.0.113.10\n443\nn\n10.203.0.9:29443\nn\n1\nn\n{new_tok}\n"
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
                # 1. Start real Egress 1 with old_tok (--network-host on 127.0.0.1:eg1_port).
                stdin_eg1 = f"2\n1\n127.0.0.1\n{eg1_port}\nn\n{old_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_eg1), "--project", p_eg1, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_eg1)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)

                # 2. Start real Egress 2 with new_tok (--network-host on 127.0.0.1:eg2_port).
                stdin_eg2 = f"2\n1\n127.0.0.1\n{eg2_port}\nn\n{new_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_eg2), "--project", p_eg2, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_eg2)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)

                # 3. Start real Edge connected to Egress 1 with old_tok.
                stdin_edge1 = f"2\n2\n127.0.0.1\n{edge_port}\nn\n127.0.0.1:{eg1_port}\nn\n1\n{old_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_edge), "--project", p_edge, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_edge1)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                ):
                    self.assertEqual(setup.main(), 0)

                edge_base = setup.compose_cmd(d_edge, p_edge)
                self.assertEqual(setup.read_volume_secret(edge_base, "/var/lib/mtevil/egress-token"), old_tok)

                # Prepare the prototype vector proxy-secret BEFORE rotation so that after
                # setup.main() rolls back and exits, we do NOT restart Edge in the test!
                vec_secret_hex = "000102030405060708090a0b0c0d0e0f"
                setup.write_volume_secret_stdin(edge_base, "/var/lib/mtevil/proxy-secret", vec_secret_hex)
                setup.run(edge_base + ["up", "-d", "--force-recreate", setup.compose_service(edge_base)])
                setup.wait_healthy(edge_base)

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

                stdin_edge2 = f"y\n2\n2\n127.0.0.1\n{edge_port}\nn\n127.0.0.1:{eg2_port}\nn\n1\nn\n{new_tok}\n"
                with (
                    mock.patch.object(sys, "argv", ["setup.py", "--dir", str(d_edge), "--project", p_edge, "--image", image, "--no-build", "--network-host"]),
                    mock.patch.object(sys, "stdin", io.StringIO(stdin_edge2)),
                    mock.patch.object(sys, "stdout", io.StringIO()),
                    mock.patch.object(sys, "stderr", io.StringIO()),
                    mock.patch.object(setup, "wait_healthy", side_effect=fail_first_wait_healthy),
                ):
                    self.assertEqual(setup.main(), 1)
                self.assertEqual(wait_calls, 2)

                # 5. Without restarting Edge in the test, connect a client immediately through
                #    edge's listening port and verify the session appears on Egress 1!
                self.assertEqual(setup.read_volume_secret(edge_base, "/var/lib/mtevil/egress-token"), old_tok)

                eg1_base = setup.compose_cmd(d_eg1, p_eg1)
                eg2_base = setup.compose_cmd(d_eg2, p_eg2)
                eg1_before = setup.run(eg1_base + ["logs", setup.compose_service(eg1_base)]).stdout.count('"event":"session_open"')
                eg2_before = setup.run(eg2_base + ["logs", setup.compose_service(eg2_base)]).stdout.count('"event":"session_open"')

                repo_root = Path(__file__).resolve().parent.parent
                init_frame = bytes.fromhex((repo_root / "tests" / "vectors" / "prototype" / "client-init.hex").read_text(encoding="utf-8").strip())
                ch_template = bytearray(bytes.fromhex((repo_root / "tests" / "vectors" / "prototype" / "synthetic-ch.hex").read_text(encoding="utf-8").strip()))
                import hashlib
                import hmac
                import struct
                import time
                ch_template[11:43] = b"\x00" * 32
                digest = hmac.new(bytes.fromhex(vec_secret_hex), bytes(ch_template), hashlib.sha256).digest()
                ts = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)
                ch_template[11:43] = digest[:28] + bytes(a ^ b for a, b in zip(digest[28:32], ts))
                client_payload = bytes(ch_template) + b"\x17\x03\x03\x00\x40" + init_frame

                # Connect to edge's listening port from inside the shared container network namespace
                # and complete FakeTLS ClientHello -> ServerHello -> obfuscated2 inner frame -> Egress 1!
                ch_b64 = __import__("base64").b64encode(bytes(ch_template)).decode("ascii")
                init_b64 = __import__("base64").b64encode(b"\x17\x03\x03\x00\x40" + init_frame).decode("ascii")
                bash_client = (
                    f"exec 3<>/dev/tcp/127.0.0.1/{edge_port} && "
                    f"printf '%s' '{ch_b64}' | base64 -d >&3 && "
                    "dd bs=1 count=1 <&3 >/dev/null 2>&1 && "
                    f"printf '%s' '{init_b64}' | base64 -d >&3 && "
                    "sleep 0.5 && exec 3>&-"
                )
                client_proc = setup.run(
                    edge_base
                    + [
                        "exec",
                        "-T",
                        setup.compose_service(edge_base),
                        "/bin/bash",
                        "-c",
                        bash_client,
                    ],
                    check=False,
                )
                self.assertEqual(client_proc.returncode, 0, client_proc.stdout + client_proc.stderr)

                edge_logs = setup.run(edge_base + ["logs", setup.compose_service(edge_base)]).stdout
                eg1_after = setup.run(eg1_base + ["logs", setup.compose_service(eg1_base)]).stdout.count('"event":"session_open"')
                eg2_after = setup.run(eg2_base + ["logs", setup.compose_service(eg2_base)]).stdout.count('"event":"session_open"')
                self.assertIn('"event":"authenticated"', edge_logs)
                self.assertGreater(eg1_after, eg1_before, f"Egress 1 did not receive forwarded session; edge logs:\n{edge_logs}")
                self.assertEqual(eg2_after, eg2_before, "Egress 2 must not receive session after rollback to Egress 1")
            finally:
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
        self.assertEqual(setup.select_latest_release(releases), "v0.1.0-alpha.10")

        releases_with_beta = releases + [rel("v0.1.0-beta.1")]
        self.assertEqual(setup.select_latest_release(releases_with_beta), "v0.1.0-beta.1")

        with self.assertRaises(ValueError):
            setup.select_latest_release([])
        with self.assertRaises(ValueError):
            setup.select_latest_release([rel("v0.1.0-alpha.6", draft=True)])

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
            image = self._local_image()
            if image is None:
                self.skipTest("no local mtevil image available")
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                pinned_path = d / "install.alpha6.sh"
                pinned_path.write_text(pinned_alpha6, encoding="utf-8", newline="\n")
                # Execute inside container or local bash if available:
                # Using `docker run --rm` or local bash? No, on Windows `bash` might be WSL stub,
                # so let's test on Linux / Git Bash or verify via python + bash when `/bin/bash` is present.
                bash_bin = "/bin/bash" if Path("/bin/bash").is_file() else None
                if bash_bin is not None:
                    env = dict(setup.os.environ)
                    env["MTEVIL_DIR"] = str(d / "install_dir")
                    env["MTEVIL_RELEASES_API_URL"] = f"http://127.0.0.1:{port}/releases"
                    env["MTEVIL_RELEASE_BASE_URL"] = f"http://127.0.0.1:{port}/download"
                    env["MTEVIL_IMAGE"] = image
                    proc = subprocess.run([bash_bin, str(pinned_path)], env=env, capture_output=True, text=True)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("/download/v0.1.0-alpha.6/setup.py", requested_paths)
                    self.assertNotIn("/releases", requested_paths)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    prog = unittest.main(verbosity=2, exit=False)
    if setup.os.environ.get("MTEVIL_REQUIRE_ALL_TESTS") == "1" and prog.result.skipped:
        print(f"ERROR: MTEVIL_REQUIRE_ALL_TESTS=1 but {len(prog.result.skipped)} test(s) were skipped", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0 if prog.result.wasSuccessful() else 1)
