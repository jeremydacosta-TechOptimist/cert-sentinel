"""End-to-end tests for the certsentinel CLI (in-process and via subprocess)."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from certsentinel.cli import EndpointError, main
from tests.helpers import EXAMPLES_PKI, LEAF_SERVER, ROOT_CA, REPO_ROOT, load_example

PKI = EXAMPLES_PKI.as_posix()
LEAF_FILE = (EXAMPLES_PKI / LEAF_SERVER).as_posix()


def run_cli(*argv: str):
    """Run main() with captured stdout/stderr and return ``(code, out, err)``."""

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse raises for usage errors
            code = int(exc.code) if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


class CliBasicsTests(unittest.TestCase):
    def test_version_subcommand(self) -> None:
        code, out, err = run_cli("version")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "certsentinel 1.0.0")
        self.assertEqual(err, "")

    def test_version_flag(self) -> None:
        code, out, _err = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn("certsentinel 1.0.0", out)

    def test_help_lists_commands(self) -> None:
        code, out, _err = run_cli("--help")
        self.assertEqual(code, 0)
        for command in ("scan", "check", "endpoint", "report", "version"):
            self.assertIn(command, out)
        self.assertIn("exit codes", out)

    def test_no_command_is_usage_error(self) -> None:
        code, _out, err = run_cli()
        self.assertEqual(code, 2)
        self.assertIn("usage: certsentinel", err)

    def test_unknown_command_is_usage_error(self) -> None:
        self.assertEqual(run_cli("frobnicate")[0], 2)

    def test_invalid_fail_on_choice_is_usage_error(self) -> None:
        self.assertEqual(run_cli("scan", PKI, "--fail-on", "critical")[0], 2)


class ScanCommandTests(unittest.TestCase):
    def test_scan_default_threshold_exits_one(self) -> None:
        code, out, err = run_cli("scan", PKI)
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertIn("8 certificate(s), 9 finding(s)", out)
        self.assertIn("CERTIFICATES", out)
        self.assertIn("FINDINGS", out)
        self.assertIn("CERT-SMALL-RSA-KEY", out)

    def test_scan_fail_on_none_exits_zero(self) -> None:
        code, out, _err = run_cli("scan", PKI, "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertIn("1 error", out)

    def test_scan_fail_on_error_exits_one(self) -> None:
        self.assertEqual(run_cli("scan", PKI, "--fail-on", "error")[0], 1)

    def test_scan_clean_inventory_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "root-ca.pem"
            shutil.copyfile(REPO_ROOT / "examples" / "pki" / ROOT_CA, target)
            code, out, _err = run_cli("scan", str(target))
        self.assertEqual(code, 0)
        self.assertIn("CERT-CA-CERT", out)
        self.assertNotIn("CERT-SMALL-RSA-KEY", out)

    def test_scan_json_output(self) -> None:
        code, out, _err = run_cli("scan", PKI, "--json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["certificate_count"], 8)
        self.assertEqual(payload["max_severity"], "error")
        self.assertGreaterEqual(payload["counts"]["warning"], 1)
        self.assertTrue(payload["findings"])

    def test_scan_with_injected_now_reports_expired(self) -> None:
        code, out, _err = run_cli("scan", PKI, "--now", "2030-01-01T00:00:00Z", "--json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        expired = [
            finding for finding in payload["findings"] if finding["rule"] == "CERT-EXPIRED"
        ]
        self.assertGreaterEqual(len(expired), 6)
        self.assertGreaterEqual(payload["counts"]["error"], 7)

    def test_scan_invalid_now_is_usage_error(self) -> None:
        code, _out, err = run_cli("scan", PKI, "--now", "not-a-date")
        self.assertEqual(code, 2)
        self.assertIn("invalid --now", err)

    def test_scan_missing_path_is_runtime_error(self) -> None:
        code, out, _err = run_cli("scan", str(REPO_ROOT / "examples" / "missing"))
        self.assertEqual(code, 1)
        self.assertIn("LOAD ERRORS", out)
        self.assertIn("does not exist", out)

    def test_scan_non_certificate_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.txt"
            path.write_text("hello", encoding="utf-8")
            code, out, _err = run_cli("scan", str(path))
        self.assertEqual(code, 1)
        self.assertIn("not a certificate", out)


class CheckCommandTests(unittest.TestCase):
    def test_check_matching_host_has_no_mismatch(self) -> None:
        code, out, _err = run_cli("check", LEAF_FILE, "--host", "srv-a.example")
        self.assertEqual(code, 1)  # missing issuer warning, but no identity finding
        self.assertNotIn("CERT-HOSTNAME-MISMATCH", out)

    def test_check_mismatched_host_reports_finding(self) -> None:
        code, out, _err = run_cli("check", LEAF_FILE, "--host", "www.example")
        self.assertEqual(code, 1)
        self.assertIn("CERT-HOSTNAME-MISMATCH", out)
        self.assertIn("www.example", out)

    def test_check_ip_san_match(self) -> None:
        _code, out, _err = run_cli("check", LEAF_FILE, "--host", "192.0.2.10")
        self.assertNotIn("CERT-HOSTNAME-MISMATCH", out)

    def test_check_json_contains_hostname_finding(self) -> None:
        code, out, _err = run_cli("check", LEAF_FILE, "--host", "www.example", "--json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        rules = [finding["rule"] for finding in payload["findings"]]
        self.assertIn("CERT-HOSTNAME-MISMATCH", rules)


class ReportCommandTests(unittest.TestCase):
    def test_report_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "audit.html"
            code, out, _err = run_cli("report", PKI, "--out", str(output))
            self.assertEqual(code, 0)
            self.assertIn("report written to", out)
            document = output.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", document)
        self.assertIn('id="findings"', document)
        self.assertIn("srv-a.example", document)

    def test_report_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "audit.html"
            code, _out, _err = run_cli("report", PKI, "--out", str(output))
            self.assertEqual(code, 0)
            self.assertTrue(output.exists())

    def test_report_with_no_certificates_still_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty"
            empty.mkdir()
            output = Path(directory) / "audit.html"
            code, _out, _err = run_cli("report", str(empty), "--out", str(output))
            self.assertEqual(code, 1)
            self.assertTrue(output.exists())
            self.assertIn("No certificates loaded.", output.read_text(encoding="utf-8"))

    def test_report_invalid_now_is_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _out, err = run_cli(
                "report", PKI, "--out", str(Path(directory) / "a.html"), "--now", "x"
            )
        self.assertEqual(code, 2)
        self.assertIn("invalid --now", err)


class EndpointCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leaf = load_example(LEAF_SERVER)

    def test_endpoint_with_mocked_fetch(self) -> None:
        with mock.patch("certsentinel.cli.fetch_certificate", return_value=self.leaf) as patched:
            code, out, _err = run_cli("endpoint", "127.0.0.1:443", "--fail-on", "none", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["certificate_count"], 1)
        self.assertEqual(payload["certificates"][0]["subject_cn"], "srv-a.example")
        patched.assert_called_once()

    def test_endpoint_uses_sni_for_handshake_and_identity(self) -> None:
        with mock.patch("certsentinel.cli.fetch_certificate", return_value=self.leaf) as patched:
            code, out, _err = run_cli(
                "endpoint",
                "127.0.0.1:443",
                "--sni",
                "srv-a.example",
                "--fail-on",
                "none",
                "--json",
            )
        self.assertEqual(code, 0)
        arguments = patched.call_args
        self.assertEqual(arguments.kwargs["sni"], "srv-a.example")
        payload = json.loads(out)
        self.assertNotIn(
            "CERT-HOSTNAME-MISMATCH",
            [finding["rule"] for finding in payload["findings"]],
        )

    def test_endpoint_default_threshold_fails_on_hostname_mismatch(self) -> None:
        with mock.patch("certsentinel.cli.fetch_certificate", return_value=self.leaf):
            code, out, _err = run_cli("endpoint", "127.0.0.1:443")
        self.assertEqual(code, 1)
        self.assertIn("CERT-HOSTNAME-MISMATCH", out)

    def test_endpoint_fetch_failure_is_runtime_error(self) -> None:
        with mock.patch(
            "certsentinel.cli.fetch_certificate", side_effect=EndpointError("connection refused")
        ):
            code, _out, err = run_cli("endpoint", "192.0.2.99:443")
        self.assertEqual(code, 1)
        self.assertIn("connection refused", err)

    def test_endpoint_invalid_target_is_usage_error(self) -> None:
        self.assertEqual(run_cli("endpoint", "not-an-endpoint")[0], 2)

    def test_endpoint_invalid_timeout_is_usage_error(self) -> None:
        self.assertEqual(run_cli("endpoint", "127.0.0.1:443", "--timeout", "0")[0], 2)


class SubprocessTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPO_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "certsentinel", *arguments],
            cwd=str(REPO_ROOT),
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_module_entry_point_version(self) -> None:
        result = self._run("version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "certsentinel 1.0.0")

    def test_module_entry_point_help(self) -> None:
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: certsentinel", result.stdout)

    def test_module_entry_point_scan_json(self) -> None:
        result = self._run("scan", PKI, "--json", "--fail-on", "none")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(json.loads(result.stdout)["certificate_count"], 8)


if __name__ == "__main__":
    unittest.main()
