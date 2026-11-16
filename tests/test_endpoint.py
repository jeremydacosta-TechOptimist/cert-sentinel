"""Tests for endpoint parsing, live certificate retrieval and CLI time parsing."""

from __future__ import annotations

import datetime
import ssl
import unittest
from unittest import mock

from certsentinel.cli import (
    CliUsageError,
    EndpointError,
    fetch_certificate,
    parse_endpoint,
    parse_now,
)
from tests.helpers import EXAMPLES_PKI, LEAF_SERVER


class ParseEndpointTests(unittest.TestCase):
    def test_host_and_port(self) -> None:
        self.assertEqual(parse_endpoint("192.0.2.10:443"), ("192.0.2.10", 443))

    def test_hostname_and_port(self) -> None:
        self.assertEqual(parse_endpoint("srv-a.example:8443"), ("srv-a.example", 8443))

    def test_bracketed_ipv6(self) -> None:
        self.assertEqual(parse_endpoint("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_invalid_endpoints(self) -> None:
        for value in ("", "srv-a.example", ":443", "host:0", "host:70000", "host:https", "[::1]"):
            with self.subTest(value=value):
                with self.assertRaises(CliUsageError):
                    parse_endpoint(value)


class ParseNowTests(unittest.TestCase):
    def test_zulu_timestamp(self) -> None:
        moment = parse_now("2026-11-16T18:00:00Z")
        self.assertEqual(moment, datetime.datetime(2026, 11, 16, 18, 0, tzinfo=datetime.timezone.utc))

    def test_offset_timestamp(self) -> None:
        moment = parse_now("2026-11-16T18:00:00+02:00")
        self.assertEqual(moment.hour, 16)

    def test_naive_timestamp_is_utc(self) -> None:
        moment = parse_now("2026-11-16T18:00:00")
        self.assertEqual(moment.tzinfo, datetime.timezone.utc)

    def test_date_only(self) -> None:
        self.assertEqual(parse_now("2026-11-16").year, 2026)

    def test_invalid_timestamp(self) -> None:
        with self.assertRaises(CliUsageError):
            parse_now("not-a-date")
        with self.assertRaises(CliUsageError):
            parse_now("  ")

    def test_none_returns_current_time(self) -> None:
        self.assertIsNotNone(parse_now(None).tzinfo)


class FetchCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leaf_pem = (EXAMPLES_PKI / LEAF_SERVER).read_text(encoding="ascii")
        cls.leaf_der = (EXAMPLES_PKI / "leaf.der").read_bytes()

    def test_fetch_uses_get_server_certificate(self) -> None:
        with mock.patch(
            "certsentinel.cli.ssl.get_server_certificate", return_value=self.leaf_pem
        ) as patched:
            certificate = fetch_certificate("192.0.2.10", 443, timeout=2.0)
        self.assertEqual(certificate.subject_cn, "srv-a.example")
        self.assertEqual(certificate.source, "192.0.2.10:443")
        patched.assert_called_once_with(("192.0.2.10", 443), timeout=2.0)

    def test_fetch_invalid_pem_raises(self) -> None:
        with mock.patch(
            "certsentinel.cli.ssl.get_server_certificate", return_value="not a certificate"
        ):
            with self.assertRaises(EndpointError):
                fetch_certificate("192.0.2.10", 443)

    def test_fetch_network_error_raises(self) -> None:
        with mock.patch(
            "certsentinel.cli.ssl.get_server_certificate", side_effect=OSError("connection refused")
        ):
            with self.assertRaises(EndpointError):
                fetch_certificate("192.0.2.10", 443)

    def test_fetch_with_sni_uses_tls_context(self) -> None:
        captured = {}
        der = self.leaf_der

        class FakeTlsSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getpeercert(self, binary_form: bool = False):
                captured["binary_form"] = binary_form
                return der if binary_form else {}

        class FakeContext:
            def __init__(self, protocol):
                captured["protocol"] = protocol
                captured["context"] = self
                self.check_hostname = True
                self.verify_mode = None

            def wrap_socket(self, raw_socket, server_hostname=None):
                captured["server_hostname"] = server_hostname
                return FakeTlsSocket()

        class FakeRawSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("certsentinel.cli.ssl.SSLContext", FakeContext), mock.patch(
            "certsentinel.cli.socket.create_connection", return_value=FakeRawSocket()
        ):
            certificate = fetch_certificate("192.0.2.10", 443, timeout=1.0, sni="srv-a.example")
        context = captured["context"]
        self.assertEqual(captured["server_hostname"], "srv-a.example")
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertEqual(captured["binary_form"], True)
        self.assertEqual(certificate.subject_cn, "srv-a.example")
        self.assertEqual(certificate.source, "192.0.2.10:443")

    def test_fetch_with_sni_without_certificate_raises(self) -> None:
        class FakeTlsSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getpeercert(self, binary_form: bool = False):
                return None

        class FakeContext:
            def __init__(self, protocol):
                self.check_hostname = True
                self.verify_mode = None

            def wrap_socket(self, raw_socket, server_hostname=None):
                return FakeTlsSocket()

        class FakeRawSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("certsentinel.cli.ssl.SSLContext", FakeContext), mock.patch(
            "certsentinel.cli.socket.create_connection", return_value=FakeRawSocket()
        ):
            with self.assertRaises(EndpointError):
                fetch_certificate("192.0.2.10", 443, sni="srv-a.example")

    def test_fetch_rejects_non_positive_timeout(self) -> None:
        with self.assertRaises(ValueError):
            fetch_certificate("192.0.2.10", 443, timeout=0)


if __name__ == "__main__":
    unittest.main()
