"""Tests for the text, JSON and HTML report renderers."""

from __future__ import annotations

import datetime
import json
import unittest

from certsentinel.checks import audit
from certsentinel.report import (
    build_report,
    certificate_to_dict,
    render_html,
    render_json,
    render_text,
)
from certsentinel.x509 import LoadError, Rdn, RdnAttribute, DistinguishedName, GeneralName
from dataclasses import replace

from tests.helpers import LEAF_SERVER, load_example, load_examples

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 16, 18, 0, 0, tzinfo=UTC)


class JsonReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificates = load_examples()
        cls.result = audit(cls.certificates, NOW)

    def test_build_report_shape(self) -> None:
        report = build_report(self.result)
        self.assertEqual(report["certificate_count"], 8)
        self.assertEqual(set(report["counts"]), {"error", "warning", "notice", "info"})
        self.assertEqual(report["max_severity"], "error")
        self.assertEqual(len(report["findings"]), self.result.finding_count)
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_generated_at_is_iso_utc(self) -> None:
        report = build_report(self.result)
        self.assertEqual(report["generated_at"], "2026-11-16T18:00:00+00:00")

    def test_certificate_entry_fields(self) -> None:
        report = build_report(self.result)
        leaf = next(
            entry
            for entry in report["certificates"]
            if entry["subject_cn"] == "srv-a.example"
            and (entry["source"] or "").endswith("examples/pki/leaf-server.pem")
        )
        self.assertEqual(leaf["issuer_cn"], "NetWatch Lab Intermediate CA")
        self.assertEqual(leaf["version"], 3)
        self.assertEqual(leaf["serial"], "3001")
        self.assertEqual(leaf["not_after"], "2027-11-16T17:32:56+00:00")
        self.assertEqual(leaf["validity_days"], 365)
        self.assertEqual(leaf["public_key_algorithm"], "RSA")
        self.assertEqual(leaf["public_key_bits"], 2048)
        self.assertEqual(leaf["signature_algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(leaf["key_usage"], ["digitalSignature", "keyEncipherment"])
        self.assertEqual(leaf["extended_key_usage"], ["serverAuth"])
        self.assertEqual(leaf["san"][1], {"type": "ip", "value": "192.0.2.10"})
        self.assertEqual(leaf["authority_info_access"][0]["method"], "OCSP")

    def test_certificate_to_dict_days_remaining(self) -> None:
        leaf = load_example(LEAF_SERVER)
        self.assertEqual(certificate_to_dict(leaf, NOW)["days_remaining"], 364)
        self.assertLess(certificate_to_dict(leaf, NOW + datetime.timedelta(days=500))["days_remaining"], 0)

    def test_json_render_is_parseable(self) -> None:
        document = render_json(self.result)
        payload = json.loads(document)
        self.assertEqual(payload["certificate_count"], 8)
        self.assertTrue(payload["findings"])

    def test_load_errors_in_report(self) -> None:
        result = audit([], NOW, load_errors=[LoadError("bad.pem", "invalid DER")])
        report = build_report(result)
        self.assertEqual(report["load_errors"], [{"path": "bad.pem", "message": "invalid DER"}])
        self.assertEqual(report["certificate_count"], 0)
        self.assertIsNone(report["max_severity"])


class TextReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = audit(load_examples(), NOW)
        cls.text = render_text(cls.result)

    def test_summary_lines(self) -> None:
        self.assertIn("cert-sentinel audit - 2026-11-16 18:00 UTC", self.text)
        self.assertIn("8 certificate(s), 9 finding(s)", self.text)
        self.assertIn("1 error", self.text)
        self.assertIn("3 warning", self.text)

    def test_certificate_table(self) -> None:
        self.assertIn("CERTIFICATES", self.text)
        self.assertIn("srv-a.example", self.text)
        self.assertIn("RSA 2048", self.text)
        self.assertIn("sha256RSA", self.text)
        self.assertIn("2026-12-06 17:32 UTC", self.text)

    def test_findings_section(self) -> None:
        self.assertIn("FINDINGS", self.text)
        self.assertIn("CERT-SMALL-RSA-KEY", self.text)
        self.assertIn("CERT-DUPLICATE", self.text)
        self.assertIn("legacy-rsa.example", self.text)
        self.assertIn("below the 2048-bit minimum", self.text)

    def test_duplicate_message_mentions_source(self) -> None:
        self.assertIn("duplicate certificate also loaded from", self.text)
        self.assertIn("examples/pki/leaf-server.pem", self.text)

    def test_no_findings_and_no_certificates(self) -> None:
        text = render_text(audit([], NOW))
        self.assertIn("0 certificate(s), 0 finding(s): none", text)
        self.assertIn("No findings.", text)
        self.assertNotIn("CERTIFICATES", text)

    def test_load_errors_section(self) -> None:
        result = audit([], NOW, load_errors=[LoadError("bad.txt", "not a certificate")])
        text = render_text(result)
        self.assertIn("LOAD ERRORS", text)
        self.assertIn("bad.txt: not a certificate", text)

    def test_long_issuer_is_truncated(self) -> None:
        self.assertIn("NetWatch Lab Intermedia...", self.text)


class HtmlReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = audit(load_examples(), NOW)
        cls.document = render_html(cls.result)

    def test_document_markers(self) -> None:
        self.assertTrue(self.document.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>cert-sentinel audit</title>", self.document)
        self.assertIn('id="findings"', self.document)
        self.assertIn('id="certificates"', self.document)
        self.assertIn('<meta charset="utf-8">', self.document)
        self.assertTrue(self.document.rstrip().endswith("</html>"))

    def test_findings_are_rendered_with_badges(self) -> None:
        self.assertIn('class="badge error"', self.document)
        self.assertIn("CERT-SMALL-RSA-KEY", self.document)
        self.assertIn("CERT-DUPLICATE", self.document)

    def test_certificate_inventory_is_rendered(self) -> None:
        self.assertIn("srv-a.example", self.document)
        self.assertIn("NetWatch Lab Intermediate CA", self.document)
        self.assertIn("DNS:srv-a.example", self.document)
        self.assertIn("examples/pki/leaf-server.pem", self.document)
    def test_css_is_inline_and_assets_are_local(self) -> None:
        self.assertIn("<style>", self.document)
        for marker in ("<link", "<script", "src=", "@import", "url("):
            self.assertNotIn(marker, self.document)

    def test_html_escaping(self) -> None:
        leaf = load_example(LEAF_SERVER)
        hostile = replace(
            leaf,
            subject=DistinguishedName(
                (Rdn((RdnAttribute("2.5.4.3", "CN", '<script>alert("x")</script>'),)),)
            ),
            san=(GeneralName("dns", "<b>bad</b>"),),
        )
        document = render_html(audit([hostile], NOW))
        self.assertNotIn("<script>alert", document)
        self.assertIn("&lt;script&gt;alert", document)
        self.assertIn("&lt;b&gt;bad&lt;/b&gt;", document)

    def test_empty_report(self) -> None:
        document = render_html(audit([], NOW))
        self.assertIn("No findings.", document)
        self.assertIn("No certificates loaded.", document)
        self.assertIn("0 certificate(s)", document)

    def test_custom_title(self) -> None:
        document = render_html(self.result, title="Lab certificate audit")
        self.assertIn("<title>Lab certificate audit</title>", document)

    def test_load_errors_are_rendered(self) -> None:
        result = audit([], NOW, load_errors=[LoadError("broken.pem", "invalid DER")])
        document = render_html(result)
        self.assertIn('id="load-errors"', document)
        self.assertIn("broken.pem", document)
        self.assertIn("invalid DER", document)


if __name__ == "__main__":
    unittest.main()
