"""Tests for the certificate rule engine (per-certificate and inventory rules)."""

from __future__ import annotations

import datetime
import unittest
from dataclasses import replace

from certsentinel.checks import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_NOTICE,
    SEVERITY_WARNING,
    Finding,
    audit,
    check_certificate,
    check_inventory,
    fail_on_matches,
    matches_hostname,
)
from certsentinel.x509 import BasicConstraints, DistinguishedName, GeneralName, Rdn, RdnAttribute
from tests.helpers import (
    INTERMEDIATE_CA,
    LEAF_SELF_SIGNED,
    LEAF_SERVER,
    LEAF_SHA1,
    LEAF_SMALL_KEY,
    ROOT_CA,
    load_example,
)

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 16, 18, 0, 0, tzinfo=UTC)

LEAF = load_example(LEAF_SERVER)
ROOT = load_example(ROOT_CA)
INTERMEDIATE = load_example(INTERMEDIATE_CA)
SHA1_LEAF = load_example(LEAF_SHA1)
SMALL_KEY_LEAF = load_example(LEAF_SMALL_KEY)
SELF_SIGNED = load_example(LEAF_SELF_SIGNED)


def _rules(findings) -> set:
    return {finding.rule_id for finding in findings}


def _find(findings, rule: str):
    return [finding for finding in findings if finding.rule_id == rule]


def _with_validity(cert, days_from_now: int):
    return replace(
        cert,
        not_before=NOW - datetime.timedelta(days=1),
        not_after=NOW + datetime.timedelta(days=days_from_now),
    )


class ValidityRuleTests(unittest.TestCase):
    def test_expired_certificate_is_an_error(self) -> None:
        expired = replace(LEAF, not_after=NOW - datetime.timedelta(days=5))
        findings = check_certificate(expired, NOW)
        matches = _find(findings, "CERT-EXPIRED")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, SEVERITY_ERROR)
        self.assertIn("expired 5 day(s)", matches[0].message)

    def test_not_yet_valid_certificate_is_an_error(self) -> None:
        future = replace(LEAF, not_before=NOW + datetime.timedelta(days=5))
        findings = check_certificate(future, NOW)
        matches = _find(findings, "CERT-NOT-YET-VALID")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, SEVERITY_ERROR)
        self.assertIn("not valid before", matches[0].message)

    def test_expiring_warning_boundary(self) -> None:
        findings = check_certificate(_with_validity(LEAF, 30), NOW)
        matches = _find(findings, "CERT-EXPIRING")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, SEVERITY_WARNING)
        self.assertIn("expires in 30 day(s)", matches[0].message)

    def test_expiring_notice_boundary(self) -> None:
        findings = check_certificate(_with_validity(LEAF, 31), NOW)
        matches = _find(findings, "CERT-EXPIRING")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, SEVERITY_NOTICE)
        findings = check_certificate(_with_validity(LEAF, 90), NOW)
        self.assertEqual(_find(findings, "CERT-EXPIRING")[0].severity, SEVERITY_NOTICE)

    def test_certificate_above_notice_window_has_no_expiry_finding(self) -> None:
        findings = check_certificate(_with_validity(LEAF, 91), NOW)
        self.assertEqual(_find(findings, "CERT-EXPIRING"), [])
        self.assertEqual(_find(findings, "CERT-EXPIRED"), [])

    def test_normal_certificate_has_no_expiry_finding(self) -> None:
        findings = check_certificate(LEAF, NOW)
        self.assertEqual(_find(findings, "CERT-EXPIRING"), [])
        self.assertEqual(_find(findings, "CERT-EXPIRED"), [])

    def test_expired_takes_precedence_over_expiring(self) -> None:
        expired = replace(LEAF, not_after=NOW - datetime.timedelta(days=1))
        rules = _rules(check_certificate(expired, NOW))
        self.assertIn("CERT-EXPIRED", rules)
        self.assertNotIn("CERT-EXPIRING", rules)


class SignatureRuleTests(unittest.TestCase):
    def test_sha1_signature_is_a_warning(self) -> None:
        findings = check_certificate(SHA1_LEAF, NOW)
        matches = _find(findings, "CERT-WEAK-HASH")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, SEVERITY_WARNING)
        self.assertIn("SHA-1", matches[0].message)

    def test_md5_signature_is_an_error(self) -> None:
        md5_cert = replace(
            LEAF,
            signature_algorithm_oid="1.2.840.113549.1.1.4",
            signature_algorithm="md5WithRSAEncryption",
        )
        findings = _find(check_certificate(md5_cert, NOW), "CERT-WEAK-HASH")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_ERROR)
        self.assertIn("MD5", findings[0].message)

    def test_sha256_has_no_weak_hash_finding(self) -> None:
        self.assertEqual(_find(check_certificate(LEAF, NOW), "CERT-WEAK-HASH"), [])

    def test_small_rsa_key_is_an_error(self) -> None:
        findings = _find(check_certificate(SMALL_KEY_LEAF, NOW), "CERT-SMALL-RSA-KEY")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_ERROR)
        self.assertIn("1024 bits", findings[0].message)

    def test_2048_bit_rsa_key_is_accepted(self) -> None:
        self.assertEqual(_find(check_certificate(LEAF, NOW), "CERT-SMALL-RSA-KEY"), [])

    def test_rsa_bits_unknown_produces_no_small_key_finding(self) -> None:
        unknown = replace(LEAF, public_key_bits=None)
        self.assertEqual(_find(check_certificate(unknown, NOW), "CERT-SMALL-RSA-KEY"), [])


class ProfileRuleTests(unittest.TestCase):
    def test_self_signed_non_ca_is_a_notice(self) -> None:
        findings = _find(check_certificate(SELF_SIGNED, NOW), "CERT-SELF-SIGNED")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_NOTICE)

    def test_self_signed_rule_is_ignored_for_ca_certificates(self) -> None:
        as_ca = replace(SELF_SIGNED, basic_constraints=BasicConstraints(ca=True))
        self.assertEqual(_find(check_certificate(as_ca, NOW), "CERT-SELF-SIGNED"), [])

    def test_missing_san_is_a_warning_for_non_ca(self) -> None:
        no_san = replace(LEAF, san=())
        findings = _find(check_certificate(no_san, NOW), "CERT-NO-SAN")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_WARNING)

    def test_missing_san_is_not_reported_for_ca(self) -> None:
        self.assertEqual(_find(check_certificate(ROOT, NOW), "CERT-NO-SAN"), [])

    def test_wildcard_san_is_a_notice(self) -> None:
        wildcard = replace(LEAF, san=(GeneralName("dns", "*.example"),))
        findings = _find(check_certificate(wildcard, NOW), "CERT-WILDCARD")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_NOTICE)
        self.assertIn("*.example", findings[0].message)

    def test_non_wildcard_san_has_no_wildcard_finding(self) -> None:
        self.assertEqual(_find(check_certificate(LEAF, NOW), "CERT-WILDCARD"), [])

    def test_long_validity_is_a_notice(self) -> None:
        long_lived = replace(
            LEAF,
            not_before=NOW - datetime.timedelta(days=1000),
            not_after=NOW + datetime.timedelta(days=1000),
        )
        findings = _find(check_certificate(long_lived, NOW), "CERT-LONG-VALIDITY")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_NOTICE)
        self.assertIn("2000 days", findings[0].message)

    def test_validity_of_398_days_is_accepted(self) -> None:
        borderline = replace(
            LEAF,
            not_before=NOW - datetime.timedelta(days=100),
            not_after=NOW + datetime.timedelta(days=298),
        )
        self.assertEqual(borderline.validity_days, 398)
        self.assertEqual(_find(check_certificate(borderline, NOW), "CERT-LONG-VALIDITY"), [])

    def test_ca_certificate_is_an_info(self) -> None:
        findings = _find(check_certificate(ROOT, NOW), "CERT-CA-CERT")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_INFO)
        self.assertIn("pathLenConstraint 1", findings[0].message)

    def test_leaf_is_not_a_ca_info(self) -> None:
        self.assertEqual(_find(check_certificate(LEAF, NOW), "CERT-CA-CERT"), [])


class HostnameRuleTests(unittest.TestCase):
    def test_exact_dns_match(self) -> None:
        self.assertTrue(matches_hostname(LEAF, "srv-a.example"))
        self.assertTrue(matches_hostname(LEAF, "SRV-A.EXAMPLE"))
        self.assertEqual(_find(check_certificate(LEAF, NOW, "srv-a.example"), "CERT-HOSTNAME-MISMATCH"), [])

    def test_dns_mismatch_is_an_error(self) -> None:
        findings = _find(check_certificate(LEAF, NOW, "other.example"), "CERT-HOSTNAME-MISMATCH")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_ERROR)
        self.assertIn("other.example", findings[0].message)
        self.assertIn("DNS:srv-a.example", findings[0].message)

    def test_ip_san_match_and_mismatch(self) -> None:
        self.assertTrue(matches_hostname(LEAF, "192.0.2.10"))
        self.assertEqual(
            _find(check_certificate(LEAF, NOW, "192.0.2.10"), "CERT-HOSTNAME-MISMATCH"), []
        )
        self.assertFalse(matches_hostname(LEAF, "192.0.2.11"))
        self.assertEqual(
            len(_find(check_certificate(LEAF, NOW, "192.0.2.11"), "CERT-HOSTNAME-MISMATCH")), 1
        )

    def test_wildcard_matches_single_label(self) -> None:
        wildcard = replace(LEAF, san=(GeneralName("dns", "*.example"),))
        self.assertTrue(matches_hostname(wildcard, "srv-a.example"))
        self.assertFalse(matches_hostname(wildcard, "a.b.example"))
        self.assertEqual(
            _find(check_certificate(wildcard, NOW, "srv-a.example"), "CERT-HOSTNAME-MISMATCH"), []
        )
        self.assertEqual(
            len(_find(check_certificate(wildcard, NOW, "a.b.example"), "CERT-HOSTNAME-MISMATCH")), 1
        )

    def test_cn_fallback_when_no_san(self) -> None:
        legacy = replace(LEAF, san=())
        self.assertTrue(matches_hostname(legacy, "srv-a.example"))
        self.assertFalse(matches_hostname(legacy, "other.example"))
        self.assertEqual(
            _find(check_certificate(legacy, NOW, "srv-a.example"), "CERT-HOSTNAME-MISMATCH"), []
        )

    def test_no_hostname_expected_skips_rule(self) -> None:
        self.assertEqual(_find(check_certificate(LEAF, NOW), "CERT-HOSTNAME-MISMATCH"), [])

    def test_empty_hostname_never_matches(self) -> None:
        self.assertFalse(matches_hostname(LEAF, ""))

    def test_mismatch_message_when_no_names(self) -> None:
        empty = replace(LEAF, san=(), subject=DistinguishedName(()))
        findings = _find(check_certificate(empty, NOW, "srv-a.example"), "CERT-HOSTNAME-MISMATCH")
        self.assertEqual(len(findings), 1)
        self.assertIn("no DNS or IP names", findings[0].message)


class InventoryRuleTests(unittest.TestCase):
    def test_duplicate_fingerprints_are_warnings(self) -> None:
        first = LEAF.with_source("a/leaf.pem")
        second = LEAF.with_source("b/leaf.pem")
        third = LEAF.with_source("c/leaf.pem")
        findings = _find(check_inventory([first, second, third], NOW), "CERT-DUPLICATE")
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding.severity == SEVERITY_WARNING for finding in findings))
        self.assertIn("a/leaf.pem", findings[0].message)

    def test_distinct_certificates_are_not_duplicates(self) -> None:
        findings = _find(check_inventory([ROOT, INTERMEDIATE, LEAF], NOW), "CERT-DUPLICATE")
        self.assertEqual(findings, [])

    def test_missing_issuer_is_a_warning(self) -> None:
        findings = _find(check_inventory([LEAF], NOW), "CERT-CHAIN-MISSING-ISSUER")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_WARNING)
        self.assertIn("NetWatch Lab Intermediate CA", findings[0].message)

    def test_complete_chain_has_no_missing_issuer(self) -> None:
        findings = _find(check_inventory([ROOT, INTERMEDIATE, LEAF], NOW), "CERT-CHAIN-MISSING-ISSUER")
        self.assertEqual(findings, [])

    def test_self_signed_certificate_has_no_missing_issuer(self) -> None:
        findings = _find(check_inventory([SELF_SIGNED], NOW), "CERT-CHAIN-MISSING-ISSUER")
        self.assertEqual(findings, [])

    def test_intermediate_without_root_reports_missing_issuer(self) -> None:
        rules = _rules(check_inventory([INTERMEDIATE], NOW))
        self.assertIn("CERT-CHAIN-MISSING-ISSUER", rules)


class AuditResultTests(unittest.TestCase):
    def test_counts_include_all_severities(self) -> None:
        result = audit([LEAF], NOW)
        self.assertEqual(set(result.counts), {"error", "warning", "notice", "info"})
        self.assertEqual(result.counts["error"], 0)
        self.assertEqual(sum(result.counts.values()), result.finding_count)

    def test_max_severity_and_fail_thresholds(self) -> None:
        result = audit([SHA1_LEAF], NOW)
        self.assertEqual(result.max_severity, SEVERITY_WARNING)
        self.assertTrue(result.has_findings_at_or_above("warning"))
        self.assertFalse(result.has_findings_at_or_above("error"))
        self.assertFalse(result.has_findings_at_or_above("none"))
        self.assertTrue(fail_on_matches(result, "warning"))

    def test_clean_audit(self) -> None:
        # A CA certificate with a normal two-century window yields only the
        # informational CA finding, which is below the warning threshold.
        quiet_ca = replace(
            ROOT,
            not_before=NOW - datetime.timedelta(days=100),
            not_after=NOW + datetime.timedelta(days=100),
        )
        result = audit([quiet_ca], NOW)
        self.assertEqual([finding.rule_id for finding in result.findings], ["CERT-CA-CERT"])
        self.assertEqual(result.max_severity, SEVERITY_INFO)
        self.assertFalse(result.has_findings_at_or_above("warning"))
        self.assertFalse(fail_on_matches(result, "warning"))

    def test_unsupported_fail_threshold_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            audit([LEAF], NOW).has_findings_at_or_above("critical")

    def test_findings_are_sorted_by_severity(self) -> None:
        mixed = replace(
            LEAF,
            not_after=NOW - datetime.timedelta(days=1),
        )
        result = audit([mixed, SELF_SIGNED], NOW)
        severities = [finding.severity for finding in result.findings]
        self.assertEqual(severities[0], SEVERITY_ERROR)
        self.assertIn(SEVERITY_NOTICE, severities)
        self.assertEqual(severities, sorted(severities, key=lambda severity: {
            "info": 0, "notice": 1, "warning": 2, "error": 3
        }[severity], reverse=True))

    def test_finding_to_dict(self) -> None:
        finding = Finding(
            rule_id="CERT-TEST",
            severity=SEVERITY_INFO,
            subject="example",
            fingerprint="abcd",
            message="message",
        )
        self.assertEqual(
            finding.to_dict(),
            {
                "rule": "CERT-TEST",
                "severity": "info",
                "subject": "example",
                "fingerprint": "abcd",
                "message": "message",
            },
        )

    def test_load_errors_are_kept(self) -> None:
        from certsentinel.x509 import LoadError

        error = LoadError("bad.txt", "no PEM CERTIFICATE block found")
        result = audit([], NOW, load_errors=[error])
        self.assertEqual(result.load_errors, [error])
        self.assertEqual(result.findings, [])

    def test_audit_accepts_naive_datetime(self) -> None:
        result = audit([LEAF], datetime.datetime(2026, 11, 16, 18, 0, 0))
        self.assertEqual(result.generated_at.tzinfo, UTC)

    def test_default_subject_is_empty_marker(self) -> None:
        without_names = replace(LEAF, san=(), subject=DistinguishedName(()))
        findings = _find(check_certificate(without_names, NOW), "CERT-NO-SAN")
        self.assertEqual(findings[0].subject, "(empty subject)")

    def test_dn_rdn_helpers_used_by_rules(self) -> None:
        dn = DistinguishedName(
            (
                Rdn((RdnAttribute("2.5.4.6", "C", "PT"),)),
                Rdn((RdnAttribute("2.5.4.10", "O", "Lab"), RdnAttribute("2.5.4.3", "CN", "edge"))),
            )
        )
        self.assertEqual(dn.common_name, "edge")
        self.assertEqual(dn.get_all("C"), ("PT",))
        self.assertIsNone(dn.get("OU"))


if __name__ == "__main__":
    unittest.main()
