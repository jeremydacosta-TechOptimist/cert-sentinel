"""Tests for the X.509 certificate model and DER/PEM parsing."""

from __future__ import annotations

import datetime
import unittest

from certsentinel.x509 import (
    Certificate,
    GeneralName,
    X509Error,
    from_der,
    from_pem,
    load_bundle,
)
from tests.helpers import (
    EXAMPLES_PKI,
    ROOT_CA,
    INTERMEDIATE_CA,
    LEAF_SERVER,
    LEAF_DER,
    LEAF_EXPIRING,
    LEAF_SHA1,
    LEAF_SMALL_KEY,
    LEAF_SELF_SIGNED,
    load_ec_fixture,
    load_example,
    load_examples,
)

UTC = datetime.timezone.utc
GENERATED = datetime.datetime(2026, 11, 16, 17, 32, 56, tzinfo=UTC)


class CertificateParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.examples = load_examples()
        cls.root = load_example(ROOT_CA)
        cls.intermediate = load_example(INTERMEDIATE_CA)
        cls.leaf = load_example(LEAF_SERVER)
        cls.leaf_der = load_example(LEAF_DER)
        cls.expiring = load_example(LEAF_EXPIRING)
        cls.sha1 = load_example(LEAF_SHA1)
        cls.small_key = load_example(LEAF_SMALL_KEY)
        cls.self_signed = load_example(LEAF_SELF_SIGNED)
        cls.ec = load_ec_fixture()

    def test_all_example_certificates_load(self) -> None:
        self.assertEqual(len(self.examples), 8)
        self.assertTrue(all(isinstance(certificate, Certificate) for certificate in self.examples))

    def test_root_ca_identity(self) -> None:
        self.assertEqual(self.root.version, 3)
        self.assertEqual(self.root.serial, 0x1000)
        self.assertEqual(self.root.serial_hex, "1000")
        self.assertEqual(self.root.subject_cn, "NetWatch Lab Root CA")
        self.assertEqual(self.root.issuer_cn, "NetWatch Lab Root CA")
        self.assertEqual(self.root.subject, self.root.issuer)
        self.assertTrue(self.root.is_ca)
        self.assertEqual(self.root.basic_constraints.path_len, 1)
        self.assertEqual(self.root.key_usage, frozenset({"keyCertSign", "cRLSign"}))
        self.assertEqual(self.root.san, ())

    def test_root_ca_validity_and_signature(self) -> None:
        self.assertEqual(self.root.not_before, GENERATED)
        self.assertEqual(self.root.not_after, datetime.datetime(2036, 11, 13, 17, 32, 56, tzinfo=UTC))
        self.assertEqual(self.root.validity_days, 3650)
        self.assertEqual(self.root.signature_algorithm, "sha256WithRSAEncryption")
        self.assertEqual(self.root.signature_hash, "sha256")
        self.assertEqual(self.root.public_key_algorithm, "RSA")
        self.assertEqual(self.root.public_key_bits, 2048)
        self.assertIsNone(self.root.ec_curve)

    def test_intermediate_ca_links_to_root(self) -> None:
        self.assertEqual(self.intermediate.subject_cn, "NetWatch Lab Intermediate CA")
        self.assertEqual(self.intermediate.issuer_cn, "NetWatch Lab Root CA")
        self.assertTrue(self.intermediate.is_ca)
        self.assertEqual(self.intermediate.basic_constraints.path_len, 0)
        self.assertEqual(self.intermediate.authority_key_identifier, self.root.subject_key_identifier)
        self.assertNotEqual(self.intermediate.subject_key_identifier, self.root.subject_key_identifier)

    def test_leaf_server_names(self) -> None:
        self.assertEqual(self.leaf.subject_cn, "srv-a.example")
        self.assertEqual(self.leaf.issuer_cn, "NetWatch Lab Intermediate CA")
        self.assertEqual(
            self.leaf.san,
            (
                GeneralName("dns", "srv-a.example"),
                GeneralName("ip", "192.0.2.10"),
                GeneralName("email", "admin@example"),
                GeneralName("uri", "https://srv-a.example/"),
            ),
        )
        self.assertEqual(self.leaf.dns_names, ("srv-a.example",))
        self.assertEqual(self.leaf.ip_addresses, ("192.0.2.10",))

    def test_leaf_server_extensions(self) -> None:
        self.assertFalse(self.leaf.is_ca)
        self.assertIsNone(self.leaf.basic_constraints.path_len)
        self.assertEqual(self.leaf.key_usage, frozenset({"digitalSignature", "keyEncipherment"}))
        self.assertEqual(self.leaf.extended_key_usage, ("serverAuth",))
        # Subject key identifiers are 20-byte SHA-1 digests -> 40 hex characters.
        self.assertEqual(len(self.leaf.subject_key_identifier or ""), 40)
        self.assertEqual(
            self.leaf.authority_key_identifier, self.intermediate.subject_key_identifier
        )

    def test_leaf_server_aia(self) -> None:
        self.assertEqual(
            [(entry.method, entry.location.kind, entry.location.value) for entry in self.leaf.authority_info_access],
            [
                ("OCSP", "uri", "http://ocsp.example/ocsp"),
                ("caIssuers", "uri", "http://ca.example/intermediate-ca.pem"),
            ],
        )
        self.assertEqual(
            self.leaf.aia_urls,
            ("http://ocsp.example/ocsp", "http://ca.example/intermediate-ca.pem"),
        )

    def test_leaf_server_validity(self) -> None:
        self.assertEqual(self.leaf.not_before, GENERATED)
        self.assertEqual(self.leaf.validity_days, 365)
        self.assertEqual(self.leaf.days_remaining(datetime.datetime(2026, 11, 17, tzinfo=UTC)), 364)
        self.assertLess(self.leaf.days_remaining(datetime.datetime(2030, 1, 1, tzinfo=UTC)), 0)

    def test_der_copy_has_the_same_fingerprint(self) -> None:
        self.assertEqual(self.leaf.sha256_fingerprint, self.leaf_der.sha256_fingerprint)
        self.assertEqual(self.leaf.serial, self.leaf_der.serial)
        self.assertEqual(self.leaf.subject, self.leaf_der.subject)

    def test_sha1_certificate(self) -> None:
        self.assertEqual(self.sha1.signature_algorithm, "sha1WithRSAEncryption")
        self.assertEqual(self.sha1.signature_hash, "sha1")
        self.assertEqual(self.sha1.subject_cn, "legacy-sha1.example")

    def test_small_rsa_key(self) -> None:
        self.assertEqual(self.small_key.public_key_algorithm, "RSA")
        self.assertEqual(self.small_key.public_key_bits, 1024)
        self.assertEqual(self.small_key.subject_cn, "legacy-rsa.example")

    def test_expiring_certificate(self) -> None:
        self.assertEqual(self.expiring.validity_days, 20)
        self.assertEqual(self.expiring.subject_cn, "srv-b.example")
        self.assertEqual(
            self.expiring.not_after, datetime.datetime(2026, 12, 6, 17, 32, 56, tzinfo=UTC)
        )

    def test_self_signed_certificate(self) -> None:
        self.assertEqual(self.self_signed.subject, self.self_signed.issuer)
        self.assertEqual(
            self.self_signed.subject_key_identifier, self.self_signed.authority_key_identifier
        )
        self.assertFalse(self.self_signed.is_ca)

    def test_ec_certificate(self) -> None:
        self.assertEqual(self.ec.public_key_algorithm, "EC")
        self.assertEqual(self.ec.ec_curve, "prime256v1 (P-256)")
        self.assertEqual(self.ec.public_key_bits, 256)
        self.assertEqual(self.ec.signature_algorithm, "ecdsa-with-SHA256")
        self.assertFalse(self.ec.is_ca)
        self.assertEqual(self.ec.signature_hash, "sha256")
        self.assertEqual(self.ec.dns_names, ("ec.example",))

    def test_fingerprint_format(self) -> None:
        self.assertEqual(len(self.root.sha256_fingerprint), 64)
        self.assertTrue(all(character in "0123456789abcdef" for character in self.root.sha256_fingerprint))
        self.assertEqual(len(self.root.fingerprint_prefix), 16)

    def test_distinguished_name_helpers(self) -> None:
        self.assertEqual(self.root.subject.organization, "NetWatch Lab")
        self.assertEqual(self.root.subject.country, "PT")
        self.assertEqual(self.root.subject.get("CN"), "NetWatch Lab Root CA")
        self.assertIsNone(self.root.subject.get("OU"))
        self.assertIn("C=PT", str(self.root.subject))
        self.assertIn("CN=NetWatch Lab Root CA", str(self.root.subject))

    def test_general_name_to_dict(self) -> None:
        self.assertEqual(self.leaf.san[1].to_dict(), {"type": "ip", "value": "192.0.2.10"})

    def test_with_source_returns_copy(self) -> None:
        bare = from_der(self.root.der)
        self.assertIsNone(bare.source)
        copy = bare.with_source("examples/pki/root-ca.pem")
        self.assertEqual(copy.source, "examples/pki/root-ca.pem")
        self.assertEqual(copy.sha256_fingerprint, bare.sha256_fingerprint)
        self.assertIsNone(bare.source)
        self.assertIsNot(copy, bare)

    def test_der_round_trip(self) -> None:
        reparsed = from_der(self.leaf.der)
        self.assertEqual(reparsed.sha256_fingerprint, self.leaf.sha256_fingerprint)
        self.assertEqual(reparsed.serial, self.leaf.serial)
        self.assertEqual(reparsed.subject_cn, "srv-a.example")

    def test_empty_and_invalid_der_are_rejected(self) -> None:
        with self.assertRaises(X509Error):
            from_der(b"")
        with self.assertRaises(X509Error):
            from_der(self.leaf.der[:20])
        with self.assertRaises(X509Error):
            from_der(b"\x30\x00")


class PemParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root_pem = (EXAMPLES_PKI / ROOT_CA).read_bytes()
        cls.intermediate_pem = (EXAMPLES_PKI / INTERMEDIATE_CA).read_bytes()
        cls.leaf_pem = (EXAMPLES_PKI / LEAF_SERVER).read_bytes()

    def test_from_pem_single_certificate(self) -> None:
        certificates = from_pem(self.leaf_pem)
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0].subject_cn, "srv-a.example")

    def test_from_pem_accepts_text_input(self) -> None:
        certificates = from_pem(self.leaf_pem.decode("ascii"))
        self.assertEqual(len(certificates), 1)

    def test_from_pem_bundle(self) -> None:
        bundle = self.root_pem + b"\n" + self.intermediate_pem
        certificates = from_pem(bundle)
        self.assertEqual([certificate.subject_cn for certificate in certificates], [
            "NetWatch Lab Root CA",
            "NetWatch Lab Intermediate CA",
        ])

    def test_from_pem_without_block_is_rejected(self) -> None:
        with self.assertRaises(X509Error):
            from_pem(b"not a certificate")

    def test_from_pem_invalid_base64_is_rejected(self) -> None:
        broken = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"!!!not-base64!!!\n"
            b"-----END CERTIFICATE-----\n"
        )
        with self.assertRaises(X509Error):
            from_pem(broken)

    def test_from_pem_ignores_other_pem_blocks(self) -> None:
        mixed = (
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
            + self.leaf_pem
        )
        self.assertEqual(len(from_pem(mixed)), 1)

    def test_load_bundle_pem_and_der(self) -> None:
        der = (EXAMPLES_PKI / LEAF_DER).read_bytes()
        self.assertEqual(len(load_bundle(self.leaf_pem)), 1)
        self.assertEqual(len(load_bundle(der)), 1)
        self.assertEqual(load_bundle(der)[0].subject_cn, "srv-a.example")

    def test_load_bundle_empty_is_rejected(self) -> None:
        with self.assertRaises(X509Error):
            load_bundle(b"")


if __name__ == "__main__":
    unittest.main()
