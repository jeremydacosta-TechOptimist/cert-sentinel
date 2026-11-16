"""Tests for certificate discovery: files, bundles and directory trees."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from certsentinel.x509 import (
    CERTIFICATE_EXTENSIONS,
    X509Error,
    load_bundle,
    load_file,
    load_paths,
)
from tests.helpers import EXAMPLES_PKI, LEAF_SERVER, ROOT_CA, load_example


class LoadPathsTests(unittest.TestCase):
    def test_load_single_file(self) -> None:
        result = load_paths([EXAMPLES_PKI / LEAF_SERVER])
        self.assertEqual(len(result.certificates), 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(
            result.certificates[0].source,
            (EXAMPLES_PKI / LEAF_SERVER).as_posix(),
        )

    def test_load_directory_tree(self) -> None:
        result = load_paths([EXAMPLES_PKI])
        self.assertEqual(len(result.certificates), 8)
        self.assertEqual(result.errors, [])
        sources = result.sources
        self.assertIn((EXAMPLES_PKI / ROOT_CA).as_posix(), sources)
        self.assertIn((EXAMPLES_PKI / "leaf.der").as_posix(), sources)

    def test_missing_path_is_reported(self) -> None:
        result = load_paths(["examples/does-not-exist"])
        self.assertEqual(result.certificates, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("does not exist", result.errors[0].message)

    def test_non_certificate_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.txt"
            path.write_text("not a certificate", encoding="utf-8")
            result = load_paths([path])
        self.assertEqual(result.certificates, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("not a certificate", result.errors[0].message)

    def test_directory_without_certificates_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty"
            path.mkdir()
            result = load_paths([path])
        self.assertEqual(result.certificates, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("no certificate files", result.errors[0].message)

    def test_directory_extension_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "leaf.pem").write_bytes((EXAMPLES_PKI / LEAF_SERVER).read_bytes())
            (root / "ignored.key").write_text("placeholder", encoding="utf-8")
            (root / "ignored.txt").write_text("placeholder", encoding="utf-8")
            result = load_paths([root])
        self.assertEqual(len(result.certificates), 1)
        self.assertEqual(result.errors, [])

    def test_multi_certificate_bundle_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "chain.pem"
            bundle_path.write_bytes(
                (EXAMPLES_PKI / ROOT_CA).read_bytes()
                + b"\n"
                + (EXAMPLES_PKI / "intermediate-ca.pem").read_bytes()
            )
            result = load_paths([bundle_path])
        self.assertEqual([certificate.subject_cn for certificate in result.certificates], [
            "NetWatch Lab Root CA",
            "NetWatch Lab Intermediate CA",
        ])
        self.assertEqual(result.sources, [str(bundle_path.as_posix())])

    def test_explicit_file_with_unknown_extension_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.bin"
            target.write_bytes((EXAMPLES_PKI / "leaf.der").read_bytes())
            result = load_paths([target])
        self.assertEqual(len(result.certificates), 1)
        self.assertEqual(result.certificates[0].subject_cn, "srv-a.example")

    def test_certificate_extensions_constant(self) -> None:
        self.assertEqual(CERTIFICATE_EXTENSIONS, {".pem", ".crt", ".cer", ".der"})


class LoadFileTests(unittest.TestCase):
    def test_load_file_pem(self) -> None:
        certificates = load_file(EXAMPLES_PKI / ROOT_CA)
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0].subject_cn, "NetWatch Lab Root CA")

    def test_load_file_der(self) -> None:
        certificates = load_file(EXAMPLES_PKI / "leaf.der")
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0].subject_cn, "srv-a.example")

    def test_load_file_missing_raises(self) -> None:
        with self.assertRaises(X509Error):
            load_file(EXAMPLES_PKI / "missing.pem")

    def test_load_bundle_text_pem(self) -> None:
        text = (EXAMPLES_PKI / LEAF_SERVER).read_text(encoding="ascii")
        certificates = load_bundle(text)
        self.assertEqual(len(certificates), 1)

    def test_load_result_extend(self) -> None:
        first = load_paths([EXAMPLES_PKI / ROOT_CA])
        second = load_paths([EXAMPLES_PKI / LEAF_SERVER])
        first.extend(second)
        self.assertEqual(len(first.certificates), 2)
        self.assertEqual(first.errors, [])

    def test_certificate_source_is_posix_style(self) -> None:
        certificate = load_example(LEAF_SERVER)
        self.assertTrue((certificate.source or "").endswith("examples/pki/leaf-server.pem"))
        self.assertNotIn("\\", certificate.source or "")


if __name__ == "__main__":
    unittest.main()
