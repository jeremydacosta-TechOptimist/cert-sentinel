"""Shared helpers and small DER builders for the cert-sentinel test suite."""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence

from certsentinel.x509 import Certificate, load_file, load_paths

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PKI = REPO_ROOT / "examples" / "pki"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

ROOT_CA = "root-ca.pem"
INTERMEDIATE_CA = "intermediate-ca.pem"
LEAF_SERVER = "leaf-server.pem"
LEAF_DER = "leaf.der"
LEAF_EXPIRING = "leaf-expiring-soon.pem"
LEAF_SHA1 = "leaf-sha1.pem"
LEAF_SMALL_KEY = "leaf-small-key.pem"
LEAF_SELF_SIGNED = "leaf-self-signed.pem"
EC_LEAF = "ec-leaf.pem"


def tlv(tag: int, content: bytes) -> bytes:
    """Build a DER TLV with a minimal length (test fixtures only)."""

    length = len(content)
    if length < 0x80:
        header = bytes((tag, length))
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes((tag, 0x80 | len(encoded))) + encoded
    return header + content


def sequence(*items: bytes) -> bytes:
    """Build a DER SEQUENCE from already encoded items."""

    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    """Build a DER SET from already encoded items."""

    return tlv(0x31, b"".join(items))


def integer(value: int) -> bytes:
    """Build a minimal DER INTEGER for a test fixture."""

    if value == 0:
        payload = b"\x00"
    elif value > 0:
        payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    else:
        count = 1
        while value < -(1 << (8 * count - 1)):
            count += 1
        payload = value.to_bytes(count, "big", signed=True)
    return tlv(0x02, payload)


def string_value(text: str, tag: int = 0x0C) -> bytes:
    """Build a DER string value with the requested string tag."""

    return tlv(tag, text.encode("utf-8"))


def load_example(name: str) -> Certificate:
    """Load one certificate from the committed examples/pki directory."""

    return load_file(EXAMPLES_PKI / name)[0]


def load_examples() -> List[Certificate]:
    """Load every committed example certificate (deterministic order)."""

    return load_paths([EXAMPLES_PKI]).certificates


def load_ec_fixture() -> Certificate:
    """Load the EC P-256 certificate committed under tests/fixtures."""

    return load_file(FIXTURES / EC_LEAF)[0]


def as_text(data: bytes) -> str:
    """Decode bytes as UTF-8 text for assertions."""

    return data.decode("utf-8")


__all__: Sequence[str] = [
    "REPO_ROOT",
    "EXAMPLES_PKI",
    "FIXTURES",
    "ROOT_CA",
    "INTERMEDIATE_CA",
    "LEAF_SERVER",
    "LEAF_DER",
    "LEAF_EXPIRING",
    "LEAF_SHA1",
    "LEAF_SMALL_KEY",
    "LEAF_SELF_SIGNED",
    "EC_LEAF",
    "tlv",
    "sequence",
    "set_of",
    "integer",
    "string_value",
    "load_example",
    "load_examples",
    "load_ec_fixture",
]
