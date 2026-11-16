"""X.509 certificate model and PEM/DER inventory loader.

The module turns DER bytes into a :class:`Certificate` dataclass: names,
validity, signature algorithm, public key details (RSA modulus bits or EC named
curve), and the extensions that matter for an audit (SAN, basic constraints,
key usage, extended key usage, key identifiers, AIA). It also discovers
certificates in files, bundles and directory trees, reporting clear errors for
files that are not certificates.

No cryptographic verification is performed: this is an inventory and
configuration auditor, not a TLS stack.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple, Union

from .der import (
    CLASS_CONTEXT,
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    DerError,
    DerNode,
    decode_bit_string,
    decode_boolean,
    decode_octet_string,
    decode_oid,
    decode_positive_integer,
    decode_string,
    decode_time,
    expect_tag,
    format_hex,
    parse_der,
    read_children,
    bit_string_flags,
)

__all__ = [
    "X509Error",
    "RdnAttribute",
    "Rdn",
    "DistinguishedName",
    "GeneralName",
    "BasicConstraints",
    "AuthorityInfoAccess",
    "Certificate",
    "LoadError",
    "LoadResult",
    "CERTIFICATE_EXTENSIONS",
    "parse_certificate",
    "from_der",
    "from_pem",
    "load_bundle",
    "load_paths",
    "load_file",
]

CERTIFICATE_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".der"})

# Attribute type OIDs used in X.500 names (RFC 4519 and friends).
_ATTRIBUTE_NAMES: Dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.17": "postalCode",
    "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}

_SIGNATURE_ALGORITHMS: Dict[str, str] = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

_SIGNATURE_HASHES: Dict[str, str] = {
    "1.2.840.113549.1.1.2": "md2",
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}

_PUBLIC_KEY_ALGORITHMS: Dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

_EC_CURVES: Dict[str, Tuple[str, Optional[int]]] = {
    "1.2.840.10045.3.1.7": ("prime256v1 (P-256)", 256),
    "1.3.132.0.34": ("secp384r1 (P-384)", 384),
    "1.3.132.0.35": ("secp521r1 (P-521)", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}

_EKU_NAMES: Dict[str, str] = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "1.3.6.1.5.5.7.3.5": "ipsecEndSystem",
    "1.3.6.1.5.5.7.3.6": "ipsecTunnel",
    "1.3.6.1.5.5.7.3.7": "ipsecUser",
    "1.3.6.1.5.5.7.3.10": "dvcs",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}

_AIA_METHODS: Dict[str, str] = {
    "1.3.6.1.5.5.7.48.1": "OCSP",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
}

_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_KEY_USAGE = "2.5.29.15"
_OID_EXTENDED_KEY_USAGE = "2.5.29.37"
_OID_SUBJECT_ALT_NAME = "2.5.29.17"
_OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
_OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
_OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"

_KEY_USAGE_BITS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)

_PEM_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----"
)


class X509Error(ValueError):
    """Raised when bytes cannot be interpreted as an X.509 certificate."""


@dataclass(frozen=True)
class RdnAttribute:
    """One attribute inside a relative distinguished name."""

    oid: str
    name: str
    value: str


@dataclass(frozen=True)
class Rdn:
    """A relative distinguished name; may contain several attributes."""

    attributes: Tuple[RdnAttribute, ...]

    def __str__(self) -> str:
        return "+".join(f"{attribute.name}={attribute.value}" for attribute in self.attributes)


@dataclass(frozen=True)
class DistinguishedName:
    """An ordered X.500 distinguished name."""

    rdns: Tuple[Rdn, ...] = ()

    def get(self, name: str) -> Optional[str]:
        """Return the first value for an attribute (friendly name or OID)."""

        for rdn in self.rdns:
            for attribute in rdn.attributes:
                if name in (attribute.name, attribute.oid):
                    return attribute.value
        return None

    def get_all(self, name: str) -> Tuple[str, ...]:
        """Return every value for an attribute, in encoding order."""

        values = []
        for rdn in self.rdns:
            for attribute in rdn.attributes:
                if name in (attribute.name, attribute.oid):
                    values.append(attribute.value)
        return tuple(values)

    @property
    def common_name(self) -> Optional[str]:
        """Shorthand for the first CN value."""

        return self.get("CN")

    @property
    def organization(self) -> Optional[str]:
        """Shorthand for the first O value."""

        return self.get("O")

    @property
    def country(self) -> Optional[str]:
        """Shorthand for the first C value."""

        return self.get("C")

    @property
    def email_address(self) -> Optional[str]:
        """Shorthand for the first emailAddress value."""

        return self.get("emailAddress") or self.get("1.2.840.113549.1.9.1")

    def __str__(self) -> str:
        return ", ".join(str(rdn) for rdn in self.rdns)


@dataclass(frozen=True)
class GeneralName:
    """One subject alternative name entry."""

    kind: str
    value: str

    def to_dict(self) -> Dict[str, str]:
        """JSON-friendly representation."""

        return {"type": self.kind, "value": self.value}


@dataclass(frozen=True)
class BasicConstraints:
    """Decoded basicConstraints extension."""

    ca: bool = False
    path_len: Optional[int] = None


@dataclass(frozen=True)
class AuthorityInfoAccess:
    """One AIA access description (OCSP responder or CA issuer URL)."""

    method: str
    location: GeneralName


@dataclass(frozen=True)
class Extension:
    """Raw certificate extension."""

    oid: str
    critical: bool
    value: bytes


@dataclass(frozen=True)
class Certificate:
    """Parsed X.509 certificate with an inventory-friendly subset of fields."""

    der: bytes
    sha256_fingerprint: str
    version: int
    serial: int
    serial_hex: str
    signature_algorithm_oid: str
    signature_algorithm: str
    issuer: DistinguishedName
    subject: DistinguishedName
    not_before: datetime
    not_after: datetime
    public_key_algorithm_oid: str
    public_key_algorithm: str
    public_key_bits: Optional[int]
    ec_curve: Optional[str]
    san: Tuple[GeneralName, ...] = ()
    basic_constraints: BasicConstraints = BasicConstraints()
    key_usage: FrozenSet[str] = frozenset()
    extended_key_usage: Tuple[str, ...] = ()
    subject_key_identifier: Optional[str] = None
    authority_key_identifier: Optional[str] = None
    authority_info_access: Tuple[AuthorityInfoAccess, ...] = ()
    source: Optional[str] = None

    @property
    def subject_cn(self) -> Optional[str]:
        """Subject common name, when present."""

        return self.subject.common_name

    @property
    def issuer_cn(self) -> Optional[str]:
        """Issuer common name, when present."""

        return self.issuer.common_name

    @property
    def fingerprint_prefix(self) -> str:
        """First 16 hexadecimal characters of the SHA-256 fingerprint."""

        return self.sha256_fingerprint[:16]

    @property
    def is_ca(self) -> bool:
        """True when basicConstraints marks the certificate as a CA."""

        return self.basic_constraints.ca

    @property
    def signature_hash(self) -> Optional[str]:
        """Hash name used by the signature algorithm, when known."""

        return _SIGNATURE_HASHES.get(self.signature_algorithm_oid)

    @property
    def validity_days(self) -> int:
        """Total validity window in whole days."""

        return (self.not_after - self.not_before).days

    @property
    def aia_urls(self) -> Tuple[str, ...]:
        """HTTP(S) URLs advertised through the AIA extension."""

        return tuple(
            entry.location.value
            for entry in self.authority_info_access
            if entry.location.kind == "uri"
        )

    @property
    def dns_names(self) -> Tuple[str, ...]:
        """dNSName SAN entries."""

        return tuple(name.value for name in self.san if name.kind == "dns")

    @property
    def ip_addresses(self) -> Tuple[str, ...]:
        """iPAddress SAN entries in canonical compressed form."""

        return tuple(name.value for name in self.san if name.kind == "ip")

    def days_remaining(self, now: datetime) -> int:
        """Whole days between ``now`` and notAfter (negative when expired)."""

        return (self.not_after - now).days

    def with_source(self, source: Optional[str]) -> "Certificate":
        """Return a copy carrying the file path it was loaded from."""

        return replace(self, source=source)


@dataclass(frozen=True)
class LoadError:
    """A file that could not be loaded as a certificate."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class LoadResult:
    """Certificates and per-file errors discovered by :func:`load_paths`."""

    certificates: List[Certificate] = field(default_factory=list)
    errors: List[LoadError] = field(default_factory=list)

    @property
    def sources(self) -> List[str]:
        """Distinct source paths, in load order."""

        result: List[str] = []
        for certificate in self.certificates:
            if certificate.source and certificate.source not in result:
                result.append(certificate.source)
        return result

    def extend(self, other: "LoadResult") -> None:
        """Append another load result into this one."""

        self.certificates.extend(other.certificates)
        self.errors.extend(other.errors)


def _wrap_der_error(action: str, error: DerError) -> X509Error:
    return X509Error(f"{action}: {error}")


def _parse_algorithm_identifier(node: DerNode) -> Tuple[str, Optional[DerNode]]:
    children = read_children(expect_tag(node, TAG_SEQUENCE, "AlgorithmIdentifier"))
    if not 1 <= len(children) <= 2:
        raise X509Error(
            f"AlgorithmIdentifier must have one or two elements, got {len(children)}"
        )
    return decode_oid(children[0]), (children[1] if len(children) == 2 else None)


def _parse_name(node: DerNode, what: str) -> DistinguishedName:
    rdns: List[Rdn] = []
    for rdn_node in read_children(expect_tag(node, TAG_SEQUENCE, what)):
        expect_tag(rdn_node, TAG_SET, f"{what} RDN")
        attributes: List[RdnAttribute] = []
        for atv in read_children(rdn_node):
            parts = read_children(expect_tag(atv, TAG_SEQUENCE, "AttributeTypeAndValue"))
            if len(parts) != 2:
                raise X509Error("AttributeTypeAndValue must have exactly two elements")
            oid = decode_oid(parts[0])
            attributes.append(
                RdnAttribute(
                    oid=oid,
                    name=_ATTRIBUTE_NAMES.get(oid, oid),
                    value=decode_string(parts[1]),
                )
            )
        if not attributes:
            raise X509Error(f"{what} contains an empty RDN")
        rdns.append(Rdn(tuple(attributes)))
    return DistinguishedName(tuple(rdns))


def _decode_ascii(node: DerNode, what: str) -> str:
    content = decode_octet_string(node) if node.tag == TAG_OCTET_STRING else node.content
    try:
        return content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise X509Error(f"{what} is not ASCII") from exc


def _parse_general_name(node: DerNode) -> GeneralName:
    if node.tag_class != CLASS_CONTEXT:
        raise X509Error(f"GeneralName must use a context-specific tag, got 0x{node.tag:02x}")
    number = node.tag_number
    if number == 4:  # directoryName [4] EXPLICIT Name
        if not node.constructed:
            raise X509Error("directoryName GeneralName must be constructed")
        children = read_children(node)
        if len(children) != 1:
            raise X509Error("directoryName GeneralName must wrap exactly one Name")
        return GeneralName("directory", str(_parse_name(children[0], "directoryName")))
    if node.constructed:
        return GeneralName("other", format_hex(node.content))
    if number == 1:
        return GeneralName("email", _decode_ascii(node, "rfc822Name"))
    if number == 2:
        return GeneralName("dns", _decode_ascii(node, "dNSName"))
    if number == 6:
        return GeneralName("uri", _decode_ascii(node, "uniformResourceIdentifier"))
    if number == 7:
        content = node.content
        if len(content) not in (4, 16):
            raise X509Error(f"iPAddress SAN must be 4 or 16 octets, got {len(content)}")
        return GeneralName("ip", str(ipaddress.ip_address(content)))
    if number == 8:
        try:
            oid = decode_oid(DerNode(tag=TAG_OID, content=node.content))
        except DerError as exc:
            raise X509Error(f"invalid registeredID GeneralName: {exc}") from exc
        return GeneralName("registered", oid)
    return GeneralName("other", format_hex(node.content))


def _parse_general_names(node: DerNode) -> Tuple[GeneralName, ...]:
    sequence = expect_tag(node, TAG_SEQUENCE, "GeneralNames")
    return tuple(_parse_general_name(child) for child in read_children(sequence))


def _parse_extensions(node: DerNode) -> List[Extension]:
    extensions: List[Extension] = []
    seen: set = set()
    for child in read_children(node):
        parts = read_children(expect_tag(child, TAG_SEQUENCE, "Extension"))
        if not 2 <= len(parts) <= 3:
            raise X509Error(f"Extension must have two or three elements, got {len(parts)}")
        oid = decode_oid(parts[0])
        critical = False
        value_index = 1
        if parts[1].tag == TAG_BOOLEAN:
            critical = decode_boolean(parts[1])
            value_index = 2
        if value_index >= len(parts):
            raise X509Error("Extension is missing its extnValue")
        value = decode_octet_string(parts[value_index])
        if len(parts) > value_index + 1:
            raise X509Error("Extension has trailing elements")
        if oid in seen:
            raise X509Error(f"duplicate extension {oid}")
        seen.add(oid)
        extensions.append(Extension(oid=oid, critical=critical, value=value))
    return extensions


def _extension_node(extension: Extension, expected: str) -> DerNode:
    try:
        node = parse_der(extension.value)
    except DerError as exc:
        raise X509Error(f"invalid {expected} extension value: {exc}") from exc
    return node


def _parse_san(extension: Extension) -> Tuple[GeneralName, ...]:
    return _parse_general_names(_extension_node(extension, "subjectAltName"))


def _parse_basic_constraints(extension: Extension) -> BasicConstraints:
    children = read_children(_extension_node(extension, "basicConstraints"))
    ca = False
    path_len: Optional[int] = None
    for index, child in enumerate(children):
        if index == 0 and child.tag == TAG_BOOLEAN:
            ca = decode_boolean(child)
        elif child.tag == TAG_INTEGER:
            path_len = decode_positive_integer(child)
        else:
            raise X509Error(f"unexpected element in basicConstraints (tag 0x{child.tag:02x})")
    if path_len is not None and not ca:
        raise X509Error("basicConstraints has pathLenConstraint but cA is FALSE")
    return BasicConstraints(ca=ca, path_len=path_len)


def _parse_key_usage(extension: Extension) -> FrozenSet[str]:
    node = _extension_node(extension, "keyUsage")
    expect_tag(node, TAG_BIT_STRING, "keyUsage")
    return bit_string_flags(node, _KEY_USAGE_BITS)


def _parse_extended_key_usage(extension: Extension) -> Tuple[str, ...]:
    sequence = expect_tag(
        _extension_node(extension, "extendedKeyUsage"), TAG_SEQUENCE, "extendedKeyUsage"
    )
    names: List[str] = []
    for child in read_children(sequence):
        oid = decode_oid(expect_tag(child, TAG_OID, "extendedKeyUsage OID"))
        names.append(_EKU_NAMES.get(oid, oid))
    return tuple(names)


def _parse_subject_key_identifier(extension: Extension) -> str:
    node = _extension_node(extension, "subjectKeyIdentifier")
    return format_hex(
        decode_octet_string(expect_tag(node, TAG_OCTET_STRING, "subjectKeyIdentifier"))
    )


def _parse_authority_key_identifier(extension: Extension) -> Optional[str]:
    sequence = expect_tag(
        _extension_node(extension, "authorityKeyIdentifier"),
        TAG_SEQUENCE,
        "authorityKeyIdentifier",
    )
    key_identifier: Optional[str] = None
    for child in read_children(sequence):
        if child.tag_class == CLASS_CONTEXT and child.tag_number == 0 and not child.constructed:
            key_identifier = format_hex(child.content)
    return key_identifier


def _parse_authority_info_access(extension: Extension) -> Tuple[AuthorityInfoAccess, ...]:
    sequence = expect_tag(
        _extension_node(extension, "authorityInfoAccess"),
        TAG_SEQUENCE,
        "authorityInfoAccess",
    )
    entries: List[AuthorityInfoAccess] = []
    for child in read_children(sequence):
        parts = read_children(expect_tag(child, TAG_SEQUENCE, "AccessDescription"))
        if len(parts) != 2:
            raise X509Error("AccessDescription must have exactly two elements")
        method_oid = decode_oid(expect_tag(parts[0], TAG_OID, "accessMethod"))
        entries.append(
            AuthorityInfoAccess(
                method=_AIA_METHODS.get(method_oid, method_oid),
                location=_parse_general_name(parts[1]),
            )
        )
    return tuple(entries)


def _parse_subject_public_key_info(
    node: DerNode,
) -> Tuple[str, str, Optional[int], Optional[str]]:
    parts = read_children(expect_tag(node, TAG_SEQUENCE, "SubjectPublicKeyInfo"))
    if len(parts) != 2:
        raise X509Error("SubjectPublicKeyInfo must have exactly two elements")
    algorithm_oid, parameters = _parse_algorithm_identifier(parts[0])
    algorithm = _PUBLIC_KEY_ALGORITHMS.get(algorithm_oid, algorithm_oid)
    key_bits, unused = decode_bit_string(parts[1])
    if unused:
        raise X509Error("SubjectPublicKeyInfo key data must not use padding bits")
    if algorithm == "RSA":
        if parameters is not None and parameters.tag != TAG_NULL:
            raise X509Error("RSA AlgorithmIdentifier parameters must be NULL or absent")
        return algorithm_oid, algorithm, _rsa_modulus_bits(key_bits), None
    if algorithm == "EC":
        curve: Optional[str] = None
        bits: Optional[int] = None
        if parameters is None:
            raise X509Error("EC SubjectPublicKeyInfo is missing its named curve")
        if parameters.tag == TAG_OID:
            curve_oid = decode_oid(parameters)
            curve, bits = _EC_CURVES.get(curve_oid, (curve_oid, None))
        elif parameters.tag == TAG_SEQUENCE:
            curve = "explicit"
        else:
            raise X509Error(f"unexpected EC parameters tag 0x{parameters.tag:02x}")
        return algorithm_oid, algorithm, bits, curve
    if algorithm == "Ed25519":
        return algorithm_oid, algorithm, 256, None
    if algorithm == "Ed448":
        return algorithm_oid, algorithm, 448, None
    return algorithm_oid, algorithm, None, None


def _rsa_modulus_bits(key_bits: bytes) -> int:
    try:
        key_node = parse_der(key_bits)
    except DerError as exc:
        raise X509Error(f"invalid RSA public key: {exc}") from exc
    parts = read_children(expect_tag(key_node, TAG_SEQUENCE, "RSAPublicKey"))
    if len(parts) != 2:
        raise X509Error("RSAPublicKey must have a modulus and an exponent")
    modulus = decode_positive_integer(parts[0])
    decode_positive_integer(parts[1])
    if modulus <= 0:
        raise X509Error("RSA modulus must be positive")
    return modulus.bit_length()


def parse_certificate(data: bytes, source: Optional[str] = None) -> Certificate:
    """Parse one DER certificate and return the :class:`Certificate` model."""

    try:
        return _parse_certificate(data, source)
    except DerError as exc:
        raise _wrap_der_error("invalid certificate DER", exc) from exc


def _parse_certificate(data: bytes, source: Optional[str]) -> Certificate:
    root = parse_der(data)
    parts = read_children(expect_tag(root, TAG_SEQUENCE, "Certificate"))
    if len(parts) != 3:
        raise X509Error(f"Certificate must have three elements, got {len(parts)}")
    tbs_node, outer_algorithm, signature_node = parts

    # TBSCertificate.
    tbs = read_children(expect_tag(tbs_node, TAG_SEQUENCE, "TBSCertificate"))
    index = 0
    version = 1
    if tbs and tbs[0].tag_class == CLASS_CONTEXT and tbs[0].tag_number == 0:
        explicit = read_children(tbs[0])
        if len(explicit) != 1:
            raise X509Error("explicit version element must contain one INTEGER")
        raw_version = decode_positive_integer(explicit[0])
        if raw_version not in (0, 1, 2):
            raise X509Error(f"unsupported certificate version {raw_version}")
        version = raw_version + 1
        index += 1
    if len(tbs) < index + 6:
        raise X509Error("TBSCertificate is missing required fields")
    serial_node = tbs[index]
    serial = decode_positive_integer(serial_node)
    serial_hex = serial_node.content.hex().upper()
    index += 1
    tbs_algorithm_oid, _tbs_parameters = _parse_algorithm_identifier(tbs[index])
    index += 1
    issuer = _parse_name(tbs[index], "issuer")
    index += 1
    validity_parts = read_children(expect_tag(tbs[index], TAG_SEQUENCE, "Validity"))
    if len(validity_parts) != 2:
        raise X509Error("Validity must contain notBefore and notAfter")
    not_before = decode_time(validity_parts[0])
    not_after = decode_time(validity_parts[1])
    index += 1
    subject = _parse_name(tbs[index], "subject")
    index += 1
    key_oid, key_algorithm, key_bits, ec_curve = _parse_subject_public_key_info(tbs[index])
    index += 1

    # Optional unique identifiers and extensions.
    extensions: List[Extension] = []
    while index < len(tbs):
        field_node = tbs[index]
        if field_node.tag_class != CLASS_CONTEXT:
            raise X509Error(f"unexpected TBSCertificate element 0x{field_node.tag:02x}")
        number = field_node.tag_number
        if number in (1, 2):
            if field_node.constructed:
                raise X509Error("unique identifier fields must be primitive")
        elif number == 3:
            if not field_node.constructed:
                raise X509Error("extensions field must be constructed")
            inner = read_children(field_node)
            if len(inner) != 1:
                raise X509Error("extensions field must wrap exactly one SEQUENCE")
            extensions = _parse_extensions(inner[0])
        else:
            raise X509Error(f"unknown TBSCertificate context field [{number}]")
        index += 1

    # Outer signature algorithm.
    outer_oid, _outer_parameters = _parse_algorithm_identifier(outer_algorithm)
    if outer_oid != tbs_algorithm_oid:
        raise X509Error(
            f"signature algorithm mismatch: TBS uses {tbs_algorithm_oid}, message uses {outer_oid}"
        )
    signature_value = expect_tag(signature_node, TAG_BIT_STRING, "signatureValue")
    signature_bits, signature_unused = decode_bit_string(signature_value)
    if signature_unused:
        raise X509Error("signatureValue must not use padding bits")
    if not signature_bits:
        raise X509Error("signatureValue cannot be empty")

    san: Tuple[GeneralName, ...] = ()
    basic_constraints = BasicConstraints()
    key_usage: FrozenSet[str] = frozenset()
    extended_key_usage: Tuple[str, ...] = ()
    subject_key_identifier: Optional[str] = None
    authority_key_identifier: Optional[str] = None
    authority_info_access: Tuple[AuthorityInfoAccess, ...] = ()
    for extension in extensions:
        if extension.oid == _OID_SUBJECT_ALT_NAME:
            san = _parse_san(extension)
        elif extension.oid == _OID_BASIC_CONSTRAINTS:
            basic_constraints = _parse_basic_constraints(extension)
        elif extension.oid == _OID_KEY_USAGE:
            key_usage = _parse_key_usage(extension)
        elif extension.oid == _OID_EXTENDED_KEY_USAGE:
            extended_key_usage = _parse_extended_key_usage(extension)
        elif extension.oid == _OID_SUBJECT_KEY_IDENTIFIER:
            subject_key_identifier = _parse_subject_key_identifier(extension)
        elif extension.oid == _OID_AUTHORITY_KEY_IDENTIFIER:
            authority_key_identifier = _parse_authority_key_identifier(extension)
        elif extension.oid == _OID_AUTHORITY_INFO_ACCESS:
            authority_info_access = _parse_authority_info_access(extension)

    return Certificate(
        der=bytes(data),
        sha256_fingerprint=hashlib.sha256(data).hexdigest(),
        version=version,
        serial=serial,
        serial_hex=serial_hex,
        signature_algorithm_oid=outer_oid,
        signature_algorithm=_SIGNATURE_ALGORITHMS.get(outer_oid, outer_oid),
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        public_key_algorithm_oid=key_oid,
        public_key_algorithm=key_algorithm,
        public_key_bits=key_bits,
        ec_curve=ec_curve,
        san=san,
        basic_constraints=basic_constraints,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        subject_key_identifier=subject_key_identifier,
        authority_key_identifier=authority_key_identifier,
        authority_info_access=authority_info_access,
        source=source,
    )


def from_der(data: bytes, source: Optional[str] = None) -> Certificate:
    """Parse a single DER certificate."""

    if not data:
        raise X509Error("certificate data is empty")
    return parse_certificate(bytes(data), source)


def from_pem(data: Union[str, bytes], source: Optional[str] = None) -> List[Certificate]:
    """Parse every CERTIFICATE block in a PEM document."""

    text = data.decode("ascii", "strict") if isinstance(data, (bytes, bytearray)) else data
    blocks = _PEM_PATTERN.findall(text)
    if not blocks:
        raise X509Error("no PEM CERTIFICATE block found")
    certificates: List[Certificate] = []
    for index, body in enumerate(blocks, start=1):
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise X509Error(f"invalid base64 in PEM block {index}: {exc}") from exc
        certificates.append(parse_certificate(der, source=source))
    return certificates


def load_bundle(data: Union[str, bytes], source: Optional[str] = None) -> List[Certificate]:
    """Load a PEM document (one or more certificates) or a single DER file."""

    raw = data.encode("ascii", "strict") if isinstance(data, str) else bytes(data)
    stripped = raw.lstrip()
    if not stripped:
        raise X509Error("certificate data is empty")
    if stripped.startswith(b"-----BEGIN"):
        return from_pem(stripped.decode("ascii"), source=source)
    try:
        return [from_der(stripped, source=source)]
    except X509Error as exc:
        if b"-----BEGIN" in raw:
            return from_pem(stripped.decode("ascii"), source=source)
        raise X509Error(f"not a certificate: {exc}") from exc


def load_file(path: Union[str, Path]) -> List[Certificate]:
    """Load the certificates contained in one file."""

    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise X509Error(f"cannot read file: {exc}") from exc
    return load_bundle(data, source=target.as_posix())


def load_paths(paths: Iterable[Union[str, Path]]) -> LoadResult:
    """Load certificates from files and directories (recursively).

    Directories are scanned for the common certificate file extensions;
    explicit files are always attempted regardless of their extension.
    Failures are collected as :class:`LoadError` entries instead of aborting
    the whole inventory.
    """

    result = LoadResult()
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            result.errors.append(LoadError(path.as_posix(), "path does not exist"))
            continue
        if path.is_dir():
            files = sorted(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.lower() in CERTIFICATE_EXTENSIONS
            )
            if not files:
                result.errors.append(
                    LoadError(
                        path.as_posix(),
                        "no certificate files with .pem/.crt/.cer/.der found",
                    )
                )
                continue
            for file_path in files:
                _load_into(result, file_path)
        else:
            _load_into(result, path)
    return result


def _load_into(result: LoadResult, path: Path) -> None:
    try:
        certificates = load_file(path)
    except X509Error as exc:
        result.errors.append(LoadError(path.as_posix(), str(exc)))
        return
    result.certificates.extend(certificates)
