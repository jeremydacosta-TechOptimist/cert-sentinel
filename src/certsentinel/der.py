"""Strict DER (Distinguished Encoding Rules) TLV reader.

The parser implements the subset of ASN.1 DER needed to read X.509
certificates: low and high tag numbers, short and long definitive lengths,
constructed and primitive values, and decoders for the universal types found in
certificates (INTEGER, BOOLEAN, BIT STRING, OCTET STRING, NULL, OBJECT
IDENTIFIER, string types, UTCTime and GeneralizedTime).

DER is stricter than BER, and the parser enforces the strictness where it
matters for certificate parsing: indefinite lengths are rejected, long-form
lengths must be minimal, high tag numbers must be minimal, BOOLEAN must be
0x00/0xFF, INTEGER and BIT STRING must not carry redundant padding, and
malformed input raises :class:`DerError` with a byte offset instead of
returning partial data.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

__all__ = [
    "DerError",
    "TAG_BOOLEAN",
    "TAG_INTEGER",
    "TAG_BIT_STRING",
    "TAG_OCTET_STRING",
    "TAG_NULL",
    "TAG_OID",
    "TAG_UTF8_STRING",
    "TAG_NUMERIC_STRING",
    "TAG_PRINTABLE_STRING",
    "TAG_TELETEX_STRING",
    "TAG_IA5_STRING",
    "TAG_UTC_TIME",
    "TAG_GENERALIZED_TIME",
    "TAG_VISIBLE_STRING",
    "TAG_UNIVERSAL_STRING",
    "TAG_BMP_STRING",
    "TAG_SEQUENCE",
    "TAG_SET",
    "CLASS_UNIVERSAL",
    "CLASS_APPLICATION",
    "CLASS_CONTEXT",
    "CLASS_PRIVATE",
    "context_tag",
    "DerNode",
    "parse_tlv",
    "parse_der",
    "read_children",
    "expect_tag",
    "decode_boolean",
    "decode_integer",
    "decode_positive_integer",
    "decode_bit_string",
    "decode_octet_string",
    "decode_oid",
    "decode_string",
    "decode_utc_time",
    "decode_generalized_time",
    "decode_time",
    "bit_string_flags",
    "format_hex",
]

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_NUMERIC_STRING = 0x12
TAG_PRINTABLE_STRING = 0x13
TAG_TELETEX_STRING = 0x14
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_VISIBLE_STRING = 0x1A
TAG_UNIVERSAL_STRING = 0x1C
TAG_BMP_STRING = 0x1E
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

_MAX_LENGTH_OCTETS = 8
_STRING_TAGS = {
    TAG_UTF8_STRING,
    TAG_NUMERIC_STRING,
    TAG_PRINTABLE_STRING,
    TAG_TELETEX_STRING,
    TAG_IA5_STRING,
    TAG_VISIBLE_STRING,
    TAG_UNIVERSAL_STRING,
    TAG_BMP_STRING,
}


class DerError(ValueError):
    """Raised when DER input is malformed or outside the supported subset."""


def context_tag(number: int, constructed: bool = False) -> int:
    """Return the DER tag octet for a context-specific tag number."""

    if not 0 <= number <= 30:
        raise DerError(f"context tag number {number} does not fit in the low tag form")
    return 0x80 | (0x20 if constructed else 0) | number


@dataclass(frozen=True)
class DerNode:
    """One decoded TLV: class, tag number, constructed flag and content bytes."""

    tag: int
    content: bytes
    resolved_tag_number: Optional[int] = field(default=None, repr=False)

    @property
    def tag_class(self) -> int:
        """ASN.1 tag class (0 universal, 1 application, 2 context, 3 private)."""

        return (self.tag >> 6) & 0x03

    @property
    def constructed(self) -> bool:
        """True when the encoding is constructed (content is child TLVs)."""

        return bool(self.tag & 0x20)

    @property
    def tag_number(self) -> int:
        """Tag number within the class (resolved for high-tag-number form)."""

        if self.resolved_tag_number is not None:
            return self.resolved_tag_number
        return self.tag & 0x1F


def _read_tag(data: bytes, offset: int) -> Tuple[int, Optional[int], int]:
    if offset >= len(data):
        raise DerError(f"truncated tag at offset {offset}")
    first = data[offset]
    offset += 1
    if first & 0x1F != 0x1F:
        return first, None, offset
    # High tag number form: base-128, high bit set on all but the last octet.
    number = 0
    first_part = True
    while True:
        if offset >= len(data):
            raise DerError("truncated high tag number")
        octet = data[offset]
        offset += 1
        if first_part and octet == 0x80:
            raise DerError("non-minimal high tag number")
        first_part = False
        if number.bit_length() > 28:
            raise DerError("high tag number is too large")
        number = (number << 7) | (octet & 0x7F)
        if not octet & 0x80:
            break
    if number < 0x1F:
        raise DerError(f"tag number {number} must use the low tag form")
    return first, number, offset


def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise DerError(f"truncated length at offset {offset}")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise DerError("indefinite length is not allowed in DER")
    if count > _MAX_LENGTH_OCTETS:
        raise DerError(f"length uses {count} octets, more than the supported {_MAX_LENGTH_OCTETS}")
    if offset + count > len(data):
        raise DerError("truncated long-form length")
    length_bytes = data[offset : offset + count]
    if length_bytes[0] == 0:
        raise DerError("non-minimal long-form length")
    length = int.from_bytes(length_bytes, "big")
    return length, offset + count


def parse_tlv(data: bytes, offset: int = 0) -> Tuple[DerNode, int]:
    """Parse one TLV at ``offset`` and return ``(node, next_offset)``."""

    if not isinstance(data, (bytes, bytearray)):
        raise DerError("DER input must be bytes")
    tag, tag_number, offset = _read_tag(bytes(data), offset)
    length, offset = _read_length(data, offset)
    end = offset + length
    if end > len(data):
        raise DerError(
            f"truncated value at offset {offset}: need {length} octets, have {len(data) - offset}"
        )
    return DerNode(tag=tag, content=bytes(data[offset:end]), resolved_tag_number=tag_number), end


def parse_der(data: bytes) -> DerNode:
    """Parse exactly one DER value and reject trailing bytes."""

    node, offset = parse_tlv(data, 0)
    if offset != len(data):
        raise DerError(f"trailing bytes after DER value: {len(data) - offset}")
    return node


def read_children(node: DerNode) -> List[DerNode]:
    """Decode the content of a constructed node into its child TLVs."""

    if not node.constructed:
        raise DerError(f"tag 0x{node.tag:02x} is primitive and has no children")
    children: List[DerNode] = []
    offset = 0
    data = node.content
    while offset < len(data):
        child, offset = parse_tlv(data, offset)
        children.append(child)
    return children


def expect_tag(node: DerNode, tag: int, what: str) -> DerNode:
    """Return ``node`` if it carries ``tag``, otherwise raise a clear error."""

    if node.tag != tag:
        raise DerError(f"expected {what} (tag 0x{tag:02x}), got tag 0x{node.tag:02x}")
    return node


def _require_primitive(node: DerNode, what: str) -> bytes:
    if node.constructed:
        raise DerError(f"{what} must be primitive")
    return node.content


def _require_tag(node: DerNode, tag: int, what: str) -> bytes:
    if node.tag != tag:
        raise DerError(f"expected {what} (tag 0x{tag:02x}), got tag 0x{node.tag:02x}")
    return _require_primitive(node, what)


def decode_boolean(node: DerNode) -> bool:
    """Decode a DER BOOLEAN (only 0x00 and 0xFF are valid in DER)."""

    content = _require_tag(node, TAG_BOOLEAN, "BOOLEAN")
    if len(content) != 1:
        raise DerError(f"BOOLEAN must be one octet, got {len(content)}")
    if content == b"\x00":
        return False
    if content == b"\xff":
        return True
    raise DerError(f"invalid DER BOOLEAN value 0x{content[0]:02x}")


def decode_integer(node: DerNode) -> int:
    """Decode a minimally encoded two's-complement INTEGER."""

    content = _require_tag(node, TAG_INTEGER, "INTEGER")
    if not content:
        raise DerError("INTEGER content cannot be empty")
    if len(content) > 1:
        if content[0] == 0x00 and not content[1] & 0x80:
            raise DerError("INTEGER has a redundant leading 0x00 octet")
        if content[0] == 0xFF and content[1] & 0x80:
            raise DerError("INTEGER has a redundant leading 0xFF octet")
    return int.from_bytes(content, "big", signed=True)


def decode_positive_integer(node: DerNode) -> int:
    """Decode an INTEGER that must be positive (serial numbers, path lengths)."""

    value = decode_integer(node)
    if value < 0:
        raise DerError("INTEGER value is negative but a positive value is required")
    return value


def decode_bit_string(node: DerNode) -> Tuple[bytes, int]:
    """Decode a BIT STRING into ``(value_bytes, unused_bits)``."""

    content = _require_tag(node, TAG_BIT_STRING, "BIT STRING")
    if not content:
        raise DerError("BIT STRING must contain its unused-bits octet")
    unused = content[0]
    if unused > 7:
        raise DerError(f"BIT STRING unused-bits count {unused} is invalid")
    value = content[1:]
    if not value and unused:
        raise DerError("empty BIT STRING must have zero unused bits")
    if value and unused:
        last = value[-1]
        mask = (1 << unused) - 1
        if last & mask:
            raise DerError("BIT STRING has non-zero padding bits")
    return value, unused


def bit_string_flags(node: DerNode, names: Sequence[str]) -> frozenset:
    """Decode a BIT STRING into the set of flag names whose bits are set."""

    value, _unused = decode_bit_string(node)
    flags = set()
    for bit, name in enumerate(names):
        byte_index = bit // 8
        if byte_index >= len(value):
            break
        if value[byte_index] & (0x80 >> (bit % 8)):
            flags.add(name)
    return frozenset(flags)


def decode_octet_string(node: DerNode) -> bytes:
    """Return the raw bytes of an OCTET STRING."""

    return _require_tag(node, TAG_OCTET_STRING, "OCTET STRING")


def _decode_string_content(tag: int, content: bytes) -> str:
    try:
        if tag == TAG_UTF8_STRING:
            return content.decode("utf-8")
        if tag == TAG_BMP_STRING:
            return content.decode("utf-16-be")
        if tag == TAG_UNIVERSAL_STRING:
            return content.decode("utf-32-be")
        if tag == TAG_TELETEX_STRING:
            return content.decode("latin-1")
        text = content.decode("ascii")
        if tag == TAG_PRINTABLE_STRING:
            allowed = set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
            )
            if any(character not in allowed for character in text):
                raise DerError("PrintableString contains a character outside its alphabet")
        return text
    except UnicodeDecodeError as exc:
        raise DerError(f"invalid string encoding for tag 0x{tag:02x}: {exc}") from exc
    except ValueError as exc:
        raise DerError(f"invalid string encoding for tag 0x{tag:02x}: {exc}") from exc


def decode_string(node: DerNode) -> str:
    """Decode one of the ASN.1 string types used in X.509 names."""

    if node.tag not in _STRING_TAGS:
        raise DerError(f"tag 0x{node.tag:02x} is not a supported string type")
    return _decode_string_content(node.tag, _require_primitive(node, "string"))


def decode_oid(node: DerNode) -> str:
    """Decode an OBJECT IDENTIFIER into dotted notation."""

    content = _require_tag(node, TAG_OID, "OBJECT IDENTIFIER")
    if not content:
        raise DerError("OBJECT IDENTIFIER content cannot be empty")
    arcs: List[int] = []
    value = 0
    fresh = True
    for octet in content:
        if fresh and octet == 0x80:
            raise DerError("OBJECT IDENTIFIER has a non-minimal sub-identifier")
        fresh = False
        if value.bit_length() > 28:
            raise DerError("OBJECT IDENTIFIER sub-identifier is too large")
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
            fresh = True
    if not fresh:
        raise DerError("OBJECT IDENTIFIER ends with a continuation octet")
    combined = arcs[0]
    if combined < 40:
        first, second = 0, combined
    elif combined < 80:
        first, second = 1, combined - 40
    else:
        first, second = 2, combined - 80
    return ".".join(str(arc) for arc in [first, second, *arcs[1:]])


def _parse_time_text(node: DerNode, what: str) -> str:
    content = _require_primitive(node, what)
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DerError(f"{what} is not ASCII") from exc
    if not text:
        raise DerError(f"{what} cannot be empty")
    return text


def _parse_timezone(text: str) -> Tuple[str, datetime.timedelta]:
    if text.endswith("Z"):
        return text[:-1], datetime.timedelta(0)
    # DER allows a local time with an explicit offset, e.g. +0200 or -0530.
    if len(text) >= 5 and text[-5] in "+-":
        sign = 1 if text[-5] == "+" else -1
        offset_text = text[-4:]
        if not offset_text.isdigit():
            raise DerError(f"invalid time zone offset in {text!r}")
        hours, minutes = int(offset_text[:2]), int(offset_text[2:])
        if hours > 23 or minutes > 59:
            raise DerError(f"invalid time zone offset in {text!r}")
        return text[:-5], sign * datetime.timedelta(hours=hours, minutes=minutes)
    raise DerError(f"time value {text!r} must end with Z or a UTC offset")


def _build_datetime(
    year: int, month: int, day: int, hour: int, minute: int, second: int, offset: datetime.timedelta
) -> datetime.datetime:
    try:
        local = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise DerError(f"invalid time value: {exc}") from exc
    return (local - offset).astimezone(datetime.timezone.utc)


def decode_utc_time(node: DerNode) -> datetime.datetime:
    """Decode a UTCTime value (YYMMDDHHMMSS with Z or a UTC offset)."""

    text = _parse_time_text(node, "UTCTime")
    body, offset = _parse_timezone(text)
    if len(body) != 12 or not body.isdigit():
        raise DerError(f"invalid UTCTime {text!r}; expected YYMMDDHHMMSS")
    year = int(body[0:2])
    year += 1900 if year >= 50 else 2000
    return _build_datetime(
        year, int(body[2:4]), int(body[4:6]), int(body[6:8]), int(body[8:10]), int(body[10:12]), offset
    )


def decode_generalized_time(node: DerNode) -> datetime.datetime:
    """Decode a GeneralizedTime value (YYYYMMDDHHMMSS with Z or a UTC offset).

    Fractional seconds are accepted and truncated: X.509 profile certificates
    do not use them, but other tooling sometimes writes them.
    """

    text = _parse_time_text(node, "GeneralizedTime")
    body, offset = _parse_timezone(text)
    fraction = ""
    if "." in body or "," in body:
        separator = "." if "." in body else ","
        body, fraction = body.split(separator, 1)
        if not fraction.isdigit():
            raise DerError(f"invalid fractional seconds in GeneralizedTime {text!r}")
    if len(body) != 14 or not body.isdigit():
        raise DerError(f"invalid GeneralizedTime {text!r}; expected YYYYMMDDHHMMSS")
    return _build_datetime(
        int(body[0:4]),
        int(body[4:6]),
        int(body[6:8]),
        int(body[8:10]),
        int(body[10:12]),
        int(body[12:14]),
        offset,
    )


def decode_time(node: DerNode) -> datetime.datetime:
    """Decode either UTCTime or GeneralizedTime into an aware UTC datetime."""

    if node.tag == TAG_UTC_TIME:
        return decode_utc_time(node)
    if node.tag == TAG_GENERALIZED_TIME:
        return decode_generalized_time(node)
    raise DerError(f"expected UTC or GeneralizedTime, got tag 0x{node.tag:02x}")


def format_hex(data: bytes) -> str:
    """Return lowercase hexadecimal for a byte string."""

    return bytes(data).hex()
