"""Tests for the strict DER TLV parser and value decoders."""

from __future__ import annotations

import datetime
import unittest

from certsentinel.der import (
    TAG_BIT_STRING,
    TAG_BMP_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_IA5_STRING,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_PRINTABLE_STRING,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_TELETEX_STRING,
    TAG_UTC_TIME,
    TAG_UTF8_STRING,
    DerError,
    bit_string_flags,
    context_tag,
    decode_bit_string,
    decode_boolean,
    decode_generalized_time,
    decode_integer,
    decode_oid,
    decode_octet_string,
    decode_positive_integer,
    decode_string,
    decode_time,
    decode_utc_time,
    expect_tag,
    format_hex,
    parse_der,
    parse_tlv,
    read_children,
)
from tests.helpers import integer, sequence, set_of, string_value, tlv


class LengthParsingTests(unittest.TestCase):
    def test_short_form_lengths(self) -> None:
        for length in (0, 1, 4, 127):
            node = parse_der(tlv(TAG_OCTET_STRING, b"x" * length))
            self.assertEqual(len(node.content), length)

    def test_long_form_one_byte_length(self) -> None:
        raw = b"\x04\x81\x80" + b"x" * 128
        node, offset = parse_tlv(raw)
        self.assertEqual(len(node.content), 128)
        self.assertEqual(offset, len(raw))

    def test_long_form_multibyte_length(self) -> None:
        raw = b"\x04\x82\x01\x00" + b"y" * 256
        self.assertEqual(len(parse_der(raw).content), 256)

    def test_indefinite_length_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x30\x80\x04\x00")

    def test_non_minimal_long_form_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x04\x82\x00\x80" + b"x" * 128)

    def test_too_many_length_octets_are_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x04\x89" + b"\x00" * 8 + b"x")

    def test_truncated_length_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x04")
        with self.assertRaises(DerError):
            parse_tlv(b"\x04\x82\x01")

    def test_truncated_value_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x04\x05abc")

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_der(b"")


class TagParsingTests(unittest.TestCase):
    def test_low_tag_number_is_reported(self) -> None:
        node = parse_der(tlv(TAG_INTEGER, b"\x05"))
        self.assertEqual(node.tag, TAG_INTEGER)
        self.assertEqual(node.tag_number, TAG_INTEGER)
        self.assertEqual(node.tag_class, 0)
        self.assertFalse(node.constructed)

    def test_high_tag_number_is_resolved(self) -> None:
        raw = b"\x1f\x81\x00\x01\x00"
        node, offset = parse_tlv(raw)
        self.assertEqual(node.tag_number, 128)
        self.assertEqual(node.tag_class, 0)
        self.assertFalse(node.constructed)
        self.assertEqual(offset, len(raw))

    def test_non_minimal_high_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x1f\x80\x01\x00")

    def test_high_tag_form_for_small_number_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x1f\x1e\x01\x00")

    def test_truncated_high_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            parse_tlv(b"\x1f")

    def test_context_tag_helper(self) -> None:
        self.assertEqual(context_tag(0), 0x80)
        self.assertEqual(context_tag(3), 0x83)
        self.assertEqual(context_tag(0, constructed=True), 0xA0)
        self.assertEqual(context_tag(3, constructed=True), 0xA3)
        with self.assertRaises(DerError):
            context_tag(31)

    def test_constructed_flag_is_exposed(self) -> None:
        self.assertTrue(parse_der(sequence()).constructed)
        self.assertFalse(parse_der(tlv(TAG_NULL, b"")).constructed)

    def test_read_children_parses_nested_sequence(self) -> None:
        data = sequence(integer(7), string_value("hello"))
        children = read_children(parse_der(data))
        self.assertEqual([child.tag for child in children], [TAG_INTEGER, TAG_UTF8_STRING])
        self.assertEqual(decode_integer(children[0]), 7)
        self.assertEqual(decode_string(children[1]), "hello")

    def test_read_children_rejects_primitive(self) -> None:
        with self.assertRaises(DerError):
            read_children(parse_der(tlv(TAG_OCTET_STRING, b"x")))

    def test_parse_der_rejects_trailing_bytes(self) -> None:
        with self.assertRaises(DerError):
            parse_der(tlv(TAG_NULL, b"") + b"\x00")

    def test_parse_tlv_offset(self) -> None:
        data = tlv(TAG_NULL, b"") + tlv(TAG_INTEGER, b"\x01")
        node, offset = parse_tlv(data, 2)
        self.assertEqual(node.tag, TAG_INTEGER)
        self.assertEqual(offset, len(data))

    def test_expect_tag_mismatch(self) -> None:
        node = parse_der(tlv(TAG_NULL, b""))
        with self.assertRaises(DerError):
            expect_tag(node, TAG_OCTET_STRING, "OCTET STRING")


class BooleanAndIntegerTests(unittest.TestCase):
    def test_boolean_values(self) -> None:
        self.assertFalse(decode_boolean(parse_der(tlv(TAG_BOOLEAN, b"\x00"))))
        self.assertTrue(decode_boolean(parse_der(tlv(TAG_BOOLEAN, b"\xff"))))

    def test_boolean_non_canonical_octet_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_boolean(parse_der(tlv(TAG_BOOLEAN, b"\x01")))

    def test_boolean_wrong_length_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_boolean(parse_der(tlv(TAG_BOOLEAN, b"\x00\x00")))

    def test_integer_positive_and_negative(self) -> None:
        self.assertEqual(decode_integer(parse_der(integer(0))), 0)
        self.assertEqual(decode_integer(parse_der(integer(127))), 127)
        self.assertEqual(decode_integer(parse_der(integer(128))), 128)
        self.assertEqual(decode_integer(parse_der(integer(-1))), -1)
        self.assertEqual(decode_integer(parse_der(integer(-128))), -128)

    def test_integer_redundant_padding_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_integer(parse_der(tlv(TAG_INTEGER, b"\x00\x01")))
        with self.assertRaises(DerError):
            decode_integer(parse_der(tlv(TAG_INTEGER, b"\xff\xff")))

    def test_integer_empty_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_integer(parse_der(tlv(TAG_INTEGER, b"")))

    def test_integer_wrong_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_integer(parse_der(tlv(TAG_OCTET_STRING, b"\x01")))

    def test_positive_integer_rejects_negative(self) -> None:
        with self.assertRaises(DerError):
            decode_positive_integer(parse_der(integer(-5)))

    def test_positive_integer_accepts_zero_and_large(self) -> None:
        self.assertEqual(decode_positive_integer(parse_der(integer(0))), 0)
        self.assertEqual(
            decode_positive_integer(parse_der(integer(2**128 + 7))), 2**128 + 7
        )


class BitStringTests(unittest.TestCase):
    def test_decode_bit_string(self) -> None:
        node = parse_der(tlv(TAG_BIT_STRING, b"\x00\x0f"))
        self.assertEqual(decode_bit_string(node), (b"\x0f", 0))

    def test_unused_bits_are_reported(self) -> None:
        node = parse_der(tlv(TAG_BIT_STRING, b"\x03\xf8"))
        self.assertEqual(decode_bit_string(node), (b"\xf8", 3))

    def test_non_zero_padding_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_bit_string(parse_der(tlv(TAG_BIT_STRING, b"\x03\xff")))

    def test_unused_bits_above_seven_are_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_bit_string(parse_der(tlv(TAG_BIT_STRING, b"\x08\x00")))

    def test_empty_bit_string_cases(self) -> None:
        with self.assertRaises(DerError):
            decode_bit_string(parse_der(tlv(TAG_BIT_STRING, b"")))
        self.assertEqual(decode_bit_string(parse_der(tlv(TAG_BIT_STRING, b"\x00"))), (b"", 0))
        with self.assertRaises(DerError):
            decode_bit_string(parse_der(tlv(TAG_BIT_STRING, b"\x05")))

    def test_bit_string_flags(self) -> None:
        names = ("digitalSignature", "keyEncipherment", "keyCertSign", "cRLSign")
        node = parse_der(tlv(TAG_BIT_STRING, b"\x01\xa0"))
        self.assertEqual(
            bit_string_flags(node, names),
            frozenset({"digitalSignature", "keyCertSign"}),
        )


class OidTests(unittest.TestCase):
    def test_oid_decoding(self) -> None:
        raw = bytes.fromhex("06092a864886f70d010105")
        self.assertEqual(decode_oid(parse_der(raw)), "1.2.840.113549.1.1.5")

    def test_oid_two_arc_and_large_arc(self) -> None:
        self.assertEqual(decode_oid(parse_der(bytes.fromhex("06012a"))), "1.2")
        self.assertEqual(decode_oid(parse_der(bytes.fromhex("0603813403"))), "2.100.3")

    def test_oid_empty_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_oid(parse_der(tlv(TAG_OID, b"")))

    def test_oid_truncated_subidentifier_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_oid(parse_der(tlv(TAG_OID, bytes.fromhex("2a86"))))

    def test_oid_non_minimal_subidentifier_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_oid(parse_der(tlv(TAG_OID, bytes.fromhex("2a8001"))))

    def test_oid_wrong_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_oid(parse_der(tlv(TAG_OCTET_STRING, bytes.fromhex("2a"))))

    def test_octet_string_wrong_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_octet_string(parse_der(tlv(TAG_OID, b"\x2a")))

    def test_octet_string_content(self) -> None:
        self.assertEqual(
            decode_octet_string(parse_der(tlv(TAG_OCTET_STRING, b"abc"))), b"abc"
        )


class StringTests(unittest.TestCase):
    def test_utf8_string(self) -> None:
        self.assertEqual(
            decode_string(parse_der(string_value("caf\u00e9"))), "caf\u00e9"
        )

    def test_printable_string(self) -> None:
        node = parse_der(tlv(TAG_PRINTABLE_STRING, b"NetWatch Lab"))
        self.assertEqual(decode_string(node), "NetWatch Lab")

    def test_printable_string_invalid_character_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_string(parse_der(tlv(TAG_PRINTABLE_STRING, b"caf\xe9")))

    def test_ia5_string(self) -> None:
        node = parse_der(tlv(TAG_IA5_STRING, b"admin@example"))
        self.assertEqual(decode_string(node), "admin@example")

    def test_bmp_string(self) -> None:
        node = parse_der(tlv(TAG_BMP_STRING, "hi".encode("utf-16-be")))
        self.assertEqual(decode_string(node), "hi")

    def test_teletex_string_decoded_as_latin1(self) -> None:
        node = parse_der(tlv(TAG_TELETEX_STRING, b"caf\xe9"))
        self.assertEqual(decode_string(node), "caf\u00e9")

    def test_invalid_utf8_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_string(parse_der(tlv(TAG_UTF8_STRING, b"\xff")))

    def test_non_string_tag_is_rejected(self) -> None:
        with self.assertRaises(DerError):
            decode_string(parse_der(tlv(TAG_INTEGER, b"\x01")))


class TimeTests(unittest.TestCase):
    def test_utc_time_zulu(self) -> None:
        node = parse_der(tlv(TAG_UTC_TIME, b"260116173256Z"))
        self.assertEqual(
            decode_utc_time(node),
            datetime.datetime(2026, 1, 16, 17, 32, 56, tzinfo=datetime.timezone.utc),
        )

    def test_utc_time_offset(self) -> None:
        node = parse_der(tlv(TAG_UTC_TIME, b"260116173256+0200"))
        self.assertEqual(
            decode_utc_time(node),
            datetime.datetime(2026, 1, 16, 15, 32, 56, tzinfo=datetime.timezone.utc),
        )

    def test_utc_time_century_rule(self) -> None:
        self.assertEqual(decode_utc_time(parse_der(tlv(TAG_UTC_TIME, b"500101000000Z"))).year, 1950)
        self.assertEqual(decode_utc_time(parse_der(tlv(TAG_UTC_TIME, b"490101000000Z"))).year, 2049)

    def test_utc_time_invalid_values(self) -> None:
        for value in (b"2601011200Z", b"260101120000", b"260101120000+9999", b"26010112000aZ"):
            with self.subTest(value=value):
                with self.assertRaises(DerError):
                    decode_utc_time(parse_der(tlv(TAG_UTC_TIME, value)))

    def test_generalized_time_zulu(self) -> None:
        node = parse_der(tlv(TAG_GENERALIZED_TIME, b"20260116173256Z"))
        self.assertEqual(node.tag, TAG_GENERALIZED_TIME)
        self.assertEqual(
            decode_generalized_time(node),
            datetime.datetime(2026, 1, 16, 17, 32, 56, tzinfo=datetime.timezone.utc),
        )

    def test_generalized_time_fraction_and_offset(self) -> None:
        node = parse_der(tlv(TAG_GENERALIZED_TIME, b"20260116173256.750+0100"))
        self.assertEqual(
            decode_generalized_time(node),
            datetime.datetime(2026, 1, 16, 16, 32, 56, tzinfo=datetime.timezone.utc),
        )

    def test_generalized_time_invalid(self) -> None:
        for value in (b"202601161732Z", b"20260116173256", b"20260116173256.Z"):
            with self.subTest(value=value):
                with self.assertRaises(DerError):
                    decode_generalized_time(parse_der(tlv(TAG_GENERALIZED_TIME, value)))

    def test_decode_time_dispatch(self) -> None:
        utc_node = parse_der(tlv(TAG_UTC_TIME, b"260101000000Z"))
        generalized_node = parse_der(tlv(TAG_GENERALIZED_TIME, b"20260101000000Z"))
        self.assertEqual(decode_time(utc_node), decode_time(generalized_node))
        with self.assertRaises(DerError):
            decode_time(parse_der(tlv(TAG_INTEGER, b"\x01")))


class MiscTests(unittest.TestCase):
    def test_format_hex(self) -> None:
        self.assertEqual(format_hex(b"\x00\xab\xff"), "00abff")

    def test_sequence_and_set_tags(self) -> None:
        self.assertEqual(parse_der(sequence()).tag, TAG_SEQUENCE)
        self.assertEqual(parse_der(set_of()).tag, TAG_SET)

    def test_null_has_empty_content(self) -> None:
        node = parse_der(tlv(TAG_NULL, b""))
        self.assertEqual(node.content, b"")
        self.assertEqual(node.tag, TAG_NULL)


if __name__ == "__main__":
    unittest.main()
