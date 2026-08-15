//! Minimal ASN.1 DER and RFC 7468 textual encoding support.
//!
//! DER encoding follows ITU-T X.690.
//!
//! The implementation deliberately supports only the subset BareProxy needs
//! for EC keys, PKCS#10 CSRs, X.509 certificates, and related structures.
//! High-tag-number ASN.1 identifiers and indefinite lengths are rejected.

use crate::crypto::encode_base64;

use std::{error::Error, fmt};

const DER_TAG_INTEGER: u8 = 0x02;
const DER_TAG_BIT_STRING: u8 = 0x03;
const DER_TAG_OCTET_STRING: u8 = 0x04;
const DER_TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const DER_TAG_SEQUENCE: u8 = 0x30;
const DER_TAG_SET: u8 = 0x31;

const DER_CONTEXT_SPECIFIC_CLASS: u8 = 0x80;
const DER_CONSTRUCTED_BIT: u8 = 0x20;
const DER_HIGH_TAG_NUMBER: u8 = 0x1f;

const PEM_LINE_WIDTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    Truncated,
    IndefiniteLength,
    NonCanonicalLength,
    LengthOverflow,
    HighTagNumberUnsupported { tag: u8 },
    UnexpectedTag { expected: u8, actual: u8 },
    InvalidInteger,
    InvalidObjectIdentifier,
    InvalidContextTag { tag_number: u8 },
    TrailingData { length: usize },
    InvalidPemLabel,
    PemBeginMissing,
    PemEndMissing,
    PemLabelMismatch,
    InvalidPemBase64,
}

impl fmt::Display for DerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated DER value"),
            Self::IndefiniteLength => {
                formatter.write_str("indefinite ASN.1 length is not permitted in DER")
            }
            Self::NonCanonicalLength => {
                formatter.write_str("ASN.1 length is not minimally encoded for DER")
            }
            Self::LengthOverflow => {
                formatter.write_str("ASN.1 length exceeds the supported address space")
            }
            Self::HighTagNumberUnsupported { tag } => {
                write!(
                    formatter,
                    "ASN.1 high-tag-number form is unsupported for tag 0x{tag:02x}"
                )
            }
            Self::UnexpectedTag { expected, actual } => {
                write!(
                    formatter,
                    "unexpected ASN.1 tag 0x{actual:02x}; expected 0x{expected:02x}"
                )
            }
            Self::InvalidInteger => {
                formatter.write_str("ASN.1 INTEGER is invalid or non-canonical")
            }
            Self::InvalidObjectIdentifier => {
                formatter.write_str("ASN.1 OBJECT IDENTIFIER is invalid")
            }
            Self::InvalidContextTag { tag_number } => {
                write!(
                    formatter,
                    "ASN.1 context-specific tag {tag_number} requires unsupported high-tag-number encoding"
                )
            }
            Self::TrailingData { length } => {
                write!(
                    formatter,
                    "{length} trailing byte(s) remain after DER parsing"
                )
            }
            Self::InvalidPemLabel => formatter.write_str("invalid RFC 7468 textual encoding label"),
            Self::PemBeginMissing => formatter.write_str("RFC 7468 begin boundary was not found"),
            Self::PemEndMissing => formatter.write_str("RFC 7468 end boundary was not found"),
            Self::PemLabelMismatch => {
                formatter.write_str("RFC 7468 begin and end labels do not match")
            }
            Self::InvalidPemBase64 => {
                formatter.write_str("invalid Base64 inside RFC 7468 textual encoding")
            }
        }
    }
}

impl Error for DerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerValue<'a> {
    pub tag: u8,
    pub content: &'a [u8],
}

impl<'a> DerValue<'a> {
    pub fn reader(self) -> DerReader<'a> {
        DerReader::new(self.content)
    }
}

/// Bounded reader for a single DER byte region.
///
/// Nested DER structures are parsed by constructing another reader over the
/// parent value's bounded content slice.
#[derive(Debug, Clone, Copy)]
pub struct DerReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> DerReader<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    pub fn finish(self) -> Result<(), DerError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(DerError::TrailingData {
                length: self.input.len() - self.position,
            })
        }
    }

    pub fn read_tlv(&mut self) -> Result<DerValue<'a>, DerError> {
        let tag = self.take_byte()?;

        if tag & DER_HIGH_TAG_NUMBER == DER_HIGH_TAG_NUMBER {
            return Err(DerError::HighTagNumberUnsupported { tag });
        }

        let length = self.read_length()?;

        let end = self
            .position
            .checked_add(length)
            .ok_or(DerError::LengthOverflow)?;

        if end > self.input.len() {
            return Err(DerError::Truncated);
        }

        let content = &self.input[self.position..end];

        self.position = end;

        Ok(DerValue { tag, content })
    }

    pub fn read_expected(&mut self, expected_tag: u8) -> Result<DerValue<'a>, DerError> {
        let value = self.read_tlv()?;

        if value.tag != expected_tag {
            return Err(DerError::UnexpectedTag {
                expected: expected_tag,
                actual: value.tag,
            });
        }

        Ok(value)
    }

    /// Reads a canonical non-negative DER INTEGER.
    ///
    /// The returned slice omits a DER sign-preserving leading zero when one
    /// was required by the encoding.
    pub fn read_integer_unsigned(&mut self) -> Result<&'a [u8], DerError> {
        let value = self.read_expected(DER_TAG_INTEGER)?;

        let content = value.content;

        if content.is_empty() {
            return Err(DerError::InvalidInteger);
        }

        if content[0] & 0x80 != 0 {
            return Err(DerError::InvalidInteger);
        }

        if content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
            return Err(DerError::InvalidInteger);
        }

        if content.len() > 1 && content[0] == 0 {
            Ok(&content[1..])
        } else {
            Ok(content)
        }
    }

    fn take_byte(&mut self) -> Result<u8, DerError> {
        let Some(&byte) = self.input.get(self.position) else {
            return Err(DerError::Truncated);
        };

        self.position += 1;

        Ok(byte)
    }

    fn read_length(&mut self) -> Result<usize, DerError> {
        let first = self.take_byte()?;

        if first & 0x80 == 0 {
            return Ok(usize::from(first));
        }

        let count = usize::from(first & 0x7f);

        if count == 0 {
            return Err(DerError::IndefiniteLength);
        }

        if count > std::mem::size_of::<usize>() {
            return Err(DerError::LengthOverflow);
        }

        if self.remaining() < count {
            return Err(DerError::Truncated);
        }

        if self.input[self.position] == 0 {
            return Err(DerError::NonCanonicalLength);
        }

        let mut length = 0_usize;

        for _ in 0..count {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(self.input[self.position])))
                .ok_or(DerError::LengthOverflow)?;

            self.position += 1;
        }

        if length < 128 {
            return Err(DerError::NonCanonicalLength);
        }

        Ok(length)
    }
}

/// Encodes a non-negative INTEGER using canonical DER.
///
/// Leading zeroes supplied by the caller are discarded. A sign-preserving
/// zero octet is added when the highest significant bit would otherwise make
/// the INTEGER negative.
pub fn der_integer_unsigned(value: &[u8]) -> Vec<u8> {
    let first_significant = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());

    let mut content = Vec::new();

    if first_significant == value.len() {
        content.push(0);
    } else {
        let significant = &value[first_significant..];

        if significant[0] & 0x80 != 0 {
            content.push(0);
        }

        content.extend_from_slice(significant);
    }

    der_wrap(DER_TAG_INTEGER, &content)
}

pub fn der_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();

    for element in elements {
        content.extend_from_slice(element);
    }

    der_wrap(DER_TAG_SEQUENCE, &content)
}

/// Encodes a DER SET OF-style collection.
///
/// DER requires canonical ordering, so complete encoded child values are
/// sorted lexicographically before being wrapped.
pub fn der_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = elements.to_vec();

    sorted.sort();

    let mut content = Vec::new();

    for element in sorted {
        content.extend_from_slice(&element);
    }

    der_wrap(DER_TAG_SET, &content)
}

pub fn der_object_identifier(arcs: &[u64]) -> Result<Vec<u8>, DerError> {
    if arcs.len() < 2 {
        return Err(DerError::InvalidObjectIdentifier);
    }

    let first = arcs[0];
    let second = arcs[1];

    if first > 2 {
        return Err(DerError::InvalidObjectIdentifier);
    }

    if first < 2 && second > 39 {
        return Err(DerError::InvalidObjectIdentifier);
    }

    let first_subidentifier = if first < 2 {
        first * 40 + second
    } else {
        second
            .checked_add(80)
            .ok_or(DerError::InvalidObjectIdentifier)?
    };

    let mut content = Vec::new();

    push_base128(&mut content, first_subidentifier);

    for &arc in &arcs[2..] {
        push_base128(&mut content, arc);
    }

    Ok(der_wrap(DER_TAG_OBJECT_IDENTIFIER, &content))
}

/// Encodes a byte-aligned DER BIT STRING.
///
/// BareProxy's current cryptographic structures use zero unused bits.
pub fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);

    content.push(0);
    content.extend_from_slice(bytes);

    der_wrap(DER_TAG_BIT_STRING, &content)
}

pub fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_wrap(DER_TAG_OCTET_STRING, bytes)
}

/// Wraps content using a low-number context-specific ASN.1 tag.
pub fn der_context_specific(
    tag_number: u8,
    constructed: bool,
    content: &[u8],
) -> Result<Vec<u8>, DerError> {
    if tag_number >= DER_HIGH_TAG_NUMBER {
        return Err(DerError::InvalidContextTag { tag_number });
    }

    let mut tag = DER_CONTEXT_SPECIFIC_CLASS | tag_number;

    if constructed {
        tag |= DER_CONSTRUCTED_BIT;
    }

    Ok(der_wrap(tag, content))
}

/// Produces RFC 7468 textual encoding.
///
/// Output Base64 is wrapped at 64 characters per generated line.
pub fn pem_encode(label: &str, der: &[u8]) -> Result<String, DerError> {
    validate_pem_label(label)?;

    let base64 = encode_base64(der);

    let mut output = String::new();

    output.push_str("-----BEGIN ");
    output.push_str(label);
    output.push_str("-----\n");

    for line in base64.as_bytes().chunks(PEM_LINE_WIDTH) {
        output.push_str(std::str::from_utf8(line).expect("Base64 output must contain only ASCII"));

        output.push('\n');
    }

    output.push_str("-----END ");
    output.push_str(label);
    output.push_str("-----\n");

    Ok(output)
}

/// Decodes one RFC 7468 textual encoding instance with the expected label.
///
/// Data before the matching begin boundary is ignored. Inside the encoded
/// body, ASCII whitespace is tolerated, but malformed Base64 is rejected.
pub fn pem_decode(label: &str, input: &str) -> Result<Vec<u8>, DerError> {
    validate_pem_label(label)?;

    let begin = format!("-----BEGIN {label}-----");

    let end = format!("-----END {label}-----");

    let mut found_begin = false;
    let mut found_end = false;
    let mut base64 = Vec::new();

    for raw_line in input.lines() {
        let line = raw_line.trim_end_matches(|character| character == ' ' || character == '\t');

        if !found_begin {
            if line == begin {
                found_begin = true;
            }

            continue;
        }

        if line == end {
            found_end = true;
            break;
        }

        if line.starts_with("-----END ") {
            return Err(DerError::PemLabelMismatch);
        }

        for byte in line.bytes() {
            if byte.is_ascii_whitespace() {
                continue;
            }

            base64.push(byte);
        }
    }

    if !found_begin {
        return Err(DerError::PemBeginMissing);
    }

    if !found_end {
        return Err(DerError::PemEndMissing);
    }

    decode_base64(&base64)
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(content.len() + 10);

    output.push(tag);

    push_der_length(&mut output, content.len());

    output.extend_from_slice(content);

    output
}

fn push_der_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(u8::try_from(length).expect("short-form DER length must fit in u8"));

        return;
    }

    let bytes = length.to_be_bytes();

    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short DER length cannot be zero");

    let significant = &bytes[first_nonzero..];

    output.push(
        0x80 | u8::try_from(significant.len()).expect("usize DER length length must fit in u8"),
    );

    output.extend_from_slice(significant);
}

fn push_base128(output: &mut Vec<u8>, mut value: u64) {
    let mut bytes = [0_u8; 10];
    let mut index = bytes.len();

    loop {
        index -= 1;

        bytes[index] = u8::try_from(value & 0x7f).expect("base-128 digit must fit in seven bits");

        value >>= 7;

        if value == 0 {
            break;
        }
    }

    for position in index..bytes.len() {
        let mut byte = bytes[position];

        if position + 1 != bytes.len() {
            byte |= 0x80;
        }

        output.push(byte);
    }
}

fn validate_pem_label(label: &str) -> Result<(), DerError> {
    if label.is_empty() {
        return Err(DerError::InvalidPemLabel);
    }

    let bytes = label.as_bytes();

    if matches!(bytes.first(), Some(b' ' | b'-')) || matches!(bytes.last(), Some(b' ' | b'-')) {
        return Err(DerError::InvalidPemLabel);
    }

    let mut previous = None;

    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'0'..=b'9' => {}
            b' ' | b'-' => {
                if previous == Some(byte) {
                    return Err(DerError::InvalidPemLabel);
                }
            }
            _ => {
                return Err(DerError::InvalidPemLabel);
            }
        }

        previous = Some(byte);
    }

    Ok(())
}

fn decode_base64(encoded: &[u8]) -> Result<Vec<u8>, DerError> {
    if !encoded.len().is_multiple_of(4) {
        return Err(DerError::InvalidPemBase64);
    }

    let mut output = Vec::with_capacity(encoded.len() / 4 * 3);

    let block_count = encoded.len() / 4;

    for (block_index, quartet) in encoded.chunks_exact(4).enumerate() {
        let last = block_index + 1 == block_count;

        if quartet[0] == b'=' || quartet[1] == b'=' {
            return Err(DerError::InvalidPemBase64);
        }

        let first = decode_base64_character(quartet[0]).ok_or(DerError::InvalidPemBase64)?;

        let second = decode_base64_character(quartet[1]).ok_or(DerError::InvalidPemBase64)?;

        output.push((first << 2) | (second >> 4));

        if quartet[2] == b'=' {
            if quartet[3] != b'=' || !last || second & 0x0f != 0 {
                return Err(DerError::InvalidPemBase64);
            }

            continue;
        }

        let third = decode_base64_character(quartet[2]).ok_or(DerError::InvalidPemBase64)?;

        output.push((second << 4) | (third >> 2));

        if quartet[3] == b'=' {
            if !last || third & 0x03 != 0 {
                return Err(DerError::InvalidPemBase64);
            }

            continue;
        }

        let fourth = decode_base64_character(quartet[3]).ok_or(DerError::InvalidPemBase64)?;

        output.push((third << 6) | fourth);
    }

    Ok(output)
}

fn decode_base64_character(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DER_TAG_OCTET_STRING, DER_TAG_SEQUENCE, DerError, DerReader, der_bit_string,
        der_context_specific, der_integer_unsigned, der_object_identifier, der_octet_string,
        der_sequence, der_set, pem_decode, pem_encode,
    };

    #[test]
    fn der_length_uses_short_form_through_127() {
        let encoded = der_octet_string(&vec![0_u8; 127]);

        assert_eq!(&encoded[..2], &[0x04, 0x7f]);

        assert_eq!(encoded.len(), 129);
    }

    #[test]
    fn der_length_uses_minimal_long_form_from_128() {
        let encoded_128 = der_octet_string(&vec![0_u8; 128]);

        assert_eq!(&encoded_128[..3], &[0x04, 0x81, 0x80]);

        let encoded_256 = der_octet_string(&vec![0_u8; 256]);

        assert_eq!(&encoded_256[..4], &[0x04, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_is_minimal_and_positive() {
        assert_eq!(der_integer_unsigned(&[]), vec![0x02, 0x01, 0x00]);

        assert_eq!(der_integer_unsigned(&[0, 0, 0x7f]), vec![0x02, 0x01, 0x7f]);

        assert_eq!(der_integer_unsigned(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn der_sequence_concatenates_children() {
        let encoded = der_sequence(&[der_integer_unsigned(&[1]), der_octet_string(b"A")]);

        assert_eq!(
            encoded,
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x41,]
        );
    }

    #[test]
    fn der_set_sorts_encoded_children() {
        let encoded = der_set(&[der_integer_unsigned(&[2]), der_integer_unsigned(&[1])]);

        assert_eq!(
            encoded,
            vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,]
        );
    }

    #[test]
    fn der_oid_matches_ec_public_key_identifier() {
        assert_eq!(
            der_object_identifier(&[1, 2, 840, 10045, 2, 1],).unwrap(),
            vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,]
        );
    }

    #[test]
    fn der_oid_matches_p256_named_curve_identifier() {
        assert_eq!(
            der_object_identifier(&[1, 2, 840, 10045, 3, 1, 7],).unwrap(),
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,]
        );
    }

    #[test]
    fn der_oid_rejects_invalid_first_arcs() {
        assert_eq!(
            der_object_identifier(&[3, 1]),
            Err(DerError::InvalidObjectIdentifier)
        );

        assert_eq!(
            der_object_identifier(&[1, 40]),
            Err(DerError::InvalidObjectIdentifier)
        );
    }

    #[test]
    fn der_bit_and_octet_strings_encode() {
        assert_eq!(
            der_bit_string(&[0xaa, 0x55]),
            vec![0x03, 0x03, 0x00, 0xaa, 0x55,]
        );

        assert_eq!(
            der_octet_string(&[0xaa, 0x55]),
            vec![0x04, 0x02, 0xaa, 0x55,]
        );
    }

    #[test]
    fn der_context_specific_tags_encode() {
        assert_eq!(
            der_context_specific(0, true, &[0x02, 0x01, 0x01],).unwrap(),
            vec![0xa0, 0x03, 0x02, 0x01, 0x01,]
        );

        assert_eq!(
            der_context_specific(31, true, &[]),
            Err(DerError::InvalidContextTag { tag_number: 31 })
        );
    }

    #[test]
    fn der_reader_bounds_nested_structures() {
        let encoded = der_sequence(&[der_integer_unsigned(&[1]), der_octet_string(b"BareProxy")]);

        let mut outer = DerReader::new(&encoded);

        let sequence = outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        outer.finish().unwrap();

        let mut inner = sequence.reader();

        assert_eq!(inner.read_integer_unsigned().unwrap(), &[1]);

        let octets = inner.read_expected(DER_TAG_OCTET_STRING).unwrap();

        assert_eq!(octets.content, b"BareProxy");

        inner.finish().unwrap();
    }

    #[test]
    fn der_reader_rejects_indefinite_length() {
        let mut reader = DerReader::new(&[0x04, 0x80]);

        assert_eq!(reader.read_tlv(), Err(DerError::IndefiniteLength));
    }

    #[test]
    fn der_reader_rejects_long_form_for_short_length() {
        let mut reader = DerReader::new(&[0x04, 0x81, 0x7f]);

        assert_eq!(reader.read_tlv(), Err(DerError::NonCanonicalLength));
    }

    #[test]
    fn der_reader_rejects_leading_zero_length_octet() {
        let mut reader = DerReader::new(&[0x04, 0x82, 0x00, 0x80]);

        assert_eq!(reader.read_tlv(), Err(DerError::NonCanonicalLength));
    }

    #[test]
    fn der_reader_rejects_truncated_content() {
        let mut reader = DerReader::new(&[0x04, 0x02, 0xaa]);

        assert_eq!(reader.read_tlv(), Err(DerError::Truncated));
    }

    #[test]
    fn der_reader_rejects_high_tag_number_form() {
        let mut reader = DerReader::new(&[0x1f, 0x00]);

        assert_eq!(
            reader.read_tlv(),
            Err(DerError::HighTagNumberUnsupported { tag: 0x1f })
        );
    }

    #[test]
    fn der_reader_rejects_noncanonical_integer() {
        let mut reader = DerReader::new(&[0x02, 0x02, 0x00, 0x7f]);

        assert_eq!(
            reader.read_integer_unsigned(),
            Err(DerError::InvalidInteger)
        );
    }

    #[test]
    fn der_reader_rejects_negative_integer() {
        let mut reader = DerReader::new(&[0x02, 0x01, 0x80]);

        assert_eq!(
            reader.read_integer_unsigned(),
            Err(DerError::InvalidInteger)
        );
    }

    #[test]
    fn der_reader_reports_trailing_data() {
        let mut reader = DerReader::new(&[0x04, 0x01, 0xaa, 0xff]);

        reader.read_tlv().unwrap();

        assert_eq!(reader.finish(), Err(DerError::TrailingData { length: 1 }));
    }

    #[test]
    fn pem_encoding_matches_simple_fixture() {
        assert_eq!(
            pem_encode("TEST DATA", b"BareProxy",).unwrap(),
            concat!(
                "-----BEGIN TEST DATA-----\n",
                "QmFyZVByb3h5\n",
                "-----END TEST DATA-----\n",
            )
        );
    }

    #[test]
    fn pem_round_trips_binary_data() {
        let input: Vec<u8> = (0..=u8::MAX).collect();

        let encoded = pem_encode("TEST DATA", &input).unwrap();

        let decoded = pem_decode("TEST DATA", &encoded).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn pem_generator_wraps_base64_at_64_characters() {
        let encoded = pem_encode("TEST DATA", &[0x42; 100]).unwrap();

        let body_lines: Vec<&str> = encoded
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();

        assert_eq!(body_lines[0].len(), 64);

        assert!(body_lines.iter().all(|line| { line.len() <= 64 }));
    }

    #[test]
    fn pem_decoder_tolerates_ascii_whitespace() {
        let encoded = concat!(
            "ignored prefix\n",
            "-----BEGIN TEST DATA-----   \n",
            "QmFy ZVBy\tb3h5\n",
            "-----END TEST DATA-----\n",
        );

        assert_eq!(pem_decode("TEST DATA", encoded,).unwrap(), b"BareProxy");
    }

    #[test]
    fn pem_decoder_rejects_label_mismatch() {
        let encoded = concat!(
            "-----BEGIN TEST DATA-----\n",
            "QQ==\n",
            "-----END OTHER DATA-----\n",
        );

        assert_eq!(
            pem_decode("TEST DATA", encoded,),
            Err(DerError::PemLabelMismatch)
        );
    }

    #[test]
    fn pem_decoder_rejects_invalid_base64() {
        let encoded = concat!(
            "-----BEGIN TEST DATA-----\n",
            "Q===\n",
            "-----END TEST DATA-----\n",
        );

        assert_eq!(
            pem_decode("TEST DATA", encoded,),
            Err(DerError::InvalidPemBase64)
        );
    }

    #[test]
    fn pem_decoder_rejects_noncanonical_padding_bits() {
        let encoded = concat!(
            "-----BEGIN TEST DATA-----\n",
            "QR==\n",
            "-----END TEST DATA-----\n",
        );

        assert_eq!(
            pem_decode("TEST DATA", encoded,),
            Err(DerError::InvalidPemBase64)
        );
    }

    #[test]
    fn pem_rejects_invalid_label() {
        assert_eq!(
            pem_encode("bad label", b"",),
            Err(DerError::InvalidPemLabel)
        );
    }
}
