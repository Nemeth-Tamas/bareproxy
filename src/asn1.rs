//! Minimal ASN.1 DER and RFC 7468 textual encoding support.
//!
//! DER encoding follows ITU-T X.690.
//!
//! The implementation deliberately supports only the subset BareProxy needs
//! for EC keys, PKCS#10 CSRs, X.509 certificates, and related structures.
//! High-tag-number ASN.1 identifiers and indefinite lengths are rejected.

use crate::{
    crypto::{encode_base64, wipe_bytes},
    p256::{P256Point, P256Signature, Scalar, p256_ecdsa_sign_sha256, p256_generator_multiply},
};

use std::{error::Error, fmt, io, path::Path};

const DER_TAG_BOOLEAN: u8 = 0x01;
const DER_TAG_INTEGER: u8 = 0x02;
const DER_TAG_BIT_STRING: u8 = 0x03;
const DER_TAG_OCTET_STRING: u8 = 0x04;
const DER_TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const DER_TAG_UTC_TIME: u8 = 0x17;
const DER_TAG_GENERALIZED_TIME: u8 = 0x18;
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
    InvalidP256PrivateKey,
    InvalidP256PublicKey,
    InvalidDnsName,
    InvalidCertificate,
    InvalidTime,
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
            Self::InvalidP256PrivateKey => formatter.write_str("P-256 private key cannot be zero"),
            Self::InvalidP256PublicKey => {
                formatter.write_str("P-256 public key cannot be the identity point")
            }
            Self::InvalidDnsName => formatter.write_str("invalid DNS name for subjectAltName"),
            Self::InvalidCertificate => {
                formatter.write_str("invalid or unsupported X.509 certificate structure")
            }
            Self::InvalidTime => formatter.write_str("invalid X.509 certificate validity time"),
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
    der_wrap(DER_TAG_SET, &der_set_content(elements))
}

fn der_set_content(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = elements.to_vec();

    sorted.sort();

    let mut content = Vec::new();

    for element in sorted {
        content.extend_from_slice(&element);
    }

    content
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
        let line = raw_line.trim_end_matches([' ', '\t']);

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

const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];

const OID_SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];

const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];

const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];

fn p256_algorithm_identifier() -> Vec<u8> {
    der_sequence(&[
        der_object_identifier(OID_EC_PUBLIC_KEY).expect("fixed id-ecPublicKey OID must encode"),
        der_object_identifier(OID_SECP256R1).expect("fixed secp256r1 OID must encode"),
    ])
}

/// Encodes an RFC 5915 ECPrivateKey for P-256.
///
/// The private scalar is encoded as exactly 32 big-endian octets. The
/// secp256r1 parameters and matching uncompressed public key are included.
pub fn encode_p256_sec1_private_key_der(private_key: Scalar) -> Result<Vec<u8>, DerError> {
    if private_key == Scalar::ZERO {
        return Err(DerError::InvalidP256PrivateKey);
    }

    let public_key = p256_generator_multiply(private_key)
        .to_sec1_uncompressed()
        .map_err(|_| DerError::InvalidP256PublicKey)?;

    let parameters = der_object_identifier(OID_SECP256R1).expect("fixed secp256r1 OID must encode");

    let public_key = der_bit_string(&public_key);

    Ok(der_sequence(&[
        der_integer_unsigned(&[1]),
        der_octet_string(&private_key.value().to_be_bytes()),
        der_context_specific(0, true, &parameters).expect("context-specific tag zero must encode"),
        der_context_specific(1, true, &public_key).expect("context-specific tag one must encode"),
    ]))
}

/// Encodes an RFC 5915 P-256 private key using the conventional
/// `EC PRIVATE KEY` textual representation.
pub fn encode_p256_sec1_private_key_pem(private_key: Scalar) -> Result<String, DerError> {
    let mut der = encode_p256_sec1_private_key_der(private_key)?;

    let result = pem_encode("EC PRIVATE KEY", &der);

    wipe_bytes(&mut der);

    result
}

/// Encodes a P-256 SubjectPublicKeyInfo structure following RFC 5480.
pub fn encode_p256_spki_der(public_key: P256Point) -> Result<Vec<u8>, DerError> {
    let encoded_point = public_key
        .to_sec1_uncompressed()
        .map_err(|_| DerError::InvalidP256PublicKey)?;

    Ok(der_sequence(&[
        p256_algorithm_identifier(),
        der_bit_string(&encoded_point),
    ]))
}

/// Encodes a P-256 SubjectPublicKeyInfo using the RFC 7468 `PUBLIC KEY` label.
pub fn encode_p256_spki_pem(public_key: P256Point) -> Result<String, DerError> {
    let der = encode_p256_spki_der(public_key)?;

    pem_encode("PUBLIC KEY", &der)
}

/// Encodes one or more DNS identities as an RFC 5280 SubjectAltName value.
///
/// DNS names must already be ASCII. Internationalized names therefore need
/// to be supplied in their A-label form.
pub fn encode_subject_alt_name_dns(dns_names: &[&str]) -> Result<Vec<u8>, DerError> {
    if dns_names.is_empty() {
        return Err(DerError::InvalidDnsName);
    }

    let mut general_names = Vec::with_capacity(dns_names.len());

    for dns_name in dns_names {
        validate_dns_name(dns_name)?;

        general_names.push(
            der_context_specific(2, false, dns_name.as_bytes())
                .expect("GeneralName dNSName tag must fit in low-tag-number form"),
        );
    }

    Ok(der_sequence(&general_names))
}

fn validate_dns_name(dns_name: &str) -> Result<(), DerError> {
    if dns_name.is_empty()
        || !dns_name.is_ascii()
        || dns_name.len() > 253
        || dns_name.ends_with('.')
    {
        return Err(DerError::InvalidDnsName);
    }

    let hostname = if let Some(hostname) = dns_name.strip_prefix("*.") {
        if hostname.is_empty() {
            return Err(DerError::InvalidDnsName);
        }

        hostname
    } else {
        if dns_name.contains('*') {
            return Err(DerError::InvalidDnsName);
        }

        dns_name
    };

    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DerError::InvalidDnsName);
        }
    }

    Ok(())
}

fn ecdsa_sha256_algorithm_identifier() -> Vec<u8> {
    der_sequence(&[der_object_identifier(OID_ECDSA_WITH_SHA256)
        .expect("fixed ecdsa-with-SHA256 OID must encode")])
}

fn encode_p256_signature_der(signature: P256Signature) -> Vec<u8> {
    let (r, s) = signature.components();

    der_sequence(&[
        der_integer_unsigned(&r.to_be_bytes()),
        der_integer_unsigned(&s.to_be_bytes()),
    ])
}

/// Builds and signs a PKCS#10 certification request for P-256.
///
/// DNS identities are requested through the PKCS#9 extensionRequest
/// attribute containing an RFC 5280 SubjectAltName extension.
pub fn encode_p256_csr_der(private_key: Scalar, dns_names: &[&str]) -> Result<Vec<u8>, DerError> {
    if private_key == Scalar::ZERO {
        return Err(DerError::InvalidP256PrivateKey);
    }

    let public_key = p256_generator_multiply(private_key);

    let subject_public_key_info = encode_p256_spki_der(public_key)?;

    let subject_alt_name = encode_subject_alt_name_dns(dns_names)?;

    let subject_alt_name_extension = der_sequence(&[
        der_object_identifier(OID_SUBJECT_ALT_NAME).expect("fixed subjectAltName OID must encode"),
        der_octet_string(&subject_alt_name),
    ]);

    let extensions = der_sequence(&[subject_alt_name_extension]);

    let extension_request = der_sequence(&[
        der_object_identifier(OID_EXTENSION_REQUEST)
            .expect("fixed extensionRequest OID must encode"),
        der_set(&[extensions]),
    ]);

    let attributes = der_context_specific(0, true, &der_set_content(&[extension_request]))
        .expect("PKCS#10 attributes tag must encode");

    let certification_request_info = der_sequence(&[
        der_integer_unsigned(&[0]),
        der_sequence(&[]),
        subject_public_key_info,
        attributes,
    ]);

    let signature = p256_ecdsa_sign_sha256(private_key, &certification_request_info)
        .map_err(|_| DerError::InvalidP256PrivateKey)?;

    let signature = encode_p256_signature_der(signature);

    Ok(der_sequence(&[
        certification_request_info,
        ecdsa_sha256_algorithm_identifier(),
        der_bit_string(&signature),
    ]))
}

/// Builds a signed P-256 PKCS#10 request using the RFC 7468
/// `CERTIFICATE REQUEST` textual label.
pub fn encode_p256_csr_pem(private_key: Scalar, dns_names: &[&str]) -> Result<String, DerError> {
    let der = encode_p256_csr_der(private_key, dns_names)?;

    pem_encode("CERTIFICATE REQUEST", &der)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct X509Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509Validity {
    pub not_before: X509Time,
    pub not_after: X509Time,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509PublicKeyInfo {
    pub algorithm_oid: Vec<u8>,
    pub subject_public_key: Vec<u8>,
    pub p256_public_key: Option<P256Point>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509CertificateInfo {
    pub validity: X509Validity,
    pub dns_names: Vec<String>,
    pub public_key: X509PublicKeyInfo,
}

const OID_EC_PUBLIC_KEY_CONTENT: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

const OID_SECP256R1_CONTENT: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const OID_SUBJECT_ALT_NAME_CONTENT: &[u8] = &[0x55, 0x1d, 0x11];

/// Parses the portions of an RFC 5280 certificate currently needed by
/// BareProxy: validity, SubjectAltName DNS entries, and public-key data.
pub fn parse_x509_certificate_der(der: &[u8]) -> Result<X509CertificateInfo, DerError> {
    let mut outer = DerReader::new(der);

    let certificate = outer.read_expected(DER_TAG_SEQUENCE)?;

    outer.finish()?;

    let mut certificate = certificate.reader();

    let tbs_certificate = certificate.read_expected(DER_TAG_SEQUENCE)?;

    certificate.read_expected(DER_TAG_SEQUENCE)?;

    let signature = certificate.read_expected(DER_TAG_BIT_STRING)?;

    if signature.content.is_empty() || signature.content[0] != 0 {
        return Err(DerError::InvalidCertificate);
    }

    certificate.finish()?;

    let mut tbs = tbs_certificate.reader();

    let first = tbs.read_tlv()?;

    let version = if first.tag == 0xa0 {
        let mut version = first.reader();

        let version_value = version.read_integer_unsigned()?;

        version.finish()?;

        if version_value.len() != 1 || version_value[0] > 2 {
            return Err(DerError::InvalidCertificate);
        }

        let version_value = version_value[0];

        let serial_number = tbs.read_expected(DER_TAG_INTEGER)?;

        if serial_number.content.is_empty() {
            return Err(DerError::InvalidCertificate);
        }

        version_value
    } else {
        if first.tag != DER_TAG_INTEGER || first.content.is_empty() {
            return Err(DerError::InvalidCertificate);
        }

        0
    };

    tbs.read_expected(DER_TAG_SEQUENCE)?;
    tbs.read_expected(DER_TAG_SEQUENCE)?;

    let validity = parse_x509_validity(tbs.read_expected(DER_TAG_SEQUENCE)?)?;

    tbs.read_expected(DER_TAG_SEQUENCE)?;

    let public_key = parse_x509_public_key_info(tbs.read_expected(DER_TAG_SEQUENCE)?)?;

    let mut dns_names = Vec::new();

    let mut extensions_seen = false;

    while !tbs.is_empty() {
        let optional = tbs.read_tlv()?;

        match optional.tag {
            0x81 | 0x82 => {}
            0xa3 => {
                if extensions_seen || version != 2 {
                    return Err(DerError::InvalidCertificate);
                }

                extensions_seen = true;

                dns_names = parse_x509_extensions(optional.content)?;
            }
            _ => {
                return Err(DerError::InvalidCertificate);
            }
        }
    }

    Ok(X509CertificateInfo {
        validity,
        dns_names,
        public_key,
    })
}

/// Parses every RFC 7468 `CERTIFICATE` instance in a PEM certificate chain.
pub fn parse_x509_certificate_chain_pem(input: &str) -> Result<Vec<X509CertificateInfo>, DerError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";

    const END: &str = "-----END CERTIFICATE-----";

    let mut certificates = Vec::new();

    let mut inside_certificate = false;
    let mut base64 = Vec::new();

    for raw_line in input.lines() {
        let line = raw_line.trim_end_matches([' ', '\t']);

        if !inside_certificate {
            if line == BEGIN {
                inside_certificate = true;
                base64.clear();
            }

            continue;
        }

        if line == END {
            let der = decode_base64(&base64)?;

            certificates.push(parse_x509_certificate_der(&der)?);

            inside_certificate = false;
            base64.clear();

            continue;
        }

        if line.starts_with("-----BEGIN ") || line.starts_with("-----END ") {
            return Err(DerError::PemLabelMismatch);
        }

        for byte in line.bytes() {
            if !byte.is_ascii_whitespace() {
                base64.push(byte);
            }
        }
    }

    if inside_certificate {
        return Err(DerError::PemEndMissing);
    }

    if certificates.is_empty() {
        return Err(DerError::PemBeginMissing);
    }

    Ok(certificates)
}

fn parse_x509_validity(validity: DerValue<'_>) -> Result<X509Validity, DerError> {
    let mut validity = validity.reader();

    let not_before = parse_x509_time(validity.read_tlv()?)?;

    let not_after = parse_x509_time(validity.read_tlv()?)?;

    validity.finish()?;

    Ok(X509Validity {
        not_before,
        not_after,
    })
}

fn parse_x509_time(value: DerValue<'_>) -> Result<X509Time, DerError> {
    let bytes = value.content;

    let (year, offset) = match value.tag {
        DER_TAG_UTC_TIME => {
            if bytes.len() != 13 || bytes[12] != b'Z' {
                return Err(DerError::InvalidTime);
            }

            let short_year = u16::from(parse_two_digits(&bytes[0..2])?);

            let year = if short_year >= 50 {
                1900 + short_year
            } else {
                2000 + short_year
            };

            (year, 2)
        }
        DER_TAG_GENERALIZED_TIME => {
            if bytes.len() != 15 || bytes[14] != b'Z' {
                return Err(DerError::InvalidTime);
            }

            (parse_four_digits(&bytes[0..4])?, 4)
        }
        _ => {
            return Err(DerError::InvalidTime);
        }
    };

    let month = parse_two_digits(&bytes[offset..offset + 2])?;

    let day = parse_two_digits(&bytes[offset + 2..offset + 4])?;

    let hour = parse_two_digits(&bytes[offset + 4..offset + 6])?;

    let minute = parse_two_digits(&bytes[offset + 6..offset + 8])?;

    let second = parse_two_digits(&bytes[offset + 8..offset + 10])?;

    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
        || day == 0
        || day > days_in_month(year, month)
    {
        return Err(DerError::InvalidTime);
    }

    Ok(X509Time {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

fn parse_two_digits(bytes: &[u8]) -> Result<u8, DerError> {
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(DerError::InvalidTime);
    }

    Ok((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn parse_four_digits(bytes: &[u8]) -> Result<u16, DerError> {
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(DerError::InvalidTime);
    }

    let mut value = 0_u16;

    for &byte in bytes {
        value = value * 10 + u16::from(byte - b'0');
    }

    Ok(value)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn parse_x509_public_key_info(spki: DerValue<'_>) -> Result<X509PublicKeyInfo, DerError> {
    let mut spki = spki.reader();

    let algorithm = spki.read_expected(DER_TAG_SEQUENCE)?;

    let subject_public_key = spki.read_expected(DER_TAG_BIT_STRING)?;

    spki.finish()?;

    if subject_public_key.content.is_empty() || subject_public_key.content[0] != 0 {
        return Err(DerError::InvalidCertificate);
    }

    let mut algorithm = algorithm.reader();

    let algorithm_oid = algorithm.read_expected(DER_TAG_OBJECT_IDENTIFIER)?;

    let parameters = if algorithm.is_empty() {
        None
    } else {
        Some(algorithm.read_tlv()?)
    };

    algorithm.finish()?;

    let encoded_key = &subject_public_key.content[1..];

    let is_p256 = algorithm_oid.content == OID_EC_PUBLIC_KEY_CONTENT
        && parameters.is_some_and(|parameter| {
            parameter.tag == DER_TAG_OBJECT_IDENTIFIER && parameter.content == OID_SECP256R1_CONTENT
        });

    let p256_public_key = if is_p256 {
        Some(
            P256Point::from_sec1_uncompressed(encoded_key)
                .map_err(|_| DerError::InvalidP256PublicKey)?,
        )
    } else {
        None
    };

    Ok(X509PublicKeyInfo {
        algorithm_oid: algorithm_oid.content.to_vec(),
        subject_public_key: encoded_key.to_vec(),
        p256_public_key,
    })
}

fn parse_x509_extensions(content: &[u8]) -> Result<Vec<String>, DerError> {
    let mut explicit = DerReader::new(content);

    let extensions = explicit.read_expected(DER_TAG_SEQUENCE)?;

    explicit.finish()?;

    let mut extensions = extensions.reader();

    let mut dns_names = Vec::new();

    let mut san_seen = false;

    while !extensions.is_empty() {
        let extension = extensions.read_expected(DER_TAG_SEQUENCE)?;

        let mut extension = extension.reader();

        let oid = extension.read_expected(DER_TAG_OBJECT_IDENTIFIER)?;

        let next = extension.read_tlv()?;

        let extension_value = if next.tag == DER_TAG_BOOLEAN {
            if next.content.len() != 1 || (next.content[0] != 0x00 && next.content[0] != 0xff) {
                return Err(DerError::InvalidCertificate);
            }

            extension.read_expected(DER_TAG_OCTET_STRING)?
        } else {
            if next.tag != DER_TAG_OCTET_STRING {
                return Err(DerError::InvalidCertificate);
            }

            next
        };

        extension.finish()?;

        if oid.content == OID_SUBJECT_ALT_NAME_CONTENT {
            if san_seen {
                return Err(DerError::InvalidCertificate);
            }

            san_seen = true;

            dns_names = parse_x509_subject_alt_name(extension_value.content)?;
        }
    }

    Ok(dns_names)
}

fn parse_x509_subject_alt_name(encoded: &[u8]) -> Result<Vec<String>, DerError> {
    let mut outer = DerReader::new(encoded);

    let names = outer.read_expected(DER_TAG_SEQUENCE)?;

    outer.finish()?;

    let mut names = names.reader();

    let mut dns_names = Vec::new();

    while !names.is_empty() {
        let name = names.read_tlv()?;

        if name.tag != 0x82 {
            continue;
        }

        if !name.content.is_ascii() {
            return Err(DerError::InvalidDnsName);
        }

        let dns_name = std::str::from_utf8(name.content).map_err(|_| DerError::InvalidDnsName)?;

        validate_dns_name(dns_name)?;

        dns_names.push(dns_name.to_owned());
    }

    Ok(dns_names)
}

/// Persists an RFC 5915 P-256 private key with restrictive filesystem
/// permissions.
///
/// On platforms where BareProxy cannot currently guarantee restrictive
/// permissions, this function fails closed instead of writing the key.
pub fn persist_p256_private_key_pem(path: impl AsRef<Path>, private_key: Scalar) -> io::Result<()> {
    let pem = encode_p256_sec1_private_key_pem(private_key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let mut bytes = pem.into_bytes();

    let result = private_key_storage::write(path.as_ref(), &bytes);

    wipe_bytes(&mut bytes);

    result
}

#[cfg(unix)]
mod private_key_storage {
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    const PRIVATE_KEY_MODE: u32 = 0o600;

    pub(super) fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(PRIVATE_KEY_MODE)
            .open(path)?;

        file.set_permissions(fs::Permissions::from_mode(PRIVATE_KEY_MODE))?;

        file.write_all(bytes)?;
        file.sync_all()
    }
}

#[cfg(not(unix))]
mod private_key_storage {
    use std::{io, path::Path};

    pub(super) fn write(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "restrictive private-key persistence is not implemented for this platform yet",
        ))
    }
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
        DER_TAG_BIT_STRING, DER_TAG_GENERALIZED_TIME, DER_TAG_INTEGER, DER_TAG_OBJECT_IDENTIFIER,
        DER_TAG_OCTET_STRING, DER_TAG_SEQUENCE, DER_TAG_SET, DER_TAG_UTC_TIME, DerError, DerReader,
        OID_SUBJECT_ALT_NAME, X509Time, der_bit_string, der_context_specific, der_integer_unsigned,
        der_object_identifier, der_octet_string, der_sequence, der_set, der_wrap,
        ecdsa_sha256_algorithm_identifier, encode_p256_csr_der, encode_p256_csr_pem,
        encode_p256_sec1_private_key_der, encode_p256_sec1_private_key_pem, encode_p256_spki_der,
        encode_p256_spki_pem, encode_subject_alt_name_dns, parse_x509_certificate_chain_pem,
        parse_x509_certificate_der, pem_decode, pem_encode, persist_p256_private_key_pem,
    };

    use crate::p256::{
        P256Point, P256Signature, Scalar, Uint256, p256_ecdsa_verify_sha256,
        p256_generator_multiply,
    };

    fn uint256_from_der_unsigned(bytes: &[u8]) -> Uint256 {
        assert!(bytes.len() <= 32);

        let mut padded = [0_u8; 32];

        padded[32 - bytes.len()..].copy_from_slice(bytes);

        Uint256::from_be_bytes(padded)
    }

    fn test_x509_certificate_der(serial: u8, dns_name: &str) -> Vec<u8> {
        let validity = der_sequence(&[
            der_wrap(DER_TAG_UTC_TIME, b"260815190000Z"),
            der_wrap(DER_TAG_GENERALIZED_TIME, b"20500815200000Z"),
        ]);

        let subject_alt_name = encode_subject_alt_name_dns(&[dns_name]).unwrap();

        let subject_alt_name_extension = der_sequence(&[
            der_object_identifier(OID_SUBJECT_ALT_NAME).unwrap(),
            der_octet_string(&subject_alt_name),
        ]);

        let extensions = der_sequence(&[subject_alt_name_extension]);

        let version = der_context_specific(0, true, &der_integer_unsigned(&[2])).unwrap();

        let tbs_certificate = der_sequence(&[
            version,
            der_integer_unsigned(&[serial]),
            ecdsa_sha256_algorithm_identifier(),
            der_sequence(&[]),
            validity,
            der_sequence(&[]),
            encode_p256_spki_der(P256Point::generator()).unwrap(),
            der_context_specific(3, true, &extensions).unwrap(),
        ]);

        der_sequence(&[
            tbs_certificate,
            ecdsa_sha256_algorithm_identifier(),
            der_bit_string(&der_sequence(&[])),
        ])
    }

    #[test]
    fn der_length_uses_short_form_through_127() {
        let encoded = der_octet_string(&[0_u8; 127]);

        assert_eq!(&encoded[..2], &[0x04, 0x7f]);

        assert_eq!(encoded.len(), 129);
    }

    #[test]
    fn der_length_uses_minimal_long_form_from_128() {
        let encoded_128 = der_octet_string(&[0_u8; 128]);

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

    #[test]
    fn p256_sec1_private_key_has_rfc5915_structure() {
        let der = encode_p256_sec1_private_key_der(Scalar::ONE).unwrap();

        let mut outer = DerReader::new(&der);

        let sequence = outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        outer.finish().unwrap();

        let mut key = sequence.reader();

        assert_eq!(key.read_expected(DER_TAG_INTEGER).unwrap().content, &[1]);

        let private_key = key.read_expected(DER_TAG_OCTET_STRING).unwrap();

        assert_eq!(private_key.content.len(), 32);

        assert_eq!(private_key.content[31], 1);

        assert!(private_key.content[..31].iter().all(|byte| *byte == 0));

        let parameters = key.read_expected(0xa0).unwrap();

        let mut parameters = parameters.reader();

        let curve = parameters.read_expected(DER_TAG_OBJECT_IDENTIFIER).unwrap();

        assert_eq!(
            curve.content,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,]
        );

        parameters.finish().unwrap();

        let public_key = key.read_expected(0xa1).unwrap();

        let mut public_key = public_key.reader();

        let public_key = public_key.read_expected(DER_TAG_BIT_STRING).unwrap();

        assert_eq!(public_key.content[0], 0);

        assert_eq!(public_key.content[1], 0x04);

        assert_eq!(public_key.content.len(), 66);

        key.finish().unwrap();
    }

    #[test]
    fn p256_sec1_private_key_pem_round_trips() {
        let pem = encode_p256_sec1_private_key_pem(Scalar::ONE).unwrap();

        let decoded = pem_decode("EC PRIVATE KEY", &pem).unwrap();

        assert_eq!(
            decoded,
            encode_p256_sec1_private_key_der(Scalar::ONE,).unwrap()
        );
    }

    #[test]
    fn p256_private_key_rejects_zero_scalar() {
        assert_eq!(
            encode_p256_sec1_private_key_der(Scalar::ZERO,),
            Err(DerError::InvalidP256PrivateKey)
        );
    }

    #[test]
    fn p256_spki_has_rfc5480_structure() {
        let der = encode_p256_spki_der(P256Point::generator()).unwrap();

        assert_eq!(der.len(), 91);

        let mut outer = DerReader::new(&der);

        let sequence = outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        outer.finish().unwrap();

        let mut spki = sequence.reader();

        let algorithm = spki.read_expected(DER_TAG_SEQUENCE).unwrap();

        let mut algorithm = algorithm.reader();

        let algorithm_oid = algorithm.read_expected(DER_TAG_OBJECT_IDENTIFIER).unwrap();

        assert_eq!(
            algorithm_oid.content,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,]
        );

        let curve_oid = algorithm.read_expected(DER_TAG_OBJECT_IDENTIFIER).unwrap();

        assert_eq!(
            curve_oid.content,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,]
        );

        algorithm.finish().unwrap();

        let public_key = spki.read_expected(DER_TAG_BIT_STRING).unwrap();

        assert_eq!(public_key.content.len(), 66);

        assert_eq!(public_key.content[0], 0);

        assert_eq!(public_key.content[1], 0x04);

        spki.finish().unwrap();
    }

    #[test]
    fn p256_spki_pem_round_trips() {
        let pem = encode_p256_spki_pem(P256Point::generator()).unwrap();

        let decoded = pem_decode("PUBLIC KEY", &pem).unwrap();

        assert_eq!(
            decoded,
            encode_p256_spki_der(P256Point::generator(),).unwrap()
        );
    }

    #[test]
    fn p256_spki_rejects_identity_point() {
        assert_eq!(
            encode_p256_spki_der(P256Point::IDENTITY,),
            Err(DerError::InvalidP256PublicKey)
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_persistence_uses_owner_only_permissions() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "bareproxy-p256-{}-{unique}.pem",
            std::process::id(),
        ));

        persist_p256_private_key_pem(&path, Scalar::ONE).unwrap();

        let metadata = fs::metadata(&path).unwrap();

        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let encoded = fs::read_to_string(&path).unwrap();

        assert!(encoded.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn subject_alt_name_dns_encodes_general_names() {
        let encoded = encode_subject_alt_name_dns(&["example.com", "*.example.net"]).unwrap();

        let mut outer = DerReader::new(&encoded);

        let sequence = outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        outer.finish().unwrap();

        let mut names = sequence.reader();

        assert_eq!(names.read_expected(0x82).unwrap().content, b"example.com");

        assert_eq!(names.read_expected(0x82).unwrap().content, b"*.example.net");

        names.finish().unwrap();
    }

    #[test]
    fn subject_alt_name_dns_rejects_invalid_names() {
        assert_eq!(
            encode_subject_alt_name_dns(&[]),
            Err(DerError::InvalidDnsName)
        );

        assert_eq!(
            encode_subject_alt_name_dns(&["bad name.example"],),
            Err(DerError::InvalidDnsName)
        );

        assert_eq!(
            encode_subject_alt_name_dns(&["münich.example"],),
            Err(DerError::InvalidDnsName)
        );

        assert_eq!(
            encode_subject_alt_name_dns(&["-example.com"],),
            Err(DerError::InvalidDnsName)
        );
    }

    #[test]
    fn p256_csr_contains_san_and_valid_ecdsa_signature() {
        let private_key = Scalar::ONE;

        let public_key = p256_generator_multiply(private_key);

        let der = encode_p256_csr_der(private_key, &["example.com", "www.example.com"]).unwrap();

        let mut outer = DerReader::new(&der);

        let request = outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        outer.finish().unwrap();

        let mut request = request.reader();

        let certification_request_info = request.read_expected(DER_TAG_SEQUENCE).unwrap();

        let signed_bytes = der_wrap(DER_TAG_SEQUENCE, certification_request_info.content);

        let mut info = certification_request_info.reader();

        assert_eq!(info.read_integer_unsigned().unwrap(), &[0]);

        assert!(
            info.read_expected(DER_TAG_SEQUENCE,)
                .unwrap()
                .content
                .is_empty()
        );

        info.read_expected(DER_TAG_SEQUENCE).unwrap();

        let attributes = info.read_expected(0xa0).unwrap();

        info.finish().unwrap();

        let mut attributes = attributes.reader();

        let extension_request = attributes.read_expected(DER_TAG_SEQUENCE).unwrap();

        attributes.finish().unwrap();

        let mut extension_request = extension_request.reader();

        assert_eq!(
            extension_request
                .read_expected(DER_TAG_OBJECT_IDENTIFIER,)
                .unwrap()
                .content,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,]
        );

        let values = extension_request.read_expected(DER_TAG_SET).unwrap();

        extension_request.finish().unwrap();

        let mut values = values.reader();

        let extensions = values.read_expected(DER_TAG_SEQUENCE).unwrap();

        values.finish().unwrap();

        let mut extensions = extensions.reader();

        let extension = extensions.read_expected(DER_TAG_SEQUENCE).unwrap();

        extensions.finish().unwrap();

        let mut extension = extension.reader();

        assert_eq!(
            extension
                .read_expected(DER_TAG_OBJECT_IDENTIFIER,)
                .unwrap()
                .content,
            &[0x55, 0x1d, 0x11]
        );

        let extension_value = extension.read_expected(DER_TAG_OCTET_STRING).unwrap();

        extension.finish().unwrap();

        let mut general_names = DerReader::new(extension_value.content);

        let general_names = general_names.read_expected(DER_TAG_SEQUENCE).unwrap();

        let mut names = general_names.reader();

        assert_eq!(names.read_expected(0x82).unwrap().content, b"example.com");

        assert_eq!(
            names.read_expected(0x82).unwrap().content,
            b"www.example.com"
        );

        names.finish().unwrap();

        let signature_algorithm = request.read_expected(DER_TAG_SEQUENCE).unwrap();

        let mut signature_algorithm = signature_algorithm.reader();

        assert_eq!(
            signature_algorithm
                .read_expected(DER_TAG_OBJECT_IDENTIFIER,)
                .unwrap()
                .content,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,]
        );

        signature_algorithm.finish().unwrap();

        let signature = request.read_expected(DER_TAG_BIT_STRING).unwrap();

        request.finish().unwrap();

        assert_eq!(signature.content[0], 0);

        let mut signature_outer = DerReader::new(&signature.content[1..]);

        let signature_sequence = signature_outer.read_expected(DER_TAG_SEQUENCE).unwrap();

        signature_outer.finish().unwrap();

        let mut signature_values = signature_sequence.reader();

        let r = uint256_from_der_unsigned(signature_values.read_integer_unsigned().unwrap());

        let s = uint256_from_der_unsigned(signature_values.read_integer_unsigned().unwrap());

        signature_values.finish().unwrap();

        let signature = P256Signature::from_components(r, s).unwrap();

        assert!(p256_ecdsa_verify_sha256(
            public_key,
            &signed_bytes,
            signature,
        ));
    }

    #[test]
    fn p256_csr_pem_round_trips() {
        let pem = encode_p256_csr_pem(Scalar::ONE, &["example.com"]).unwrap();

        let decoded = pem_decode("CERTIFICATE REQUEST", &pem).unwrap();

        assert_eq!(
            decoded,
            encode_p256_csr_der(Scalar::ONE, &["example.com"],).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires the OpenSSL command-line tool"]
    fn p256_csr_openssl_interoperability() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };

        let pem = encode_p256_csr_pem(Scalar::ONE, &["example.com", "www.example.com"]).unwrap();

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir()
            .join(format!("bareproxy-csr-{}-{unique}.pem", std::process::id(),));

        fs::write(&path, pem).unwrap();

        let output = Command::new("openssl")
            .arg("req")
            .arg("-in")
            .arg(&path)
            .args(["-noout", "-verify", "-text"])
            .output()
            .expect("OpenSSL must be installed for this ignored interoperability test");

        fs::remove_file(path).unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);

        let stderr = String::from_utf8_lossy(&output.stderr);

        let combined = format!("{stdout}\n{stderr}");

        assert!(
            output.status.success(),
            "OpenSSL rejected BareProxy CSR:\n{combined}"
        );

        assert!(
            combined.contains("DNS:example.com"),
            "OpenSSL did not decode the requested SAN:\n{combined}"
        );
    }

    #[test]
    fn x509_certificate_inspection_extracts_required_fields() {
        let der = test_x509_certificate_der(1, "example.com");

        let certificate = parse_x509_certificate_der(&der).unwrap();

        assert_eq!(
            certificate.validity.not_before,
            X509Time {
                year: 2026,
                month: 8,
                day: 15,
                hour: 19,
                minute: 0,
                second: 0,
            }
        );

        assert_eq!(
            certificate.validity.not_after,
            X509Time {
                year: 2050,
                month: 8,
                day: 15,
                hour: 20,
                minute: 0,
                second: 0,
            }
        );

        assert_eq!(certificate.dns_names, vec!["example.com"]);

        assert_eq!(
            certificate.public_key.algorithm_oid,
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,]
        );

        assert_eq!(certificate.public_key.subject_public_key[0], 0x04);

        assert_eq!(
            certificate.public_key.p256_public_key,
            Some(P256Point::generator())
        );
    }

    #[test]
    fn x509_certificate_chain_parses_multiple_pem_certificates() {
        let first = pem_encode(
            "CERTIFICATE",
            &test_x509_certificate_der(1, "leaf.example.com"),
        )
        .unwrap();

        let second = pem_encode(
            "CERTIFICATE",
            &test_x509_certificate_der(2, "issuer.example.com"),
        )
        .unwrap();

        let chain = format!("certificate chain\n{first}\n{second}");

        let certificates = parse_x509_certificate_chain_pem(&chain).unwrap();

        assert_eq!(certificates.len(), 2);

        assert_eq!(certificates[0].dns_names, vec!["leaf.example.com"]);

        assert_eq!(certificates[1].dns_names, vec!["issuer.example.com"]);
    }

    #[test]
    fn x509_certificate_chain_rejects_unterminated_pem() {
        assert_eq!(
            parse_x509_certificate_chain_pem(concat!("-----BEGIN CERTIFICATE-----\n", "QQ==\n",),),
            Err(DerError::PemEndMissing)
        );
    }

    #[test]
    fn x509_certificate_parser_rejects_invalid_validity_time() {
        let invalid_validity = der_sequence(&[
            der_wrap(DER_TAG_UTC_TIME, b"261315190000Z"),
            der_wrap(DER_TAG_UTC_TIME, b"270815190000Z"),
        ]);

        let tbs_certificate = der_sequence(&[
            der_context_specific(0, true, &der_integer_unsigned(&[2])).unwrap(),
            der_integer_unsigned(&[1]),
            ecdsa_sha256_algorithm_identifier(),
            der_sequence(&[]),
            invalid_validity,
            der_sequence(&[]),
            encode_p256_spki_der(P256Point::generator()).unwrap(),
        ]);

        let certificate = der_sequence(&[
            tbs_certificate,
            ecdsa_sha256_algorithm_identifier(),
            der_bit_string(&der_sequence(&[])),
        ]);

        assert_eq!(
            parse_x509_certificate_der(&certificate,),
            Err(DerError::InvalidTime)
        );
    }
}
