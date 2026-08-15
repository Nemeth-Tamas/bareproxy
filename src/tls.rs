//! BareProxy TLS 1.3 record-layer foundation.
//!
//! The record framing implemented here follows RFC 8446 section 5.
//!
//! This module deliberately stops below the TLS handshake state machine.
//! It understands record framing, content types, fragmentation, and the
//! generic 4-byte handshake-message envelope, but not ClientHello,
//! ServerHello, certificate, or Finished message contents yet.

use crate::crypto::{
    ChaCha20Poly1305Error, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, wipe_bytes,
};

use std::{error::Error, fmt};

pub const TLS_RECORD_HEADER_SIZE: usize = 5;
pub const TLS_PLAINTEXT_FRAGMENT_LIMIT: usize = 1 << 14;
pub const TLS_INNER_PLAINTEXT_LIMIT: usize = TLS_PLAINTEXT_FRAGMENT_LIMIT + 1;
pub const TLS_CIPHERTEXT_FRAGMENT_LIMIT: usize = TLS_PLAINTEXT_FRAGMENT_LIMIT + 256;
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0303;

const HANDSHAKE_HEADER_SIZE: usize = 4;
const CHACHA20_POLY1305_TAG_SIZE: usize = 16;
const TLS_CHACHA20_POLY1305_CIPHERTEXT_LIMIT: usize =
    TLS_INNER_PLAINTEXT_LIMIT + CHACHA20_POLY1305_TAG_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = TlsRecordError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            _ => Err(TlsRecordError::UnknownContentType(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRecordError {
    UnknownContentType(u8),
    RecordOverflow { length: usize, maximum: usize },
    EmptyHandshakeFragment,
    InvalidAlertLength { length: usize },
    InvalidChangeCipherSpec,
    UnprotectedApplicationData,
    InterleavedHandshake { next_type: ContentType },
    HandshakeNotAligned { buffered_bytes: usize },
    InvalidCiphertextContentType { content_type: u8 },
    InvalidCiphertextVersion { version: u16 },
    CiphertextOverflow { length: usize, maximum: usize },
    CiphertextTooShort { length: usize, minimum: usize },
    InnerPlaintextOverflow { length: usize, maximum: usize },
    MissingInnerContentType,
    InvalidInnerContentType(u8),
    SequenceNumberExhausted { direction: RecordDirection },
    Aead(ChaCha20Poly1305Error),
}

impl fmt::Display for TlsRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContentType(content_type) => {
                write!(formatter, "unsupported TLS content type {content_type}")
            }
            Self::RecordOverflow { length, maximum } => {
                write!(
                    formatter,
                    "TLS plaintext fragment is {length} bytes, exceeding the {maximum}-byte limit"
                )
            }
            Self::EmptyHandshakeFragment => {
                formatter.write_str("TLS handshake records cannot contain an empty fragment")
            }
            Self::InvalidAlertLength { length } => {
                write!(
                    formatter,
                    "TLS alert record must contain exactly one 2-byte alert message, got {length} bytes"
                )
            }
            Self::InvalidChangeCipherSpec => formatter.write_str(
                "TLS change_cipher_spec compatibility record must contain the single byte 0x01",
            ),
            Self::UnprotectedApplicationData => {
                formatter.write_str("TLS 1.3 application data cannot be serialized unprotected")
            }
            Self::InterleavedHandshake { next_type } => {
                write!(
                    formatter,
                    "fragmented TLS handshake message was interrupted by {next_type:?}"
                )
            }
            Self::HandshakeNotAligned { buffered_bytes } => {
                write!(
                    formatter,
                    "TLS handshake has {buffered_bytes} buffered byte(s) that do not end on a message boundary"
                )
            }
            Self::InvalidCiphertextContentType { content_type } => {
                write!(
                    formatter,
                    "TLS 1.3 ciphertext outer content type must be application_data (23), got {content_type}"
                )
            }
            Self::InvalidCiphertextVersion { version } => {
                write!(
                    formatter,
                    "TLS 1.3 ciphertext legacy record version must be 0x0303, got 0x{version:04x}"
                )
            }
            Self::CiphertextOverflow { length, maximum } => {
                write!(
                    formatter,
                    "TLS ciphertext fragment is {length} bytes, exceeding the {maximum}-byte limit"
                )
            }
            Self::CiphertextTooShort { length, minimum } => {
                write!(
                    formatter,
                    "TLS ciphertext fragment is {length} bytes, below the {minimum}-byte minimum"
                )
            }
            Self::InnerPlaintextOverflow { length, maximum } => {
                write!(
                    formatter,
                    "TLSInnerPlaintext is {length} bytes, exceeding the {maximum}-byte limit"
                )
            }
            Self::MissingInnerContentType => {
                formatter.write_str("TLSInnerPlaintext contains no non-zero content type")
            }
            Self::InvalidInnerContentType(content_type) => {
                write!(
                    formatter,
                    "invalid TLSInnerPlaintext content type {content_type}"
                )
            }
            Self::SequenceNumberExhausted { direction } => {
                let direction = match direction {
                    RecordDirection::Read => "read",
                    RecordDirection::Write => "write",
                };

                write!(
                    formatter,
                    "TLS {direction} record sequence number is exhausted"
                )
            }
            Self::Aead(error) => write!(formatter, "TLS record AEAD failure: {error}"),
        }
    }
}

impl Error for TlsRecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Aead(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ChaCha20Poly1305Error> for TlsRecordError {
    fn from(error: ChaCha20Poly1305Error) -> Self {
        Self::Aead(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPlaintextRecord {
    content_type: ContentType,
    legacy_record_version: u16,
    fragment: Vec<u8>,
}

impl TlsPlaintextRecord {
    pub fn new(content_type: ContentType, fragment: Vec<u8>) -> Result<Self, TlsRecordError> {
        validate_plaintext_fragment(content_type, &fragment)?;

        Ok(Self {
            content_type,
            legacy_record_version: TLS_LEGACY_RECORD_VERSION,
            fragment,
        })
    }

    pub fn content_type(&self) -> ContentType {
        self.content_type
    }

    pub fn legacy_record_version(&self) -> u16 {
        self.legacy_record_version
    }

    pub fn fragment(&self) -> &[u8] {
        &self.fragment
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TlsRecordError> {
        validate_plaintext_fragment(self.content_type, &self.fragment)?;

        if self.content_type == ContentType::ApplicationData {
            return Err(TlsRecordError::UnprotectedApplicationData);
        }

        let fragment_length = self.fragment.len();
        let mut output = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + fragment_length);

        output.push(self.content_type as u8);
        output.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        output.extend_from_slice(&(fragment_length as u16).to_be_bytes());
        output.extend_from_slice(&self.fragment);

        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCiphertextRecord {
    legacy_record_version: u16,
    encrypted_record: Vec<u8>,
}

impl TlsCiphertextRecord {
    pub fn content_type(&self) -> ContentType {
        ContentType::ApplicationData
    }

    pub fn legacy_record_version(&self) -> u16 {
        self.legacy_record_version
    }

    pub fn encrypted_record(&self) -> &[u8] {
        &self.encrypted_record
    }

    pub fn serialize(&self) -> Vec<u8> {
        let header = self.header();
        let mut output = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + self.encrypted_record.len());

        output.extend_from_slice(&header);
        output.extend_from_slice(&self.encrypted_record);

        output
    }

    fn header(&self) -> [u8; TLS_RECORD_HEADER_SIZE] {
        let encoded_length = u16::try_from(self.encrypted_record.len())
            .expect("validated TLSCiphertext length must fit in uint16");

        let version = self.legacy_record_version.to_be_bytes();
        let length = encoded_length.to_be_bytes();

        [
            ContentType::ApplicationData as u8,
            version[0],
            version[1],
            length[0],
            length[1],
        ]
    }
}

#[derive(Debug, Default)]
pub struct CiphertextRecordDecoder {
    buffer: Vec<u8>,
}

impl CiphertextRecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<TlsCiphertextRecord>, TlsRecordError> {
        self.buffer.extend_from_slice(input);

        let mut records = Vec::new();
        let mut consumed = 0;

        loop {
            let available = self.buffer.len() - consumed;

            if available < TLS_RECORD_HEADER_SIZE {
                break;
            }

            let content_type = self.buffer[consumed];

            if content_type != ContentType::ApplicationData as u8 {
                return Err(TlsRecordError::InvalidCiphertextContentType { content_type });
            }

            let legacy_record_version =
                u16::from_be_bytes([self.buffer[consumed + 1], self.buffer[consumed + 2]]);

            if legacy_record_version != TLS_LEGACY_RECORD_VERSION {
                return Err(TlsRecordError::InvalidCiphertextVersion {
                    version: legacy_record_version,
                });
            }

            let encrypted_length = usize::from(u16::from_be_bytes([
                self.buffer[consumed + 3],
                self.buffer[consumed + 4],
            ]));

            if encrypted_length > TLS_CIPHERTEXT_FRAGMENT_LIMIT {
                return Err(TlsRecordError::CiphertextOverflow {
                    length: encrypted_length,
                    maximum: TLS_CIPHERTEXT_FRAGMENT_LIMIT,
                });
            }

            let record_length = TLS_RECORD_HEADER_SIZE + encrypted_length;

            if available < record_length {
                break;
            }

            let encrypted_start = consumed + TLS_RECORD_HEADER_SIZE;
            let encrypted_end = consumed + record_length;

            records.push(TlsCiphertextRecord {
                legacy_record_version,
                encrypted_record: self.buffer[encrypted_start..encrypted_end].to_vec(),
            });

            consumed += record_length;
        }

        if consumed != 0 {
            drop(self.buffer.drain(..consumed));
        }

        Ok(records)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

pub struct Tls13RecordProtection {
    write_key: [u8; 32],
    write_iv: [u8; 12],
    read_key: [u8; 32],
    read_iv: [u8; 12],
    write_sequence_number: Option<u64>,
    read_sequence_number: Option<u64>,
}

impl Tls13RecordProtection {
    pub fn new(
        write_key: [u8; 32],
        write_iv: [u8; 12],
        read_key: [u8; 32],
        read_iv: [u8; 12],
    ) -> Self {
        Self {
            write_key,
            write_iv,
            read_key,
            read_iv,
            write_sequence_number: Some(0),
            read_sequence_number: Some(0),
        }
    }

    pub fn write_sequence_number(&self) -> Option<u64> {
        self.write_sequence_number
    }

    pub fn read_sequence_number(&self) -> Option<u64> {
        self.read_sequence_number
    }

    pub fn encrypt_record(
        &mut self,
        record: &TlsPlaintextRecord,
        padding_length: usize,
    ) -> Result<TlsCiphertextRecord, TlsRecordError> {
        let sequence_number =
            self.write_sequence_number
                .ok_or(TlsRecordError::SequenceNumberExhausted {
                    direction: RecordDirection::Write,
                })?;

        let mut inner_plaintext = encode_tls_inner_plaintext(record, padding_length)?;

        let encrypted_length = inner_plaintext.len() + CHACHA20_POLY1305_TAG_SIZE;

        if encrypted_length > TLS_CHACHA20_POLY1305_CIPHERTEXT_LIMIT {
            wipe_bytes(&mut inner_plaintext);

            return Err(TlsRecordError::CiphertextOverflow {
                length: encrypted_length,
                maximum: TLS_CHACHA20_POLY1305_CIPHERTEXT_LIMIT,
            });
        }

        let header = tls_ciphertext_header(encrypted_length)?;
        let nonce = tls13_record_nonce(&self.write_iv, sequence_number);

        let encrypted =
            chacha20_poly1305_encrypt(&self.write_key, &nonce, &header, &inner_plaintext);

        wipe_bytes(&mut inner_plaintext);

        let (mut ciphertext, tag) = encrypted?;

        ciphertext.extend_from_slice(&tag);

        self.write_sequence_number = sequence_number.checked_add(1);

        Ok(TlsCiphertextRecord {
            legacy_record_version: TLS_LEGACY_RECORD_VERSION,
            encrypted_record: ciphertext,
        })
    }

    pub fn decrypt_record(
        &mut self,
        record: &TlsCiphertextRecord,
    ) -> Result<TlsPlaintextRecord, TlsRecordError> {
        validate_chacha20_poly1305_ciphertext(record)?;

        let sequence_number =
            self.read_sequence_number
                .ok_or(TlsRecordError::SequenceNumberExhausted {
                    direction: RecordDirection::Read,
                })?;

        let ciphertext_length = record.encrypted_record.len() - CHACHA20_POLY1305_TAG_SIZE;

        let ciphertext = &record.encrypted_record[..ciphertext_length];

        let mut tag = [0_u8; CHACHA20_POLY1305_TAG_SIZE];
        tag.copy_from_slice(&record.encrypted_record[ciphertext_length..]);

        let header = record.header();
        let nonce = tls13_record_nonce(&self.read_iv, sequence_number);

        let mut inner_plaintext =
            chacha20_poly1305_decrypt(&self.read_key, &nonce, &header, ciphertext, &tag)?;

        let decoded = decode_tls_inner_plaintext(&inner_plaintext);

        wipe_bytes(&mut inner_plaintext);

        let plaintext_record = decoded?;

        self.read_sequence_number = sequence_number.checked_add(1);

        Ok(plaintext_record)
    }
}

impl Drop for Tls13RecordProtection {
    fn drop(&mut self) {
        wipe_bytes(&mut self.write_key);
        wipe_bytes(&mut self.write_iv);
        wipe_bytes(&mut self.read_key);
        wipe_bytes(&mut self.read_iv);
    }
}

pub fn tls13_record_nonce(static_iv: &[u8; 12], sequence_number: u64) -> [u8; 12] {
    let mut nonce = *static_iv;
    let encoded_sequence = sequence_number.to_be_bytes();

    for (index, sequence_byte) in encoded_sequence.iter().enumerate() {
        nonce[4 + index] ^= sequence_byte;
    }

    nonce
}

fn tls_ciphertext_header(
    encrypted_length: usize,
) -> Result<[u8; TLS_RECORD_HEADER_SIZE], TlsRecordError> {
    if encrypted_length > TLS_CIPHERTEXT_FRAGMENT_LIMIT {
        return Err(TlsRecordError::CiphertextOverflow {
            length: encrypted_length,
            maximum: TLS_CIPHERTEXT_FRAGMENT_LIMIT,
        });
    }

    let encoded_length =
        u16::try_from(encrypted_length).expect("validated TLSCiphertext length must fit in uint16");

    let version = TLS_LEGACY_RECORD_VERSION.to_be_bytes();
    let length = encoded_length.to_be_bytes();

    Ok([
        ContentType::ApplicationData as u8,
        version[0],
        version[1],
        length[0],
        length[1],
    ])
}

fn encode_tls_inner_plaintext(
    record: &TlsPlaintextRecord,
    padding_length: usize,
) -> Result<Vec<u8>, TlsRecordError> {
    validate_plaintext_fragment(record.content_type, &record.fragment)?;

    if record.content_type == ContentType::ChangeCipherSpec {
        return Err(TlsRecordError::InvalidInnerContentType(
            ContentType::ChangeCipherSpec as u8,
        ));
    }

    if padding_length > TLS_INNER_PLAINTEXT_LIMIT {
        return Err(TlsRecordError::InnerPlaintextOverflow {
            length: padding_length,
            maximum: TLS_INNER_PLAINTEXT_LIMIT,
        });
    }

    let encoded_length = record.fragment.len() + 1 + padding_length;

    if encoded_length > TLS_INNER_PLAINTEXT_LIMIT {
        return Err(TlsRecordError::InnerPlaintextOverflow {
            length: encoded_length,
            maximum: TLS_INNER_PLAINTEXT_LIMIT,
        });
    }

    let mut output = Vec::with_capacity(encoded_length);

    output.extend_from_slice(&record.fragment);
    output.push(record.content_type as u8);
    output.resize(encoded_length, 0);

    Ok(output)
}

fn decode_tls_inner_plaintext(
    inner_plaintext: &[u8],
) -> Result<TlsPlaintextRecord, TlsRecordError> {
    if inner_plaintext.len() > TLS_INNER_PLAINTEXT_LIMIT {
        return Err(TlsRecordError::InnerPlaintextOverflow {
            length: inner_plaintext.len(),
            maximum: TLS_INNER_PLAINTEXT_LIMIT,
        });
    }

    let Some(content_type_index) = inner_plaintext.iter().rposition(|byte| *byte != 0) else {
        return Err(TlsRecordError::MissingInnerContentType);
    };

    let encoded_content_type = inner_plaintext[content_type_index];

    let content_type = match ContentType::try_from(encoded_content_type) {
        Ok(ContentType::ChangeCipherSpec) | Err(_) => {
            return Err(TlsRecordError::InvalidInnerContentType(
                encoded_content_type,
            ));
        }
        Ok(content_type) => content_type,
    };

    let fragment = inner_plaintext[..content_type_index].to_vec();

    validate_plaintext_fragment(content_type, &fragment)?;

    Ok(TlsPlaintextRecord {
        content_type,
        legacy_record_version: TLS_LEGACY_RECORD_VERSION,
        fragment,
    })
}

fn validate_chacha20_poly1305_ciphertext(
    record: &TlsCiphertextRecord,
) -> Result<(), TlsRecordError> {
    if record.legacy_record_version != TLS_LEGACY_RECORD_VERSION {
        return Err(TlsRecordError::InvalidCiphertextVersion {
            version: record.legacy_record_version,
        });
    }

    if record.encrypted_record.len() > TLS_CHACHA20_POLY1305_CIPHERTEXT_LIMIT {
        return Err(TlsRecordError::CiphertextOverflow {
            length: record.encrypted_record.len(),
            maximum: TLS_CHACHA20_POLY1305_CIPHERTEXT_LIMIT,
        });
    }

    if record.encrypted_record.len() < CHACHA20_POLY1305_TAG_SIZE {
        return Err(TlsRecordError::CiphertextTooShort {
            length: record.encrypted_record.len(),
            minimum: CHACHA20_POLY1305_TAG_SIZE,
        });
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct PlaintextRecordDecoder {
    buffer: Vec<u8>,
}

impl PlaintextRecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<TlsPlaintextRecord>, TlsRecordError> {
        self.buffer.extend_from_slice(input);

        let mut records = Vec::new();
        let mut consumed = 0;

        loop {
            let available = self.buffer.len() - consumed;

            if available < TLS_RECORD_HEADER_SIZE {
                break;
            }

            let content_type = ContentType::try_from(self.buffer[consumed])?;

            let legacy_record_version =
                u16::from_be_bytes([self.buffer[consumed + 1], self.buffer[consumed + 2]]);

            let fragment_length = usize::from(u16::from_be_bytes([
                self.buffer[consumed + 3],
                self.buffer[consumed + 4],
            ]));

            if fragment_length > TLS_PLAINTEXT_FRAGMENT_LIMIT {
                return Err(TlsRecordError::RecordOverflow {
                    length: fragment_length,
                    maximum: TLS_PLAINTEXT_FRAGMENT_LIMIT,
                });
            }

            let record_length = TLS_RECORD_HEADER_SIZE + fragment_length;

            if available < record_length {
                break;
            }

            let fragment_start = consumed + TLS_RECORD_HEADER_SIZE;
            let fragment_end = consumed + record_length;
            let fragment = self.buffer[fragment_start..fragment_end].to_vec();

            validate_plaintext_fragment(content_type, &fragment)?;

            records.push(TlsPlaintextRecord {
                content_type,
                legacy_record_version,
                fragment,
            });

            consumed += record_length;
        }

        if consumed != 0 {
            drop(self.buffer.drain(..consumed));
        }

        Ok(records)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[derive(Debug, Default)]
pub struct HandshakeDeframer {
    buffer: Vec<u8>,
}

impl HandshakeDeframer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_record(
        &mut self,
        record: &TlsPlaintextRecord,
    ) -> Result<Vec<Vec<u8>>, TlsRecordError> {
        if record.content_type != ContentType::Handshake {
            if self.buffer.is_empty() {
                return Ok(Vec::new());
            }

            return Err(TlsRecordError::InterleavedHandshake {
                next_type: record.content_type,
            });
        }

        self.buffer.extend_from_slice(&record.fragment);

        let mut messages = Vec::new();
        let mut consumed = 0;

        loop {
            let available = self.buffer.len() - consumed;

            if available < HANDSHAKE_HEADER_SIZE {
                break;
            }

            let message_length = (usize::from(self.buffer[consumed + 1]) << 16)
                | (usize::from(self.buffer[consumed + 2]) << 8)
                | usize::from(self.buffer[consumed + 3]);

            let framed_length = HANDSHAKE_HEADER_SIZE + message_length;

            if available < framed_length {
                break;
            }

            messages.push(self.buffer[consumed..consumed + framed_length].to_vec());

            consumed += framed_length;
        }

        if consumed != 0 {
            drop(self.buffer.drain(..consumed));
        }

        Ok(messages)
    }

    pub fn require_message_boundary(&self) -> Result<(), TlsRecordError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(TlsRecordError::HandshakeNotAligned {
                buffered_bytes: self.buffer.len(),
            })
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

fn validate_plaintext_fragment(
    content_type: ContentType,
    fragment: &[u8],
) -> Result<(), TlsRecordError> {
    if fragment.len() > TLS_PLAINTEXT_FRAGMENT_LIMIT {
        return Err(TlsRecordError::RecordOverflow {
            length: fragment.len(),
            maximum: TLS_PLAINTEXT_FRAGMENT_LIMIT,
        });
    }

    match content_type {
        ContentType::Handshake if fragment.is_empty() => {
            Err(TlsRecordError::EmptyHandshakeFragment)
        }
        ContentType::Alert if fragment.len() != 2 => Err(TlsRecordError::InvalidAlertLength {
            length: fragment.len(),
        }),
        ContentType::ChangeCipherSpec if fragment != [1_u8] => {
            Err(TlsRecordError::InvalidChangeCipherSpec)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_match_tls_registry_values() {
        assert_eq!(ContentType::try_from(20), Ok(ContentType::ChangeCipherSpec));
        assert_eq!(ContentType::try_from(21), Ok(ContentType::Alert));
        assert_eq!(ContentType::try_from(22), Ok(ContentType::Handshake));
        assert_eq!(ContentType::try_from(23), Ok(ContentType::ApplicationData));
        assert_eq!(
            ContentType::try_from(24),
            Err(TlsRecordError::UnknownContentType(24))
        );
    }

    #[test]
    fn plaintext_record_round_trips() {
        let record =
            TlsPlaintextRecord::new(ContentType::Handshake, vec![1, 0, 0, 3, 0xaa, 0xbb, 0xcc])
                .expect("record should be valid");

        let encoded = record.serialize().expect("record should serialize");

        let mut decoder = PlaintextRecordDecoder::new();

        let decoded = decoder.push(&encoded).expect("record should parse");

        assert_eq!(decoded, vec![record]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn plaintext_parser_does_not_use_legacy_record_version_for_negotiation() {
        let wire = [
            ContentType::Handshake as u8,
            0x12,
            0x34,
            0x00,
            0x04,
            1,
            0,
            0,
            0,
        ];

        let mut decoder = PlaintextRecordDecoder::new();

        let records = decoder.push(&wire).expect("record should parse");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].legacy_record_version(), 0x1234);
        assert_eq!(records[0].content_type(), ContentType::Handshake);
    }

    #[test]
    fn decoder_handles_fragmented_transport_input_and_multiple_records() {
        let first = TlsPlaintextRecord::new(ContentType::Handshake, vec![1, 0, 0, 1, 0xaa])
            .expect("first record should be valid")
            .serialize()
            .expect("first record should serialize");

        let second = TlsPlaintextRecord::new(ContentType::Alert, vec![2, 0])
            .expect("second record should be valid")
            .serialize()
            .expect("second record should serialize");

        let mut wire = first.clone();
        wire.extend_from_slice(&second);

        let mut decoder = PlaintextRecordDecoder::new();

        assert!(
            decoder
                .push(&wire[..2])
                .expect("partial header should be accepted")
                .is_empty()
        );

        assert!(
            decoder
                .push(&wire[2..first.len() - 1])
                .expect("partial body should be accepted")
                .is_empty()
        );

        let records = decoder
            .push(&wire[first.len() - 1..])
            .expect("remaining bytes should complete both records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].content_type(), ContentType::Handshake);
        assert_eq!(records[1].content_type(), ContentType::Alert);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn oversized_plaintext_record_is_rejected_from_header_alone() {
        let oversized_length = TLS_PLAINTEXT_FRAGMENT_LIMIT + 1;

        let header = [
            ContentType::Handshake as u8,
            0x03,
            0x03,
            ((oversized_length >> 8) & 0xff) as u8,
            (oversized_length & 0xff) as u8,
        ];

        let mut decoder = PlaintextRecordDecoder::new();

        assert_eq!(
            decoder.push(&header),
            Err(TlsRecordError::RecordOverflow {
                length: oversized_length,
                maximum: TLS_PLAINTEXT_FRAGMENT_LIMIT,
            })
        );
    }

    #[test]
    fn plaintext_record_semantics_are_checked() {
        assert_eq!(
            TlsPlaintextRecord::new(ContentType::Handshake, Vec::new()),
            Err(TlsRecordError::EmptyHandshakeFragment)
        );

        assert_eq!(
            TlsPlaintextRecord::new(ContentType::Alert, vec![2]),
            Err(TlsRecordError::InvalidAlertLength { length: 1 })
        );

        assert_eq!(
            TlsPlaintextRecord::new(ContentType::ChangeCipherSpec, vec![0]),
            Err(TlsRecordError::InvalidChangeCipherSpec)
        );

        assert!(TlsPlaintextRecord::new(ContentType::ApplicationData, Vec::new()).is_ok());
    }

    #[test]
    fn handshake_deframer_extracts_multiple_messages_from_one_record() {
        let record = TlsPlaintextRecord::new(
            ContentType::Handshake,
            vec![1, 0, 0, 2, 0xaa, 0xbb, 2, 0, 0, 1, 0xcc],
        )
        .expect("handshake record should be valid");

        let mut deframer = HandshakeDeframer::new();

        let messages = deframer
            .push_record(&record)
            .expect("coalesced handshake messages should deframe");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], vec![1, 0, 0, 2, 0xaa, 0xbb]);
        assert_eq!(messages[1], vec![2, 0, 0, 1, 0xcc]);

        assert_eq!(deframer.buffered_len(), 0);
        assert!(deframer.require_message_boundary().is_ok());
    }

    #[test]
    fn handshake_deframer_reassembles_messages_across_records() {
        let first = TlsPlaintextRecord::new(ContentType::Handshake, vec![11, 0, 0, 5, 1, 2])
            .expect("first handshake fragment should be valid");

        let second = TlsPlaintextRecord::new(ContentType::Handshake, vec![3, 4, 5])
            .expect("second handshake fragment should be valid");

        let mut deframer = HandshakeDeframer::new();

        assert!(
            deframer
                .push_record(&first)
                .expect("first fragment should buffer")
                .is_empty()
        );

        assert_eq!(
            deframer.require_message_boundary(),
            Err(TlsRecordError::HandshakeNotAligned { buffered_bytes: 6 })
        );

        let messages = deframer
            .push_record(&second)
            .expect("second fragment should complete the message");

        assert_eq!(messages, vec![vec![11, 0, 0, 5, 1, 2, 3, 4, 5]]);

        assert!(deframer.require_message_boundary().is_ok());
    }

    #[test]
    fn fragmented_handshake_cannot_be_interleaved_with_another_record_type() {
        let handshake = TlsPlaintextRecord::new(ContentType::Handshake, vec![1, 0, 0, 2, 0xaa])
            .expect("partial handshake record should be valid");

        let alert = TlsPlaintextRecord::new(ContentType::Alert, vec![2, 10])
            .expect("alert should be valid");

        let mut deframer = HandshakeDeframer::new();

        assert!(
            deframer
                .push_record(&handshake)
                .expect("partial handshake should buffer")
                .is_empty()
        );

        assert_eq!(
            deframer.push_record(&alert),
            Err(TlsRecordError::InterleavedHandshake {
                next_type: ContentType::Alert,
            })
        );
    }

    fn record_protection_pair() -> (Tls13RecordProtection, Tls13RecordProtection) {
        let client_write_key = [0x11_u8; 32];
        let client_write_iv = [0x22_u8; 12];

        let server_write_key = [0x33_u8; 32];
        let server_write_iv = [0x44_u8; 12];

        (
            Tls13RecordProtection::new(
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            ),
            Tls13RecordProtection::new(
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            ),
        )
    }

    #[test]
    fn application_data_cannot_be_serialized_without_record_protection() {
        let record = TlsPlaintextRecord::new(ContentType::ApplicationData, b"hello".to_vec())
            .expect("application data should be a valid logical TLS plaintext record");

        assert_eq!(
            record.serialize(),
            Err(TlsRecordError::UnprotectedApplicationData)
        );
    }

    #[test]
    fn tls13_nonce_xors_big_endian_sequence_into_static_iv() {
        let static_iv = [0x11_u8; 12];

        let nonce = tls13_record_nonce(&static_iv, 0x0102_0304_0506_0708);

        assert_eq!(
            nonce,
            [
                0x11, 0x11, 0x11, 0x11, 0x10, 0x13, 0x12, 0x15, 0x14, 0x17, 0x16, 0x19,
            ]
        );
    }

    #[test]
    fn encrypted_record_matches_direct_aead_with_record_header_as_aad() {
        let write_key = [0x42_u8; 32];
        let write_iv = [0x24_u8; 12];

        let mut protection =
            Tls13RecordProtection::new(write_key, write_iv, [0x55_u8; 32], [0x66_u8; 12]);

        let plaintext = TlsPlaintextRecord::new(ContentType::Handshake, vec![1, 0, 0, 0])
            .expect("handshake record should be valid");

        let protected = protection
            .encrypt_record(&plaintext, 0)
            .expect("record protection should succeed");

        let inner_plaintext = [1_u8, 0, 0, 0, ContentType::Handshake as u8];

        let encrypted_length = inner_plaintext.len() + CHACHA20_POLY1305_TAG_SIZE;

        let header =
            tls_ciphertext_header(encrypted_length).expect("ciphertext header should be valid");

        let nonce = tls13_record_nonce(&write_iv, 0);

        let (mut expected_ciphertext, expected_tag) =
            crate::crypto::chacha20_poly1305_encrypt(&write_key, &nonce, &header, &inner_plaintext)
                .expect("direct AEAD should succeed");

        expected_ciphertext.extend_from_slice(&expected_tag);

        assert_eq!(protected.encrypted_record(), expected_ciphertext);

        let serialized = protected.serialize();

        assert_eq!(&serialized[..TLS_RECORD_HEADER_SIZE], header.as_slice());
    }

    #[test]
    fn encrypted_records_round_trip_in_both_directions() {
        let (mut client, mut server) = record_protection_pair();

        let request =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"hello server".to_vec())
                .expect("request record should be valid");

        let encrypted_request = client
            .encrypt_record(&request, 0)
            .expect("client should encrypt request");

        let decrypted_request = server
            .decrypt_record(&encrypted_request)
            .expect("server should decrypt request");

        assert_eq!(decrypted_request, request);

        let response =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"hello client".to_vec())
                .expect("response record should be valid");

        let encrypted_response = server
            .encrypt_record(&response, 0)
            .expect("server should encrypt response");

        let decrypted_response = client
            .decrypt_record(&encrypted_response)
            .expect("client should decrypt response");

        assert_eq!(decrypted_response, response);

        assert_eq!(client.write_sequence_number(), Some(1));
        assert_eq!(client.read_sequence_number(), Some(1));
        assert_eq!(server.write_sequence_number(), Some(1));
        assert_eq!(server.read_sequence_number(), Some(1));
    }

    #[test]
    fn ciphertext_decoder_handles_fragmented_transport_input() {
        let (mut client, mut server) = record_protection_pair();

        let plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"fragment me".to_vec())
                .expect("application record should be valid");

        let encrypted = client
            .encrypt_record(&plaintext, 0)
            .expect("record encryption should succeed");

        let wire = encrypted.serialize();

        let mut decoder = CiphertextRecordDecoder::new();

        assert!(
            decoder
                .push(&wire[..3])
                .expect("partial ciphertext header should buffer")
                .is_empty()
        );

        assert!(
            decoder
                .push(&wire[3..wire.len() - 1])
                .expect("partial ciphertext body should buffer")
                .is_empty()
        );

        let records = decoder
            .push(&wire[wire.len() - 1..])
            .expect("final byte should complete ciphertext record");

        assert_eq!(records, vec![encrypted]);
        assert_eq!(decoder.buffered_len(), 0);

        let decrypted = server
            .decrypt_record(&records[0])
            .expect("decoded ciphertext should decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_padding_is_removed_without_losing_content_zeros() {
        let (mut client, mut server) = record_protection_pair();

        let plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, vec![0xaa, 0x00, 0xbb, 0x00])
                .expect("application record should be valid");

        let encrypted = client
            .encrypt_record(&plaintext, 32)
            .expect("padded encryption should succeed");

        let decrypted = server
            .decrypt_record(&encrypted)
            .expect("padded record should decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bad_aead_tag_is_rejected_without_advancing_read_sequence() {
        let (mut client, mut server) = record_protection_pair();

        let plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"authenticate me".to_vec())
                .expect("application record should be valid");

        let mut encrypted = client
            .encrypt_record(&plaintext, 0)
            .expect("record encryption should succeed");

        let last_index = encrypted.encrypted_record.len() - 1;
        encrypted.encrypted_record[last_index] ^= 0x01;

        assert_eq!(
            server.decrypt_record(&encrypted),
            Err(TlsRecordError::Aead(
                crate::crypto::ChaCha20Poly1305Error::AuthenticationFailed
            ))
        );

        assert_eq!(server.read_sequence_number(), Some(0));
    }

    #[test]
    fn ciphertext_decoder_rejects_invalid_outer_header_and_size() {
        let mut wrong_type = CiphertextRecordDecoder::new();

        assert_eq!(
            wrong_type.push(&[ContentType::Handshake as u8, 0x03, 0x03, 0x00, 0x00,]),
            Err(TlsRecordError::InvalidCiphertextContentType {
                content_type: ContentType::Handshake as u8,
            })
        );

        let mut wrong_version = CiphertextRecordDecoder::new();

        assert_eq!(
            wrong_version.push(&[ContentType::ApplicationData as u8, 0x03, 0x02, 0x00, 0x00,]),
            Err(TlsRecordError::InvalidCiphertextVersion { version: 0x0302 })
        );

        let oversized_length = TLS_CIPHERTEXT_FRAGMENT_LIMIT + 1;

        let mut oversized = CiphertextRecordDecoder::new();

        assert_eq!(
            oversized.push(&[
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                ((oversized_length >> 8) & 0xff) as u8,
                (oversized_length & 0xff) as u8,
            ]),
            Err(TlsRecordError::CiphertextOverflow {
                length: oversized_length,
                maximum: TLS_CIPHERTEXT_FRAGMENT_LIMIT,
            })
        );
    }

    #[test]
    fn inner_plaintext_size_limit_is_enforced() {
        let (mut client, _) = record_protection_pair();

        let plaintext = TlsPlaintextRecord::new(ContentType::ApplicationData, vec![0_u8; 16_384])
            .expect("maximum application fragment should be valid");

        assert_eq!(
            client.encrypt_record(&plaintext, 1),
            Err(TlsRecordError::InnerPlaintextOverflow {
                length: TLS_INNER_PLAINTEXT_LIMIT + 1,
                maximum: TLS_INNER_PLAINTEXT_LIMIT,
            })
        );
    }

    #[test]
    fn sequence_number_uses_u64_max_once_then_refuses_to_wrap() {
        let (mut client, mut server) = record_protection_pair();

        client.write_sequence_number = Some(u64::MAX);
        server.read_sequence_number = Some(u64::MAX);

        let plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"last record".to_vec())
                .expect("application record should be valid");

        let encrypted = client
            .encrypt_record(&plaintext, 0)
            .expect("u64::MAX write sequence should still be usable");

        assert_eq!(client.write_sequence_number(), None);

        let decrypted = server
            .decrypt_record(&encrypted)
            .expect("u64::MAX read sequence should still be usable");

        assert_eq!(decrypted, plaintext);
        assert_eq!(server.read_sequence_number(), None);

        assert_eq!(
            client.encrypt_record(&plaintext, 0),
            Err(TlsRecordError::SequenceNumberExhausted {
                direction: RecordDirection::Write,
            })
        );

        assert_eq!(
            server.decrypt_record(&encrypted),
            Err(TlsRecordError::SequenceNumberExhausted {
                direction: RecordDirection::Read,
            })
        );
    }
}
