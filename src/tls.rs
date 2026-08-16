//! BareProxy TLS 1.3 protocol foundation.
//!
//! Record framing and handshake parsing follow RFC 9846, the current TLS 1.3
//! specification. RFC 9846 obsoletes RFC 8446 while retaining TLS 1.3 wire
//! compatibility.
//!
//! This module owns bounded TLS record framing and handshake wire parsing.
//! Higher-level server handshake state is added incrementally as BareProxy
//! learns to negotiate and authenticate real TLS connections.

use crate::crypto::{
    ChaCha20Poly1305Error, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, wipe_bytes,
};

use std::{error::Error, fmt, net::IpAddr};

pub const TLS_RECORD_HEADER_SIZE: usize = 5;
pub const TLS_PLAINTEXT_FRAGMENT_LIMIT: usize = 1 << 14;
pub const TLS_INNER_PLAINTEXT_LIMIT: usize = TLS_PLAINTEXT_FRAGMENT_LIMIT + 1;
pub const TLS_CIPHERTEXT_FRAGMENT_LIMIT: usize = TLS_PLAINTEXT_FRAGMENT_LIMIT + 256;
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0303;

pub const TLS_VERSION_1_3: u16 = 0x0304;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const TLS_GROUP_SECP256R1: u16 = 0x0017;
pub const TLS_SIGNATURE_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

const HANDSHAKE_HEADER_SIZE: usize = 4;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const EXTENSION_PRE_SHARED_KEY: u16 = 41;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const EXTENSION_KEY_SHARE: u16 = 51;

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
pub enum TlsHandshakeError {
    Truncated,
    UnexpectedHandshakeType { message_type: u8 },
    HandshakeLengthMismatch { declared: usize, actual: usize },
    InvalidLegacyVersion { version: u16 },
    InvalidSessionIdLength { length: usize },
    InvalidCipherSuiteVector { length: usize },
    InvalidCompressionMethods,
    MissingExtensions,
    MalformedVector { field: &'static str },
    DuplicateExtension { extension_type: u16 },
    Tls13Required,
    MissingRequiredExtension { extension_type: u16 },
    PreSharedKeyNotLast,
    InvalidServerName,
    DuplicateServerName,
    DuplicateKeyShareGroup { group: u16 },
    KeyShareGroupNotOffered { group: u16 },
    KeyShareOrderMismatch,
}

impl fmt::Display for TlsHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated TLS handshake structure"),
            Self::UnexpectedHandshakeType { message_type } => {
                write!(
                    formatter,
                    "expected TLS ClientHello handshake type 1, got {message_type}"
                )
            }
            Self::HandshakeLengthMismatch { declared, actual } => {
                write!(
                    formatter,
                    "TLS handshake declares {declared} body bytes but contains {actual}"
                )
            }
            Self::InvalidLegacyVersion { version } => {
                write!(
                    formatter,
                    "TLS 1.3 ClientHello legacy_version must be 0x0303, got 0x{version:04x}"
                )
            }
            Self::InvalidSessionIdLength { length } => {
                write!(
                    formatter,
                    "TLS ClientHello legacy_session_id is {length} bytes, exceeding 32"
                )
            }
            Self::InvalidCipherSuiteVector { length } => {
                write!(
                    formatter,
                    "TLS ClientHello cipher suite vector has invalid length {length}"
                )
            }
            Self::InvalidCompressionMethods => formatter.write_str(
                "TLS 1.3 ClientHello legacy_compression_methods must contain exactly the null method",
            ),
            Self::MissingExtensions => {
                formatter.write_str("TLS 1.3 ClientHello contains no extension block")
            }
            Self::MalformedVector { field } => {
                write!(formatter, "malformed TLS ClientHello {field} vector")
            }
            Self::DuplicateExtension { extension_type } => {
                write!(
                    formatter,
                    "TLS ClientHello repeats extension type {extension_type}"
                )
            }
            Self::Tls13Required => formatter.write_str(
                "BareProxy requires TLS 1.3 but ClientHello does not offer version 0x0304",
            ),
            Self::MissingRequiredExtension { extension_type } => {
                write!(
                    formatter,
                    "TLS 1.3 ClientHello is missing required extension type {extension_type}"
                )
            }
            Self::PreSharedKeyNotLast => formatter.write_str(
                "TLS ClientHello pre_shared_key extension must be the final extension",
            ),
            Self::InvalidServerName => {
                formatter.write_str("invalid TLS server_name host_name value")
            }
            Self::DuplicateServerName => {
                formatter.write_str("TLS server_name list repeats a name type")
            }
            Self::DuplicateKeyShareGroup { group } => {
                write!(
                    formatter,
                    "TLS ClientHello contains multiple key shares for group 0x{group:04x}"
                )
            }
            Self::KeyShareGroupNotOffered { group } => {
                write!(
                    formatter,
                    "TLS ClientHello key share group 0x{group:04x} is absent from supported_groups"
                )
            }
            Self::KeyShareOrderMismatch => formatter.write_str(
                "TLS ClientHello key shares do not preserve supported_groups ordering",
            ),
        }
    }
}

impl Error for TlsHandshakeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyShareEntry {
    group: u16,
    key_exchange: Vec<u8>,
}

impl TlsKeyShareEntry {
    pub fn group(&self) -> u16 {
        self.group
    }

    pub fn key_exchange(&self) -> &[u8] {
        &self.key_exchange
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    random: [u8; 32],
    legacy_session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    server_name: Option<String>,
    supported_versions: Vec<u16>,
    supported_groups: Vec<u16>,
    key_shares: Vec<TlsKeyShareEntry>,
    signature_algorithms: Vec<u16>,
    pre_shared_key_present: bool,
}

impl ClientHello {
    pub fn random(&self) -> &[u8; 32] {
        &self.random
    }

    pub fn legacy_session_id(&self) -> &[u8] {
        &self.legacy_session_id
    }

    pub fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn supported_versions(&self) -> &[u16] {
        &self.supported_versions
    }

    pub fn supported_groups(&self) -> &[u16] {
        &self.supported_groups
    }

    pub fn key_shares(&self) -> &[TlsKeyShareEntry] {
        &self.key_shares
    }

    pub fn signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    pub fn pre_shared_key_present(&self) -> bool {
        self.pre_shared_key_present
    }

    pub fn offers_tls13(&self) -> bool {
        self.supported_versions.contains(&TLS_VERSION_1_3)
    }

    pub fn offers_chacha20_poly1305_sha256(&self) -> bool {
        self.cipher_suites.contains(&TLS_CHACHA20_POLY1305_SHA256)
    }

    pub fn supports_secp256r1(&self) -> bool {
        self.supported_groups.contains(&TLS_GROUP_SECP256R1)
    }

    pub fn supports_ecdsa_secp256r1_sha256(&self) -> bool {
        self.signature_algorithms
            .contains(&TLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
    }

    pub fn secp256r1_key_share(&self) -> Option<&[u8]> {
        self.key_shares
            .iter()
            .find(|share| share.group == TLS_GROUP_SECP256R1)
            .map(TlsKeyShareEntry::key_exchange)
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

pub fn parse_client_hello(message: &[u8]) -> Result<ClientHello, TlsHandshakeError> {
    if message.len() < HANDSHAKE_HEADER_SIZE {
        return Err(TlsHandshakeError::Truncated);
    }

    let message_type = message[0];

    if message_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(TlsHandshakeError::UnexpectedHandshakeType { message_type });
    }

    let declared_length =
        (usize::from(message[1]) << 16) | (usize::from(message[2]) << 8) | usize::from(message[3]);

    let actual_length = message.len() - HANDSHAKE_HEADER_SIZE;

    if declared_length != actual_length {
        return Err(TlsHandshakeError::HandshakeLengthMismatch {
            declared: declared_length,
            actual: actual_length,
        });
    }

    let mut reader = HandshakeReader::new(&message[HANDSHAKE_HEADER_SIZE..]);

    let legacy_version = reader.read_u16()?;

    if legacy_version != TLS_LEGACY_RECORD_VERSION {
        return Err(TlsHandshakeError::InvalidLegacyVersion {
            version: legacy_version,
        });
    }

    let random_bytes = reader.read_exact(32)?;

    let mut random = [0_u8; 32];
    random.copy_from_slice(random_bytes);

    let legacy_session_id = reader.read_vector_u8("legacy_session_id")?.to_vec();

    if legacy_session_id.len() > 32 {
        return Err(TlsHandshakeError::InvalidSessionIdLength {
            length: legacy_session_id.len(),
        });
    }

    let cipher_suite_bytes = reader.read_vector_u16("cipher_suites")?;

    if cipher_suite_bytes.len() < 2 || !cipher_suite_bytes.len().is_multiple_of(2) {
        return Err(TlsHandshakeError::InvalidCipherSuiteVector {
            length: cipher_suite_bytes.len(),
        });
    }

    let cipher_suites = cipher_suite_bytes
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect();

    let compression_methods = reader.read_vector_u8("legacy_compression_methods")?;

    if compression_methods != [0_u8] {
        return Err(TlsHandshakeError::InvalidCompressionMethods);
    }

    if reader.remaining() == 0 {
        return Err(TlsHandshakeError::MissingExtensions);
    }

    let extension_block = reader.read_vector_u16("extensions")?;

    reader.finish("ClientHello")?;

    let ParsedClientHelloExtensions {
        server_name,
        supported_versions,
        supported_groups,
        key_shares,
        signature_algorithms,
        pre_shared_key_present,
    } = parse_client_hello_extensions(extension_block)?;

    let supported_versions =
        supported_versions.ok_or(TlsHandshakeError::MissingRequiredExtension {
            extension_type: EXTENSION_SUPPORTED_VERSIONS,
        })?;

    if !supported_versions.contains(&TLS_VERSION_1_3) {
        return Err(TlsHandshakeError::Tls13Required);
    }

    if !pre_shared_key_present {
        if signature_algorithms.is_none() {
            return Err(TlsHandshakeError::MissingRequiredExtension {
                extension_type: EXTENSION_SIGNATURE_ALGORITHMS,
            });
        }

        if supported_groups.is_none() {
            return Err(TlsHandshakeError::MissingRequiredExtension {
                extension_type: EXTENSION_SUPPORTED_GROUPS,
            });
        }
    }

    match (&supported_groups, &key_shares) {
        (Some(_), None) => {
            return Err(TlsHandshakeError::MissingRequiredExtension {
                extension_type: EXTENSION_KEY_SHARE,
            });
        }
        (None, Some(_)) => {
            return Err(TlsHandshakeError::MissingRequiredExtension {
                extension_type: EXTENSION_SUPPORTED_GROUPS,
            });
        }
        (Some(groups), Some(shares)) => {
            validate_key_share_groups(groups, shares)?;
        }
        (None, None) => {}
    }

    Ok(ClientHello {
        random,
        legacy_session_id,
        cipher_suites,
        server_name,
        supported_versions,
        supported_groups: supported_groups.unwrap_or_default(),
        key_shares: key_shares.unwrap_or_default(),
        signature_algorithms: signature_algorithms.unwrap_or_default(),
        pre_shared_key_present,
    })
}

#[derive(Debug, Default)]
struct ParsedClientHelloExtensions {
    server_name: Option<String>,
    supported_versions: Option<Vec<u16>>,
    supported_groups: Option<Vec<u16>>,
    key_shares: Option<Vec<TlsKeyShareEntry>>,
    signature_algorithms: Option<Vec<u16>>,
    pre_shared_key_present: bool,
}

fn parse_client_hello_extensions(
    input: &[u8],
) -> Result<ParsedClientHelloExtensions, TlsHandshakeError> {
    let mut reader = HandshakeReader::new(input);
    let mut parsed = ParsedClientHelloExtensions::default();
    let mut seen_extensions = Vec::new();

    while reader.remaining() != 0 {
        let extension_type = reader.read_u16()?;
        let extension_data = reader.read_vector_u16("extension_data")?;

        if seen_extensions.contains(&extension_type) {
            return Err(TlsHandshakeError::DuplicateExtension { extension_type });
        }

        seen_extensions.push(extension_type);

        let is_last_extension = reader.remaining() == 0;

        match extension_type {
            EXTENSION_SERVER_NAME => {
                parsed.server_name = parse_server_name(extension_data)?;
            }
            EXTENSION_SUPPORTED_GROUPS => {
                parsed.supported_groups =
                    Some(parse_u16_vector_u16(extension_data, "supported_groups")?);
            }
            EXTENSION_SIGNATURE_ALGORITHMS => {
                parsed.signature_algorithms = Some(parse_u16_vector_u16(
                    extension_data,
                    "signature_algorithms",
                )?);
            }
            EXTENSION_PRE_SHARED_KEY => {
                if !is_last_extension {
                    return Err(TlsHandshakeError::PreSharedKeyNotLast);
                }

                parsed.pre_shared_key_present = true;
            }
            EXTENSION_SUPPORTED_VERSIONS => {
                parsed.supported_versions =
                    Some(parse_u16_vector_u8(extension_data, "supported_versions")?);
            }
            EXTENSION_KEY_SHARE => {
                parsed.key_shares = Some(parse_client_key_shares(extension_data)?);
            }
            _ => {}
        }
    }

    Ok(parsed)
}

fn parse_server_name(input: &[u8]) -> Result<Option<String>, TlsHandshakeError> {
    let mut outer = HandshakeReader::new(input);
    let server_name_list = outer.read_vector_u16("server_name_list")?;

    outer.finish("server_name")?;

    if server_name_list.is_empty() {
        return Err(TlsHandshakeError::MalformedVector {
            field: "server_name_list",
        });
    }

    let mut reader = HandshakeReader::new(server_name_list);
    let mut seen_name_types = Vec::new();
    let mut server_name = None;

    while reader.remaining() != 0 {
        let name_type = reader.read_u8()?;
        let name = reader.read_vector_u16("server_name")?;

        if seen_name_types.contains(&name_type) {
            return Err(TlsHandshakeError::DuplicateServerName);
        }

        seen_name_types.push(name_type);

        if name_type == 0 {
            if !is_valid_server_name(name) {
                return Err(TlsHandshakeError::InvalidServerName);
            }

            let host_name =
                std::str::from_utf8(name).map_err(|_| TlsHandshakeError::InvalidServerName)?;

            server_name = Some(host_name.to_ascii_lowercase());
        }
    }

    Ok(server_name)
}

fn is_valid_server_name(name: &[u8]) -> bool {
    if name.is_empty() || !name.is_ascii() {
        return false;
    }

    let Ok(host_name) = std::str::from_utf8(name) else {
        return false;
    };

    if host_name.len() > 253 || host_name.ends_with('.') || host_name.parse::<IpAddr>().is_ok() {
        return false;
    }

    host_name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn parse_u16_vector_u8(input: &[u8], field: &'static str) -> Result<Vec<u16>, TlsHandshakeError> {
    let mut reader = HandshakeReader::new(input);
    let values = reader.read_vector_u8(field)?;

    reader.finish(field)?;

    parse_u16_values(values, field)
}

fn parse_u16_vector_u16(input: &[u8], field: &'static str) -> Result<Vec<u16>, TlsHandshakeError> {
    let mut reader = HandshakeReader::new(input);
    let values = reader.read_vector_u16(field)?;

    reader.finish(field)?;

    parse_u16_values(values, field)
}

fn parse_u16_values(input: &[u8], field: &'static str) -> Result<Vec<u16>, TlsHandshakeError> {
    if input.len() < 2 || !input.len().is_multiple_of(2) {
        return Err(TlsHandshakeError::MalformedVector { field });
    }

    Ok(input
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect())
}

fn parse_client_key_shares(input: &[u8]) -> Result<Vec<TlsKeyShareEntry>, TlsHandshakeError> {
    let mut outer = HandshakeReader::new(input);
    let encoded_shares = outer.read_vector_u16("key_share")?;

    outer.finish("key_share")?;

    let mut reader = HandshakeReader::new(encoded_shares);
    let mut shares = Vec::new();

    while reader.remaining() != 0 {
        let group = reader.read_u16()?;
        let key_exchange = reader.read_vector_u16("key_exchange")?;

        if key_exchange.is_empty() {
            return Err(TlsHandshakeError::MalformedVector {
                field: "key_exchange",
            });
        }

        if shares
            .iter()
            .any(|share: &TlsKeyShareEntry| share.group == group)
        {
            return Err(TlsHandshakeError::DuplicateKeyShareGroup { group });
        }

        shares.push(TlsKeyShareEntry {
            group,
            key_exchange: key_exchange.to_vec(),
        });
    }

    Ok(shares)
}

fn validate_key_share_groups(
    supported_groups: &[u16],
    key_shares: &[TlsKeyShareEntry],
) -> Result<(), TlsHandshakeError> {
    let mut previous_group_index = None;

    for key_share in key_shares {
        let Some(group_index) = supported_groups
            .iter()
            .position(|group| *group == key_share.group)
        else {
            return Err(TlsHandshakeError::KeyShareGroupNotOffered {
                group: key_share.group,
            });
        };

        if previous_group_index.is_some_and(|previous| group_index <= previous) {
            return Err(TlsHandshakeError::KeyShareOrderMismatch);
        }

        previous_group_index = Some(group_index);
    }

    Ok(())
}

struct HandshakeReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> HandshakeReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    fn read_u8(&mut self) -> Result<u8, TlsHandshakeError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, TlsHandshakeError> {
        let bytes = self.read_exact(2)?;

        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], TlsHandshakeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TlsHandshakeError::Truncated)?;

        if end > self.input.len() {
            return Err(TlsHandshakeError::Truncated);
        }

        let value = &self.input[self.offset..end];
        self.offset = end;

        Ok(value)
    }

    fn read_vector_u8(&mut self, field: &'static str) -> Result<&'a [u8], TlsHandshakeError> {
        let length = usize::from(self.read_u8()?);

        self.read_exact(length)
            .map_err(|_| TlsHandshakeError::MalformedVector { field })
    }

    fn read_vector_u16(&mut self, field: &'static str) -> Result<&'a [u8], TlsHandshakeError> {
        let length = usize::from(self.read_u16()?);

        self.read_exact(length)
            .map_err(|_| TlsHandshakeError::MalformedVector { field })
    }

    fn finish(&self, field: &'static str) -> Result<(), TlsHandshakeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(TlsHandshakeError::MalformedVector { field })
        }
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

    fn test_extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(data.len())
                .expect("test extension must fit in uint16")
                .to_be_bytes(),
        );
        output.extend_from_slice(data);

        output
    }

    fn test_server_name_extension(host_name: &str) -> Vec<u8> {
        let mut name = Vec::new();

        name.push(0);
        name.extend_from_slice(
            &u16::try_from(host_name.len())
                .expect("test host name must fit in uint16")
                .to_be_bytes(),
        );
        name.extend_from_slice(host_name.as_bytes());

        let mut data = Vec::new();

        data.extend_from_slice(
            &u16::try_from(name.len())
                .expect("test server name list must fit in uint16")
                .to_be_bytes(),
        );
        data.extend_from_slice(&name);

        test_extension(EXTENSION_SERVER_NAME, &data)
    }

    fn test_supported_versions_extension(versions: &[u16]) -> Vec<u8> {
        let mut encoded_versions = Vec::new();

        for version in versions {
            encoded_versions.extend_from_slice(&version.to_be_bytes());
        }

        let mut data = Vec::new();

        data.push(
            u8::try_from(encoded_versions.len())
                .expect("test supported versions must fit in uint8"),
        );
        data.extend_from_slice(&encoded_versions);

        test_extension(EXTENSION_SUPPORTED_VERSIONS, &data)
    }

    fn test_u16_list_extension(extension_type: u16, values: &[u16]) -> Vec<u8> {
        let mut encoded_values = Vec::new();

        for value in values {
            encoded_values.extend_from_slice(&value.to_be_bytes());
        }

        let mut data = Vec::new();

        data.extend_from_slice(
            &u16::try_from(encoded_values.len())
                .expect("test vector must fit in uint16")
                .to_be_bytes(),
        );
        data.extend_from_slice(&encoded_values);

        test_extension(extension_type, &data)
    }

    fn test_key_share_extension(group: u16, key_exchange: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();

        entry.extend_from_slice(&group.to_be_bytes());
        entry.extend_from_slice(
            &u16::try_from(key_exchange.len())
                .expect("test key share must fit in uint16")
                .to_be_bytes(),
        );
        entry.extend_from_slice(key_exchange);

        let mut data = Vec::new();

        data.extend_from_slice(
            &u16::try_from(entry.len())
                .expect("test key share list must fit in uint16")
                .to_be_bytes(),
        );
        data.extend_from_slice(&entry);

        test_extension(EXTENSION_KEY_SHARE, &data)
    }

    fn test_client_hello(
        legacy_version: u16,
        compression_methods: &[u8],
        cipher_suites: &[u16],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut body = Vec::new();

        body.extend_from_slice(&legacy_version.to_be_bytes());
        body.extend_from_slice(&[0x11_u8; 32]);

        body.push(0);

        let mut encoded_cipher_suites = Vec::new();

        for cipher_suite in cipher_suites {
            encoded_cipher_suites.extend_from_slice(&cipher_suite.to_be_bytes());
        }

        body.extend_from_slice(
            &u16::try_from(encoded_cipher_suites.len())
                .expect("test cipher suites must fit in uint16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&encoded_cipher_suites);

        body.push(
            u8::try_from(compression_methods.len())
                .expect("test compression methods must fit in uint8"),
        );
        body.extend_from_slice(compression_methods);

        let mut encoded_extensions = Vec::new();

        for extension in extensions {
            encoded_extensions.extend_from_slice(extension);
        }

        body.extend_from_slice(
            &u16::try_from(encoded_extensions.len())
                .expect("test extensions must fit in uint16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&encoded_extensions);

        assert!(body.len() <= 0x00ff_ffff);

        let body_length = body.len();

        let mut message = Vec::new();

        message.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        message.push(((body_length >> 16) & 0xff) as u8);
        message.push(((body_length >> 8) & 0xff) as u8);
        message.push((body_length & 0xff) as u8);
        message.extend_from_slice(&body);

        message
    }

    fn valid_client_hello_extensions() -> Vec<Vec<u8>> {
        vec![
            test_server_name_extension("Example.Test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(TLS_GROUP_SECP256R1, &[4_u8; 65]),
            test_extension(0x0a0a, &[0xde, 0xad]),
        ]
    }

    #[test]
    fn client_hello_parser_extracts_tls13_negotiation_inputs() {
        let message = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[0x1301, TLS_CHACHA20_POLY1305_SHA256],
            &valid_client_hello_extensions(),
        );

        let client_hello = parse_client_hello(&message).expect("ClientHello should parse");

        assert_eq!(client_hello.random(), &[0x11_u8; 32]);
        assert!(client_hello.legacy_session_id().is_empty());

        assert_eq!(
            client_hello.cipher_suites(),
            &[0x1301, TLS_CHACHA20_POLY1305_SHA256]
        );

        assert_eq!(client_hello.server_name(), Some("example.test"));
        assert_eq!(client_hello.supported_versions(), &[TLS_VERSION_1_3]);
        assert_eq!(client_hello.supported_groups(), &[TLS_GROUP_SECP256R1]);
        assert_eq!(
            client_hello.signature_algorithms(),
            &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256]
        );

        assert_eq!(client_hello.key_shares().len(), 1);
        assert_eq!(client_hello.key_shares()[0].group(), TLS_GROUP_SECP256R1);
        assert_eq!(client_hello.key_shares()[0].key_exchange(), &[4_u8; 65]);

        assert!(client_hello.offers_tls13());
        assert!(client_hello.offers_chacha20_poly1305_sha256());
        assert!(client_hello.supports_secp256r1());
        assert!(client_hello.supports_ecdsa_secp256r1_sha256());
        assert_eq!(client_hello.secp256r1_key_share(), Some(&[4_u8; 65][..]));
        assert!(!client_hello.pre_shared_key_present());
    }

    #[test]
    fn client_hello_requires_tls13_and_legacy_0303() {
        let extensions = valid_client_hello_extensions();

        let wrong_legacy_version =
            test_client_hello(0x0304, &[0], &[TLS_CHACHA20_POLY1305_SHA256], &extensions);

        assert_eq!(
            parse_client_hello(&wrong_legacy_version),
            Err(TlsHandshakeError::InvalidLegacyVersion { version: 0x0304 })
        );

        let mut old_version_extensions = valid_client_hello_extensions();

        old_version_extensions.retain(|extension| {
            u16::from_be_bytes([extension[0], extension[1]]) != EXTENSION_SUPPORTED_VERSIONS
        });

        old_version_extensions.push(test_supported_versions_extension(&[0x0303]));

        let no_tls13 = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &old_version_extensions,
        );

        assert_eq!(
            parse_client_hello(&no_tls13),
            Err(TlsHandshakeError::Tls13Required)
        );
    }

    #[test]
    fn client_hello_rejects_non_null_legacy_compression() {
        let message = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0, 1],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &valid_client_hello_extensions(),
        );

        assert_eq!(
            parse_client_hello(&message),
            Err(TlsHandshakeError::InvalidCompressionMethods)
        );
    }

    #[test]
    fn client_hello_rejects_duplicate_extensions() {
        let mut extensions = valid_client_hello_extensions();

        extensions.push(test_supported_versions_extension(&[TLS_VERSION_1_3]));

        let message = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert_eq!(
            parse_client_hello(&message),
            Err(TlsHandshakeError::DuplicateExtension {
                extension_type: EXTENSION_SUPPORTED_VERSIONS,
            })
        );
    }

    #[test]
    fn client_hello_rejects_key_share_not_in_supported_groups() {
        let mut extensions = valid_client_hello_extensions();

        extensions.retain(|extension| {
            u16::from_be_bytes([extension[0], extension[1]]) != EXTENSION_SUPPORTED_GROUPS
        });

        extensions.push(test_u16_list_extension(
            EXTENSION_SUPPORTED_GROUPS,
            &[0x001d],
        ));

        let message = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert_eq!(
            parse_client_hello(&message),
            Err(TlsHandshakeError::KeyShareGroupNotOffered {
                group: TLS_GROUP_SECP256R1,
            })
        );
    }

    #[test]
    fn client_hello_rejects_truncated_and_misframed_messages() {
        assert_eq!(
            parse_client_hello(&[HANDSHAKE_TYPE_CLIENT_HELLO, 0, 0]),
            Err(TlsHandshakeError::Truncated)
        );

        let mut message = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &valid_client_hello_extensions(),
        );

        message[3] = message[3].wrapping_add(1);

        let actual_length = message.len() - HANDSHAKE_HEADER_SIZE;

        assert_eq!(
            parse_client_hello(&message),
            Err(TlsHandshakeError::HandshakeLengthMismatch {
                declared: actual_length + 1,
                actual: actual_length,
            })
        );
    }
}
