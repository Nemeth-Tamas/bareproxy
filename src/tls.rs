//! BareProxy TLS 1.3 protocol foundation.
//!
//! Record framing and handshake parsing follow RFC 9846, the current TLS 1.3
//! specification. RFC 9846 obsoletes RFC 8446 while retaining TLS 1.3 wire
//! compatibility.
//!
//! This module owns bounded TLS record framing and handshake wire parsing.
//! Higher-level server handshake state is added incrementally as BareProxy
//! learns to negotiate and authenticate real TLS connections.

use crate::{
    asn1::{der_integer_unsigned, der_sequence},
    crypto::{
        ChaCha20Poly1305Error, HkdfError, Sha256, chacha20_poly1305_decrypt,
        chacha20_poly1305_encrypt, constant_time_eq, fill_random, hkdf_extract_sha256, hmac_sha256,
        sha256, tls13_hkdf_expand_label_sha256, wipe_bytes,
    },
    p256::{
        P256_GROUP_ORDER, P256EcdhError, P256EcdsaError, P256Point, P256PointError, P256Signature,
        Scalar, Uint256, p256_ecdh, p256_ecdsa_sign_sha256, p256_generator_multiply,
    },
};

use std::{error::Error, fmt, io, net::IpAddr};

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
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_TYPE_FINISHED: u8 = 20;
const HANDSHAKE_TYPE_MESSAGE_HASH: u8 = 254;

const TLS_UINT24_MAX: usize = 0x00ff_ffff;
const TLS_SERVER_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
const TLS13_HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
const EXTENSION_PADDING: u16 = 21;
const EXTENSION_PRE_SHARED_KEY: u16 = 41;
const EXTENSION_EARLY_DATA: u16 = 42;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const EXTENSION_COOKIE: u16 = 44;
const EXTENSION_KEY_SHARE: u16 = 51;

const TLS_SHA256_HASH_SIZE: usize = 32;
const TLS_CHACHA20_POLY1305_KEY_SIZE: usize = 32;
const TLS_CHACHA20_POLY1305_IV_SIZE: usize = 12;
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

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
pub enum TlsAlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    GeneralError,
    NoApplicationProtocol,
    Unknown(u8),
}

impl TlsAlertDescription {
    pub fn from_code(value: u8) -> Self {
        match value {
            0 => Self::CloseNotify,
            10 => Self::UnexpectedMessage,
            20 => Self::BadRecordMac,
            22 => Self::RecordOverflow,
            40 => Self::HandshakeFailure,
            42 => Self::BadCertificate,
            43 => Self::UnsupportedCertificate,
            44 => Self::CertificateRevoked,
            45 => Self::CertificateExpired,
            46 => Self::CertificateUnknown,
            47 => Self::IllegalParameter,
            48 => Self::UnknownCa,
            49 => Self::AccessDenied,
            50 => Self::DecodeError,
            51 => Self::DecryptError,
            70 => Self::ProtocolVersion,
            71 => Self::InsufficientSecurity,
            80 => Self::InternalError,
            86 => Self::InappropriateFallback,
            90 => Self::UserCanceled,
            109 => Self::MissingExtension,
            110 => Self::UnsupportedExtension,
            112 => Self::UnrecognizedName,
            113 => Self::BadCertificateStatusResponse,
            115 => Self::UnknownPskIdentity,
            116 => Self::CertificateRequired,
            117 => Self::GeneralError,
            120 => Self::NoApplicationProtocol,
            unknown => Self::Unknown(unknown),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::CloseNotify => 0,
            Self::UnexpectedMessage => 10,
            Self::BadRecordMac => 20,
            Self::RecordOverflow => 22,
            Self::HandshakeFailure => 40,
            Self::BadCertificate => 42,
            Self::UnsupportedCertificate => 43,
            Self::CertificateRevoked => 44,
            Self::CertificateExpired => 45,
            Self::CertificateUnknown => 46,
            Self::IllegalParameter => 47,
            Self::UnknownCa => 48,
            Self::AccessDenied => 49,
            Self::DecodeError => 50,
            Self::DecryptError => 51,
            Self::ProtocolVersion => 70,
            Self::InsufficientSecurity => 71,
            Self::InternalError => 80,
            Self::InappropriateFallback => 86,
            Self::UserCanceled => 90,
            Self::MissingExtension => 109,
            Self::UnsupportedExtension => 110,
            Self::UnrecognizedName => 112,
            Self::BadCertificateStatusResponse => 113,
            Self::UnknownPskIdentity => 115,
            Self::CertificateRequired => 116,
            Self::GeneralError => 117,
            Self::NoApplicationProtocol => 120,
            Self::Unknown(value) => value,
        }
    }

    fn is_closure(self) -> bool {
        matches!(self, Self::CloseNotify | Self::UserCanceled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAlert {
    level: u8,
    description: TlsAlertDescription,
}

impl TlsAlert {
    pub fn close_notify() -> Self {
        Self {
            level: 1,
            description: TlsAlertDescription::CloseNotify,
        }
    }

    pub fn fatal(description: TlsAlertDescription) -> Result<Self, TlsRecordError> {
        if description.is_closure() {
            return Err(TlsRecordError::InvalidFatalAlertDescription { description });
        }

        Ok(Self {
            level: 2,
            description,
        })
    }

    pub fn parse(fragment: &[u8]) -> Result<Self, TlsRecordError> {
        if fragment.len() != 2 {
            return Err(TlsRecordError::InvalidAlertLength {
                length: fragment.len(),
            });
        }

        Ok(Self {
            level: fragment[0],
            description: TlsAlertDescription::from_code(fragment[1]),
        })
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn description(&self) -> TlsAlertDescription {
        self.description
    }

    pub fn plaintext_record(self) -> Result<TlsPlaintextRecord, TlsRecordError> {
        TlsPlaintextRecord::new(
            ContentType::Alert,
            vec![self.level, self.description.code()],
        )
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
    InvalidFatalAlertDescription { description: TlsAlertDescription },
    WriteAfterCloseNotify,
    CloseNotifyAlreadySent,
    ConnectionFailed,
    UnexpectedProtectedContentType { content_type: ContentType },
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
            Self::InvalidFatalAlertDescription { description } => {
                write!(
                    formatter,
                    "TLS closure alert {description:?} cannot be sent as a fatal error alert"
                )
            }
            Self::WriteAfterCloseNotify => {
                formatter.write_str("TLS write side is closed after close_notify")
            }
            Self::CloseNotifyAlreadySent => {
                formatter.write_str("TLS close_notify was already sent")
            }
            Self::ConnectionFailed => {
                formatter.write_str("TLS connection is closed after a fatal alert")
            }
            Self::UnexpectedProtectedContentType { content_type } => {
                write!(
                    formatter,
                    "unexpected protected TLS content type {content_type:?} in application state"
                )
            }
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

impl TlsRecordError {
    pub fn alert_description(&self) -> TlsAlertDescription {
        match self {
            Self::UnknownContentType(_)
            | Self::EmptyHandshakeFragment
            | Self::InvalidChangeCipherSpec
            | Self::InterleavedHandshake { .. }
            | Self::HandshakeNotAligned { .. }
            | Self::MissingInnerContentType
            | Self::InvalidInnerContentType(_)
            | Self::InvalidCiphertextContentType { .. }
            | Self::UnexpectedProtectedContentType { .. } => TlsAlertDescription::UnexpectedMessage,
            Self::RecordOverflow { .. }
            | Self::CiphertextOverflow { .. }
            | Self::InnerPlaintextOverflow { .. } => TlsAlertDescription::RecordOverflow,
            Self::InvalidAlertLength { .. } => TlsAlertDescription::DecodeError,
            Self::CiphertextTooShort { .. } | Self::Aead(_) => TlsAlertDescription::BadRecordMac,
            Self::InvalidCiphertextVersion { .. } => TlsAlertDescription::ProtocolVersion,
            Self::UnprotectedApplicationData
            | Self::SequenceNumberExhausted { .. }
            | Self::InvalidFatalAlertDescription { .. }
            | Self::WriteAfterCloseNotify
            | Self::CloseNotifyAlreadySent
            | Self::ConnectionFailed => TlsAlertDescription::InternalError,
        }
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
    InvalidAlpn,
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
            Self::InvalidAlpn => {
                formatter.write_str("invalid application_layer_protocol_negotiation extension")
            }
        }
    }
}

impl Error for TlsHandshakeError {}

impl TlsHandshakeError {
    pub fn alert_description(&self) -> TlsAlertDescription {
        match self {
            Self::Truncated
            | Self::HandshakeLengthMismatch { .. }
            | Self::InvalidSessionIdLength { .. }
            | Self::InvalidCipherSuiteVector { .. }
            | Self::MissingExtensions
            | Self::MalformedVector { .. }
            | Self::InvalidAlpn => TlsAlertDescription::DecodeError,
            Self::InvalidLegacyVersion { .. }
            | Self::InvalidCompressionMethods
            | Self::DuplicateExtension { .. }
            | Self::PreSharedKeyNotLast
            | Self::InvalidServerName
            | Self::DuplicateServerName
            | Self::DuplicateKeyShareGroup { .. }
            | Self::KeyShareGroupNotOffered { .. }
            | Self::KeyShareOrderMismatch => TlsAlertDescription::IllegalParameter,
            Self::Tls13Required => TlsAlertDescription::ProtocolVersion,
            Self::MissingRequiredExtension { .. } => TlsAlertDescription::MissingExtension,
            Self::UnexpectedHandshakeType { .. } => TlsAlertDescription::UnexpectedMessage,
        }
    }
}

#[derive(Debug)]
pub enum TlsServerHandshakeError {
    ClientHello(TlsHandshakeError),
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedSignatureAlgorithm,
    NoApplicationProtocol,
    HelloRetryRequired { group: u16 },
    InvalidRetryClientHello,
    InvalidRetryKeyShare,
    InvalidP256KeyShare(P256PointError),
    ServerPublicKey(P256PointError),
    Random(io::Error),
    Ecdh(P256EcdhError),
    Signing(P256EcdsaError),
    KeySchedule(HkdfError),
    RecordProtection(TlsRecordError),
    EmptyCertificateChain,
    EmptyCertificate { index: usize },
    CertificateTooLong { index: usize, length: usize },
    CertificateListTooLong { length: usize },
    AuthenticationAlreadyStarted,
    ServerAuthenticationRequired,
    UnexpectedClientFinishedContentType { content_type: ContentType },
    InvalidClientFinished,
    ClientFinishedMismatch,
    HandshakeMessageTooLong { length: usize },
}

impl fmt::Display for TlsServerHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientHello(error) => write!(formatter, "invalid ClientHello: {error}"),
            Self::UnsupportedCipherSuite => {
                formatter.write_str("client does not offer TLS_CHACHA20_POLY1305_SHA256")
            }
            Self::UnsupportedGroup => {
                formatter.write_str("client does not support the P-256 key exchange group")
            }
            Self::UnsupportedSignatureAlgorithm => {
                formatter.write_str("client does not support ecdsa_secp256r1_sha256")
            }
            Self::NoApplicationProtocol => {
                formatter.write_str("client ALPN list contains no protocol supported by BareProxy")
            }
            Self::HelloRetryRequired { group } => {
                write!(
                    formatter,
                    "client supports group 0x{group:04x} but did not provide a usable key share; HelloRetryRequest is required"
                )
            }
            Self::InvalidRetryClientHello => formatter.write_str(
                "retried TLS ClientHello changed fields not permitted after HelloRetryRequest",
            ),
            Self::InvalidRetryKeyShare => formatter
                .write_str("retried TLS ClientHello does not contain exactly one P-256 key share"),
            Self::InvalidP256KeyShare(error) => {
                write!(formatter, "invalid client P-256 key share: {error}")
            }
            Self::ServerPublicKey(error) => {
                write!(
                    formatter,
                    "failed to encode server P-256 key share: {error}"
                )
            }
            Self::Random(error) => {
                write!(
                    formatter,
                    "failed to generate TLS handshake randomness: {error}"
                )
            }
            Self::Ecdh(error) => write!(formatter, "P-256 ECDH failed: {error}"),
            Self::Signing(error) => {
                write!(formatter, "TLS CertificateVerify signing failed: {error}")
            }
            Self::KeySchedule(error) => {
                write!(formatter, "TLS 1.3 key schedule failed: {error}")
            }
            Self::RecordProtection(error) => {
                write!(formatter, "TLS handshake record protection failed: {error}")
            }
            Self::EmptyCertificateChain => {
                formatter.write_str("TLS server certificate chain cannot be empty")
            }
            Self::EmptyCertificate { index } => {
                write!(
                    formatter,
                    "TLS certificate chain entry {index} contains no DER certificate bytes"
                )
            }
            Self::CertificateTooLong { index, length } => {
                write!(
                    formatter,
                    "TLS certificate chain entry {index} is {length} bytes and exceeds uint24"
                )
            }
            Self::CertificateListTooLong { length } => {
                write!(
                    formatter,
                    "TLS Certificate certificate_list is {length} bytes and exceeds uint24"
                )
            }
            Self::AuthenticationAlreadyStarted => {
                formatter.write_str("TLS server authentication flight was already started")
            }
            Self::ServerAuthenticationRequired => {
                formatter.write_str("TLS server authentication must finish before client Finished")
            }
            Self::UnexpectedClientFinishedContentType { content_type } => {
                write!(
                    formatter,
                    "expected encrypted client Finished handshake data, got {content_type:?}"
                )
            }
            Self::InvalidClientFinished => {
                formatter.write_str("malformed TLS client Finished message")
            }
            Self::ClientFinishedMismatch => {
                formatter.write_str("TLS client Finished verification failed")
            }
            Self::HandshakeMessageTooLong { length } => {
                write!(
                    formatter,
                    "TLS handshake message body is {length} bytes and exceeds uint24"
                )
            }
        }
    }
}

impl Error for TlsServerHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ClientHello(error) => Some(error),
            Self::InvalidP256KeyShare(error) | Self::ServerPublicKey(error) => Some(error),
            Self::Random(error) => Some(error),
            Self::Ecdh(error) => Some(error),
            Self::Signing(error) => Some(error),
            Self::KeySchedule(error) => Some(error),
            Self::RecordProtection(error) => Some(error),
            _ => None,
        }
    }
}

impl TlsServerHandshakeError {
    pub fn alert_description(&self) -> TlsAlertDescription {
        match self {
            Self::ClientHello(error) => error.alert_description(),
            Self::UnsupportedCipherSuite
            | Self::UnsupportedGroup
            | Self::UnsupportedSignatureAlgorithm
            | Self::HelloRetryRequired { .. } => TlsAlertDescription::HandshakeFailure,
            Self::NoApplicationProtocol => TlsAlertDescription::NoApplicationProtocol,
            Self::InvalidRetryClientHello | Self::InvalidRetryKeyShare => {
                TlsAlertDescription::IllegalParameter
            }
            Self::InvalidP256KeyShare(_) => TlsAlertDescription::IllegalParameter,
            Self::RecordProtection(error) => error.alert_description(),
            Self::UnexpectedClientFinishedContentType { .. } => {
                TlsAlertDescription::UnexpectedMessage
            }
            Self::InvalidClientFinished => TlsAlertDescription::DecodeError,
            Self::ClientFinishedMismatch => TlsAlertDescription::DecryptError,
            Self::ServerPublicKey(_)
            | Self::Random(_)
            | Self::Ecdh(_)
            | Self::Signing(_)
            | Self::KeySchedule(_)
            | Self::EmptyCertificateChain
            | Self::EmptyCertificate { .. }
            | Self::CertificateTooLong { .. }
            | Self::CertificateListTooLong { .. }
            | Self::AuthenticationAlreadyStarted
            | Self::ServerAuthenticationRequired
            | Self::HandshakeMessageTooLong { .. } => TlsAlertDescription::InternalError,
        }
    }
}

impl From<TlsHandshakeError> for TlsServerHandshakeError {
    fn from(error: TlsHandshakeError) -> Self {
        Self::ClientHello(error)
    }
}

impl From<HkdfError> for TlsServerHandshakeError {
    fn from(error: HkdfError) -> Self {
        Self::KeySchedule(error)
    }
}

impl From<TlsRecordError> for TlsServerHandshakeError {
    fn from(error: TlsRecordError) -> Self {
        Self::RecordProtection(error)
    }
}

#[derive(Clone)]
pub struct TlsTranscript {
    sha256: Sha256,
}

impl TlsTranscript {
    pub fn new() -> Self {
        Self {
            sha256: Sha256::new(),
        }
    }

    fn after_hello_retry(
        client_hello_message: &[u8],
        hello_retry_request: &[u8],
    ) -> Result<Self, TlsServerHandshakeError> {
        let client_hello_hash = sha256(client_hello_message);

        let message_hash =
            encode_handshake_message(HANDSHAKE_TYPE_MESSAGE_HASH, &client_hello_hash)?;

        let mut transcript = Self::new();

        transcript.update_handshake_message(&message_hash);
        transcript.update_handshake_message(hello_retry_request);

        Ok(transcript)
    }

    pub fn update_handshake_message(&mut self, message: &[u8]) {
        self.sha256.update(message);
    }

    pub fn hash(&self) -> [u8; 32] {
        self.sha256.clone().finalize()
    }
}

impl Default for TlsTranscript {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Tls13ServerFirstFlight {
    ServerHello(Tls13ServerHelloFlight),
    HelloRetry(Tls13HelloRetryFlight),
}

pub struct Tls13HelloRetryFlight {
    hello_retry_request: Vec<u8>,
    client_hello: ClientHello,
    transcript: TlsTranscript,
}

impl Tls13HelloRetryFlight {
    pub fn hello_retry_request(&self) -> &[u8] {
        &self.hello_retry_request
    }

    pub fn selected_group(&self) -> u16 {
        TLS_GROUP_SECP256R1
    }

    pub fn continue_with_client_hello(
        self,
        client_hello_message: &[u8],
    ) -> Result<Tls13ServerHelloFlight, TlsServerHandshakeError> {
        let client_hello = parse_client_hello(client_hello_message)?;

        validate_tls13_server_client_hello(&client_hello)?;
        validate_retry_client_hello(&self.client_hello, &client_hello)?;

        negotiate_tls13_server_hello_from_client_hello(
            client_hello_message,
            client_hello,
            self.transcript,
        )
    }
}

pub struct Tls13ServerHelloFlight {
    server_hello: Vec<u8>,
    server_key_share: [u8; 65],
    encrypted_extensions: Vec<u8>,
    encrypted_extensions_record: TlsCiphertextRecord,
    negotiated_alpn: Option<Vec<u8>>,
    client_handshake_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    server_handshake_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    main_secret: [u8; TLS_SHA256_HASH_SIZE],
    transcript: TlsTranscript,
    handshake_record_protection: Tls13RecordProtection,
    server_authentication_started: bool,
}

pub struct Tls13ServerAuthenticationFlight {
    certificate: Vec<u8>,
    certificate_records: Vec<TlsCiphertextRecord>,
    certificate_verify: Vec<u8>,
    certificate_verify_records: Vec<TlsCiphertextRecord>,
    finished: Vec<u8>,
    finished_records: Vec<TlsCiphertextRecord>,
}

impl Tls13ServerAuthenticationFlight {
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    pub fn certificate_records(&self) -> &[TlsCiphertextRecord] {
        &self.certificate_records
    }

    pub fn certificate_verify(&self) -> &[u8] {
        &self.certificate_verify
    }

    pub fn certificate_verify_records(&self) -> &[TlsCiphertextRecord] {
        &self.certificate_verify_records
    }

    pub fn finished(&self) -> &[u8] {
        &self.finished
    }

    pub fn finished_records(&self) -> &[TlsCiphertextRecord] {
        &self.finished_records
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls13ApplicationEvent {
    ApplicationData(Vec<u8>),
    CloseNotify,
    UserCanceled,
    FatalAlert(TlsAlertDescription),
    IgnoredAfterCloseNotify,
}

pub struct Tls13ApplicationState {
    negotiated_alpn: Option<Vec<u8>>,
    client_application_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    server_application_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    transcript_hash: [u8; TLS_SHA256_HASH_SIZE],
    record_protection: Tls13RecordProtection,
    close_notify_sent: bool,
    close_notify_received: bool,
    failed: bool,
}

impl Tls13ApplicationState {
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    pub fn transcript_hash(&self) -> [u8; TLS_SHA256_HASH_SIZE] {
        self.transcript_hash
    }

    pub fn encrypt_application_data_record(
        &mut self,
        fragment: &[u8],
    ) -> Result<TlsCiphertextRecord, TlsRecordError> {
        if self.failed {
            return Err(TlsRecordError::ConnectionFailed);
        }

        if self.close_notify_sent {
            return Err(TlsRecordError::WriteAfterCloseNotify);
        }

        let plaintext = TlsPlaintextRecord::new(ContentType::ApplicationData, fragment.to_vec())?;

        self.record_protection.encrypt_record(&plaintext, 0)
    }

    pub fn encrypt_close_notify(&mut self) -> Result<TlsCiphertextRecord, TlsRecordError> {
        if self.failed {
            return Err(TlsRecordError::ConnectionFailed);
        }

        if self.close_notify_sent {
            return Err(TlsRecordError::CloseNotifyAlreadySent);
        }

        let plaintext = TlsAlert::close_notify().plaintext_record()?;
        let encrypted = self.record_protection.encrypt_record(&plaintext, 0)?;

        self.close_notify_sent = true;

        Ok(encrypted)
    }

    pub fn encrypt_fatal_alert(
        &mut self,
        description: TlsAlertDescription,
    ) -> Result<TlsCiphertextRecord, TlsRecordError> {
        if self.failed {
            return Err(TlsRecordError::ConnectionFailed);
        }

        let plaintext = TlsAlert::fatal(description)?.plaintext_record()?;
        let encrypted = self.record_protection.encrypt_record(&plaintext, 0)?;

        self.fail();

        Ok(encrypted)
    }

    pub fn receive_protected_record(
        &mut self,
        record: &TlsCiphertextRecord,
    ) -> Result<Tls13ApplicationEvent, TlsRecordError> {
        if self.failed {
            return Err(TlsRecordError::ConnectionFailed);
        }

        let plaintext = self.record_protection.decrypt_record(record)?;

        if self.close_notify_received {
            return Ok(Tls13ApplicationEvent::IgnoredAfterCloseNotify);
        }

        match plaintext.content_type() {
            ContentType::ApplicationData => Ok(Tls13ApplicationEvent::ApplicationData(
                plaintext.fragment().to_vec(),
            )),
            ContentType::Alert => {
                let alert = TlsAlert::parse(plaintext.fragment())?;

                match alert.description() {
                    TlsAlertDescription::CloseNotify => {
                        self.close_notify_received = true;

                        Ok(Tls13ApplicationEvent::CloseNotify)
                    }
                    TlsAlertDescription::UserCanceled => Ok(Tls13ApplicationEvent::UserCanceled),
                    description => {
                        self.fail();

                        Ok(Tls13ApplicationEvent::FatalAlert(description))
                    }
                }
            }
            content_type => Err(TlsRecordError::UnexpectedProtectedContentType { content_type }),
        }
    }

    pub fn decrypt_protected_record(
        &mut self,
        record: &TlsCiphertextRecord,
    ) -> Result<TlsPlaintextRecord, TlsRecordError> {
        if self.failed {
            return Err(TlsRecordError::ConnectionFailed);
        }

        self.record_protection.decrypt_record(record)
    }

    pub fn record_protection_mut(&mut self) -> &mut Tls13RecordProtection {
        &mut self.record_protection
    }

    fn fail(&mut self) {
        wipe_bytes(&mut self.client_application_traffic_secret);
        wipe_bytes(&mut self.server_application_traffic_secret);

        self.record_protection.erase();

        self.failed = true;
    }
}

impl Drop for Tls13ApplicationState {
    fn drop(&mut self) {
        wipe_bytes(&mut self.client_application_traffic_secret);
        wipe_bytes(&mut self.server_application_traffic_secret);
    }
}

impl Tls13ServerHelloFlight {
    pub fn server_hello(&self) -> &[u8] {
        &self.server_hello
    }

    pub fn server_key_share(&self) -> &[u8; 65] {
        &self.server_key_share
    }

    pub fn encrypted_extensions(&self) -> &[u8] {
        &self.encrypted_extensions
    }

    pub fn encrypted_extensions_record(&self) -> &TlsCiphertextRecord {
        &self.encrypted_extensions_record
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript.hash()
    }

    pub fn handshake_record_protection_mut(&mut self) -> &mut Tls13RecordProtection {
        &mut self.handshake_record_protection
    }

    pub fn authenticate_server(
        &mut self,
        certificate_chain: &[Vec<u8>],
        signing_key: Scalar,
    ) -> Result<Tls13ServerAuthenticationFlight, TlsServerHandshakeError> {
        if self.server_authentication_started {
            return Err(TlsServerHandshakeError::AuthenticationAlreadyStarted);
        }

        let certificate = build_tls13_certificate(certificate_chain)?;

        let mut next_transcript = self.transcript.clone();

        next_transcript.update_handshake_message(&certificate);

        let certificate_verify =
            build_tls13_server_certificate_verify(signing_key, &next_transcript.hash())?;

        next_transcript.update_handshake_message(&certificate_verify);

        let finished = build_tls13_finished(
            &self.server_handshake_traffic_secret,
            &next_transcript.hash(),
        )?;

        next_transcript.update_handshake_message(&finished);

        self.server_authentication_started = true;

        let certificate_records =
            encrypt_handshake_message_records(&mut self.handshake_record_protection, &certificate)?;

        let certificate_verify_records = encrypt_handshake_message_records(
            &mut self.handshake_record_protection,
            &certificate_verify,
        )?;

        let finished_records =
            encrypt_handshake_message_records(&mut self.handshake_record_protection, &finished)?;

        self.transcript = next_transcript;

        Ok(Tls13ServerAuthenticationFlight {
            certificate,
            certificate_records,
            certificate_verify,
            certificate_verify_records,
            finished,
            finished_records,
        })
    }

    pub fn complete_handshake(
        mut self,
        client_finished_records: &[TlsCiphertextRecord],
    ) -> Result<Tls13ApplicationState, TlsServerHandshakeError> {
        if !self.server_authentication_started {
            return Err(TlsServerHandshakeError::ServerAuthenticationRequired);
        }

        let server_finished_transcript_hash = self.transcript.hash();

        let application_key_schedule = derive_tls13_application_key_schedule(
            &self.main_secret,
            &server_finished_transcript_hash,
        )?;

        let client_finished = decrypt_tls13_client_finished(
            &mut self.handshake_record_protection,
            client_finished_records,
        )?;

        let expected_verify_data = tls13_finished_verify_data(
            &self.client_handshake_traffic_secret,
            &server_finished_transcript_hash,
        )?;

        if !constant_time_eq(
            &client_finished[HANDSHAKE_HEADER_SIZE..],
            &expected_verify_data,
        ) {
            return Err(TlsServerHandshakeError::ClientFinishedMismatch);
        }

        self.transcript.update_handshake_message(&client_finished);

        let transcript_hash = self.transcript.hash();

        let record_protection = Tls13RecordProtection::new(
            application_key_schedule.server_key,
            application_key_schedule.server_iv,
            application_key_schedule.client_key,
            application_key_schedule.client_iv,
        );

        Ok(Tls13ApplicationState {
            negotiated_alpn: self.negotiated_alpn.clone(),
            client_application_traffic_secret: application_key_schedule
                .client_application_traffic_secret,
            server_application_traffic_secret: application_key_schedule
                .server_application_traffic_secret,
            transcript_hash,
            record_protection,
            close_notify_sent: false,
            close_notify_received: false,
            failed: false,
        })
    }
}

impl Drop for Tls13ServerHelloFlight {
    fn drop(&mut self) {
        wipe_bytes(&mut self.client_handshake_traffic_secret);
        wipe_bytes(&mut self.server_handshake_traffic_secret);
        wipe_bytes(&mut self.main_secret);
    }
}

struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

struct Tls13HandshakeKeySchedule {
    client_handshake_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    server_handshake_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    main_secret: [u8; TLS_SHA256_HASH_SIZE],
    client_key: [u8; TLS_CHACHA20_POLY1305_KEY_SIZE],
    client_iv: [u8; TLS_CHACHA20_POLY1305_IV_SIZE],
    server_key: [u8; TLS_CHACHA20_POLY1305_KEY_SIZE],
    server_iv: [u8; TLS_CHACHA20_POLY1305_IV_SIZE],
}

impl Drop for Tls13HandshakeKeySchedule {
    fn drop(&mut self) {
        wipe_bytes(&mut self.client_handshake_traffic_secret);
        wipe_bytes(&mut self.server_handshake_traffic_secret);
        wipe_bytes(&mut self.main_secret);
        wipe_bytes(&mut self.client_key);
        wipe_bytes(&mut self.client_iv);
        wipe_bytes(&mut self.server_key);
        wipe_bytes(&mut self.server_iv);
    }
}

struct Tls13ApplicationKeySchedule {
    client_application_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    server_application_traffic_secret: [u8; TLS_SHA256_HASH_SIZE],
    client_key: [u8; TLS_CHACHA20_POLY1305_KEY_SIZE],
    client_iv: [u8; TLS_CHACHA20_POLY1305_IV_SIZE],
    server_key: [u8; TLS_CHACHA20_POLY1305_KEY_SIZE],
    server_iv: [u8; TLS_CHACHA20_POLY1305_IV_SIZE],
}

impl Drop for Tls13ApplicationKeySchedule {
    fn drop(&mut self) {
        wipe_bytes(&mut self.client_application_traffic_secret);
        wipe_bytes(&mut self.server_application_traffic_secret);
        wipe_bytes(&mut self.client_key);
        wipe_bytes(&mut self.client_iv);
        wipe_bytes(&mut self.server_key);
        wipe_bytes(&mut self.server_iv);
    }
}

fn derive_tls13_application_key_schedule(
    main_secret: &[u8; TLS_SHA256_HASH_SIZE],
    server_finished_transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<Tls13ApplicationKeySchedule, HkdfError> {
    let client_application_traffic_secret =
        SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
            main_secret,
            "c ap traffic",
            server_finished_transcript_hash,
        )?);

    let server_application_traffic_secret =
        SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
            main_secret,
            "s ap traffic",
            server_finished_transcript_hash,
        )?);

    let (client_key, client_iv) =
        derive_tls13_traffic_key_iv(&client_application_traffic_secret.0)?;

    let (server_key, server_iv) =
        derive_tls13_traffic_key_iv(&server_application_traffic_secret.0)?;

    Ok(Tls13ApplicationKeySchedule {
        client_application_traffic_secret: client_application_traffic_secret.0,
        server_application_traffic_secret: server_application_traffic_secret.0,
        client_key,
        client_iv,
        server_key,
        server_iv,
    })
}

fn derive_tls13_handshake_key_schedule(
    shared_secret: &[u8; TLS_SHA256_HASH_SIZE],
    hello_transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<Tls13HandshakeKeySchedule, HkdfError> {
    let zero_secret = [0_u8; TLS_SHA256_HASH_SIZE];
    let empty_hash = sha256(&[]);

    let early_secret = SecretArray(hkdf_extract_sha256(&zero_secret, &zero_secret));

    let derived_early_secret = SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
        &early_secret.0,
        "derived",
        &empty_hash,
    )?);

    let handshake_secret = SecretArray(hkdf_extract_sha256(&derived_early_secret.0, shared_secret));

    let client_handshake_traffic_secret =
        SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
            &handshake_secret.0,
            "c hs traffic",
            hello_transcript_hash,
        )?);

    let server_handshake_traffic_secret =
        SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
            &handshake_secret.0,
            "s hs traffic",
            hello_transcript_hash,
        )?);

    let derived_handshake_secret = SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
        &handshake_secret.0,
        "derived",
        &empty_hash,
    )?);

    let main_secret = SecretArray(hkdf_extract_sha256(
        &derived_handshake_secret.0,
        &zero_secret,
    ));

    let (client_key, client_iv) = derive_tls13_traffic_key_iv(&client_handshake_traffic_secret.0)?;

    let (server_key, server_iv) = derive_tls13_traffic_key_iv(&server_handshake_traffic_secret.0)?;

    Ok(Tls13HandshakeKeySchedule {
        client_handshake_traffic_secret: client_handshake_traffic_secret.0,
        server_handshake_traffic_secret: server_handshake_traffic_secret.0,
        main_secret: main_secret.0,
        client_key,
        client_iv,
        server_key,
        server_iv,
    })
}

fn derive_tls13_traffic_key_iv(
    traffic_secret: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<
    (
        [u8; TLS_CHACHA20_POLY1305_KEY_SIZE],
        [u8; TLS_CHACHA20_POLY1305_IV_SIZE],
    ),
    HkdfError,
> {
    let key =
        tls13_expand_label_array::<TLS_CHACHA20_POLY1305_KEY_SIZE>(traffic_secret, "key", &[])?;

    let iv = tls13_expand_label_array::<TLS_CHACHA20_POLY1305_IV_SIZE>(traffic_secret, "iv", &[])?;

    Ok((key, iv))
}

fn tls13_expand_label_array<const N: usize>(
    secret: &[u8],
    label: &str,
    context: &[u8],
) -> Result<[u8; N], HkdfError> {
    let mut expanded = tls13_hkdf_expand_label_sha256(secret, label, context, N)?;

    let output: [u8; N] = expanded
        .as_slice()
        .try_into()
        .expect("HKDF-Expand-Label returned the requested output length");

    wipe_bytes(&mut expanded);

    Ok(output)
}

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
    alpn_protocols: Vec<Vec<u8>>,
    raw_extensions: Vec<(u16, Vec<u8>)>,
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

    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    fn has_extension(&self, extension_type: u16) -> bool {
        self.raw_extensions
            .iter()
            .any(|(candidate, _)| *candidate == extension_type)
    }

    pub fn offers_http11(&self) -> bool {
        self.alpn_protocols
            .iter()
            .any(|protocol| protocol.as_slice() == ALPN_HTTP_1_1)
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

impl Tls13RecordProtection {
    fn erase(&mut self) {
        wipe_bytes(&mut self.write_key);
        wipe_bytes(&mut self.write_iv);
        wipe_bytes(&mut self.read_key);
        wipe_bytes(&mut self.read_iv);

        self.write_sequence_number = None;
        self.read_sequence_number = None;
    }
}

impl Drop for Tls13RecordProtection {
    fn drop(&mut self) {
        self.erase();
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
        alpn_protocols,
        raw_extensions,
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
        alpn_protocols: alpn_protocols.unwrap_or_default(),
        raw_extensions,
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
    alpn_protocols: Option<Vec<Vec<u8>>>,
    raw_extensions: Vec<(u16, Vec<u8>)>,
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

        parsed
            .raw_extensions
            .push((extension_type, extension_data.to_vec()));

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
            EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                parsed.alpn_protocols = Some(parse_alpn_protocols(extension_data)?);
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

fn parse_alpn_protocols(input: &[u8]) -> Result<Vec<Vec<u8>>, TlsHandshakeError> {
    let mut outer = HandshakeReader::new(input);

    let encoded_protocols = outer.read_vector_u16("application_layer_protocol_negotiation")?;

    outer.finish("application_layer_protocol_negotiation")?;

    if encoded_protocols.is_empty() {
        return Err(TlsHandshakeError::InvalidAlpn);
    }

    let mut reader = HandshakeReader::new(encoded_protocols);
    let mut protocols = Vec::new();

    while reader.remaining() != 0 {
        let protocol = reader.read_vector_u8("alpn_protocol_name")?;

        if protocol.is_empty() {
            return Err(TlsHandshakeError::InvalidAlpn);
        }

        protocols.push(protocol.to_vec());
    }

    Ok(protocols)
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

pub fn negotiate_tls13_server_first_flight(
    client_hello_message: &[u8],
) -> Result<Tls13ServerFirstFlight, TlsServerHandshakeError> {
    let client_hello = parse_client_hello(client_hello_message)?;

    validate_tls13_server_client_hello(&client_hello)?;

    if client_hello.secp256r1_key_share().is_some() {
        let flight = negotiate_tls13_server_hello_from_client_hello(
            client_hello_message,
            client_hello,
            TlsTranscript::new(),
        )?;

        return Ok(Tls13ServerFirstFlight::ServerHello(flight));
    }

    let hello_retry_request = build_tls13_hello_retry_request(&client_hello)?;

    let transcript = TlsTranscript::after_hello_retry(client_hello_message, &hello_retry_request)?;

    Ok(Tls13ServerFirstFlight::HelloRetry(Tls13HelloRetryFlight {
        hello_retry_request,
        client_hello,
        transcript,
    }))
}

pub fn negotiate_tls13_server_hello(
    client_hello_message: &[u8],
) -> Result<Tls13ServerHelloFlight, TlsServerHandshakeError> {
    let client_hello = parse_client_hello(client_hello_message)?;

    validate_tls13_server_client_hello(&client_hello)?;

    negotiate_tls13_server_hello_from_client_hello(
        client_hello_message,
        client_hello,
        TlsTranscript::new(),
    )
}

fn validate_tls13_server_client_hello(
    client_hello: &ClientHello,
) -> Result<(), TlsServerHandshakeError> {
    if !client_hello.offers_chacha20_poly1305_sha256() {
        return Err(TlsServerHandshakeError::UnsupportedCipherSuite);
    }

    if !client_hello.supports_secp256r1() {
        return Err(TlsServerHandshakeError::UnsupportedGroup);
    }

    if !client_hello.supports_ecdsa_secp256r1_sha256() {
        return Err(TlsServerHandshakeError::UnsupportedSignatureAlgorithm);
    }

    Ok(())
}

fn negotiate_tls13_server_hello_from_client_hello(
    client_hello_message: &[u8],
    client_hello: ClientHello,
    mut transcript: TlsTranscript,
) -> Result<Tls13ServerHelloFlight, TlsServerHandshakeError> {
    let encoded_client_key_share =
        client_hello
            .secp256r1_key_share()
            .ok_or(TlsServerHandshakeError::HelloRetryRequired {
                group: TLS_GROUP_SECP256R1,
            })?;

    let client_public_key = P256Point::from_sec1_uncompressed(encoded_client_key_share)
        .map_err(TlsServerHandshakeError::InvalidP256KeyShare)?;

    let server_private_key =
        generate_ephemeral_p256_private_key().map_err(TlsServerHandshakeError::Random)?;

    let server_public_key = p256_generator_multiply(server_private_key);

    let server_key_share = server_public_key
        .to_sec1_uncompressed()
        .map_err(TlsServerHandshakeError::ServerPublicKey)?;

    let mut shared_secret =
        p256_ecdh(server_private_key, client_public_key).map_err(TlsServerHandshakeError::Ecdh)?;

    let mut server_random = [0_u8; 32];

    fill_random(&mut server_random).map_err(TlsServerHandshakeError::Random)?;

    let server_hello = build_tls13_server_hello(&client_hello, &server_random, &server_key_share)?;

    transcript.update_handshake_message(client_hello_message);
    transcript.update_handshake_message(&server_hello);

    let hello_transcript_hash = transcript.hash();

    let key_schedule_result =
        derive_tls13_handshake_key_schedule(&shared_secret, &hello_transcript_hash);

    wipe_bytes(&mut shared_secret);

    let key_schedule = key_schedule_result?;

    let mut handshake_record_protection = Tls13RecordProtection::new(
        key_schedule.server_key,
        key_schedule.server_iv,
        key_schedule.client_key,
        key_schedule.client_iv,
    );

    let (encrypted_extensions, negotiated_alpn) = build_tls13_encrypted_extensions(&client_hello)?;

    let encrypted_extensions_plaintext =
        TlsPlaintextRecord::new(ContentType::Handshake, encrypted_extensions.clone())?;

    let encrypted_extensions_record =
        handshake_record_protection.encrypt_record(&encrypted_extensions_plaintext, 0)?;

    transcript.update_handshake_message(&encrypted_extensions);

    Ok(Tls13ServerHelloFlight {
        server_hello,
        server_key_share,
        encrypted_extensions,
        encrypted_extensions_record,
        negotiated_alpn,
        client_handshake_traffic_secret: key_schedule.client_handshake_traffic_secret,
        server_handshake_traffic_secret: key_schedule.server_handshake_traffic_secret,
        main_secret: key_schedule.main_secret,
        transcript,
        handshake_record_protection,
        server_authentication_started: false,
    })
}

fn validate_retry_client_hello(
    original: &ClientHello,
    retry: &ClientHello,
) -> Result<(), TlsServerHandshakeError> {
    if original.random != retry.random
        || original.legacy_session_id != retry.legacy_session_id
        || original.cipher_suites != retry.cipher_suites
    {
        return Err(TlsServerHandshakeError::InvalidRetryClientHello);
    }

    if !original.pre_shared_key_present && retry.pre_shared_key_present {
        return Err(TlsServerHandshakeError::InvalidRetryClientHello);
    }

    if retry.has_extension(EXTENSION_EARLY_DATA) || retry.has_extension(EXTENSION_COOKIE) {
        return Err(TlsServerHandshakeError::InvalidRetryClientHello);
    }

    if retry.key_shares.len() != 1 || retry.key_shares[0].group != TLS_GROUP_SECP256R1 {
        return Err(TlsServerHandshakeError::InvalidRetryKeyShare);
    }

    if retry_invariant_extensions(original) != retry_invariant_extensions(retry) {
        return Err(TlsServerHandshakeError::InvalidRetryClientHello);
    }

    Ok(())
}

fn retry_invariant_extensions(client_hello: &ClientHello) -> Vec<(u16, &[u8])> {
    client_hello
        .raw_extensions
        .iter()
        .filter_map(|(extension_type, extension_data)| {
            if matches!(
                *extension_type,
                EXTENSION_KEY_SHARE
                    | EXTENSION_PADDING
                    | EXTENSION_PRE_SHARED_KEY
                    | EXTENSION_EARLY_DATA
            ) {
                None
            } else {
                Some((*extension_type, extension_data.as_slice()))
            }
        })
        .collect()
}

fn build_tls13_hello_retry_request(
    client_hello: &ClientHello,
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    let mut extensions = Vec::new();

    append_tls_extension(
        &mut extensions,
        EXTENSION_SUPPORTED_VERSIONS,
        &TLS_VERSION_1_3.to_be_bytes(),
    );

    append_tls_extension(
        &mut extensions,
        EXTENSION_KEY_SHARE,
        &TLS_GROUP_SECP256R1.to_be_bytes(),
    );

    let mut body = Vec::with_capacity(
        2 + TLS13_HELLO_RETRY_REQUEST_RANDOM.len()
            + 1
            + client_hello.legacy_session_id.len()
            + 2
            + 1
            + 2
            + extensions.len(),
    );

    body.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
    body.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);

    body.push(
        u8::try_from(client_hello.legacy_session_id.len())
            .expect("validated TLS legacy session ID must fit in uint8"),
    );
    body.extend_from_slice(&client_hello.legacy_session_id);

    body.extend_from_slice(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.push(0);

    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("TLS HelloRetryRequest extensions must fit in uint16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    encode_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body)
}

fn build_tls13_certificate(
    certificate_chain: &[Vec<u8>],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    if certificate_chain.is_empty() {
        return Err(TlsServerHandshakeError::EmptyCertificateChain);
    }

    let mut certificate_list = Vec::new();

    for (index, certificate) in certificate_chain.iter().enumerate() {
        if certificate.is_empty() {
            return Err(TlsServerHandshakeError::EmptyCertificate { index });
        }

        if certificate.len() > TLS_UINT24_MAX {
            return Err(TlsServerHandshakeError::CertificateTooLong {
                index,
                length: certificate.len(),
            });
        }

        append_uint24(&mut certificate_list, certificate.len());
        certificate_list.extend_from_slice(certificate);

        certificate_list.extend_from_slice(&0_u16.to_be_bytes());

        if certificate_list.len() > TLS_UINT24_MAX {
            return Err(TlsServerHandshakeError::CertificateListTooLong {
                length: certificate_list.len(),
            });
        }
    }

    let mut body = Vec::with_capacity(1 + 3 + certificate_list.len());

    body.push(0);
    append_uint24(&mut body, certificate_list.len());
    body.extend_from_slice(&certificate_list);

    encode_handshake_message(HANDSHAKE_TYPE_CERTIFICATE, &body)
}

fn build_tls13_server_certificate_verify(
    signing_key: Scalar,
    transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    let signed_content = tls13_server_certificate_verify_content(transcript_hash);

    let signature = p256_ecdsa_sign_sha256(signing_key, &signed_content)
        .map_err(TlsServerHandshakeError::Signing)?;

    let signature = encode_tls_p256_signature_der(signature);

    let mut body = Vec::with_capacity(4 + signature.len());

    body.extend_from_slice(&TLS_SIGNATURE_ECDSA_SECP256R1_SHA256.to_be_bytes());

    body.extend_from_slice(
        &u16::try_from(signature.len())
            .expect("P-256 ECDSA DER signature must fit in uint16")
            .to_be_bytes(),
    );

    body.extend_from_slice(&signature);

    encode_handshake_message(HANDSHAKE_TYPE_CERTIFICATE_VERIFY, &body)
}

fn tls13_server_certificate_verify_content(
    transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Vec<u8> {
    let mut content = Vec::with_capacity(
        64 + TLS_SERVER_CERTIFICATE_VERIFY_CONTEXT.len() + 1 + transcript_hash.len(),
    );

    content.extend_from_slice(&[0x20_u8; 64]);
    content.extend_from_slice(TLS_SERVER_CERTIFICATE_VERIFY_CONTEXT);
    content.push(0);
    content.extend_from_slice(transcript_hash);

    content
}

fn encode_tls_p256_signature_der(signature: P256Signature) -> Vec<u8> {
    let (r, s) = signature.components();

    der_sequence(&[
        der_integer_unsigned(&r.to_be_bytes()),
        der_integer_unsigned(&s.to_be_bytes()),
    ])
}

fn build_tls13_finished(
    handshake_traffic_secret: &[u8; TLS_SHA256_HASH_SIZE],
    transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    let verify_data = tls13_finished_verify_data(handshake_traffic_secret, transcript_hash)?;

    encode_handshake_message(HANDSHAKE_TYPE_FINISHED, &verify_data)
}

fn tls13_finished_verify_data(
    handshake_traffic_secret: &[u8; TLS_SHA256_HASH_SIZE],
    transcript_hash: &[u8; TLS_SHA256_HASH_SIZE],
) -> Result<[u8; TLS_SHA256_HASH_SIZE], HkdfError> {
    let finished_key = SecretArray(tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
        handshake_traffic_secret,
        "finished",
        &[],
    )?);

    Ok(hmac_sha256(&finished_key.0, transcript_hash))
}

fn decrypt_tls13_client_finished(
    record_protection: &mut Tls13RecordProtection,
    records: &[TlsCiphertextRecord],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    if records.is_empty() {
        return Err(TlsServerHandshakeError::InvalidClientFinished);
    }

    let mut message = Vec::new();

    for record in records {
        let plaintext = record_protection.decrypt_record(record)?;

        if plaintext.content_type() != ContentType::Handshake {
            return Err(
                TlsServerHandshakeError::UnexpectedClientFinishedContentType {
                    content_type: plaintext.content_type(),
                },
            );
        }

        message.extend_from_slice(plaintext.fragment());

        if message.len() > HANDSHAKE_HEADER_SIZE + TLS_SHA256_HASH_SIZE {
            return Err(TlsServerHandshakeError::InvalidClientFinished);
        }
    }

    if message.len() != HANDSHAKE_HEADER_SIZE + TLS_SHA256_HASH_SIZE
        || message[0] != HANDSHAKE_TYPE_FINISHED
    {
        return Err(TlsServerHandshakeError::InvalidClientFinished);
    }

    let declared_length =
        (usize::from(message[1]) << 16) | (usize::from(message[2]) << 8) | usize::from(message[3]);

    if declared_length != TLS_SHA256_HASH_SIZE {
        return Err(TlsServerHandshakeError::InvalidClientFinished);
    }

    Ok(message)
}

fn encrypt_handshake_message_records(
    record_protection: &mut Tls13RecordProtection,
    message: &[u8],
) -> Result<Vec<TlsCiphertextRecord>, TlsServerHandshakeError> {
    let mut records = Vec::new();

    for fragment in message.chunks(TLS_PLAINTEXT_FRAGMENT_LIMIT) {
        let plaintext = TlsPlaintextRecord::new(ContentType::Handshake, fragment.to_vec())?;

        records.push(record_protection.encrypt_record(&plaintext, 0)?);
    }

    Ok(records)
}

fn append_uint24(output: &mut Vec<u8>, value: usize) {
    debug_assert!(value <= TLS_UINT24_MAX);

    output.extend_from_slice(&[
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]);
}

fn generate_ephemeral_p256_private_key() -> io::Result<Scalar> {
    let mut candidate_bytes = [0_u8; 32];

    loop {
        fill_random(&mut candidate_bytes)?;

        let candidate = Uint256::from_be_bytes(candidate_bytes);

        wipe_bytes(&mut candidate_bytes);

        if candidate != Uint256::ZERO && candidate < P256_GROUP_ORDER {
            return Ok(Scalar::new(candidate));
        }
    }
}

fn build_tls13_encrypted_extensions(
    client_hello: &ClientHello,
) -> Result<(Vec<u8>, Option<Vec<u8>>), TlsServerHandshakeError> {
    let mut extensions = Vec::new();

    let negotiated_alpn = if client_hello.offers_http11() {
        let mut protocol_name_list = vec![
            u8::try_from(ALPN_HTTP_1_1.len())
                .expect("HTTP/1.1 ALPN protocol identifier must fit in uint8"),
        ];

        protocol_name_list.extend_from_slice(ALPN_HTTP_1_1);

        let mut alpn_data = Vec::with_capacity(2 + protocol_name_list.len());

        alpn_data.extend_from_slice(
            &u16::try_from(protocol_name_list.len())
                .expect("HTTP/1.1 ALPN protocol list must fit in uint16")
                .to_be_bytes(),
        );
        alpn_data.extend_from_slice(&protocol_name_list);

        append_tls_extension(
            &mut extensions,
            EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            &alpn_data,
        );

        Some(ALPN_HTTP_1_1.to_vec())
    } else if client_hello.alpn_protocols().is_empty() {
        None
    } else {
        return Err(TlsServerHandshakeError::NoApplicationProtocol);
    };

    let mut body = Vec::with_capacity(2 + extensions.len());

    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("TLS EncryptedExtensions block must fit in uint16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    let message = encode_handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &body)?;

    Ok((message, negotiated_alpn))
}

fn build_tls13_server_hello(
    client_hello: &ClientHello,
    random: &[u8; 32],
    server_key_share: &[u8; 65],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    let mut extensions = Vec::new();

    append_tls_extension(
        &mut extensions,
        EXTENSION_SUPPORTED_VERSIONS,
        &TLS_VERSION_1_3.to_be_bytes(),
    );

    let mut key_share_extension = Vec::with_capacity(69);

    key_share_extension.extend_from_slice(&TLS_GROUP_SECP256R1.to_be_bytes());
    key_share_extension.extend_from_slice(&(server_key_share.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(server_key_share);

    append_tls_extension(&mut extensions, EXTENSION_KEY_SHARE, &key_share_extension);

    let mut body = Vec::with_capacity(
        2 + random.len() + 1 + client_hello.legacy_session_id.len() + 2 + 1 + 2 + extensions.len(),
    );

    body.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
    body.extend_from_slice(random);

    body.push(
        u8::try_from(client_hello.legacy_session_id.len())
            .expect("validated TLS legacy session ID must fit in uint8"),
    );
    body.extend_from_slice(&client_hello.legacy_session_id);

    body.extend_from_slice(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.push(0);

    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("TLS 1.3 ServerHello extensions must fit in uint16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    encode_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body)
}

fn append_tls_extension(output: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(
        &u16::try_from(data.len())
            .expect("TLS extension data must fit in uint16")
            .to_be_bytes(),
    );
    output.extend_from_slice(data);
}

fn encode_handshake_message(
    message_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, TlsServerHandshakeError> {
    if body.len() > TLS_UINT24_MAX {
        return Err(TlsServerHandshakeError::HandshakeMessageTooLong { length: body.len() });
    }

    let body_length = body.len();

    let mut message = Vec::with_capacity(HANDSHAKE_HEADER_SIZE + body_length);

    message.extend_from_slice(&[
        message_type,
        ((body_length >> 16) & 0xff) as u8,
        ((body_length >> 8) & 0xff) as u8,
        (body_length & 0xff) as u8,
    ]);
    message.extend_from_slice(body);

    Ok(message)
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

    #[cfg(test)]
    fn read_u24(&mut self) -> Result<usize, TlsHandshakeError> {
        let bytes = self.read_exact(3)?;

        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
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

    #[cfg(test)]
    fn read_vector_u24(&mut self, field: &'static str) -> Result<&'a [u8], TlsHandshakeError> {
        let length = self.read_u24()?;

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

    fn test_alpn_extension(protocols: &[&[u8]]) -> Vec<u8> {
        let mut encoded_protocols = Vec::new();

        for protocol in protocols {
            assert!(!protocol.is_empty());

            encoded_protocols.push(
                u8::try_from(protocol.len())
                    .expect("test ALPN protocol identifier must fit in uint8"),
            );
            encoded_protocols.extend_from_slice(protocol);
        }

        let mut data = Vec::new();

        data.extend_from_slice(
            &u16::try_from(encoded_protocols.len())
                .expect("test ALPN protocol list must fit in uint16")
                .to_be_bytes(),
        );
        data.extend_from_slice(&encoded_protocols);

        test_extension(EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &data)
    }

    fn test_hex32(input: &str) -> [u8; 32] {
        crate::crypto::decode_hex(input)
            .expect("test hex should decode")
            .try_into()
            .expect("test value should contain 32 bytes")
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

        let mut message = vec![
            HANDSHAKE_TYPE_CLIENT_HELLO,
            ((body_length >> 16) & 0xff) as u8,
            ((body_length >> 8) & 0xff) as u8,
            (body_length & 0xff) as u8,
        ];

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

    fn p256_negotiation_client_hello(client_private_key: Scalar, cipher_suites: &[u16]) -> Vec<u8> {
        let client_public_key = p256_generator_multiply(client_private_key)
            .to_sec1_uncompressed()
            .expect("test P-256 public key should encode");

        let extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_alpn_extension(&[&b"h2"[..], &b"http/1.1"[..]]),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(TLS_GROUP_SECP256R1, &client_public_key),
        ];

        test_client_hello(TLS_LEGACY_RECORD_VERSION, &[0], cipher_suites, &extensions)
    }

    fn p256_retry_client_hellos(second_private_key: Scalar) -> (Vec<u8>, Vec<u8>) {
        const X25519: u16 = 0x001d;

        let second_public_key = p256_generator_multiply(second_private_key)
            .to_sec1_uncompressed()
            .expect("retry P-256 public key should encode");

        let first_extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1, X25519]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_alpn_extension(&[&b"h2"[..], &b"http/1.1"[..]]),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(X25519, &[0x22_u8; 32]),
        ];

        let second_extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1, X25519]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_alpn_extension(&[&b"h2"[..], &b"http/1.1"[..]]),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(TLS_GROUP_SECP256R1, &second_public_key),
        ];

        (
            test_client_hello(
                TLS_LEGACY_RECORD_VERSION,
                &[0],
                &[TLS_CHACHA20_POLY1305_SHA256],
                &first_extensions,
            ),
            test_client_hello(
                TLS_LEGACY_RECORD_VERSION,
                &[0],
                &[TLS_CHACHA20_POLY1305_SHA256],
                &second_extensions,
            ),
        )
    }

    fn decrypt_handshake_records(
        record_protection: &mut Tls13RecordProtection,
        records: &[TlsCiphertextRecord],
    ) -> Vec<u8> {
        let mut message = Vec::new();

        for record in records {
            let plaintext = record_protection
                .decrypt_record(record)
                .expect("test handshake record should decrypt");

            assert_eq!(plaintext.content_type(), ContentType::Handshake);

            message.extend_from_slice(plaintext.fragment());
        }

        message
    }

    fn authenticated_test_handshake() -> (Tls13ServerHelloFlight, Tls13RecordProtection) {
        let client_private_key = Scalar::new(Uint256::from_limbs([12, 0, 0, 0]));

        let client_hello =
            p256_negotiation_client_hello(client_private_key, &[TLS_CHACHA20_POLY1305_SHA256]);

        let signing_key = Scalar::new(Uint256::from_limbs([13, 0, 0, 0]));

        let certificate_chain = vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]];

        let mut flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 handshake start should succeed");

        let (client_key, client_iv) =
            derive_tls13_traffic_key_iv(&flight.client_handshake_traffic_secret)
                .expect("client handshake traffic key should derive");

        let (server_key, server_iv) =
            derive_tls13_traffic_key_iv(&flight.server_handshake_traffic_secret)
                .expect("server handshake traffic key should derive");

        let mut client_record_protection =
            Tls13RecordProtection::new(client_key, client_iv, server_key, server_iv);

        client_record_protection
            .decrypt_record(flight.encrypted_extensions_record())
            .expect("client should decrypt EncryptedExtensions");

        let authentication = flight
            .authenticate_server(&certificate_chain, signing_key)
            .expect("server authentication flight should succeed");

        decrypt_handshake_records(
            &mut client_record_protection,
            authentication.certificate_records(),
        );

        decrypt_handshake_records(
            &mut client_record_protection,
            authentication.certificate_verify_records(),
        );

        decrypt_handshake_records(
            &mut client_record_protection,
            authentication.finished_records(),
        );

        (flight, client_record_protection)
    }

    fn completed_application_test_states() -> (Tls13ApplicationState, Tls13RecordProtection) {
        let (flight, mut client_handshake_record_protection) = authenticated_test_handshake();

        let server_finished_transcript_hash = flight.transcript_hash();

        let application_schedule = derive_tls13_application_key_schedule(
            &flight.main_secret,
            &server_finished_transcript_hash,
        )
        .expect("application traffic secrets should derive");

        let client_finished = build_tls13_finished(
            &flight.client_handshake_traffic_secret,
            &server_finished_transcript_hash,
        )
        .expect("client Finished should build");

        let client_finished_plaintext =
            TlsPlaintextRecord::new(ContentType::Handshake, client_finished)
                .expect("client Finished plaintext should be valid");

        let client_finished_record = client_handshake_record_protection
            .encrypt_record(&client_finished_plaintext, 0)
            .expect("client Finished should encrypt");

        let application_state = flight
            .complete_handshake(&[client_finished_record])
            .expect("client Finished should complete the handshake");

        let client_application_record_protection = Tls13RecordProtection::new(
            application_schedule.client_key,
            application_schedule.client_iv,
            application_schedule.server_key,
            application_schedule.server_iv,
        );

        (application_state, client_application_record_protection)
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

    #[test]
    fn server_hello_negotiates_p256_and_matches_client_ecdh() {
        let client_private_key = Scalar::new(Uint256::from_limbs([2, 0, 0, 0]));

        let client_hello = p256_negotiation_client_hello(
            client_private_key,
            &[0x1301, TLS_CHACHA20_POLY1305_SHA256],
        );

        let flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 ServerHello negotiation should succeed");

        let server_hello = flight.server_hello();

        assert_eq!(server_hello[0], HANDSHAKE_TYPE_SERVER_HELLO);

        let declared_length = (usize::from(server_hello[1]) << 16)
            | (usize::from(server_hello[2]) << 8)
            | usize::from(server_hello[3]);

        assert_eq!(declared_length, server_hello.len() - HANDSHAKE_HEADER_SIZE);

        let mut body = HandshakeReader::new(&server_hello[HANDSHAKE_HEADER_SIZE..]);

        assert_eq!(
            body.read_u16().expect("legacy version should parse"),
            TLS_LEGACY_RECORD_VERSION
        );

        body.read_exact(32).expect("server random should exist");

        assert!(
            body.read_vector_u8("legacy_session_id_echo")
                .expect("session ID echo should parse")
                .is_empty()
        );

        assert_eq!(
            body.read_u16().expect("cipher suite should parse"),
            TLS_CHACHA20_POLY1305_SHA256
        );

        assert_eq!(body.read_u8().expect("compression method should parse"), 0);

        let extensions = body
            .read_vector_u16("ServerHello extensions")
            .expect("ServerHello extensions should parse");

        body.finish("ServerHello")
            .expect("ServerHello should end cleanly");

        let mut extensions = HandshakeReader::new(extensions);

        assert_eq!(
            extensions
                .read_u16()
                .expect("supported_versions type should parse"),
            EXTENSION_SUPPORTED_VERSIONS
        );

        assert_eq!(
            extensions
                .read_vector_u16("supported_versions")
                .expect("supported_versions data should parse"),
            TLS_VERSION_1_3.to_be_bytes()
        );

        assert_eq!(
            extensions.read_u16().expect("key_share type should parse"),
            EXTENSION_KEY_SHARE
        );

        let key_share = extensions
            .read_vector_u16("key_share")
            .expect("key_share data should parse");

        extensions
            .finish("ServerHello extensions")
            .expect("extension block should end cleanly");

        let mut key_share = HandshakeReader::new(key_share);

        assert_eq!(
            key_share.read_u16().expect("server group should parse"),
            TLS_GROUP_SECP256R1
        );

        assert_eq!(
            key_share
                .read_vector_u16("server key exchange")
                .expect("server key exchange should parse"),
            flight.server_key_share()
        );

        key_share
            .finish("server key share")
            .expect("server key share should end cleanly");

        let server_public_key = P256Point::from_sec1_uncompressed(flight.server_key_share())
            .expect("server P-256 key share should be valid");

        let client_shared_secret = p256_ecdh(client_private_key, server_public_key)
            .expect("client-side ECDH should succeed");

        let mut hello_transcript_bytes = client_hello.clone();
        hello_transcript_bytes.extend_from_slice(server_hello);

        let hello_transcript_hash = crate::crypto::sha256(&hello_transcript_bytes);

        let client_key_schedule =
            derive_tls13_handshake_key_schedule(&client_shared_secret, &hello_transcript_hash)
                .expect("client-side TLS key schedule should succeed");

        assert_eq!(
            client_key_schedule.client_handshake_traffic_secret,
            flight.client_handshake_traffic_secret
        );

        assert_eq!(
            client_key_schedule.server_handshake_traffic_secret,
            flight.server_handshake_traffic_secret
        );

        assert_eq!(client_key_schedule.main_secret, flight.main_secret);

        hello_transcript_bytes.extend_from_slice(flight.encrypted_extensions());

        assert_eq!(
            flight.transcript_hash(),
            crate::crypto::sha256(&hello_transcript_bytes)
        );
    }

    #[test]
    fn server_hello_rejects_invalid_p256_client_share() {
        let extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(TLS_GROUP_SECP256R1, &[0x04_u8; 64]),
        ];

        let client_hello = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert!(matches!(
            negotiate_tls13_server_hello(&client_hello),
            Err(TlsServerHandshakeError::InvalidP256KeyShare(
                P256PointError::InvalidEncodingLength { length: 64 }
            ))
        ));
    }

    #[test]
    fn server_hello_rejects_unsupported_cipher_suite_cleanly() {
        let client_private_key = Scalar::new(Uint256::from_limbs([3, 0, 0, 0]));

        let client_hello = p256_negotiation_client_hello(client_private_key, &[0x1301]);

        assert!(matches!(
            negotiate_tls13_server_hello(&client_hello),
            Err(TlsServerHandshakeError::UnsupportedCipherSuite)
        ));
    }

    #[test]
    fn server_hello_rejects_unsupported_group_cleanly() {
        const X25519: u16 = 0x001d;

        let extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[X25519]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(X25519, &[0x11_u8; 32]),
        ];

        let client_hello = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert!(matches!(
            negotiate_tls13_server_hello(&client_hello),
            Err(TlsServerHandshakeError::UnsupportedGroup)
        ));
    }

    #[test]
    fn server_hello_requests_retry_when_p256_has_no_client_share() {
        const X25519: u16 = 0x001d;

        let extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1, X25519]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(X25519, &[0x22_u8; 32]),
        ];

        let client_hello = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert!(matches!(
            negotiate_tls13_server_hello(&client_hello),
            Err(TlsServerHandshakeError::HelloRetryRequired {
                group: TLS_GROUP_SECP256R1,
            })
        ));
    }

    #[test]
    fn hello_retry_request_selects_p256_and_rewrites_transcript() {
        let second_private_key = Scalar::new(Uint256::from_limbs([15, 0, 0, 0]));

        let (client_hello1, client_hello2) = p256_retry_client_hellos(second_private_key);

        let first_flight = negotiate_tls13_server_first_flight(&client_hello1)
            .expect("initial ClientHello should negotiate");

        let retry = match first_flight {
            Tls13ServerFirstFlight::HelloRetry(retry) => retry,
            Tls13ServerFirstFlight::ServerHello(_) => {
                panic!("initial ClientHello should require HelloRetryRequest")
            }
        };

        assert_eq!(retry.selected_group(), TLS_GROUP_SECP256R1);

        let hello_retry_request = retry.hello_retry_request().to_vec();

        assert_eq!(hello_retry_request[0], HANDSHAKE_TYPE_SERVER_HELLO);

        let mut body = HandshakeReader::new(&hello_retry_request[HANDSHAKE_HEADER_SIZE..]);

        assert_eq!(
            body.read_u16().expect("HRR legacy version should parse"),
            TLS_LEGACY_RECORD_VERSION
        );

        assert_eq!(
            body.read_exact(32).expect("HRR random should exist"),
            &TLS13_HELLO_RETRY_REQUEST_RANDOM
        );

        assert!(
            body.read_vector_u8("legacy_session_id_echo")
                .expect("HRR session ID should parse")
                .is_empty()
        );

        assert_eq!(
            body.read_u16().expect("HRR cipher suite should parse"),
            TLS_CHACHA20_POLY1305_SHA256
        );

        assert_eq!(
            body.read_u8().expect("HRR compression method should parse"),
            0
        );

        let extension_block = body
            .read_vector_u16("HelloRetryRequest extensions")
            .expect("HRR extensions should parse");

        body.finish("HelloRetryRequest")
            .expect("HRR body should end cleanly");

        let mut extensions = HandshakeReader::new(extension_block);

        assert_eq!(
            extensions
                .read_u16()
                .expect("supported_versions extension should parse"),
            EXTENSION_SUPPORTED_VERSIONS
        );

        assert_eq!(
            extensions
                .read_vector_u16("supported_versions")
                .expect("supported_versions data should parse"),
            TLS_VERSION_1_3.to_be_bytes()
        );

        assert_eq!(
            extensions
                .read_u16()
                .expect("HRR key_share extension should parse"),
            EXTENSION_KEY_SHARE
        );

        assert_eq!(
            extensions
                .read_vector_u16("HRR key_share")
                .expect("HRR selected group should parse"),
            TLS_GROUP_SECP256R1.to_be_bytes()
        );

        extensions
            .finish("HelloRetryRequest extensions")
            .expect("HRR should contain only the required extensions");

        let flight = retry
            .continue_with_client_hello(&client_hello2)
            .expect("valid retry ClientHello should continue the handshake");

        let client_hello1_hash = sha256(&client_hello1);

        let message_hash =
            encode_handshake_message(HANDSHAKE_TYPE_MESSAGE_HASH, &client_hello1_hash)
                .expect("synthetic message_hash should encode");

        let mut expected_transcript = message_hash;

        expected_transcript.extend_from_slice(&hello_retry_request);
        expected_transcript.extend_from_slice(&client_hello2);
        expected_transcript.extend_from_slice(flight.server_hello());
        expected_transcript.extend_from_slice(flight.encrypted_extensions());

        assert_eq!(flight.transcript_hash(), sha256(&expected_transcript));
    }

    #[test]
    fn hello_retry_rejects_modified_client_hello2() {
        let second_private_key = Scalar::new(Uint256::from_limbs([16, 0, 0, 0]));

        let (client_hello1, mut client_hello2) = p256_retry_client_hellos(second_private_key);

        let first_flight = negotiate_tls13_server_first_flight(&client_hello1)
            .expect("initial ClientHello should negotiate");

        let retry = match first_flight {
            Tls13ServerFirstFlight::HelloRetry(retry) => retry,
            Tls13ServerFirstFlight::ServerHello(_) => {
                panic!("initial ClientHello should require HelloRetryRequest")
            }
        };

        client_hello2[HANDSHAKE_HEADER_SIZE + 2] ^= 0x01;

        assert!(matches!(
            retry.continue_with_client_hello(&client_hello2),
            Err(TlsServerHandshakeError::InvalidRetryClientHello)
        ));
    }

    #[test]
    fn hello_retry_requires_exactly_one_requested_p256_share() {
        let second_private_key = Scalar::new(Uint256::from_limbs([17, 0, 0, 0]));

        let (client_hello1, _) = p256_retry_client_hellos(second_private_key);

        let first_flight = negotiate_tls13_server_first_flight(&client_hello1)
            .expect("initial ClientHello should negotiate");

        let retry = match first_flight {
            Tls13ServerFirstFlight::HelloRetry(retry) => retry,
            Tls13ServerFirstFlight::ServerHello(_) => {
                panic!("initial ClientHello should require HelloRetryRequest")
            }
        };

        assert!(matches!(
            retry.continue_with_client_hello(&client_hello1),
            Err(TlsServerHandshakeError::InvalidRetryKeyShare)
        ));
    }

    #[test]
    fn tls13_handshake_key_schedule_matches_rfc8448_trace() {
        let shared_secret =
            test_hex32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

        let hello_transcript_hash =
            test_hex32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

        let schedule = derive_tls13_handshake_key_schedule(&shared_secret, &hello_transcript_hash)
            .expect("RFC 8448 key schedule should derive");

        assert_eq!(
            schedule.client_handshake_traffic_secret,
            test_hex32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );

        assert_eq!(
            schedule.server_handshake_traffic_secret,
            test_hex32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );

        assert_eq!(
            schedule.main_secret,
            test_hex32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
    }

    #[test]
    fn encrypted_extensions_selects_and_encrypts_http11_alpn() {
        let client_private_key = Scalar::new(Uint256::from_limbs([5, 0, 0, 0]));

        let client_hello =
            p256_negotiation_client_hello(client_private_key, &[TLS_CHACHA20_POLY1305_SHA256]);

        let flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 handshake start should succeed");

        assert_eq!(flight.negotiated_alpn(), Some(ALPN_HTTP_1_1));

        let (client_key, client_iv) =
            derive_tls13_traffic_key_iv(&flight.client_handshake_traffic_secret)
                .expect("client handshake traffic key should derive");

        let (server_key, server_iv) =
            derive_tls13_traffic_key_iv(&flight.server_handshake_traffic_secret)
                .expect("server handshake traffic key should derive");

        let mut client_record_protection =
            Tls13RecordProtection::new(client_key, client_iv, server_key, server_iv);

        let decrypted = client_record_protection
            .decrypt_record(flight.encrypted_extensions_record())
            .expect("client should decrypt server EncryptedExtensions");

        assert_eq!(decrypted.content_type(), ContentType::Handshake);
        assert_eq!(decrypted.fragment(), flight.encrypted_extensions());
        assert_eq!(client_record_protection.read_sequence_number(), Some(1));

        let message = decrypted.fragment();

        assert_eq!(message[0], HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);

        let declared_length = (usize::from(message[1]) << 16)
            | (usize::from(message[2]) << 8)
            | usize::from(message[3]);

        assert_eq!(declared_length, message.len() - HANDSHAKE_HEADER_SIZE);

        let mut body = HandshakeReader::new(&message[HANDSHAKE_HEADER_SIZE..]);

        let extension_block = body
            .read_vector_u16("EncryptedExtensions")
            .expect("EncryptedExtensions block should parse");

        body.finish("EncryptedExtensions")
            .expect("EncryptedExtensions should end cleanly");

        let mut extensions = HandshakeReader::new(extension_block);

        assert_eq!(
            extensions.read_u16().expect("ALPN extension should parse"),
            EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );

        let alpn_data = extensions
            .read_vector_u16("ALPN extension data")
            .expect("ALPN extension data should parse");

        extensions
            .finish("EncryptedExtensions extensions")
            .expect("extension list should end cleanly");

        let mut alpn = HandshakeReader::new(alpn_data);

        let protocol_list = alpn
            .read_vector_u16("ALPN protocol list")
            .expect("ALPN protocol list should parse");

        alpn.finish("ALPN")
            .expect("ALPN extension should end cleanly");

        let mut protocols = HandshakeReader::new(protocol_list);

        assert_eq!(
            protocols
                .read_vector_u8("ALPN selected protocol")
                .expect("selected ALPN protocol should parse"),
            ALPN_HTTP_1_1
        );

        protocols
            .finish("ALPN selected protocol list")
            .expect("ALPN should contain exactly one selected protocol");
    }

    #[test]
    fn server_authentication_builds_signs_finishes_and_encrypts() {
        let client_private_key = Scalar::new(Uint256::from_limbs([6, 0, 0, 0]));

        let client_hello =
            p256_negotiation_client_hello(client_private_key, &[TLS_CHACHA20_POLY1305_SHA256]);

        let signing_key = Scalar::new(Uint256::from_limbs([7, 0, 0, 0]));

        let certificate_chain = vec![
            vec![0x30, 0x03, 0x02, 0x01, 0x01],
            vec![0x30, 0x03, 0x02, 0x01, 0x02],
        ];

        let mut flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 handshake start should succeed");

        let (client_key, client_iv) =
            derive_tls13_traffic_key_iv(&flight.client_handshake_traffic_secret)
                .expect("client handshake traffic key should derive");

        let (server_key, server_iv) =
            derive_tls13_traffic_key_iv(&flight.server_handshake_traffic_secret)
                .expect("server handshake traffic key should derive");

        let mut client_record_protection =
            Tls13RecordProtection::new(client_key, client_iv, server_key, server_iv);

        let decrypted_extensions = client_record_protection
            .decrypt_record(flight.encrypted_extensions_record())
            .expect("client should decrypt EncryptedExtensions");

        assert_eq!(
            decrypted_extensions.fragment(),
            flight.encrypted_extensions()
        );

        let authentication = flight
            .authenticate_server(&certificate_chain, signing_key)
            .expect("server authentication flight should succeed");

        let certificate = decrypt_handshake_records(
            &mut client_record_protection,
            authentication.certificate_records(),
        );

        let certificate_verify = decrypt_handshake_records(
            &mut client_record_protection,
            authentication.certificate_verify_records(),
        );

        let finished = decrypt_handshake_records(
            &mut client_record_protection,
            authentication.finished_records(),
        );

        assert_eq!(certificate, authentication.certificate());
        assert_eq!(certificate_verify, authentication.certificate_verify());
        assert_eq!(finished, authentication.finished());

        assert_eq!(certificate[0], HANDSHAKE_TYPE_CERTIFICATE);
        assert_eq!(certificate_verify[0], HANDSHAKE_TYPE_CERTIFICATE_VERIFY);
        assert_eq!(finished[0], HANDSHAKE_TYPE_FINISHED);

        let mut certificate_body = HandshakeReader::new(&certificate[HANDSHAKE_HEADER_SIZE..]);

        assert!(
            certificate_body
                .read_vector_u8("certificate_request_context")
                .expect("certificate request context should parse")
                .is_empty()
        );

        let encoded_certificate_list = certificate_body
            .read_vector_u24("certificate_list")
            .expect("certificate list should parse");

        certificate_body
            .finish("Certificate")
            .expect("Certificate should end cleanly");

        let mut certificates = HandshakeReader::new(encoded_certificate_list);

        for expected_certificate in &certificate_chain {
            assert_eq!(
                certificates
                    .read_vector_u24("cert_data")
                    .expect("certificate DER should parse"),
                expected_certificate
            );

            assert!(
                certificates
                    .read_vector_u16("certificate extensions")
                    .expect("certificate extensions should parse")
                    .is_empty()
            );
        }

        certificates
            .finish("certificate_list")
            .expect("certificate list should contain exactly the supplied chain");

        let mut transcript_before_certificate_verify = client_hello.clone();

        transcript_before_certificate_verify.extend_from_slice(flight.server_hello());
        transcript_before_certificate_verify.extend_from_slice(flight.encrypted_extensions());
        transcript_before_certificate_verify.extend_from_slice(&certificate);

        let certificate_transcript_hash =
            crate::crypto::sha256(&transcript_before_certificate_verify);

        let expected_signature = p256_ecdsa_sign_sha256(
            signing_key,
            &tls13_server_certificate_verify_content(&certificate_transcript_hash),
        )
        .expect("expected CertificateVerify signature should succeed");

        let expected_signature = encode_tls_p256_signature_der(expected_signature);

        let mut certificate_verify_body =
            HandshakeReader::new(&certificate_verify[HANDSHAKE_HEADER_SIZE..]);

        assert_eq!(
            certificate_verify_body
                .read_u16()
                .expect("CertificateVerify algorithm should parse"),
            TLS_SIGNATURE_ECDSA_SECP256R1_SHA256
        );

        assert_eq!(
            certificate_verify_body
                .read_vector_u16("CertificateVerify signature")
                .expect("CertificateVerify signature should parse"),
            expected_signature
        );

        certificate_verify_body
            .finish("CertificateVerify")
            .expect("CertificateVerify should end cleanly");

        transcript_before_certificate_verify.extend_from_slice(&certificate_verify);

        let transcript_before_finished =
            crate::crypto::sha256(&transcript_before_certificate_verify);

        let finished_key = tls13_expand_label_array::<TLS_SHA256_HASH_SIZE>(
            &flight.server_handshake_traffic_secret,
            "finished",
            &[],
        )
        .expect("server Finished key should derive");

        let expected_verify_data = hmac_sha256(&finished_key, &transcript_before_finished);

        assert_eq!(
            &finished[HANDSHAKE_HEADER_SIZE..],
            expected_verify_data.as_slice()
        );

        transcript_before_certificate_verify.extend_from_slice(&finished);

        assert_eq!(
            flight.transcript_hash(),
            crate::crypto::sha256(&transcript_before_certificate_verify)
        );

        assert_eq!(client_record_protection.read_sequence_number(), Some(4));

        assert_eq!(
            flight.handshake_record_protection.write_sequence_number(),
            Some(4)
        );
    }

    #[test]
    fn large_certificate_message_is_fragmented_across_encrypted_records() {
        let client_private_key = Scalar::new(Uint256::from_limbs([8, 0, 0, 0]));

        let client_hello =
            p256_negotiation_client_hello(client_private_key, &[TLS_CHACHA20_POLY1305_SHA256]);

        let signing_key = Scalar::new(Uint256::from_limbs([9, 0, 0, 0]));

        let large_certificate = vec![0x42_u8; TLS_PLAINTEXT_FRAGMENT_LIMIT + 128];

        let mut flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 handshake start should succeed");

        let (client_key, client_iv) =
            derive_tls13_traffic_key_iv(&flight.client_handshake_traffic_secret)
                .expect("client handshake traffic key should derive");

        let (server_key, server_iv) =
            derive_tls13_traffic_key_iv(&flight.server_handshake_traffic_secret)
                .expect("server handshake traffic key should derive");

        let mut client_record_protection =
            Tls13RecordProtection::new(client_key, client_iv, server_key, server_iv);

        client_record_protection
            .decrypt_record(flight.encrypted_extensions_record())
            .expect("client should decrypt EncryptedExtensions");

        let authentication = flight
            .authenticate_server(&[large_certificate], signing_key)
            .expect("large certificate handshake should succeed");

        assert!(authentication.certificate_records().len() > 1);

        let reassembled_certificate = decrypt_handshake_records(
            &mut client_record_protection,
            authentication.certificate_records(),
        );

        assert_eq!(reassembled_certificate, authentication.certificate());
    }

    #[test]
    fn server_authentication_rejects_empty_certificate_chain() {
        let client_private_key = Scalar::new(Uint256::from_limbs([10, 0, 0, 0]));

        let client_hello =
            p256_negotiation_client_hello(client_private_key, &[TLS_CHACHA20_POLY1305_SHA256]);

        let mut flight = negotiate_tls13_server_hello(&client_hello)
            .expect("TLS 1.3 handshake start should succeed");

        let signing_key = Scalar::new(Uint256::from_limbs([11, 0, 0, 0]));

        assert!(matches!(
            flight.authenticate_server(&[], signing_key),
            Err(TlsServerHandshakeError::EmptyCertificateChain)
        ));
    }

    #[test]
    fn tls13_application_traffic_secrets_match_rfc8448_trace() {
        let main_secret =
            test_hex32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");

        let server_finished_transcript_hash =
            test_hex32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

        let schedule =
            derive_tls13_application_key_schedule(&main_secret, &server_finished_transcript_hash)
                .expect("RFC 8448 application key schedule should derive");

        assert_eq!(
            schedule.client_application_traffic_secret,
            test_hex32("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );

        assert_eq!(
            schedule.server_application_traffic_secret,
            test_hex32("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );
    }

    #[test]
    fn client_finished_completes_handshake_and_switches_to_application_keys() {
        let (flight, mut client_handshake_record_protection) = authenticated_test_handshake();

        let server_finished_transcript_hash = flight.transcript_hash();

        let expected_application_schedule = derive_tls13_application_key_schedule(
            &flight.main_secret,
            &server_finished_transcript_hash,
        )
        .expect("application traffic secrets should derive");

        let client_finished = build_tls13_finished(
            &flight.client_handshake_traffic_secret,
            &server_finished_transcript_hash,
        )
        .expect("client Finished should build");

        let client_finished_plaintext =
            TlsPlaintextRecord::new(ContentType::Handshake, client_finished)
                .expect("client Finished plaintext should be valid");

        let client_finished_record = client_handshake_record_protection
            .encrypt_record(&client_finished_plaintext, 0)
            .expect("client Finished should encrypt");

        let mut application_state = flight
            .complete_handshake(&[client_finished_record])
            .expect("valid client Finished should complete the handshake");

        assert_eq!(
            application_state.client_application_traffic_secret,
            expected_application_schedule.client_application_traffic_secret
        );

        assert_eq!(
            application_state.server_application_traffic_secret,
            expected_application_schedule.server_application_traffic_secret
        );

        assert_eq!(application_state.negotiated_alpn(), Some(ALPN_HTTP_1_1));

        let mut client_application_record_protection = Tls13RecordProtection::new(
            expected_application_schedule.client_key,
            expected_application_schedule.client_iv,
            expected_application_schedule.server_key,
            expected_application_schedule.server_iv,
        );

        let server_application_record = application_state
            .encrypt_application_data_record(b"hello client")
            .expect("server application data should encrypt");

        let server_application_plaintext = client_application_record_protection
            .decrypt_record(&server_application_record)
            .expect("client should decrypt server application data");

        assert_eq!(
            server_application_plaintext.content_type(),
            ContentType::ApplicationData
        );

        assert_eq!(server_application_plaintext.fragment(), b"hello client");

        let client_application_plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"hello server".to_vec())
                .expect("client application plaintext should be valid");

        let client_application_record = client_application_record_protection
            .encrypt_record(&client_application_plaintext, 0)
            .expect("client application data should encrypt");

        let client_application_plaintext = application_state
            .decrypt_protected_record(&client_application_record)
            .expect("server should decrypt client application data");

        assert_eq!(
            client_application_plaintext.content_type(),
            ContentType::ApplicationData
        );

        assert_eq!(client_application_plaintext.fragment(), b"hello server");

        assert_eq!(
            application_state.record_protection.write_sequence_number(),
            Some(1)
        );

        assert_eq!(
            application_state.record_protection.read_sequence_number(),
            Some(1)
        );

        assert_eq!(
            client_application_record_protection.write_sequence_number(),
            Some(1)
        );

        assert_eq!(
            client_application_record_protection.read_sequence_number(),
            Some(1)
        );
    }

    #[test]
    fn incorrect_client_finished_is_rejected() {
        let (flight, mut client_handshake_record_protection) = authenticated_test_handshake();

        let server_finished_transcript_hash = flight.transcript_hash();

        let mut client_finished = build_tls13_finished(
            &flight.client_handshake_traffic_secret,
            &server_finished_transcript_hash,
        )
        .expect("client Finished should build");

        let last_index = client_finished.len() - 1;
        client_finished[last_index] ^= 0x01;

        let client_finished_plaintext =
            TlsPlaintextRecord::new(ContentType::Handshake, client_finished)
                .expect("tampered client Finished should remain structurally valid");

        let client_finished_record = client_handshake_record_protection
            .encrypt_record(&client_finished_plaintext, 0)
            .expect("tampered client Finished should still AEAD-encrypt");

        assert!(matches!(
            flight.complete_handshake(&[client_finished_record]),
            Err(TlsServerHandshakeError::ClientFinishedMismatch)
        ));
    }

    #[test]
    fn protocol_errors_select_the_expected_tls_alerts() {
        assert_eq!(
            TlsHandshakeError::MalformedVector { field: "test" }.alert_description(),
            TlsAlertDescription::DecodeError
        );

        assert_eq!(
            TlsHandshakeError::MissingRequiredExtension {
                extension_type: EXTENSION_KEY_SHARE,
            }
            .alert_description(),
            TlsAlertDescription::MissingExtension
        );

        assert_eq!(
            TlsHandshakeError::InvalidCompressionMethods.alert_description(),
            TlsAlertDescription::IllegalParameter
        );

        assert_eq!(
            TlsServerHandshakeError::UnsupportedCipherSuite.alert_description(),
            TlsAlertDescription::HandshakeFailure
        );

        assert_eq!(
            TlsServerHandshakeError::ClientFinishedMismatch.alert_description(),
            TlsAlertDescription::DecryptError
        );

        assert_eq!(
            TlsServerHandshakeError::NoApplicationProtocol.alert_description(),
            TlsAlertDescription::NoApplicationProtocol
        );

        assert_eq!(
            TlsRecordError::Aead(ChaCha20Poly1305Error::AuthenticationFailed).alert_description(),
            TlsAlertDescription::BadRecordMac
        );
    }

    #[test]
    fn explicit_incompatible_alpn_offer_is_rejected() {
        let client_private_key = Scalar::new(Uint256::from_limbs([14, 0, 0, 0]));

        let client_public_key = p256_generator_multiply(client_private_key)
            .to_sec1_uncompressed()
            .expect("test P-256 public key should encode");

        let extensions = vec![
            test_server_name_extension("example.test"),
            test_u16_list_extension(EXTENSION_SUPPORTED_GROUPS, &[TLS_GROUP_SECP256R1]),
            test_u16_list_extension(
                EXTENSION_SIGNATURE_ALGORITHMS,
                &[TLS_SIGNATURE_ECDSA_SECP256R1_SHA256],
            ),
            test_alpn_extension(&[&b"h2"[..]]),
            test_supported_versions_extension(&[TLS_VERSION_1_3]),
            test_key_share_extension(TLS_GROUP_SECP256R1, &client_public_key),
        ];

        let client_hello = test_client_hello(
            TLS_LEGACY_RECORD_VERSION,
            &[0],
            &[TLS_CHACHA20_POLY1305_SHA256],
            &extensions,
        );

        assert!(matches!(
            negotiate_tls13_server_hello(&client_hello),
            Err(TlsServerHandshakeError::NoApplicationProtocol)
        ));
    }

    #[test]
    fn close_notify_is_encrypted_and_closes_only_the_write_side() {
        let (mut server, mut client) = completed_application_test_states();

        let close_notify = server
            .encrypt_close_notify()
            .expect("server close_notify should encrypt");

        let plaintext = client
            .decrypt_record(&close_notify)
            .expect("client should decrypt close_notify");

        let alert = TlsAlert::parse(plaintext.fragment()).expect("close_notify alert should parse");

        assert_eq!(plaintext.content_type(), ContentType::Alert);
        assert_eq!(alert.level(), 1);
        assert_eq!(alert.description(), TlsAlertDescription::CloseNotify);

        assert_eq!(
            server.encrypt_application_data_record(b"too late"),
            Err(TlsRecordError::WriteAfterCloseNotify)
        );

        assert_eq!(
            server.encrypt_close_notify(),
            Err(TlsRecordError::CloseNotifyAlreadySent)
        );

        let peer_close_notify = TlsAlert::close_notify()
            .plaintext_record()
            .expect("client close_notify plaintext should be valid");

        let peer_close_notify = client
            .encrypt_record(&peer_close_notify, 0)
            .expect("client close_notify should encrypt");

        assert_eq!(
            server
                .receive_protected_record(&peer_close_notify)
                .expect("server should process peer close_notify"),
            Tls13ApplicationEvent::CloseNotify
        );

        let late_plaintext =
            TlsPlaintextRecord::new(ContentType::ApplicationData, b"ignored".to_vec())
                .expect("late application plaintext should be valid");

        let late_record = client
            .encrypt_record(&late_plaintext, 0)
            .expect("late record should still be cryptographically valid");

        assert_eq!(
            server
                .receive_protected_record(&late_record)
                .expect("data after peer close_notify should be ignored"),
            Tls13ApplicationEvent::IgnoredAfterCloseNotify
        );
    }

    #[test]
    fn received_fatal_alert_erases_application_keys() {
        let (mut server, mut client) = completed_application_test_states();

        let fatal_alert = TlsAlert::fatal(TlsAlertDescription::DecodeError)
            .expect("decode_error is a fatal alert")
            .plaintext_record()
            .expect("fatal alert plaintext should be valid");

        let fatal_alert = client
            .encrypt_record(&fatal_alert, 0)
            .expect("client fatal alert should encrypt");

        assert_eq!(
            server
                .receive_protected_record(&fatal_alert)
                .expect("server should process fatal alert"),
            Tls13ApplicationEvent::FatalAlert(TlsAlertDescription::DecodeError)
        );

        assert_eq!(
            server.encrypt_application_data_record(b"forbidden"),
            Err(TlsRecordError::ConnectionFailed)
        );

        assert_eq!(server.record_protection.write_sequence_number(), None);

        assert_eq!(server.record_protection.read_sequence_number(), None);
    }

    #[test]
    fn sent_fatal_alert_erases_application_keys_after_encryption() {
        let (mut server, mut client) = completed_application_test_states();

        let fatal_alert = server
            .encrypt_fatal_alert(TlsAlertDescription::InternalError)
            .expect("server fatal alert should encrypt");

        let plaintext = client
            .decrypt_record(&fatal_alert)
            .expect("client should decrypt server fatal alert");

        let alert = TlsAlert::parse(plaintext.fragment()).expect("server fatal alert should parse");

        assert_eq!(alert.level(), 2);
        assert_eq!(alert.description(), TlsAlertDescription::InternalError);

        assert_eq!(
            server.encrypt_application_data_record(b"forbidden"),
            Err(TlsRecordError::ConnectionFailed)
        );
    }
}
