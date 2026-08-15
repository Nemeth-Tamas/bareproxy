//! BareProxy TLS 1.3 record-layer foundation.
//!
//! The record framing implemented here follows RFC 8446 section 5.
//!
//! This module deliberately stops below the TLS handshake state machine.
//! It understands record framing, content types, fragmentation, and the
//! generic 4-byte handshake-message envelope, but not ClientHello,
//! ServerHello, certificate, or Finished message contents yet.

use std::{error::Error, fmt};

pub const TLS_RECORD_HEADER_SIZE: usize = 5;
pub const TLS_PLAINTEXT_FRAGMENT_LIMIT: usize = 1 << 14;
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0303;

const HANDSHAKE_HEADER_SIZE: usize = 4;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRecordError {
    UnknownContentType(u8),
    RecordOverflow { length: usize, maximum: usize },
    EmptyHandshakeFragment,
    InvalidAlertLength { length: usize },
    InvalidChangeCipherSpec,
    InterleavedHandshake { next_type: ContentType },
    HandshakeNotAligned { buffered_bytes: usize },
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
        }
    }
}

impl Error for TlsRecordError {}

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

        let fragment_length = self.fragment.len();
        let mut output = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + fragment_length);

        output.push(self.content_type as u8);
        output.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        output.extend_from_slice(&(fragment_length as u16).to_be_bytes());
        output.extend_from_slice(&self.fragment);

        Ok(output)
    }
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
}
