//! BareProxy cryptographic foundation.
//!
//! Implemented primitives and source specifications:
//!
//! - OS-backed secure randomness:
//!   Unix/WSL reads from `/dev/urandom`, backed by the operating-system CSPRNG.
//! - Base64 and URL-safe Base64:
//!   RFC 4648 sections 4 and 5.
//! - SHA-256:
//!   FIPS 180-4, with RFC 6234 as an implementation reference.
//! - HMAC-SHA256:
//!   RFC 2104, tested with RFC 4231 vectors.
//! - HKDF-SHA256:
//!   RFC 5869.
//! - TLS 1.3 HKDF-Expand-Label:
//!   RFC 8446 section 7.1, tested with RFC 8448 vectors.
//! - ChaCha20:
//!   RFC 8439 sections 2.1 through 2.4.
//! - Poly1305:
//!   RFC 8439 section 2.5.
//! - ChaCha20-Poly1305 AEAD:
//!   RFC 8439 sections 2.6 and 2.8.
//!
//! Secret-handling policy:
//!
//! Controlled temporary buffers containing key material or intermediate
//! secret state are kept stack-sized where practical and explicitly wiped
//! with volatile writes after use. This reduces residual secret material,
//! but cannot guarantee clearing compiler-created temporaries, CPU registers,
//! or copies made outside this module.

use std::{error::Error, fmt, io};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const BASE64_STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_LENGTH_OFFSET: usize = 56;

const HMAC_INNER_PAD_BYTE: u8 = 0x36;
const HMAC_OUTER_PAD_BYTE: u8 = 0x5c;

const SHA256_DIGEST_SIZE: usize = 32;
const HKDF_MAX_OUTPUT_SIZE: usize = 255 * SHA256_DIGEST_SIZE;

const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const TLS13_MAX_LABEL_SIZE: usize = u8::MAX as usize - TLS13_LABEL_PREFIX.len();
const TLS13_MAX_CONTEXT_SIZE: usize = u8::MAX as usize;

const CHACHA20_BLOCK_SIZE: usize = 64;
const CHACHA20_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

const POLY1305_BLOCK_SIZE: usize = 16;
const POLY1305_LIMB_MASK: u64 = (1_u64 << 26) - 1;
const POLY1305_FULL_BLOCK_HIGH_BIT: u64 = 1_u64 << 24;

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidDigit { index: usize, byte: u8 },
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => formatter.write_str("hex input has an odd number of digits"),
            Self::InvalidDigit { index, byte } => {
                write!(
                    formatter,
                    "invalid hex digit 0x{byte:02x} at byte index {index}"
                )
            }
        }
    }
}

impl Error for HexError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HkdfError {
    PrkTooShort { length: usize },
    OutputTooLong { length: usize },
    TlsLabelEmpty,
    TlsLabelTooLong { length: usize },
    TlsContextTooLong { length: usize },
}

impl fmt::Display for HkdfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrkTooShort { length } => {
                write!(
                    formatter,
                    "HKDF-SHA256 PRK must be at least {SHA256_DIGEST_SIZE} bytes, got {length}"
                )
            }
            Self::OutputTooLong { length } => {
                write!(
                    formatter,
                    "HKDF-SHA256 output cannot exceed {HKDF_MAX_OUTPUT_SIZE} bytes, got {length}"
                )
            }
            Self::TlsLabelEmpty => formatter.write_str("TLS 1.3 HKDF label cannot be empty"),
            Self::TlsLabelTooLong { length } => {
                write!(
                    formatter,
                    "TLS 1.3 HKDF label cannot exceed {TLS13_MAX_LABEL_SIZE} bytes, got {length}"
                )
            }
            Self::TlsContextTooLong { length } => {
                write!(
                    formatter,
                    "TLS 1.3 HKDF context cannot exceed {TLS13_MAX_CONTEXT_SIZE} bytes, got {length}"
                )
            }
        }
    }
}

impl Error for HkdfError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaCha20Error {
    CounterExhausted { counter: u32, blocks: u64 },
}

impl fmt::Display for ChaCha20Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterExhausted { counter, blocks } => {
                write!(
                    formatter,
                    "ChaCha20 counter {counter} cannot cover {blocks} block(s)"
                )
            }
        }
    }
}

impl Error for ChaCha20Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaCha20Poly1305Error {
    ChaCha20(ChaCha20Error),
    AuthenticationFailed,
}

impl fmt::Display for ChaCha20Poly1305Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChaCha20(error) => {
                write!(formatter, "ChaCha20-Poly1305 cipher failure: {error}")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("ChaCha20-Poly1305 authentication failed")
            }
        }
    }
}

impl Error for ChaCha20Poly1305Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ChaCha20(error) => Some(error),
            Self::AuthenticationFailed => None,
        }
    }
}

impl From<ChaCha20Error> for ChaCha20Poly1305Error {
    fn from(error: ChaCha20Error) -> Self {
        Self::ChaCha20(error)
    }
}

fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

fn wipe_words(words: &mut [u32]) {
    for word in words {
        unsafe {
            std::ptr::write_volatile(word, 0);
        }
    }
}

/// Fills a buffer using the operating-system cryptographically secure
/// random source.
///
/// The current Unix/WSL backend reads from `/dev/urandom`. Other platforms
/// fail closed until a native secure-random implementation is provided.
pub fn fill_random(output: &mut [u8]) -> io::Result<()> {
    platform::fill_random(output)
}

/// Compares equal-length byte strings without data-dependent early exit.
///
/// Length is not treated as secret. Callers comparing secret values should
/// use fixed-size encodings so both inputs always have the same length.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0_u8;

    for (&left_byte, &right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }

    difference == 0
}

pub fn encode_hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);

    for &byte in input {
        output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }

    output
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, HexError> {
    let input = input.as_bytes();

    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }

    let mut output = Vec::with_capacity(input.len() / 2);

    for index in (0..input.len()).step_by(2) {
        let high = decode_hex_nibble(input[index]).ok_or(HexError::InvalidDigit {
            index,
            byte: input[index],
        })?;

        let low = decode_hex_nibble(input[index + 1]).ok_or(HexError::InvalidDigit {
            index: index + 1,
            byte: input[index + 1],
        })?;

        output.push((high << 4) | low);
    }

    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Encodes bytes using the standard Base64 alphabet from RFC 4648 section 4.
///
/// Output includes `=` padding where required.
pub fn encode_base64(input: &[u8]) -> String {
    encode_base64_inner(input, BASE64_STANDARD_ALPHABET, true)
}

/// Encodes bytes using the URL-safe Base64 alphabet from RFC 4648 section 5.
///
/// Padding is deliberately omitted for protocols such as JWS and ACME.
pub fn encode_base64_url_no_pad(input: &[u8]) -> String {
    encode_base64_inner(input, BASE64_URL_ALPHABET, false)
}

fn encode_base64_inner(input: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let full_groups = input.len() / 3;
    let remainder_length = input.len() % 3;

    let remainder_output_length = match remainder_length {
        0 => 0,
        1 if padded => 4,
        1 => 2,
        2 if padded => 4,
        2 => 3,
        _ => unreachable!(),
    };

    let output_capacity = full_groups
        .saturating_mul(4)
        .saturating_add(remainder_output_length);

    let mut output = String::with_capacity(output_capacity);
    let mut chunks = input.chunks_exact(3);

    for chunk in &mut chunks {
        push_base64_character(&mut output, alphabet, chunk[0] >> 2);

        push_base64_character(
            &mut output,
            alphabet,
            ((chunk[0] & 0x03) << 4) | (chunk[1] >> 4),
        );

        push_base64_character(
            &mut output,
            alphabet,
            ((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6),
        );

        push_base64_character(&mut output, alphabet, chunk[2] & 0x3f);
    }

    let remainder = chunks.remainder();

    if remainder.len() == 1 {
        push_base64_character(&mut output, alphabet, remainder[0] >> 2);

        push_base64_character(&mut output, alphabet, (remainder[0] & 0x03) << 4);

        if padded {
            output.push_str("==");
        }
    } else if remainder.len() == 2 {
        push_base64_character(&mut output, alphabet, remainder[0] >> 2);

        push_base64_character(
            &mut output,
            alphabet,
            ((remainder[0] & 0x03) << 4) | (remainder[1] >> 4),
        );

        push_base64_character(&mut output, alphabet, (remainder[1] & 0x0f) << 2);

        if padded {
            output.push('=');
        }
    }

    output
}

fn push_base64_character(output: &mut String, alphabet: &[u8; 64], value: u8) {
    output.push(char::from(alphabet[usize::from(value)]));
}

/// Streaming SHA-256 implementation following FIPS 180-4 and RFC 6234.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_len: usize,
    message_len_bytes: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0_u8; SHA256_BLOCK_SIZE],
            buffer_len: 0,
            message_len_bytes: 0,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let input_len =
            u64::try_from(input.len()).expect("SHA-256 input length does not fit in u64");

        self.message_len_bytes = self
            .message_len_bytes
            .checked_add(input_len)
            .filter(|length| *length <= u64::MAX / 8)
            .expect("SHA-256 message exceeds the 2^64-bit length limit");

        let mut input = input;

        if self.buffer_len != 0 {
            let available = SHA256_BLOCK_SIZE - self.buffer_len;
            let bytes_to_copy = available.min(input.len());

            self.buffer[self.buffer_len..self.buffer_len + bytes_to_copy]
                .copy_from_slice(&input[..bytes_to_copy]);

            self.buffer_len += bytes_to_copy;
            input = &input[bytes_to_copy..];

            if self.buffer_len != SHA256_BLOCK_SIZE {
                return;
            }

            let block = self.buffer;

            self.compress_block(&block);
            self.buffer_len = 0;
        }

        let mut chunks = input.chunks_exact(SHA256_BLOCK_SIZE);

        for chunk in &mut chunks {
            let block: &[u8; SHA256_BLOCK_SIZE] = chunk
                .try_into()
                .expect("SHA-256 block must contain 64 bytes");

            self.compress_block(block);
        }

        let remainder = chunks.remainder();

        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffer_len = remainder.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let message_len_bits = self.message_len_bytes * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > SHA256_LENGTH_OFFSET {
            self.buffer[self.buffer_len..].fill(0);

            let block = self.buffer;

            self.compress_block(&block);

            self.buffer.fill(0);
            self.buffer_len = 0;
        }

        self.buffer[self.buffer_len..SHA256_LENGTH_OFFSET].fill(0);

        self.buffer[SHA256_LENGTH_OFFSET..].copy_from_slice(&message_len_bits.to_be_bytes());

        let block = self.buffer;

        self.compress_block(&block);

        let mut digest = [0_u8; 32];

        for (word, output) in self.state.iter().zip(digest.chunks_exact_mut(4)) {
            output.copy_from_slice(&word.to_be_bytes());
        }

        digest
    }

    fn compress_block(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        let mut schedule = [0_u32; 64];

        for (index, word) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes(
                word.try_into()
                    .expect("SHA-256 message word must contain four bytes"),
            );
        }

        for index in 16..64 {
            schedule[index] = small_sigma1(schedule[index - 2])
                .wrapping_add(schedule[index - 7])
                .wrapping_add(small_sigma0(schedule[index - 15]))
                .wrapping_add(schedule[index - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for index in 0..64 {
            let temporary1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(choice(e, f, g))
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);

            let temporary2 = big_sigma0(a).wrapping_add(majority(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        wipe_words(&mut schedule);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        wipe_words(&mut self.state);
        wipe_bytes(&mut self.buffer);

        self.buffer_len = 0;
        self.message_len_bytes = 0;
    }
}

/// Computes the SHA-256 digest of an entire byte slice.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(input);

    hasher.finalize()
}

/// Computes HMAC-SHA256 following RFC 2104.
///
/// Keys longer than SHA-256's 64-byte block size are hashed first.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

fn hmac_sha256_parts(key: &[u8], data_parts: &[&[u8]]) -> [u8; 32] {
    let mut key_block = [0_u8; SHA256_BLOCK_SIZE];

    if key.len() > SHA256_BLOCK_SIZE {
        let mut hashed_key = sha256(key);

        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
        wipe_bytes(&mut hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = key_block;
    let mut outer_pad = key_block;

    for byte in &mut inner_pad {
        *byte ^= HMAC_INNER_PAD_BYTE;
    }

    for byte in &mut outer_pad {
        *byte ^= HMAC_OUTER_PAD_BYTE;
    }

    let mut inner = Sha256::new();

    inner.update(&inner_pad);

    for part in data_parts {
        inner.update(part);
    }

    let mut inner_digest = inner.finalize();

    let mut outer = Sha256::new();

    outer.update(&outer_pad);
    outer.update(&inner_digest);

    wipe_bytes(&mut inner_digest);
    wipe_bytes(&mut key_block);
    wipe_bytes(&mut inner_pad);
    wipe_bytes(&mut outer_pad);

    outer.finalize()
}

/// Performs HKDF-Extract using HMAC-SHA256 as specified by RFC 5869.
///
/// An empty salt has the same effect as RFC 5869's omitted-salt default for
/// HMAC-SHA256 because HMAC pads both keys with zero octets to the block size.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// Performs HKDF-Expand using HMAC-SHA256 as specified by RFC 5869.
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, HkdfError> {
    if prk.len() < SHA256_DIGEST_SIZE {
        return Err(HkdfError::PrkTooShort { length: prk.len() });
    }

    if length > HKDF_MAX_OUTPUT_SIZE {
        return Err(HkdfError::OutputTooLong { length });
    }

    let block_count = length.div_ceil(SHA256_DIGEST_SIZE);
    let mut output = Vec::with_capacity(length);
    let mut previous_block = [0_u8; SHA256_DIGEST_SIZE];

    for block_index in 1..=block_count {
        let counter =
            u8::try_from(block_index).expect("validated HKDF block count must fit in one octet");

        let next_block = if block_index == 1 {
            hmac_sha256_parts(prk, &[info, &[counter]])
        } else {
            hmac_sha256_parts(prk, &[&previous_block, info, &[counter]])
        };

        wipe_bytes(&mut previous_block);
        previous_block = next_block;

        let remaining = length - output.len();
        let bytes_to_copy = remaining.min(SHA256_DIGEST_SIZE);

        output.extend_from_slice(&previous_block[..bytes_to_copy]);
    }

    wipe_bytes(&mut previous_block);

    Ok(output)
}

/// Performs TLS 1.3 HKDF-Expand-Label as specified by RFC 8446 section 7.1.
///
/// `label` is supplied without the mandatory `tls13 ` prefix.
pub fn tls13_hkdf_expand_label_sha256(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, HkdfError> {
    if length > HKDF_MAX_OUTPUT_SIZE {
        return Err(HkdfError::OutputTooLong { length });
    }

    let info = build_tls13_hkdf_label(label, context, length)?;

    hkdf_expand_sha256(secret, &info, length)
}

fn build_tls13_hkdf_label(
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, HkdfError> {
    if label.is_empty() {
        return Err(HkdfError::TlsLabelEmpty);
    }

    if label.len() > TLS13_MAX_LABEL_SIZE {
        return Err(HkdfError::TlsLabelTooLong {
            length: label.len(),
        });
    }

    if context.len() > TLS13_MAX_CONTEXT_SIZE {
        return Err(HkdfError::TlsContextTooLong {
            length: context.len(),
        });
    }

    let encoded_length =
        u16::try_from(length).expect("validated HKDF-SHA256 output length must fit in uint16");

    let full_label_length = TLS13_LABEL_PREFIX.len() + label.len();

    let encoded_label_length =
        u8::try_from(full_label_length).expect("validated TLS 1.3 label length must fit in uint8");

    let encoded_context_length =
        u8::try_from(context.len()).expect("validated TLS 1.3 context length must fit in uint8");

    let mut info = Vec::with_capacity(2 + 1 + full_label_length + 1 + context.len());

    info.extend_from_slice(&encoded_length.to_be_bytes());

    info.push(encoded_label_length);
    info.extend_from_slice(TLS13_LABEL_PREFIX);
    info.extend_from_slice(label.as_bytes());

    info.push(encoded_context_length);
    info.extend_from_slice(context);

    Ok(info)
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0(value: u32) -> u32 {
    value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22)
}

fn big_sigma1(value: u32) -> u32 {
    value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25)
}

fn small_sigma0(value: u32) -> u32 {
    value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
}

fn small_sigma1(value: u32) -> u32 {
    value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
}

/// Performs the ChaCha quarter-round from RFC 8439 section 2.1.
fn chacha20_quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    (a, b, c, d)
}

fn chacha20_quarter_round_state(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (a_value, b_value, c_value, d_value) =
        chacha20_quarter_round(state[a], state[b], state[c], state[d]);

    state[a] = a_value;
    state[b] = b_value;
    state[c] = c_value;
    state[d] = d_value;
}

/// Generates one 64-byte ChaCha20 keystream block as specified by RFC 8439.
///
/// `nonce` must never repeat for the same key.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; CHACHA20_BLOCK_SIZE] {
    let mut state = [0_u32; 16];

    state[..4].copy_from_slice(&CHACHA20_CONSTANTS);

    for (word, bytes) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = read_u32_le(bytes);
    }

    state[12] = counter;

    for (word, bytes) in state[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = read_u32_le(bytes);
    }

    let mut initial_state = state;

    for _ in 0..10 {
        chacha20_quarter_round_state(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round_state(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round_state(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round_state(&mut state, 3, 7, 11, 15);

        chacha20_quarter_round_state(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round_state(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round_state(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round_state(&mut state, 3, 4, 9, 14);
    }

    for (word, initial_word) in state.iter_mut().zip(&initial_state) {
        *word = word.wrapping_add(*initial_word);
    }

    let mut output = [0_u8; CHACHA20_BLOCK_SIZE];

    for (word, bytes) in state.iter().zip(output.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }

    wipe_words(&mut state);
    wipe_words(&mut initial_state);

    output
}

/// Applies the ChaCha20 stream cipher from RFC 8439 section 2.4.
///
/// Encryption and decryption are the same XOR operation.
pub fn chacha20_xor(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
    input: &[u8],
) -> Result<Vec<u8>, ChaCha20Error> {
    let block_count = input.len().div_ceil(CHACHA20_BLOCK_SIZE);

    let block_count = u64::try_from(block_count).expect("ChaCha20 block count must fit in u64");

    let available_blocks = u64::from(u32::MAX - counter) + 1;

    if block_count > available_blocks {
        return Err(ChaCha20Error::CounterExhausted {
            counter,
            blocks: block_count,
        });
    }

    let mut output = input.to_vec();

    for (block_index, chunk) in output.chunks_mut(CHACHA20_BLOCK_SIZE).enumerate() {
        let block_offset =
            u32::try_from(block_index).expect("validated ChaCha20 block offset must fit in u32");

        let block_counter = counter
            .checked_add(block_offset)
            .expect("validated ChaCha20 counter must not overflow");

        let mut key_stream = chacha20_block(key, block_counter, nonce);

        for (byte, key_byte) in chunk.iter_mut().zip(&key_stream) {
            *byte ^= key_byte;
        }

        wipe_bytes(&mut key_stream);
    }

    Ok(output)
}

/// Computes a Poly1305 authentication tag as specified by RFC 8439.
///
/// The 32-byte key is a one-time key and must not be reused for unrelated
/// messages.
pub fn poly1305_authenticate(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0_u8; 16];

    r_bytes.copy_from_slice(&key[..16]);

    for index in [3, 7, 11, 15] {
        r_bytes[index] &= 0x0f;
    }

    for index in [4, 8, 12] {
        r_bytes[index] &= 0xfc;
    }

    let r0 = u64::from(read_u32_le(&r_bytes[0..4])) & POLY1305_LIMB_MASK;

    let r1 = (u64::from(read_u32_le(&r_bytes[3..7])) >> 2) & POLY1305_LIMB_MASK;

    let r2 = (u64::from(read_u32_le(&r_bytes[6..10])) >> 4) & POLY1305_LIMB_MASK;

    let r3 = (u64::from(read_u32_le(&r_bytes[9..13])) >> 6) & POLY1305_LIMB_MASK;

    let r4 = (u64::from(read_u32_le(&r_bytes[12..16])) >> 8) & POLY1305_LIMB_MASK;

    let r1_times_5 = r1 * 5;
    let r2_times_5 = r2 * 5;
    let r3_times_5 = r3 * 5;
    let r4_times_5 = r4 * 5;

    let mut h0 = 0_u64;
    let mut h1 = 0_u64;
    let mut h2 = 0_u64;
    let mut h3 = 0_u64;
    let mut h4 = 0_u64;

    for chunk in message.chunks(POLY1305_BLOCK_SIZE) {
        let mut block = [0_u8; POLY1305_BLOCK_SIZE];

        block[..chunk.len()].copy_from_slice(chunk);

        let high_bit = if chunk.len() == POLY1305_BLOCK_SIZE {
            POLY1305_FULL_BLOCK_HIGH_BIT
        } else {
            block[chunk.len()] = 1;
            0
        };

        h0 += u64::from(read_u32_le(&block[0..4])) & POLY1305_LIMB_MASK;

        h1 += (u64::from(read_u32_le(&block[3..7])) >> 2) & POLY1305_LIMB_MASK;

        h2 += (u64::from(read_u32_le(&block[6..10])) >> 4) & POLY1305_LIMB_MASK;

        h3 += (u64::from(read_u32_le(&block[9..13])) >> 6) & POLY1305_LIMB_MASK;

        h4 += (u64::from(read_u32_le(&block[12..16])) >> 8) | high_bit;

        let mut d0 =
            h0 * r0 + h1 * r4_times_5 + h2 * r3_times_5 + h3 * r2_times_5 + h4 * r1_times_5;

        let mut d1 = h0 * r1 + h1 * r0 + h2 * r4_times_5 + h3 * r3_times_5 + h4 * r2_times_5;

        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * r4_times_5 + h4 * r3_times_5;

        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * r4_times_5;

        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut carry = d0 >> 26;
        h0 = d0 & POLY1305_LIMB_MASK;
        d1 += carry;

        carry = d1 >> 26;
        h1 = d1 & POLY1305_LIMB_MASK;
        d2 += carry;

        carry = d2 >> 26;
        h2 = d2 & POLY1305_LIMB_MASK;
        d3 += carry;

        carry = d3 >> 26;
        h3 = d3 & POLY1305_LIMB_MASK;

        let mut d4 = d4 + carry;

        carry = d4 >> 26;
        h4 = d4 & POLY1305_LIMB_MASK;

        h0 += carry * 5;

        carry = h0 >> 26;
        h0 &= POLY1305_LIMB_MASK;
        h1 += carry;

        wipe_bytes(&mut block);

        d0 = 0;
        d1 = 0;
        d2 = 0;
        d3 = 0;
        d4 = 0;

        std::hint::black_box((d0, d1, d2, d3, d4));
    }

    let mut carry = h1 >> 26;
    h1 &= POLY1305_LIMB_MASK;
    h2 += carry;

    carry = h2 >> 26;
    h2 &= POLY1305_LIMB_MASK;
    h3 += carry;

    carry = h3 >> 26;
    h3 &= POLY1305_LIMB_MASK;
    h4 += carry;

    carry = h4 >> 26;
    h4 &= POLY1305_LIMB_MASK;
    h0 += carry * 5;

    carry = h0 >> 26;
    h0 &= POLY1305_LIMB_MASK;
    h1 += carry;

    let mut g0 = h0 + 5;

    carry = g0 >> 26;
    g0 &= POLY1305_LIMB_MASK;

    let mut g1 = h1 + carry;

    carry = g1 >> 26;
    g1 &= POLY1305_LIMB_MASK;

    let mut g2 = h2 + carry;

    carry = g2 >> 26;
    g2 &= POLY1305_LIMB_MASK;

    let mut g3 = h3 + carry;

    carry = g3 >> 26;
    g3 &= POLY1305_LIMB_MASK;

    let g4 = h4.wrapping_add(carry).wrapping_sub(1_u64 << 26);

    let select_g = (g4 >> 63).wrapping_sub(1);
    let select_h = !select_g;

    h0 = (h0 & select_h) | (g0 & select_g);
    h1 = (h1 & select_h) | (g1 & select_g);
    h2 = (h2 & select_h) | (g2 & select_g);
    h3 = (h3 & select_h) | (g3 & select_g);
    h4 = (h4 & select_h) | (g4 & select_g);

    let word_mask = u64::from(u32::MAX);

    let mut f0 = (h0 | (h1 << 26)) & word_mask;

    let mut f1 = ((h1 >> 6) | (h2 << 20)) & word_mask;

    let mut f2 = ((h2 >> 12) | (h3 << 14)) & word_mask;

    let mut f3 = ((h3 >> 18) | (h4 << 8)) & word_mask;

    let pad0 = u64::from(read_u32_le(&key[16..20]));
    let pad1 = u64::from(read_u32_le(&key[20..24]));
    let pad2 = u64::from(read_u32_le(&key[24..28]));
    let pad3 = u64::from(read_u32_le(&key[28..32]));

    f0 += pad0;

    f1 += pad1 + (f0 >> 32);
    f0 &= word_mask;

    f2 += pad2 + (f1 >> 32);
    f1 &= word_mask;

    f3 += pad3 + (f2 >> 32);
    f2 &= word_mask;
    f3 &= word_mask;

    let final_words = [f0, f1, f2, f3];
    let mut tag = [0_u8; 16];

    for (word, bytes) in final_words.iter().zip(tag.chunks_exact_mut(4)) {
        let word = u32::try_from(*word).expect("reduced Poly1305 word must fit in u32");

        bytes.copy_from_slice(&word.to_le_bytes());
    }

    wipe_bytes(&mut r_bytes);

    tag
}

/// Composes the 96-bit nonce form used by the RFC 8439 AEAD example.
///
/// Protocols with their own nonce construction, including TLS 1.3, may
/// construct the required 12-byte nonce differently.
pub fn compose_chacha20_poly1305_nonce(fixed_common: &[u8; 4], invocation: &[u8; 8]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];

    nonce[..4].copy_from_slice(fixed_common);
    nonce[4..].copy_from_slice(invocation);

    nonce
}

fn chacha20_poly1305_one_time_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = chacha20_block(key, 0, nonce);
    let mut one_time_key = [0_u8; 32];

    one_time_key.copy_from_slice(&block[..32]);

    wipe_bytes(&mut block);

    one_time_key
}

fn append_pad16(output: &mut Vec<u8>, input_len: usize) {
    let remainder = input_len % POLY1305_BLOCK_SIZE;

    if remainder != 0 {
        output.resize(output.len() + (POLY1305_BLOCK_SIZE - remainder), 0);
    }
}

fn chacha20_poly1305_mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aad_len = u64::try_from(aad.len()).expect("AEAD AAD length must fit in u64");

    let ciphertext_len =
        u64::try_from(ciphertext.len()).expect("AEAD ciphertext length must fit in u64");

    let mut mac_data = Vec::new();

    mac_data.extend_from_slice(aad);
    append_pad16(&mut mac_data, aad.len());

    mac_data.extend_from_slice(ciphertext);
    append_pad16(&mut mac_data, ciphertext.len());

    mac_data.extend_from_slice(&aad_len.to_le_bytes());
    mac_data.extend_from_slice(&ciphertext_len.to_le_bytes());

    mac_data
}

/// Encrypts and authenticates using AEAD_CHACHA20_POLY1305 from RFC 8439.
///
/// The 96-bit nonce must be unique for every invocation under the same key.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), ChaCha20Poly1305Error> {
    let mut one_time_key = chacha20_poly1305_one_time_key(key, nonce);

    let ciphertext = match chacha20_xor(key, 1, nonce, plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(error) => {
            wipe_bytes(&mut one_time_key);

            return Err(error.into());
        }
    };

    let mac_data = chacha20_poly1305_mac_data(aad, &ciphertext);

    let tag = poly1305_authenticate(&one_time_key, &mac_data);

    wipe_bytes(&mut one_time_key);

    Ok((ciphertext, tag))
}

/// Authenticates and decrypts AEAD_CHACHA20_POLY1305 ciphertext.
///
/// Authentication is completed before ChaCha20 is applied, so plaintext is
/// never returned when the Poly1305 tag is invalid.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, ChaCha20Poly1305Error> {
    let mut one_time_key = chacha20_poly1305_one_time_key(key, nonce);

    let mac_data = chacha20_poly1305_mac_data(aad, ciphertext);

    let mut expected_tag = poly1305_authenticate(&one_time_key, &mac_data);

    wipe_bytes(&mut one_time_key);

    let authenticated = constant_time_eq(&expected_tag, tag);

    wipe_bytes(&mut expected_tag);

    if !authenticated {
        return Err(ChaCha20Poly1305Error::AuthenticationFailed);
    }

    chacha20_xor(key, 1, nonce, ciphertext).map_err(ChaCha20Poly1305Error::from)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(
        bytes
            .try_into()
            .expect("little-endian word must contain exactly four bytes"),
    )
}

#[cfg(unix)]
mod platform {
    use std::{
        fs::File,
        io::{self, Read},
    };

    const RANDOM_DEVICE: &str = "/dev/urandom";

    pub(super) fn fill_random(output: &mut [u8]) -> io::Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        let mut source = File::open(RANDOM_DEVICE)?;

        source.read_exact(output)
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;

    pub(super) fn fill_random(_: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure OS randomness is not implemented for this platform yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChaCha20Error, ChaCha20Poly1305Error, HexError, HkdfError, Sha256, build_tls13_hkdf_label,
        chacha20_block, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
        chacha20_poly1305_one_time_key, chacha20_quarter_round, chacha20_xor,
        compose_chacha20_poly1305_nonce, constant_time_eq, decode_hex, encode_base64,
        encode_base64_url_no_pad, encode_hex, fill_random, hkdf_expand_sha256, hkdf_extract_sha256,
        hmac_sha256, poly1305_authenticate, sha256, tls13_hkdf_expand_label_sha256, wipe_bytes,
        wipe_words,
    };

    #[test]
    fn volatile_wipe_clears_controlled_buffers() {
        let mut bytes = [0xa5_u8; 64];
        let mut words = [0xdead_beef_u32; 16];

        wipe_bytes(&mut bytes);
        wipe_words(&mut words);

        assert_eq!(bytes, [0_u8; 64]);
        assert_eq!(words, [0_u32; 16]);
    }

    #[test]
    fn constant_time_comparison_accepts_equal_inputs() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"BareProxy", b"BareProxy"));
        assert!(constant_time_eq(&[0_u8; 32], &[0_u8; 32]));
    }

    #[test]
    fn constant_time_comparison_rejects_different_inputs() {
        assert!(!constant_time_eq(b"XareProxy", b"BareProxy"));
        assert!(!constant_time_eq(b"BareXroxy", b"BareProxy"));
        assert!(!constant_time_eq(b"BareProxX", b"BareProxy"));
    }

    #[test]
    fn constant_time_comparison_rejects_different_lengths() {
        assert!(!constant_time_eq(b"BareProxy", b"BareProxy!"));
    }

    #[test]
    fn fills_random_bytes_from_operating_system() {
        let mut output = [0_u8; 64];

        fill_random(&mut output).unwrap();

        assert!(
            output.iter().any(|byte| *byte != 0),
            "OS random source unexpectedly returned an all-zero buffer"
        );
    }

    #[test]
    fn consecutive_random_samples_differ() {
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];

        fill_random(&mut first).unwrap();
        fill_random(&mut second).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn accepts_empty_output_buffer() {
        let mut output = [];

        fill_random(&mut output).unwrap();
    }

    #[test]
    fn encodes_hex_in_lowercase() {
        assert_eq!(
            encode_hex(&[0x00, 0x01, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0xff]),
            "00010f10abcdefff"
        );
    }

    #[test]
    fn decodes_lowercase_and_uppercase_hex() {
        assert_eq!(
            decode_hex("00010f10abcdefff").unwrap(),
            vec![0x00, 0x01, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0xff]
        );

        assert_eq!(
            decode_hex("00010F10ABCDEFFF").unwrap(),
            vec![0x00, 0x01, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0xff]
        );
    }

    #[test]
    fn hex_round_trips_every_byte_value() {
        let input: Vec<u8> = (0..=u8::MAX).collect();

        let encoded = encode_hex(&input);
        let decoded = decode_hex(&encoded).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn hex_accepts_empty_input() {
        assert_eq!(encode_hex(&[]), "");
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_rejects_odd_length() {
        assert_eq!(decode_hex("abc"), Err(HexError::OddLength));
    }

    #[test]
    fn hex_reports_invalid_digit_position() {
        assert_eq!(
            decode_hex("00xz"),
            Err(HexError::InvalidDigit {
                index: 2,
                byte: b'x',
            })
        );

        assert_eq!(
            decode_hex("001z"),
            Err(HexError::InvalidDigit {
                index: 3,
                byte: b'z',
            })
        );
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for (input, expected) in vectors {
            assert_eq!(encode_base64(input), expected);
        }
    }

    #[test]
    fn base64_url_uses_url_safe_alphabet_without_padding() {
        assert_eq!(encode_base64(&[0xfb, 0xef, 0xff]), "++//");
        assert_eq!(encode_base64_url_no_pad(&[0xfb, 0xef, 0xff]), "--__");

        assert_eq!(encode_base64_url_no_pad(b""), "");
        assert_eq!(encode_base64_url_no_pad(b"f"), "Zg");
        assert_eq!(encode_base64_url_no_pad(b"fo"), "Zm8");
        assert_eq!(encode_base64_url_no_pad(b"foo"), "Zm9v");
        assert_eq!(encode_base64_url_no_pad(b"foob"), "Zm9vYg");
        assert_eq!(encode_base64_url_no_pad(b"fooba"), "Zm9vYmE");
        assert_eq!(encode_base64_url_no_pad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_handles_every_possible_byte_value() {
        let input: Vec<u8> = (0..=u8::MAX).collect();

        let standard = encode_base64(&input);
        let url_safe = encode_base64_url_no_pad(&input);

        assert!(!standard.is_empty());
        assert!(!url_safe.is_empty());

        assert_eq!(standard.len() % 4, 0);

        assert!(!url_safe.contains('='));
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));
    }

    #[test]
    fn sha256_matches_empty_message_vector() {
        assert_eq!(
            encode_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb924\
27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_matches_abc_vector() {
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223\
b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_matches_multiblock_padding_vector() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        assert_eq!(
            encode_hex(&sha256(input)),
            "248d6a61d20638b8e5c026930c3e6039\
a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_streaming_matches_multiblock_padding_vector() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        let mut hasher = Sha256::new();

        for chunk in input.chunks(3) {
            hasher.update(chunk);
        }

        assert_eq!(
            encode_hex(&hasher.finalize()),
            "248d6a61d20638b8e5c026930c3e6039\
a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_matches_one_million_a_vector() {
        let mut hasher = Sha256::new();
        let chunk = [b'a'; 1000];

        for _ in 0..1000 {
            hasher.update(&chunk);
        }

        assert_eq!(
            encode_hex(&hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67\
f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let key = [0x0b_u8; 20];

        assert_eq!(
            encode_hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b\
881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        assert_eq!(
            encode_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c7\
5a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_3() {
        let key = [0xaa_u8; 20];
        let data = [0xdd_u8; 50];

        assert_eq!(
            encode_hex(&hmac_sha256(&key, &data)),
            "773ea91e36800e46854db8ebd09181a7\
2959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_4() {
        let key: Vec<u8> = (1..=25).collect();
        let data = [0xcd_u8; 50];

        assert_eq!(
            encode_hex(&hmac_sha256(&key, &data)),
            "82558a389a443c0ea4cc819899f2083a\
85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn hmac_sha256_hashes_oversized_key_per_rfc_4231_case_6() {
        let key = [0xaa_u8; 131];

        assert_eq!(
            encode_hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f\
8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc_5869_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();

        let prk = hkdf_extract_sha256(&salt, &ikm);

        assert_eq!(
            encode_hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba63\
90b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let okm = hkdf_expand_sha256(&prk, &info, 42).unwrap();

        assert_eq!(
            encode_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a\
2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc_5869_case_2() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();

        let prk = hkdf_extract_sha256(&salt, &ikm);

        assert_eq!(
            encode_hex(&prk),
            "06a6b88c5853361a06104c9ceb35b45c\
ef760014904671014a193f40c15fc244"
        );

        let okm = hkdf_expand_sha256(&prk, &info, 82).unwrap();

        assert_eq!(
            encode_hex(&okm),
            "b11e398dc80327a1c8e7f78c596a4934\
4f012eda2d4efad8a050cc4c19afa97c\
59045a99cac7827271cb41c65e590e09\
da3275600c2f09b8367793a9aca3db71\
cc30c58179ec3e87c14c01d5c1f3434f\
1d87"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc_5869_case_3() {
        let ikm = [0x0b_u8; 22];

        let prk = hkdf_extract_sha256(&[], &ikm);

        assert_eq!(
            encode_hex(&prk),
            "19ef24a32c717b167f33a91d6f648bdf\
96596776afdb6377ac434c1c293ccb04"
        );

        let okm = hkdf_expand_sha256(&prk, &[], 42).unwrap();

        assert_eq!(
            encode_hex(&okm),
            "8da4e775a563c18f715f802a063c5a31\
b8a11f5c5ee1879ec3454e5f3c738d2d\
9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_expand_accepts_zero_length_output() {
        let prk = [0x42_u8; 32];

        assert_eq!(
            hkdf_expand_sha256(&prk, b"context", 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn hkdf_expand_rejects_short_prk() {
        assert_eq!(
            hkdf_expand_sha256(&[0_u8; 31], b"", 32),
            Err(HkdfError::PrkTooShort { length: 31 })
        );
    }

    #[test]
    fn hkdf_expand_rejects_output_beyond_rfc_limit() {
        let prk = [0_u8; 32];

        assert_eq!(
            hkdf_expand_sha256(&prk, b"", 8161),
            Err(HkdfError::OutputTooLong { length: 8161 })
        );
    }

    #[test]
    fn tls13_hkdf_label_matches_rfc_8448_info() {
        let context = decode_hex(
            "860c06edc07858ee8e78f0e7428c58ed\
d6b43f2ca3e6e95f02ed063cf0e1cad8",
        )
        .unwrap();

        let info = build_tls13_hkdf_label("c hs traffic", &context, 32).unwrap();

        assert_eq!(
            encode_hex(&info),
            "002012746c733133206320687320747261\
6666696320860c06edc07858ee8e78f0e7\
428c58edd6b43f2ca3e6e95f02ed063cf0\
e1cad8"
        );
    }

    #[test]
    fn tls13_hkdf_expand_label_matches_rfc_8448_vector() {
        let secret = decode_hex(
            "1dc826e93606aa6fdc0aadc12f741b01\
046aa6b99f691ed221a9f0ca043fbeac",
        )
        .unwrap();

        let context = decode_hex(
            "860c06edc07858ee8e78f0e7428c58ed\
d6b43f2ca3e6e95f02ed063cf0e1cad8",
        )
        .unwrap();

        let expanded =
            tls13_hkdf_expand_label_sha256(&secret, "c hs traffic", &context, 32).unwrap();

        assert_eq!(
            encode_hex(&expanded),
            "b3eddb126e067f35a780b3abf45e2d8f\
3b1a950738f52e9600746a0e27a55a21"
        );
    }

    #[test]
    fn tls13_hkdf_label_encodes_empty_context() {
        let info = build_tls13_hkdf_label("key", &[], 16).unwrap();

        assert_eq!(encode_hex(&info), "001009746c733133206b657900");
    }

    #[test]
    fn tls13_hkdf_label_rejects_empty_label() {
        assert_eq!(
            build_tls13_hkdf_label("", &[], 32),
            Err(HkdfError::TlsLabelEmpty)
        );
    }

    #[test]
    fn tls13_hkdf_label_rejects_oversized_label() {
        let label = "x".repeat(250);

        assert_eq!(
            build_tls13_hkdf_label(&label, &[], 32),
            Err(HkdfError::TlsLabelTooLong { length: 250 })
        );
    }

    #[test]
    fn tls13_hkdf_label_rejects_oversized_context() {
        let context = [0_u8; 256];

        assert_eq!(
            build_tls13_hkdf_label("key", &context, 32),
            Err(HkdfError::TlsContextTooLong { length: 256 })
        );
    }

    #[test]
    fn chacha20_quarter_round_matches_rfc_8439_vector() {
        assert_eq!(
            chacha20_quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567,),
            (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb,)
        );
    }

    #[test]
    fn chacha20_block_matches_rfc_8439_vector() {
        let key: [u8; 32] = decode_hex(
            "000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let nonce: [u8; 12] = decode_hex("000000090000004a00000000")
            .unwrap()
            .try_into()
            .unwrap();

        let block = chacha20_block(&key, 1, &nonce);

        assert_eq!(
            encode_hex(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4\
c7d1f4c733c068030422aa9ac3d46c4e\
d2826446079faa0914c2d705d98b02a2\
b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn chacha20_stream_matches_rfc_8439_vector() {
        let key: [u8; 32] = decode_hex(
            "000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let nonce: [u8; 12] = decode_hex("000000000000004a00000000")
            .unwrap()
            .try_into()
            .unwrap();

        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, \
sunscreen would be it.";

        let ciphertext = chacha20_xor(&key, 1, &nonce, plaintext).unwrap();

        assert_eq!(
            encode_hex(&ciphertext),
            "6e2e359a2568f98041ba0728dd0d6981\
e97e7aec1d4360c20a27afccfd9fae0b\
f91b65c5524733ab8f593dabcd62b357\
1639d624e65152ab8f530c359f0861d8\
07ca0dbf500d6a6156a38e088a22b65e\
52bc514d16ccf806818ce91ab7793736\
5af90bbf74a35be6b40b8eedf2785e42\
874d"
        );

        let decrypted = chacha20_xor(&key, 1, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn poly1305_matches_rfc_8439_vector() {
        let key: [u8; 32] = decode_hex(
            "85d6be7857556d337f4452fe42d506a8\
0103808afb0db2fd4abff6af4149f51b",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let tag = poly1305_authenticate(&key, b"Cryptographic Forum Research Group");

        assert_eq!(encode_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn poly1305_empty_message_returns_additive_key() {
        let key: [u8; 32] = decode_hex(
            "00000000000000000000000000000000\
0102030405060708090a0b0c0d0e0f10",
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            encode_hex(&poly1305_authenticate(&key, b"")),
            "0102030405060708090a0b0c0d0e0f10"
        );
    }

    #[test]
    fn chacha20_poly1305_nonce_matches_rfc_8439_example() {
        let fixed_common = [0x07, 0x00, 0x00, 0x00];
        let invocation = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

        let nonce = compose_chacha20_poly1305_nonce(&fixed_common, &invocation);

        assert_eq!(encode_hex(&nonce), "070000004041424344454647");
    }

    #[test]
    fn chacha20_poly1305_one_time_key_matches_rfc_8439_vector() {
        let key: [u8; 32] = decode_hex(
            "808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let fixed_common = [0x07, 0x00, 0x00, 0x00];
        let invocation = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

        let nonce = compose_chacha20_poly1305_nonce(&fixed_common, &invocation);

        let mut one_time_key = chacha20_poly1305_one_time_key(&key, &nonce);

        assert_eq!(
            encode_hex(&one_time_key),
            "7bac2b252db447af09b67a55a4e95584\
0ae1d6731075d9eb2a9375783ed553ff"
        );

        wipe_bytes(&mut one_time_key);
    }

    #[test]
    fn chacha20_poly1305_matches_rfc_8439_aead_vector() {
        let key: [u8; 32] = decode_hex(
            "808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
        .try_into()
        .unwrap();

        let fixed_common = [0x07, 0x00, 0x00, 0x00];
        let invocation = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

        let nonce = compose_chacha20_poly1305_nonce(&fixed_common, &invocation);

        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7").unwrap();

        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, \
sunscreen would be it.";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext).unwrap();

        assert_eq!(
            encode_hex(&ciphertext),
            "d31a8d34648e60db7b86afbc53ef7ec2\
a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b\
1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58\
fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b\
6116"
        );

        assert_eq!(encode_hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_poly1305_rejects_modified_tag_without_plaintext() {
        let key = [0x11_u8; 32];
        let nonce = [0x22_u8; 12];
        let aad = b"BareProxy authenticated metadata";
        let plaintext = b"this plaintext must remain secret";

        let (ciphertext, mut tag) =
            chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext).unwrap();

        tag[0] ^= 0x80;

        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag,),
            Err(ChaCha20Poly1305Error::AuthenticationFailed)
        );
    }

    #[test]
    fn chacha20_poly1305_authenticates_ciphertext_and_aad() {
        let key = [0x33_u8; 32];
        let nonce = [0x44_u8; 12];
        let aad = b"metadata";
        let plaintext = b"authenticated message";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext).unwrap();

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[0] ^= 1;

        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, aad, &modified_ciphertext, &tag,),
            Err(ChaCha20Poly1305Error::AuthenticationFailed)
        );

        let mut modified_aad = aad.to_vec();
        modified_aad[0] ^= 1;

        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, &modified_aad, &ciphertext, &tag,),
            Err(ChaCha20Poly1305Error::AuthenticationFailed)
        );
    }

    #[test]
    fn chacha20_poly1305_round_trips_boundary_lengths() {
        let key = [0x55_u8; 32];

        let cases = [
            (0_usize, 0_usize),
            (1, 15),
            (15, 16),
            (16, 17),
            (17, 63),
            (63, 64),
            (64, 65),
            (65, 1),
        ];

        for (case_index, (aad_len, plaintext_len)) in cases.into_iter().enumerate() {
            let mut nonce = [0_u8; 12];

            nonce[11] = u8::try_from(case_index).unwrap();

            let aad = vec![0xa5_u8; aad_len];
            let plaintext = vec![0x5a_u8; plaintext_len];

            let (ciphertext, tag) =
                chacha20_poly1305_encrypt(&key, &nonce, &aad, &plaintext).unwrap();

            assert_eq!(ciphertext.len(), plaintext.len());

            let decrypted =
                chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn chacha20_rejects_counter_exhaustion_at_block_boundary() {
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let input = [0_u8; 65];

        assert_eq!(
            chacha20_xor(&key, u32::MAX, &nonce, &input,),
            Err(ChaCha20Error::CounterExhausted {
                counter: u32::MAX,
                blocks: 2,
            })
        );
    }
}
