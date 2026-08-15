use std::{error::Error, fmt, io};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const BASE64_STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_LENGTH_OFFSET: usize = 56;

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

            if self.buffer_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;

                self.compress_block(&block);
                self.buffer_len = 0;
            }
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
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the SHA-256 digest of an entire byte slice.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(input);

    hasher.finalize()
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
        HexError, Sha256, constant_time_eq, decode_hex, encode_base64, encode_base64_url_no_pad,
        encode_hex, fill_random, sha256,
    };

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
}
