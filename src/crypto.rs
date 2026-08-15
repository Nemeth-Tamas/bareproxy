use std::{error::Error, fmt, io};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const BASE64_STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
        HexError, constant_time_eq, decode_hex, encode_base64, encode_base64_url_no_pad,
        encode_hex, fill_random,
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
}
