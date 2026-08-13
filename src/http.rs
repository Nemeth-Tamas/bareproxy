use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http11 => formatter.write_str("HTTP/1.1"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    IncompleteHeaders,
    InvalidRequestLine,
    UnsupportedVersion(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeaders => formatter.write_str("incomplete HTTP request headers"),
            Self::InvalidRequestLine => formatter.write_str("invalid HTTP request line"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported HTTP version: {version}")
            }
        }
    }
}

impl Error for ParseError {}

pub fn parse_request(input: &[u8]) -> Result<Request, ParseError> {
    let header_end = find_bytes(input, b"\r\n\r\n").ok_or(ParseError::IncompleteHeaders)?;

    let header_block = &input[..header_end];
    let request_line_end =
        find_bytes(header_block, b"\r\n").ok_or(ParseError::InvalidRequestLine)?;

    parse_request_line(&header_block[..request_line_end])
}

fn parse_request_line(input: &[u8]) -> Result<Request, ParseError> {
    let request_line = std::str::from_utf8(input).map_err(|_| ParseError::InvalidRequestLine)?;

    let mut parts = request_line.split(' ');

    let method = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    let target = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    let version = parts.next().ok_or(ParseError::InvalidRequestLine)?;

    if parts.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || !is_valid_method(method)
        || !is_valid_target(target)
    {
        return Err(ParseError::InvalidRequestLine);
    }

    let version = match version {
        "HTTP/1.1" => HttpVersion::Http11,
        version if version.starts_with("HTTP/") => {
            return Err(ParseError::UnsupportedVersion(version.to_owned()));
        }
        _ => return Err(ParseError::InvalidRequestLine),
    };

    Ok(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        version,
    })
}

fn is_valid_method(method: &str) -> bool {
    method.bytes().all(is_token_byte)
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn is_valid_target(target: &str) -> bool {
    target
        .bytes()
        .all(|byte| !byte.is_ascii_control() && byte != b' ')
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{HttpVersion, ParseError, Request, parse_request};

    #[test]
    fn parses_valid_get_request_line() {
        assert_eq!(
            parse_request(b"GET /hello?name=bare HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Ok(Request {
                method: "GET".to_owned(),
                target: "/hello?name=bare".to_owned(),
                version: HttpVersion::Http11,
            })
        );
    }

    #[test]
    fn detects_incomplete_header_block() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: localhost\r\n"),
            Err(ParseError::IncompleteHeaders)
        );
    }

    #[test]
    fn rejects_request_line_with_missing_target() {
        assert_eq!(
            parse_request(b"GET HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Err(ParseError::InvalidRequestLine)
        );
    }

    #[test]
    fn rejects_request_line_with_extra_separator() {
        assert_eq!(
            parse_request(b"GET  / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Err(ParseError::InvalidRequestLine)
        );
    }

    #[test]
    fn rejects_unsupported_http_version() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
            Err(ParseError::UnsupportedVersion("HTTP/1.0".to_owned()))
        );
    }
}
