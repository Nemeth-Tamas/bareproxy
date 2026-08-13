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

pub const MAX_REQUEST_LINE_SIZE: usize = 8192;
pub const MAX_HEADER_SIZE: usize = 8192;
pub const MAX_HEADER_BLOCK_SIZE: usize = 32768;
pub const MAX_HEADER_COUNT: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_slice())
    }

    pub fn host(&self) -> Option<&str> {
        self.header("host")
            .and_then(|value| std::str::from_utf8(value).ok())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    IncompleteHeaders,
    InvalidRequestLine,
    InvalidHeader,
    RequestLineTooLong,
    HeaderTooLong,
    HeadersTooLarge,
    TooManyHeaders,
    UnsupportedVersion(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeaders => formatter.write_str("incomplete HTTP request headers"),
            Self::InvalidRequestLine => formatter.write_str("invalid HTTP request line"),
            Self::InvalidHeader => formatter.write_str("invalid HTTP header"),
            Self::RequestLineTooLong => formatter.write_str("HTTP request line is too long"),
            Self::HeaderTooLong => formatter.write_str("HTTP header is too long"),
            Self::HeadersTooLarge => formatter.write_str("HTTP header block is too large"),
            Self::TooManyHeaders => formatter.write_str("too many HTTP headers"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported HTTP version: {version}")
            }
        }
    }
}

impl Error for ParseError {}

pub fn parse_request(input: &[u8]) -> Result<Request, ParseError> {
    let header_end = find_bytes(input, b"\r\n\r\n").ok_or(ParseError::IncompleteHeaders)?;
    let request_line_end = find_bytes(input, b"\r\n").ok_or(ParseError::InvalidRequestLine)?;

    if request_line_end > header_end {
        return Err(ParseError::InvalidRequestLine);
    }

    if request_line_end > MAX_REQUEST_LINE_SIZE {
        return Err(ParseError::RequestLineTooLong);
    }

    let header_block = if request_line_end == header_end {
        &[]
    } else {
        let headers_start = request_line_end + 2;
        &input[headers_start..header_end]
    };

    if header_block.len() > MAX_HEADER_BLOCK_SIZE {
        return Err(ParseError::HeadersTooLarge);
    }

    let (method, target, version) = parse_request_line(&input[..request_line_end])?;
    let headers = parse_headers(header_block)?;

    Ok(Request {
        method,
        target,
        version,
        headers,
    })
}

fn parse_request_line(input: &[u8]) -> Result<(String, String, HttpVersion), ParseError> {
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

    Ok((method.to_owned(), target.to_owned(), version))
}

fn parse_headers(input: &[u8]) -> Result<Vec<Header>, ParseError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut headers = Vec::new();
    let mut remaining = input;

    loop {
        let line_end = find_bytes(remaining, b"\r\n").unwrap_or(remaining.len());
        let line = &remaining[..line_end];

        if line.len() > MAX_HEADER_SIZE {
            return Err(ParseError::HeaderTooLong);
        }

        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ParseError::TooManyHeaders);
        }

        headers.push(parse_header(line)?);

        if line_end == remaining.len() {
            break;
        }

        remaining = &remaining[line_end + 2..];
    }

    Ok(headers)
}

fn parse_header(input: &[u8]) -> Result<Header, ParseError> {
    let separator = input
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(ParseError::InvalidHeader)?;

    let name = &input[..separator];
    let value = trim_optional_whitespace(&input[separator + 1..]);

    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return Err(ParseError::InvalidHeader);
    }

    if !value.iter().copied().all(is_valid_header_value_byte) {
        return Err(ParseError::InvalidHeader);
    }

    let name = std::str::from_utf8(name)
        .map_err(|_| ParseError::InvalidHeader)?
        .to_owned();

    Ok(Header {
        name,
        value: value.to_vec(),
    })
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }

    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }

    value
}

fn is_valid_header_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
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
    use super::{
        Header, HttpVersion, MAX_HEADER_BLOCK_SIZE, MAX_HEADER_COUNT, MAX_HEADER_SIZE,
        MAX_REQUEST_LINE_SIZE, ParseError, Request, parse_request,
    };

    #[test]
    fn parses_valid_get_request_and_headers() {
        assert_eq!(
            parse_request(
                b"GET /hello?name=bare HTTP/1.1\r\nHost: localhost\r\nUser-Agent: BareTest\r\n\r\n"
            ),
            Ok(Request {
                method: "GET".to_owned(),
                target: "/hello?name=bare".to_owned(),
                version: HttpVersion::Http11,
                headers: vec![
                    Header {
                        name: "Host".to_owned(),
                        value: b"localhost".to_vec(),
                    },
                    Header {
                        name: "User-Agent".to_owned(),
                        value: b"BareTest".to_vec(),
                    },
                ],
            })
        );
    }

    #[test]
    fn parses_request_without_headers() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\n\r\n"),
            Ok(Request {
                method: "GET".to_owned(),
                target: "/".to_owned(),
                version: HttpVersion::Http11,
                headers: Vec::new(),
            })
        );
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let request = parse_request(b"GET / HTTP/1.1\r\nHoSt: example.test\r\n\r\n").unwrap();

        assert_eq!(request.header("host"), Some(b"example.test".as_slice()));
        assert_eq!(request.header("HOST"), Some(b"example.test".as_slice()));
    }

    #[test]
    fn parses_host_header() {
        let request = parse_request(b"GET / HTTP/1.1\r\nHost: example.test:8080\r\n\r\n").unwrap();

        assert_eq!(request.host(), Some("example.test:8080"));
    }

    #[test]
    fn trims_optional_header_whitespace() {
        let request = parse_request(b"GET / HTTP/1.1\r\nHost:\t  example.test \t\r\n\r\n").unwrap();

        assert_eq!(request.header("host"), Some(b"example.test".as_slice()));
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

    #[test]
    fn rejects_header_without_colon() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n"),
            Err(ParseError::InvalidHeader)
        );
    }

    #[test]
    fn rejects_invalid_header_name() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost Name: localhost\r\n\r\n"),
            Err(ParseError::InvalidHeader)
        );
    }

    #[test]
    fn rejects_control_byte_in_header_value() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: local\x01host\r\n\r\n"),
            Err(ParseError::InvalidHeader)
        );
    }

    #[test]
    fn rejects_oversized_request_line() {
        let target = format!("/{}", "a".repeat(MAX_REQUEST_LINE_SIZE));
        let request = format!("GET {target} HTTP/1.1\r\n\r\n");

        assert_eq!(
            parse_request(request.as_bytes()),
            Err(ParseError::RequestLineTooLong)
        );
    }

    #[test]
    fn rejects_oversized_individual_header() {
        let value = "a".repeat(MAX_HEADER_SIZE);
        let request = format!("GET / HTTP/1.1\r\nX-Test: {value}\r\n\r\n");

        assert_eq!(
            parse_request(request.as_bytes()),
            Err(ParseError::HeaderTooLong)
        );
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut request = String::from("GET / HTTP/1.1\r\n");

        for index in 0..=MAX_HEADER_COUNT {
            request.push_str(&format!("X-{index}: a\r\n"));
        }

        request.push_str("\r\n");

        assert_eq!(
            parse_request(request.as_bytes()),
            Err(ParseError::TooManyHeaders)
        );
    }

    #[test]
    fn rejects_oversized_header_block() {
        let mut request = String::from("GET / HTTP/1.1\r\n");
        let value = "a".repeat(MAX_HEADER_SIZE - 20);

        while request.len() < MAX_HEADER_BLOCK_SIZE + MAX_REQUEST_LINE_SIZE {
            request.push_str(&format!("X-Test: {value}\r\n"));
        }

        request.push_str("\r\n");

        assert_eq!(
            parse_request(request.as_bytes()),
            Err(ParseError::HeadersTooLarge)
        );
    }
}
