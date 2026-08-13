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
pub const MAX_REQUEST_HEAD_SIZE: usize = MAX_REQUEST_LINE_SIZE + 2 + MAX_HEADER_BLOCK_SIZE + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[expect(
    dead_code,
    reason = "error status variants are staged for upcoming routing and proxy milestones"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Ok,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    ContentTooLarge,
    RequestHeaderFieldsTooLarge,
    InternalServerError,
    BadGateway,
    ServiceUnavailable,
}

impl StatusCode {
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::ContentTooLarge => 413,
            Self::RequestHeaderFieldsTooLarge => 431,
            Self::InternalServerError => 500,
            Self::BadGateway => 502,
            Self::ServiceUnavailable => 503,
        }
    }

    pub const fn reason_phrase(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::ContentTooLarge => "Content Too Large",
            Self::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            Self::InternalServerError => "Internal Server Error",
            Self::BadGateway => "Bad Gateway",
            Self::ServiceUnavailable => "Service Unavailable",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseError {
    InvalidHeaderName,
    InvalidHeaderValue,
    ManagedHeader(String),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderName => formatter.write_str("invalid HTTP response header name"),
            Self::InvalidHeaderValue => formatter.write_str("invalid HTTP response header value"),
            Self::ManagedHeader(name) => {
                write!(formatter, "BareProxy manages response header: {name}")
            }
        }
    }
}

impl Error for ResponseError {}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    status: StatusCode,
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl Response {
    pub fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &[u8]) -> Result<Self, ResponseError> {
        validate_response_header(name, value)?;

        self.headers.push(Header {
            name: name.to_owned(),
            value: value.to_vec(),
        });

        Ok(self)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ResponseError> {
        for header in &self.headers {
            validate_response_header(&header.name, &header.value)?;
        }

        let mut output = Vec::new();

        output.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status.code(),
                self.status.reason_phrase()
            )
            .as_bytes(),
        );

        for header in &self.headers {
            output.extend_from_slice(header.name.as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(&header.value);
            output.extend_from_slice(b"\r\n");
        }

        output.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(&self.body);

        Ok(output)
    }
}

fn validate_response_header(name: &str, value: &[u8]) -> Result<(), ResponseError> {
    if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
    {
        return Err(ResponseError::ManagedHeader(name.to_owned()));
    }

    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(ResponseError::InvalidHeaderName);
    }

    if !value.iter().copied().all(is_valid_header_value_byte) {
        return Err(ResponseError::InvalidHeaderValue);
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
    pub content_length: Option<u64>,
    pub has_transfer_encoding: bool,
    pub keep_alive: bool,
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
    InvalidContentLength,
    ConflictingContentLength,
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
            Self::InvalidContentLength => formatter.write_str("invalid Content-Length"),
            Self::ConflictingContentLength => {
                formatter.write_str("conflicting Content-Length values")
            }
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

#[cfg(test)]
pub fn parse_request(input: &[u8]) -> Result<Request, ParseError> {
    parse_request_with_consumed(input).map(|(request, _)| request)
}

pub fn parse_request_with_consumed(input: &[u8]) -> Result<(Request, usize), ParseError> {
    let request_line_end = match find_bytes(input, b"\r\n") {
        Some(index) => index,
        None if input.len() > MAX_REQUEST_LINE_SIZE => {
            return Err(ParseError::RequestLineTooLong);
        }
        None => return Err(ParseError::IncompleteHeaders),
    };

    if request_line_end > MAX_REQUEST_LINE_SIZE {
        return Err(ParseError::RequestLineTooLong);
    }

    let header_end = match find_bytes(input, b"\r\n\r\n") {
        Some(index) => index,
        None if input.len() >= MAX_REQUEST_HEAD_SIZE => {
            return Err(ParseError::HeadersTooLarge);
        }
        None => return Err(ParseError::IncompleteHeaders),
    };

    if request_line_end > header_end {
        return Err(ParseError::InvalidRequestLine);
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
    let content_length = parse_content_length(&headers)?;
    let has_transfer_encoding = has_header(&headers, "transfer-encoding");
    let keep_alive = !header_contains_token(&headers, "connection", b"close");
    let bytes_consumed = header_end + 4;

    Ok((
        Request {
            method,
            target,
            version,
            headers,
            content_length,
            has_transfer_encoding,
            keep_alive,
        },
        bytes_consumed,
    ))
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

fn parse_content_length(headers: &[Header]) -> Result<Option<u64>, ParseError> {
    let mut content_length = None;

    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let value =
            std::str::from_utf8(&header.value).map_err(|_| ParseError::InvalidContentLength)?;

        for value in value.split(',') {
            let value = value.trim_matches(|character| character == ' ' || character == '\t');

            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ParseError::InvalidContentLength);
            }

            let parsed = value
                .parse::<u64>()
                .map_err(|_| ParseError::InvalidContentLength)?;

            match content_length {
                Some(existing) if existing != parsed => {
                    return Err(ParseError::ConflictingContentLength);
                }
                Some(_) => {}
                None => content_length = Some(parsed),
            }
        }
    }

    Ok(content_length)
}

fn has_header(headers: &[Header], name: &str) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case(name))
}

fn header_contains_token(headers: &[Header], name: &str, token: &[u8]) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .any(|header| {
            header
                .value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|value| value.eq_ignore_ascii_case(token))
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
        MAX_REQUEST_LINE_SIZE, ParseError, Request, Response, ResponseError, StatusCode,
        parse_request,
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
                content_length: None,
                has_transfer_encoding: false,
                keep_alive: true,
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
                content_length: None,
                has_transfer_encoding: false,
                keep_alive: true,
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

    #[test]
    fn parses_content_length() {
        let request = parse_request(b"POST / HTTP/1.1\r\nContent-Length: 123\r\n\r\n").unwrap();

        assert_eq!(request.content_length, Some(123));
    }

    #[test]
    fn accepts_repeated_identical_content_length() {
        let request =
            parse_request(b"POST / HTTP/1.1\r\nContent-Length: 123\r\nContent-Length: 123\r\n\r\n")
                .unwrap();

        assert_eq!(request.content_length, Some(123));
    }

    #[test]
    fn rejects_conflicting_content_length() {
        assert_eq!(
            parse_request(b"POST / HTTP/1.1\r\nContent-Length: 123\r\nContent-Length: 124\r\n\r\n"),
            Err(ParseError::ConflictingContentLength)
        );
    }

    #[test]
    fn rejects_invalid_content_length() {
        assert_eq!(
            parse_request(b"POST / HTTP/1.1\r\nContent-Length: potato\r\n\r\n"),
            Err(ParseError::InvalidContentLength)
        );
    }

    #[test]
    fn detects_transfer_encoding() {
        let request =
            parse_request(b"POST / HTTP/1.1\r\nTrAnSfEr-EnCoDiNg: chunked\r\n\r\n").unwrap();

        assert!(request.has_transfer_encoding);
    }

    #[test]
    fn http_11_is_persistent_by_default() {
        let request = parse_request(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();

        assert!(request.keep_alive);
    }

    #[test]
    fn connection_close_disables_persistence() {
        let request =
            parse_request(b"GET / HTTP/1.1\r\nConnection: keep-alive, CLOSE\r\n\r\n").unwrap();

        assert!(!request.keep_alive);
    }

    #[test]
    fn serializes_response_headers_and_body() {
        let response = Response::new(StatusCode::Ok, b"hello".to_vec())
            .with_header("Content-Type", b"text/plain")
            .unwrap()
            .with_header("Connection", b"close")
            .unwrap()
            .serialize()
            .unwrap();

        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Connection: close\r\n\
Content-Length: 5\r\n\
\r\n\
hello"
        );
    }

    #[test]
    fn serializes_all_planned_status_codes() {
        let cases = [
            (StatusCode::Ok, "200 OK"),
            (StatusCode::BadRequest, "400 Bad Request"),
            (StatusCode::NotFound, "404 Not Found"),
            (StatusCode::MethodNotAllowed, "405 Method Not Allowed"),
            (StatusCode::ContentTooLarge, "413 Content Too Large"),
            (
                StatusCode::RequestHeaderFieldsTooLarge,
                "431 Request Header Fields Too Large",
            ),
            (StatusCode::InternalServerError, "500 Internal Server Error"),
            (StatusCode::BadGateway, "502 Bad Gateway"),
            (StatusCode::ServiceUnavailable, "503 Service Unavailable"),
        ];

        for (status, expected) in cases {
            let response = Response::new(status, Vec::new()).serialize().unwrap();
            let status_line_end = response
                .windows(2)
                .position(|window| window == b"\r\n")
                .unwrap();

            assert_eq!(
                &response[..status_line_end],
                format!("HTTP/1.1 {expected}").as_bytes()
            );
        }
    }

    #[test]
    fn serializer_calculates_content_length_from_body() {
        let response = Response::new(StatusCode::Ok, vec![0, 1, 2, 3, 4, 5, 6])
            .serialize()
            .unwrap();

        assert!(
            response
                .windows(b"Content-Length: 7\r\n".len())
                .any(|window| window == b"Content-Length: 7\r\n")
        );
    }

    #[test]
    fn rejects_invalid_response_header_name() {
        assert_eq!(
            Response::new(StatusCode::Ok, Vec::new()).with_header("Bad Header", b"value"),
            Err(ResponseError::InvalidHeaderName)
        );
    }

    #[test]
    fn rejects_response_header_injection() {
        assert_eq!(
            Response::new(StatusCode::Ok, Vec::new())
                .with_header("X-Test", b"safe\r\nInjected: absolutely-not"),
            Err(ResponseError::InvalidHeaderValue)
        );
    }

    #[test]
    fn rejects_caller_supplied_content_length() {
        assert_eq!(
            Response::new(StatusCode::Ok, Vec::new()).with_header("Content-Length", b"9001"),
            Err(ResponseError::ManagedHeader("Content-Length".to_owned()))
        );
    }

    #[test]
    fn rejects_caller_supplied_transfer_encoding() {
        assert_eq!(
            Response::new(StatusCode::Ok, Vec::new()).with_header("Transfer-Encoding", b"chunked"),
            Err(ResponseError::ManagedHeader("Transfer-Encoding".to_owned()))
        );
    }
}
