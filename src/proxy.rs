use std::{
    error::Error,
    fmt,
    io::{Read, Write},
    net::{IpAddr, TcpStream},
};

use crate::{config, http};

#[derive(Debug, PartialEq, Eq)]
pub enum ProxyError {
    MissingHost,
    Connect { address: String, message: String },
    Write { message: String },
    Read { message: String },
    EmptyResponse,
    IncompleteResponse,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHost => formatter.write_str("request has no Host header"),
            Self::Connect { address, message } => {
                write!(
                    formatter,
                    "failed to connect to upstream {address}: {message}"
                )
            }
            Self::Write { message } => {
                write!(formatter, "failed to write request to upstream: {message}")
            }
            Self::Read { message } => {
                write!(
                    formatter,
                    "failed to read response from upstream: {message}"
                )
            }
            Self::EmptyResponse => formatter.write_str("upstream closed without a response"),
            Self::IncompleteResponse => {
                formatter.write_str("upstream disconnected before completing its HTTP response")
            }
        }
    }
}

impl Error for ProxyError {}

pub fn exchange(
    route: &config::Route,
    request: &http::Request,
    request_body: &[u8],
    client_ip: IpAddr,
) -> Result<Vec<u8>, ProxyError> {
    let address = route.upstream().address();

    let mut upstream = TcpStream::connect(&address).map_err(|source| ProxyError::Connect {
        address,
        message: source.to_string(),
    })?;

    let request_head = serialize_request_head(request, client_ip)?;

    upstream
        .write_all(&request_head)
        .map_err(|source| ProxyError::Write {
            message: source.to_string(),
        })?;

    if !request_body.is_empty() {
        upstream
            .write_all(request_body)
            .map_err(|source| ProxyError::Write {
                message: source.to_string(),
            })?;
    }

    upstream.flush().map_err(|source| ProxyError::Write {
        message: source.to_string(),
    })?;

    let mut response = Vec::new();

    upstream
        .read_to_end(&mut response)
        .map_err(|source| ProxyError::Read {
            message: source.to_string(),
        })?;

    if response.is_empty() {
        return Err(ProxyError::EmptyResponse);
    }

    validate_response_completion(&response, &request.method)?;

    Ok(response)
}

fn validate_response_completion(response: &[u8], request_method: &str) -> Result<(), ProxyError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ProxyError::IncompleteResponse)?;

    if request_method.eq_ignore_ascii_case("HEAD") {
        return Ok(());
    }

    if let Some(content_length) = response_content_length(&response[..header_end]) {
        let body_length = response.len().saturating_sub(header_end + 4) as u64;

        if body_length < content_length {
            return Err(ProxyError::IncompleteResponse);
        }
    }

    Ok(())
}

fn response_content_length(headers: &[u8]) -> Option<u64> {
    for line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let separator = line.iter().position(|byte| *byte == b':')?;

        let name = &line[..separator];

        if !name.eq_ignore_ascii_case(b"content-length") {
            continue;
        }

        let value = trim_optional_whitespace(&line[separator + 1..]);
        let value = std::str::from_utf8(value).ok()?;

        return value.parse::<u64>().ok();
    }

    None
}

fn serialize_request_head(
    request: &http::Request,
    client_ip: IpAddr,
) -> Result<Vec<u8>, ProxyError> {
    let original_host = request.host().ok_or(ProxyError::MissingHost)?;

    let mut output = Vec::new();

    output.extend_from_slice(request.method.as_bytes());
    output.push(b' ');
    output.extend_from_slice(request.target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\n");

    for header in &request.headers {
        if should_replace_header(request, &header.name) {
            continue;
        }

        output.extend_from_slice(header.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(&header.value);
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"Host: ");
    output.extend_from_slice(original_host.as_bytes());
    output.extend_from_slice(b"\r\n");

    if let Some(content_length) = request.content_length {
        output.extend_from_slice(format!("Content-Length: {content_length}\r\n").as_bytes());
    }

    output.extend_from_slice(b"X-Forwarded-For: ");
    output.extend_from_slice(client_ip.to_string().as_bytes());
    output.extend_from_slice(b"\r\n");

    output.extend_from_slice(b"X-Forwarded-Host: ");
    output.extend_from_slice(original_host.as_bytes());
    output.extend_from_slice(b"\r\n");

    output.extend_from_slice(b"X-Forwarded-Proto: http\r\n");
    output.extend_from_slice(b"Connection: close\r\n");
    output.extend_from_slice(b"\r\n");

    Ok(output)
}

fn should_replace_header(request: &http::Request, name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || named_by_connection_header(request, name)
}

fn named_by_connection_header(request: &http::Request, name: &str) -> bool {
    request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .any(|header| {
            header
                .value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|token| token.eq_ignore_ascii_case(name.as_bytes()))
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

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{IpAddr, TcpListener},
        thread,
    };

    use crate::{config, http};

    use super::{ProxyError, exchange, serialize_request_head};

    #[test]
    fn serializes_request_for_upstream() {
        let request = http::parse_request_with_consumed(
            b"GET /hello?q=1 HTTP/1.1\r\n\
Host: Example.Test:8080\r\n\
User-Agent: BareTest\r\n\
Connection: keep-alive, X-Remove\r\n\
X-Remove: nope\r\n\
X-Forwarded-For: spoofed\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let serialized = serialize_request_head(&request, IpAddr::from([127, 0, 0, 42])).unwrap();

        let serialized = String::from_utf8(serialized).unwrap();

        assert!(serialized.starts_with("GET /hello?q=1 HTTP/1.1\r\n"));
        assert!(serialized.contains("User-Agent: BareTest\r\n"));
        assert!(serialized.contains("Host: Example.Test:8080\r\n"));
        assert!(serialized.contains("X-Forwarded-For: 127.0.0.42\r\n"));
        assert!(serialized.contains("X-Forwarded-Host: Example.Test:8080\r\n"));
        assert!(serialized.contains("X-Forwarded-Proto: http\r\n"));
        assert!(serialized.contains("Connection: close\r\n"));

        assert!(!serialized.contains("X-Remove: nope"));
        assert!(!serialized.contains("X-Forwarded-For: spoofed"));
        assert!(!serialized.contains("Connection: keep-alive"));
    }

    #[test]
    fn exchanges_request_with_local_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];

            loop {
                let bytes_read = stream.read(&mut chunk).unwrap();

                if bytes_read == 0 {
                    break;
                }

                request.extend_from_slice(&chunk[..bytes_read]);

                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let request = String::from_utf8(request).unwrap();

            assert!(request.starts_with("GET /through HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("Connection: close\r\n"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 15\r\n\
Connection: close\r\n\
\r\n\
upstream works\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request =
            http::parse_request_with_consumed(b"GET /through HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap()
                .0;

        let response = exchange(route, &request, &[], IpAddr::from([127, 0, 0, 1])).unwrap();

        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"upstream works\n"));
    }

    #[test]
    fn rejects_truncated_upstream_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = [0_u8; 1024];

            let _ = stream.read(&mut request).unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 100\r\n\
Connection: close\r\n\
\r\n\
tiny",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request =
            http::parse_request_with_consumed(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap()
                .0;

        let result = exchange(route, &request, &[], IpAddr::from([127, 0, 0, 1]));

        upstream_thread.join().unwrap();

        assert_eq!(result, Err(ProxyError::IncompleteResponse));
    }
}
