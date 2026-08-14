use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs},
    thread,
    time::{Duration, Instant},
};

use crate::{config, http};

const STREAM_BUFFER_SIZE: usize = 16 * 1024;
const MAX_RESPONSE_HEAD_SIZE: usize = 64 * 1024;
const MAX_CHUNK_LINE_SIZE: usize = 8192;
const MAX_TRAILER_LINE_SIZE: usize = 8192;
const MAX_TRAILER_BLOCK_SIZE: usize = 32 * 1024;
const MAX_TRAILER_COUNT: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum ProxyError {
    MissingHost,
    Connect {
        address: String,
        kind: io::ErrorKind,
        message: String,
    },
    Write {
        kind: io::ErrorKind,
        message: String,
    },
    Read {
        kind: io::ErrorKind,
        message: String,
    },
    ClientRead {
        kind: io::ErrorKind,
        message: String,
    },
    InvalidClientBody {
        message: String,
    },
    EmptyResponse,
    IncompleteResponse,
    InvalidUpstreamResponse {
        message: String,
    },
    ResponseStarted {
        message: String,
    },
    Tunnel {
        message: String,
    },
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHost => formatter.write_str("request has no Host header"),
            Self::Connect {
                address, message, ..
            } => {
                write!(
                    formatter,
                    "failed to connect to upstream {address}: {message}"
                )
            }
            Self::Write { message, .. } => {
                write!(formatter, "failed to write request to upstream: {message}")
            }
            Self::Read { message, .. } => {
                write!(
                    formatter,
                    "failed to read response from upstream: {message}"
                )
            }
            Self::ClientRead { message, .. } => {
                write!(
                    formatter,
                    "failed to read request body from client: {message}"
                )
            }
            Self::InvalidClientBody { message } => {
                write!(formatter, "invalid chunked request body: {message}")
            }
            Self::EmptyResponse => formatter.write_str("upstream closed without a response"),
            Self::IncompleteResponse => {
                formatter.write_str("upstream disconnected before completing its HTTP response")
            }
            Self::InvalidUpstreamResponse { message } => {
                write!(formatter, "invalid upstream HTTP response: {message}")
            }
            Self::ResponseStarted { message } => {
                write!(
                    formatter,
                    "upstream failed after response started: {message}"
                )
            }
            Self::Tunnel { message } => {
                write!(formatter, "upgraded connection tunnel failed: {message}")
            }
        }
    }
}

impl Error for ProxyError {}

impl ProxyError {
    pub fn is_upstream_timeout(&self) -> bool {
        match self {
            Self::Connect { kind, .. } | Self::Write { kind, .. } | Self::Read { kind, .. } => {
                is_timeout_kind(*kind)
            }
            _ => false,
        }
    }
}

fn is_timeout_kind(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseTransferFraming {
    None,
    CloseDelimited,
    Chunked,
}

#[derive(Debug, PartialEq, Eq)]
enum ContinueOutcome {
    Continue(Vec<u8>),
    FinalResponseForwarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardResponseOutcome {
    Http { client_reusable: bool },
    Upgraded,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExchangeResult {
    pub buffered_client_bytes: Vec<u8>,
    pub client_reusable: bool,
    pub upgraded: bool,
}

fn connect_upstream(address: &str, timeout: Duration) -> Result<TcpStream, ProxyError> {
    let socket_addresses = address
        .to_socket_addrs()
        .map_err(|source| ProxyError::Connect {
            address: address.to_owned(),
            kind: source.kind(),
            message: source.to_string(),
        })?;

    let started = Instant::now();
    let mut last_error = None;
    let mut resolved_address = false;

    for socket_address in socket_addresses {
        resolved_address = true;

        let elapsed = started.elapsed();

        if elapsed >= timeout {
            return Err(ProxyError::Connect {
                address: address.to_owned(),
                kind: io::ErrorKind::TimedOut,
                message: "upstream connection timed out".to_owned(),
            });
        }

        let remaining = timeout - elapsed;

        match TcpStream::connect_timeout(&socket_address, remaining) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .and_then(|()| stream.set_write_timeout(Some(timeout)))
                    .map_err(|source| ProxyError::Connect {
                        address: address.to_owned(),
                        kind: source.kind(),
                        message: source.to_string(),
                    })?;

                return Ok(stream);
            }
            Err(source) if is_timeout_kind(source.kind()) => {
                return Err(ProxyError::Connect {
                    address: address.to_owned(),
                    kind: io::ErrorKind::TimedOut,
                    message: source.to_string(),
                });
            }
            Err(source) => {
                last_error = Some((source.kind(), source.to_string()));
            }
        }
    }

    if !resolved_address {
        return Err(ProxyError::Connect {
            address: address.to_owned(),
            kind: io::ErrorKind::AddrNotAvailable,
            message: "upstream address resolved to no endpoints".to_owned(),
        });
    }

    let (kind, message) = last_error.unwrap_or((
        io::ErrorKind::Other,
        "failed to connect to upstream".to_owned(),
    ));

    Err(ProxyError::Connect {
        address: address.to_owned(),
        kind,
        message,
    })
}

struct UpstreamConnection {
    address: String,
    stream: TcpStream,
}

pub struct Session {
    upstream: Option<UpstreamConnection>,
    upgraded_upstream: Option<TcpStream>,
    upstream_timeout: Duration,
}

impl Session {
    pub fn new(upstream_timeout_seconds: u64) -> Self {
        Self {
            upstream: None,
            upgraded_upstream: None,
            upstream_timeout: Duration::from_secs(upstream_timeout_seconds),
        }
    }

    pub fn exchange<S>(
        &mut self,
        route: &config::Route,
        request: &http::Request,
        client: &mut S,
        buffered_body: &[u8],
        client_ip: IpAddr,
    ) -> Result<ExchangeResult, ProxyError>
    where
        S: Read + Write,
    {
        let requested_upgrade_protocols = request_upgrade_protocols(request)?;
        let address = route.upstream().address();

        let mut upstream_connection = match self.upstream.take() {
            Some(connection) if connection.address == address => {
                println!("Reusing upstream connection to {address}");
                connection
            }
            Some(_) | None => {
                println!("Opening upstream connection to {address}");

                let stream = connect_upstream(&address, self.upstream_timeout)?;

                UpstreamConnection { address, stream }
            }
        };

        let upstream = &mut upstream_connection.stream;

        let request_head = serialize_request_head(request, client_ip)?;

        upstream
            .write_all(&request_head)
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        let buffered_response = if request_expects_continue(request) && request_has_body(request) {
            upstream.flush().map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;

            match await_continue_or_final_response(
                upstream,
                client,
                &request.method,
                requested_upgrade_protocols.as_deref(),
            )? {
                ContinueOutcome::Continue(buffered) => buffered,
                ContinueOutcome::FinalResponseForwarded => {
                    return Ok(ExchangeResult {
                        buffered_client_bytes: Vec::new(),
                        client_reusable: false,
                        upgraded: false,
                    });
                }
            }
        } else {
            Vec::new()
        };

        let buffered_client_bytes = if request.has_transfer_encoding {
            stream_chunked_request_body(client, upstream, buffered_body)?
        } else if let Some(content_length) = request.content_length {
            stream_request_body(client, upstream, content_length, buffered_body)?
        } else {
            buffered_body.to_vec()
        };

        upstream.flush().map_err(|source| ProxyError::Write {
            kind: source.kind(),
            message: source.to_string(),
        })?;

        let response_outcome = forward_response(
            upstream,
            client,
            &request.method,
            &buffered_response,
            requested_upgrade_protocols.as_deref(),
        )?;

        match response_outcome {
            ForwardResponseOutcome::Http { client_reusable } => {
                if client_reusable {
                    self.upstream = Some(upstream_connection);
                }

                Ok(ExchangeResult {
                    buffered_client_bytes,
                    client_reusable,
                    upgraded: false,
                })
            }
            ForwardResponseOutcome::Upgraded => {
                self.upgraded_upstream = Some(upstream_connection.stream);

                Ok(ExchangeResult {
                    buffered_client_bytes,
                    client_reusable: false,
                    upgraded: true,
                })
            }
        }
    }

    pub fn tunnel_upgraded(
        &mut self,
        client: &mut TcpStream,
        buffered_client_bytes: Vec<u8>,
    ) -> Result<(), ProxyError> {
        let mut upstream = self
            .upgraded_upstream
            .take()
            .ok_or_else(|| ProxyError::Tunnel {
                message: "no upgraded upstream connection is available".to_owned(),
            })?;

        client
            .set_read_timeout(None)
            .and_then(|()| client.set_write_timeout(None))
            .map_err(|source| ProxyError::Tunnel {
                message: source.to_string(),
            })?;

        upstream
            .set_read_timeout(None)
            .and_then(|()| upstream.set_write_timeout(None))
            .map_err(|source| ProxyError::Tunnel {
                message: source.to_string(),
            })?;

        if !buffered_client_bytes.is_empty() {
            upstream
                .write_all(&buffered_client_bytes)
                .map_err(|source| ProxyError::Tunnel {
                    message: source.to_string(),
                })?;

            upstream.flush().map_err(|source| ProxyError::Tunnel {
                message: source.to_string(),
            })?;
        }

        let client_reader = client.try_clone().map_err(|source| ProxyError::Tunnel {
            message: source.to_string(),
        })?;

        let client_writer = client.try_clone().map_err(|source| ProxyError::Tunnel {
            message: source.to_string(),
        })?;

        let upstream_reader = upstream.try_clone().map_err(|source| ProxyError::Tunnel {
            message: source.to_string(),
        })?;

        let client_to_upstream =
            thread::spawn(move || copy_tunnel_direction(client_reader, upstream));

        let upstream_to_client = copy_tunnel_direction(upstream_reader, client_writer);

        if upstream_to_client.is_err() {
            let _ = client.shutdown(Shutdown::Both);
        }

        let client_to_upstream = client_to_upstream.join().map_err(|_| ProxyError::Tunnel {
            message: "client-to-upstream tunnel thread panicked".to_owned(),
        })?;

        upstream_to_client.map_err(|source| ProxyError::Tunnel {
            message: source.to_string(),
        })?;

        client_to_upstream.map_err(|source| ProxyError::Tunnel {
            message: source.to_string(),
        })?;

        Ok(())
    }
}

fn copy_tunnel_direction(mut reader: TcpStream, mut writer: TcpStream) -> io::Result<u64> {
    let result = io::copy(&mut reader, &mut writer);

    let _ = writer.shutdown(Shutdown::Write);

    result
}

#[cfg(test)]
fn exchange<S>(
    route: &config::Route,
    request: &http::Request,
    client: &mut S,
    buffered_body: &[u8],
    client_ip: IpAddr,
) -> Result<ExchangeResult, ProxyError>
where
    S: Read + Write,
{
    Session::new(30).exchange(route, request, client, buffered_body, client_ip)
}

struct PrefixedReader<'a, R> {
    prefix: &'a [u8],
    prefix_position: usize,
    inner: &'a mut R,
}

impl<'a, R> PrefixedReader<'a, R> {
    fn new(prefix: &'a [u8], inner: &'a mut R) -> Self {
        Self {
            prefix,
            prefix_position: 0,
            inner,
        }
    }

    fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.prefix_position..]
    }
}

impl<R: Read> Read for PrefixedReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        if self.prefix_position < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_position..];
            let bytes_read = remaining.len().min(output.len());

            output[..bytes_read].copy_from_slice(&remaining[..bytes_read]);
            self.prefix_position += bytes_read;

            return Ok(bytes_read);
        }

        self.inner.read(output)
    }
}

fn stream_chunked_request_body(
    client: &mut impl Read,
    upstream: &mut impl Write,
    buffered_body: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let mut reader = PrefixedReader::new(buffered_body, client);

    loop {
        let size_line = read_chunk_line(&mut reader, MAX_CHUNK_LINE_SIZE)?;
        let chunk_size = parse_chunk_size(&size_line)?;

        upstream
            .write_all(&size_line)
            .and_then(|()| upstream.write_all(b"\r\n"))
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        if chunk_size == 0 {
            stream_request_trailers(&mut reader, upstream)?;
            return Ok(reader.remaining_prefix().to_vec());
        }

        stream_chunk_data(&mut reader, upstream, chunk_size)?;

        let mut ending = [0_u8; 2];

        reader
            .read_exact(&mut ending)
            .map_err(|source| ProxyError::ClientRead {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        if ending != *b"\r\n" {
            return Err(ProxyError::InvalidClientBody {
                message: "chunk data is not followed by CRLF".to_owned(),
            });
        }

        upstream
            .write_all(b"\r\n")
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;
    }
}

fn stream_chunk_data(
    reader: &mut impl Read,
    upstream: &mut impl Write,
    mut remaining: u64,
) -> Result<(), ProxyError> {
    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];

    while remaining > 0 {
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();

        let bytes_read =
            reader
                .read(&mut buffer[..read_limit])
                .map_err(|source| ProxyError::ClientRead {
                    kind: source.kind(),
                    message: source.to_string(),
                })?;

        if bytes_read == 0 {
            return Err(ProxyError::ClientRead {
                kind: io::ErrorKind::UnexpectedEof,
                message: "client disconnected during chunk data".to_owned(),
            });
        }

        upstream
            .write_all(&buffer[..bytes_read])
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        remaining -= bytes_read as u64;
    }

    Ok(())
}

fn stream_request_trailers(
    reader: &mut impl Read,
    upstream: &mut impl Write,
) -> Result<(), ProxyError> {
    let mut trailer_count = 0;
    let mut trailer_bytes: usize = 0;

    loop {
        let line = read_chunk_line(reader, MAX_TRAILER_LINE_SIZE)?;

        trailer_bytes = trailer_bytes.checked_add(line.len() + 2).ok_or_else(|| {
            ProxyError::InvalidClientBody {
                message: "trailer section is too large".to_owned(),
            }
        })?;

        if trailer_bytes > MAX_TRAILER_BLOCK_SIZE {
            return Err(ProxyError::InvalidClientBody {
                message: "trailer section is too large".to_owned(),
            });
        }

        if line.is_empty() {
            upstream
                .write_all(b"\r\n")
                .map_err(|source| ProxyError::Write {
                    kind: source.kind(),
                    message: source.to_string(),
                })?;

            return Ok(());
        }

        if trailer_count >= MAX_TRAILER_COUNT {
            return Err(ProxyError::InvalidClientBody {
                message: "too many trailer fields".to_owned(),
            });
        }

        validate_trailer_line(&line)?;
        trailer_count += 1;

        upstream
            .write_all(&line)
            .and_then(|()| upstream.write_all(b"\r\n"))
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;
    }
}

fn read_chunk_line(reader: &mut impl Read, maximum_size: usize) -> Result<Vec<u8>, ProxyError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];

    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|source| ProxyError::ClientRead {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        match byte[0] {
            b'\r' => {
                reader
                    .read_exact(&mut byte)
                    .map_err(|source| ProxyError::ClientRead {
                        kind: source.kind(),
                        message: source.to_string(),
                    })?;

                if byte[0] != b'\n' {
                    return Err(ProxyError::InvalidClientBody {
                        message: "CR in chunk framing is not followed by LF".to_owned(),
                    });
                }

                return Ok(line);
            }
            b'\n' => {
                return Err(ProxyError::InvalidClientBody {
                    message: "bare LF in chunk framing".to_owned(),
                });
            }
            byte => {
                if line.len() >= maximum_size {
                    return Err(ProxyError::InvalidClientBody {
                        message: "chunk framing line is too long".to_owned(),
                    });
                }

                line.push(byte);
            }
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, ProxyError> {
    let extension_start = line.iter().position(|byte| *byte == b';');

    let (size, extension) = match extension_start {
        Some(index) => (&line[..index], Some(&line[index + 1..])),
        None => (line, None),
    };

    if size.is_empty() || !size.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProxyError::InvalidClientBody {
            message: "invalid hexadecimal chunk size".to_owned(),
        });
    }

    if let Some(extension) = extension
        && (extension.is_empty() || !extension.iter().copied().all(is_valid_chunk_extension_byte))
    {
        return Err(ProxyError::InvalidClientBody {
            message: "invalid chunk extension".to_owned(),
        });
    }

    let size = std::str::from_utf8(size).map_err(|_| ProxyError::InvalidClientBody {
        message: "invalid hexadecimal chunk size".to_owned(),
    })?;

    u64::from_str_radix(size, 16).map_err(|_| ProxyError::InvalidClientBody {
        message: "chunk size is too large".to_owned(),
    })
}

fn validate_trailer_line(line: &[u8]) -> Result<(), ProxyError> {
    let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
        ProxyError::InvalidClientBody {
            message: "invalid trailer field".to_owned(),
        }
    })?;

    let name = &line[..separator];
    let value = trim_optional_whitespace(&line[separator + 1..]);

    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return Err(ProxyError::InvalidClientBody {
            message: "invalid trailer field name".to_owned(),
        });
    }

    if is_forbidden_trailer_name(name) {
        return Err(ProxyError::InvalidClientBody {
            message: "forbidden trailer field".to_owned(),
        });
    }

    if !value.iter().copied().all(is_valid_trailer_value_byte) {
        return Err(ProxyError::InvalidClientBody {
            message: "invalid trailer field value".to_owned(),
        });
    }

    Ok(())
}

fn is_forbidden_trailer_name(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"trailer")
        || name.eq_ignore_ascii_case(b"upgrade")
}

fn is_valid_chunk_extension_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~')
}

fn is_valid_trailer_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
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

fn stream_request_body(
    client: &mut impl Read,
    upstream: &mut impl Write,
    content_length: u64,
    buffered_body: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let buffered_length = buffered_body.len().min(content_length as usize);
    let buffered_client_bytes = buffered_body[buffered_length..].to_vec();

    if buffered_length > 0 {
        upstream
            .write_all(&buffered_body[..buffered_length])
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;
    }

    let mut remaining = content_length.saturating_sub(buffered_length as u64);
    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];

    while remaining > 0 {
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();

        let bytes_read =
            client
                .read(&mut buffer[..read_limit])
                .map_err(|source| ProxyError::ClientRead {
                    kind: source.kind(),
                    message: source.to_string(),
                })?;

        if bytes_read == 0 {
            return Err(ProxyError::ClientRead {
                kind: io::ErrorKind::UnexpectedEof,
                message: "client disconnected before completing request body".to_owned(),
            });
        }

        upstream
            .write_all(&buffer[..bytes_read])
            .map_err(|source| ProxyError::Write {
                kind: source.kind(),
                message: source.to_string(),
            })?;

        remaining -= bytes_read as u64;
    }

    Ok(buffered_client_bytes)
}

fn request_expects_continue(request: &http::Request) -> bool {
    request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("expect"))
        .any(|header| {
            header
                .value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|expectation| expectation.eq_ignore_ascii_case(b"100-continue"))
        })
}

fn request_has_body(request: &http::Request) -> bool {
    request.has_transfer_encoding
        || request
            .content_length
            .is_some_and(|content_length| content_length > 0)
}

fn await_continue_or_final_response(
    upstream: &mut impl Read,
    client: &mut impl Write,
    request_method: &str,
    requested_upgrade_protocols: Option<&[Vec<u8>]>,
) -> Result<ContinueOutcome, ProxyError> {
    let mut buffered = Vec::new();

    loop {
        let (response_head, buffered_response) = read_response_head(upstream, &buffered)?;
        let status = response_status_code(&response_head)?;

        if status == 101 {
            return Err(ProxyError::InvalidUpstreamResponse {
                message: "101 Switching Protocols requires upgrade tunnelling".to_owned(),
            });
        }

        if status == 100 {
            let response_head = sanitize_response_head(&response_head, None, false, false)?;

            client
                .write_all(&response_head)
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            client
                .flush()
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            return Ok(ContinueOutcome::Continue(buffered_response));
        }

        if is_interim_response(status) {
            let response_head = sanitize_response_head(&response_head, None, false, false)?;

            client
                .write_all(&response_head)
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            client
                .flush()
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            buffered = buffered_response;
            continue;
        }

        let mut final_response = response_head;
        final_response.extend_from_slice(&buffered_response);

        forward_response(
            upstream,
            client,
            request_method,
            &final_response,
            requested_upgrade_protocols,
        )?;

        return Ok(ContinueOutcome::FinalResponseForwarded);
    }
}

fn forward_response(
    upstream: &mut impl Read,
    client: &mut impl Write,
    request_method: &str,
    buffered_prefix: &[u8],
    requested_upgrade_protocols: Option<&[Vec<u8>]>,
) -> Result<ForwardResponseOutcome, ProxyError> {
    let mut buffered = buffered_prefix.to_vec();

    loop {
        let (response_head, buffered_response_body) = read_response_head(upstream, &buffered)?;

        let status = response_status_code(&response_head)?;

        if status == 101 {
            let requested_upgrade_protocols =
                requested_upgrade_protocols.ok_or_else(|| ProxyError::InvalidUpstreamResponse {
                    message: "upstream switched protocols without a client Upgrade request"
                        .to_owned(),
                })?;

            validate_switching_protocols_response(&response_head, requested_upgrade_protocols)?;

            let response_head =
                sanitize_response_head(&response_head, Some(b"Upgrade"), false, true)?;

            client
                .write_all(&response_head)
                .and_then(|()| client.write_all(&buffered_response_body))
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            client
                .flush()
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            return Ok(ForwardResponseOutcome::Upgraded);
        }

        if is_interim_response(status) {
            let response_head = sanitize_response_head(&response_head, None, false, false)?;

            client
                .write_all(&response_head)
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            client
                .flush()
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            buffered = buffered_response_body;
            continue;
        }

        if response_has_no_body(request_method, status) {
            let client_reusable = response_allows_client_reuse(&response_head, false);
            let connection_header = downstream_connection_header(&response_head, client_reusable);

            let response_head =
                sanitize_response_head(&response_head, connection_header, false, false)?;

            client
                .write_all(&response_head)
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            client
                .flush()
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            return Ok(ForwardResponseOutcome::Http { client_reusable });
        }

        let header_bytes = &response_head[..response_head.len() - 4];
        let transfer_framing = response_transfer_framing(header_bytes)?;
        let content_length = response_content_length(header_bytes);

        if transfer_framing != ResponseTransferFraming::None && content_length.is_some() {
            return Err(ProxyError::InvalidUpstreamResponse {
                message: "response contains both Content-Length and Transfer-Encoding".to_owned(),
            });
        }

        let close_delimited =
            content_length.is_none() && transfer_framing != ResponseTransferFraming::Chunked;

        let client_reusable = response_allows_client_reuse(&response_head, close_delimited);
        let connection_header = downstream_connection_header(&response_head, client_reusable);

        let response_head = sanitize_response_head(
            &response_head,
            connection_header,
            transfer_framing == ResponseTransferFraming::Chunked,
            false,
        )?;

        client
            .write_all(&response_head)
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        match (transfer_framing, content_length) {
            (ResponseTransferFraming::Chunked, _) => {
                stream_chunked_response_body(upstream, client, &buffered_response_body)?;
            }
            (_, Some(content_length)) => {
                stream_fixed_response_body(
                    upstream,
                    client,
                    content_length,
                    &buffered_response_body,
                )?;
            }
            _ => {
                stream_close_delimited_response_body(upstream, client, &buffered_response_body)?;
            }
        }

        client
            .flush()
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        return Ok(ForwardResponseOutcome::Http { client_reusable });
    }
}

fn read_response_head(
    upstream: &mut impl Read,
    buffered_prefix: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
    let mut buffer = buffered_prefix.to_vec();
    let mut chunk = [0_u8; STREAM_BUFFER_SIZE];

    loop {
        if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = header_end + 4;
            let buffered_body = buffer[body_start..].to_vec();

            buffer.truncate(body_start);

            return Ok((buffer, buffered_body));
        }

        if buffer.len() >= MAX_RESPONSE_HEAD_SIZE {
            return Err(ProxyError::IncompleteResponse);
        }

        let remaining_capacity = MAX_RESPONSE_HEAD_SIZE - buffer.len();
        let read_limit = remaining_capacity.min(chunk.len());

        let bytes_read =
            upstream
                .read(&mut chunk[..read_limit])
                .map_err(|source| ProxyError::Read {
                    kind: source.kind(),
                    message: source.to_string(),
                })?;

        if bytes_read == 0 {
            if buffer.is_empty() {
                return Err(ProxyError::EmptyResponse);
            }

            return Err(ProxyError::IncompleteResponse);
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn sanitize_response_head(
    response_head: &[u8],
    connection_header: Option<&[u8]>,
    preserve_trailer_header: bool,
    preserve_upgrade_header: bool,
) -> Result<Vec<u8>, ProxyError> {
    let connection_tokens = response_connection_tokens(response_head)?;

    let mut lines = response_head.split(|byte| *byte == b'\n');

    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::InvalidUpstreamResponse {
            message: "response has no status line".to_owned(),
        })?;

    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);

    let mut output = Vec::new();

    output.extend_from_slice(status_line);
    output.extend_from_slice(b"\r\n");

    for line in response_head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if line.is_empty() {
            continue;
        }

        let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ProxyError::InvalidUpstreamResponse {
                message: "malformed response header".to_owned(),
            }
        })?;

        let name = &line[..separator];

        if should_remove_response_header(
            name,
            &connection_tokens,
            preserve_trailer_header,
            preserve_upgrade_header,
        ) {
            continue;
        }

        if name.eq_ignore_ascii_case(b"trailer") {
            validate_trailer_header_value(&line[separator + 1..]).map_err(|message| {
                ProxyError::InvalidUpstreamResponse {
                    message: message.to_owned(),
                }
            })?;
        }

        output.extend_from_slice(line);
        output.extend_from_slice(b"\r\n");
    }

    if let Some(connection_header) = connection_header {
        output.extend_from_slice(b"Connection: ");
        output.extend_from_slice(connection_header);
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");

    Ok(output)
}

fn response_connection_tokens(response_head: &[u8]) -> Result<Vec<Vec<u8>>, ProxyError> {
    let mut tokens = Vec::new();

    for line in response_head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if line.is_empty() {
            continue;
        }

        let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ProxyError::InvalidUpstreamResponse {
                message: "malformed response header".to_owned(),
            }
        })?;

        let name = &line[..separator];

        if !name.eq_ignore_ascii_case(b"connection") {
            continue;
        }

        for token in line[separator + 1..].split(|byte| *byte == b',') {
            let token = trim_optional_whitespace(token);

            if token.is_empty() || !token.iter().copied().all(is_token_byte) {
                return Err(ProxyError::InvalidUpstreamResponse {
                    message: "invalid Connection header token".to_owned(),
                });
            }

            if token.eq_ignore_ascii_case(b"content-length")
                || token.eq_ignore_ascii_case(b"transfer-encoding")
            {
                return Err(ProxyError::InvalidUpstreamResponse {
                    message: "Connection header names a response framing field".to_owned(),
                });
            }

            tokens.push(token.to_ascii_lowercase());
        }
    }

    Ok(tokens)
}

fn should_remove_response_header(
    name: &[u8],
    connection_tokens: &[Vec<u8>],
    preserve_trailer_header: bool,
    preserve_upgrade_header: bool,
) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"te")
        || (name.eq_ignore_ascii_case(b"trailer") && !preserve_trailer_header)
        || (name.eq_ignore_ascii_case(b"upgrade") && !preserve_upgrade_header)
        || connection_tokens.iter().any(|token| {
            name.eq_ignore_ascii_case(token)
                && !(preserve_upgrade_header
                    && name.eq_ignore_ascii_case(b"upgrade")
                    && token.eq_ignore_ascii_case(b"upgrade"))
        })
}

fn downstream_connection_header(
    response_head: &[u8],
    client_reusable: bool,
) -> Option<&'static [u8]> {
    if !client_reusable {
        return Some(b"close");
    }

    if response_head.starts_with(b"HTTP/1.0 ") {
        Some(b"keep-alive")
    } else {
        None
    }
}

fn response_allows_client_reuse(response_head: &[u8], close_delimited: bool) -> bool {
    if close_delimited || response_header_contains_token(response_head, b"connection", b"close") {
        return false;
    }

    if response_head.starts_with(b"HTTP/1.1 ") {
        return true;
    }

    response_header_contains_token(response_head, b"connection", b"keep-alive")
}

fn response_header_contains_token(response_head: &[u8], name: &[u8], token: &[u8]) -> bool {
    response_head
        .split(|byte| *byte == b'\n')
        .skip(1)
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let separator = line.iter().position(|byte| *byte == b':')?;

            if !line[..separator].eq_ignore_ascii_case(name) {
                return None;
            }

            Some(&line[separator + 1..])
        })
        .any(|value| {
            value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|candidate| candidate.eq_ignore_ascii_case(token))
        })
}

fn response_status_code(response_head: &[u8]) -> Result<u16, ProxyError> {
    let line_end = response_head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| ProxyError::InvalidUpstreamResponse {
            message: "response has no complete status line".to_owned(),
        })?;

    let status_line = &response_head[..line_end];

    let first_space = status_line
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| ProxyError::InvalidUpstreamResponse {
            message: "malformed response status line".to_owned(),
        })?;

    let second_space = status_line[first_space + 1..]
        .iter()
        .position(|byte| *byte == b' ')
        .map(|index| first_space + 1 + index)
        .ok_or_else(|| ProxyError::InvalidUpstreamResponse {
            message: "malformed response status line".to_owned(),
        })?;

    let version = &status_line[..first_space];
    let code = &status_line[first_space + 1..second_space];

    if version != b"HTTP/1.0" && version != b"HTTP/1.1" {
        return Err(ProxyError::InvalidUpstreamResponse {
            message: "unsupported upstream HTTP version".to_owned(),
        });
    }

    if code.len() != 3 || !code.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(ProxyError::InvalidUpstreamResponse {
            message: "invalid response status code".to_owned(),
        });
    }

    let status = u16::from(code[0] - b'0') * 100
        + u16::from(code[1] - b'0') * 10
        + u16::from(code[2] - b'0');

    if !(100..=599).contains(&status) {
        return Err(ProxyError::InvalidUpstreamResponse {
            message: "response status code is outside the valid range".to_owned(),
        });
    }

    Ok(status)
}

fn is_interim_response(status: u16) -> bool {
    (100..200).contains(&status) && status != 101
}

fn response_has_no_body(request_method: &str, status: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD") || matches!(status, 204 | 304)
}

fn stream_close_delimited_response_body(
    upstream: &mut impl Read,
    client: &mut impl Write,
    buffered_body: &[u8],
) -> Result<(), ProxyError> {
    if !buffered_body.is_empty() {
        client
            .write_all(buffered_body)
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;
    }

    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];

    loop {
        let bytes_read =
            upstream
                .read(&mut buffer)
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

        if bytes_read == 0 {
            return Ok(());
        }

        client
            .write_all(&buffer[..bytes_read])
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;
    }
}

fn stream_chunked_response_body(
    upstream: &mut impl Read,
    client: &mut impl Write,
    buffered_body: &[u8],
) -> Result<(), ProxyError> {
    let mut reader = PrefixedReader::new(buffered_body, upstream);

    loop {
        let size_line = read_response_chunk_line(&mut reader, MAX_CHUNK_LINE_SIZE)?;
        let chunk_size = parse_response_chunk_size(&size_line)?;

        client
            .write_all(&size_line)
            .and_then(|()| client.write_all(b"\r\n"))
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        if chunk_size == 0 {
            stream_response_trailers(&mut reader, client)?;
            return Ok(());
        }

        stream_response_chunk_data(&mut reader, client, chunk_size)?;

        let mut ending = [0_u8; 2];

        reader
            .read_exact(&mut ending)
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        if ending != *b"\r\n" {
            return Err(ProxyError::ResponseStarted {
                message: "chunk data is not followed by CRLF".to_owned(),
            });
        }

        client
            .write_all(b"\r\n")
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;
    }
}

fn stream_response_chunk_data(
    reader: &mut impl Read,
    client: &mut impl Write,
    mut remaining: u64,
) -> Result<(), ProxyError> {
    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];

    while remaining > 0 {
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();

        let bytes_read = reader.read(&mut buffer[..read_limit]).map_err(|source| {
            ProxyError::ResponseStarted {
                message: source.to_string(),
            }
        })?;

        if bytes_read == 0 {
            return Err(ProxyError::ResponseStarted {
                message: "upstream disconnected during chunk data".to_owned(),
            });
        }

        client
            .write_all(&buffer[..bytes_read])
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        remaining -= bytes_read as u64;
    }

    Ok(())
}

fn stream_response_trailers(
    reader: &mut impl Read,
    client: &mut impl Write,
) -> Result<(), ProxyError> {
    let mut trailer_count = 0;
    let mut trailer_bytes: usize = 0;

    loop {
        let line = read_response_chunk_line(reader, MAX_TRAILER_LINE_SIZE)?;

        trailer_bytes = trailer_bytes.checked_add(line.len() + 2).ok_or_else(|| {
            ProxyError::ResponseStarted {
                message: "upstream trailer section is too large".to_owned(),
            }
        })?;

        if trailer_bytes > MAX_TRAILER_BLOCK_SIZE {
            return Err(ProxyError::ResponseStarted {
                message: "upstream trailer section is too large".to_owned(),
            });
        }

        if line.is_empty() {
            client
                .write_all(b"\r\n")
                .map_err(|source| ProxyError::ResponseStarted {
                    message: source.to_string(),
                })?;

            return Ok(());
        }

        if trailer_count >= MAX_TRAILER_COUNT {
            return Err(ProxyError::ResponseStarted {
                message: "too many upstream trailer fields".to_owned(),
            });
        }

        validate_response_trailer_line(&line)?;
        trailer_count += 1;

        client
            .write_all(&line)
            .and_then(|()| client.write_all(b"\r\n"))
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;
    }
}

fn read_response_chunk_line(
    reader: &mut impl Read,
    maximum_size: usize,
) -> Result<Vec<u8>, ProxyError> {
    match read_chunk_line(reader, maximum_size) {
        Ok(line) => Ok(line),
        Err(ProxyError::ClientRead { message, .. })
        | Err(ProxyError::InvalidClientBody { message }) => Err(ProxyError::ResponseStarted {
            message: format!("invalid chunked upstream response: {message}"),
        }),
        Err(error) => Err(error),
    }
}

fn parse_response_chunk_size(line: &[u8]) -> Result<u64, ProxyError> {
    match parse_chunk_size(line) {
        Ok(size) => Ok(size),
        Err(ProxyError::InvalidClientBody { message }) => Err(ProxyError::ResponseStarted {
            message: format!("invalid chunked upstream response: {message}"),
        }),
        Err(error) => Err(error),
    }
}

fn validate_response_trailer_line(line: &[u8]) -> Result<(), ProxyError> {
    match validate_trailer_line(line) {
        Ok(()) => Ok(()),
        Err(ProxyError::InvalidClientBody { message }) => Err(ProxyError::ResponseStarted {
            message: format!("invalid upstream trailer: {message}"),
        }),
        Err(error) => Err(error),
    }
}

fn stream_fixed_response_body(
    upstream: &mut impl Read,
    client: &mut impl Write,
    content_length: u64,
    buffered_body: &[u8],
) -> Result<(), ProxyError> {
    let buffered_length = buffered_body.len().min(content_length as usize);

    if buffered_length > 0 {
        client
            .write_all(&buffered_body[..buffered_length])
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;
    }

    let mut remaining = content_length.saturating_sub(buffered_length as u64);
    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];

    while remaining > 0 {
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();

        let bytes_read = upstream.read(&mut buffer[..read_limit]).map_err(|source| {
            ProxyError::ResponseStarted {
                message: source.to_string(),
            }
        })?;

        if bytes_read == 0 {
            return Err(ProxyError::ResponseStarted {
                message: "upstream disconnected before completing response body".to_owned(),
            });
        }

        client
            .write_all(&buffer[..bytes_read])
            .map_err(|source| ProxyError::ResponseStarted {
                message: source.to_string(),
            })?;

        remaining -= bytes_read as u64;
    }

    Ok(())
}

fn response_transfer_framing(headers: &[u8]) -> Result<ResponseTransferFraming, ProxyError> {
    let mut codings = Vec::new();

    for line in headers.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ProxyError::InvalidUpstreamResponse {
                message: "malformed response header".to_owned(),
            }
        })?;

        let name = &line[..separator];

        if !name.eq_ignore_ascii_case(b"transfer-encoding") {
            continue;
        }

        let value = &line[separator + 1..];

        for coding in value.split(|byte| *byte == b',') {
            let coding = trim_optional_whitespace(coding);

            if coding.is_empty() {
                return Err(ProxyError::InvalidUpstreamResponse {
                    message: "empty Transfer-Encoding value".to_owned(),
                });
            }

            let coding_name = coding.split(|byte| *byte == b';').next().unwrap_or(coding);

            if coding_name.eq_ignore_ascii_case(b"chunked") && coding.len() != coding_name.len() {
                return Err(ProxyError::InvalidUpstreamResponse {
                    message: "chunked transfer coding cannot have parameters".to_owned(),
                });
            }

            codings.push(coding_name);
        }
    }

    if codings.is_empty() {
        return Ok(ResponseTransferFraming::None);
    }

    let mut chunked_count = 0;

    for (index, coding) in codings.iter().enumerate() {
        if coding.eq_ignore_ascii_case(b"chunked") {
            chunked_count += 1;

            if chunked_count > 1 || index + 1 != codings.len() {
                return Err(ProxyError::InvalidUpstreamResponse {
                    message: "chunked must appear exactly once and as the final transfer coding"
                        .to_owned(),
                });
            }
        }
    }

    if codings
        .last()
        .is_some_and(|coding| coding.eq_ignore_ascii_case(b"chunked"))
    {
        Ok(ResponseTransferFraming::Chunked)
    } else {
        Ok(ResponseTransferFraming::CloseDelimited)
    }
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
    let upgrade_protocols = request_upgrade_protocols(request)?;
    let accepts_trailers = request_accepts_trailers(request);

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

    if request.has_transfer_encoding {
        output.extend_from_slice(b"Transfer-Encoding: chunked\r\n");

        if !named_by_connection_header(request, "trailer") {
            for header in request
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("trailer"))
            {
                validate_trailer_header_value(&header.value).map_err(|message| {
                    ProxyError::InvalidClientBody {
                        message: message.to_owned(),
                    }
                })?;

                output.extend_from_slice(b"Trailer: ");
                output.extend_from_slice(&header.value);
                output.extend_from_slice(b"\r\n");
            }
        }
    }

    if accepts_trailers {
        output.extend_from_slice(b"TE: trailers\r\n");
    }

    if let Some(protocols) = &upgrade_protocols {
        output.extend_from_slice(b"Upgrade: ");

        for (index, protocol) in protocols.iter().enumerate() {
            if index > 0 {
                output.extend_from_slice(b", ");
            }

            output.extend_from_slice(protocol);
        }

        output.extend_from_slice(b"\r\n");
    }

    match (accepts_trailers, upgrade_protocols.is_some()) {
        (true, true) => output.extend_from_slice(b"Connection: TE, Upgrade\r\n"),
        (true, false) => output.extend_from_slice(b"Connection: TE\r\n"),
        (false, true) => output.extend_from_slice(b"Connection: Upgrade\r\n"),
        (false, false) => {}
    }

    output.extend_from_slice(b"X-Forwarded-For: ");
    output.extend_from_slice(client_ip.to_string().as_bytes());
    output.extend_from_slice(b"\r\n");

    output.extend_from_slice(b"X-Forwarded-Host: ");
    output.extend_from_slice(original_host.as_bytes());
    output.extend_from_slice(b"\r\n");

    output.extend_from_slice(b"X-Forwarded-Proto: http\r\n");
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

fn request_upgrade_protocols(request: &http::Request) -> Result<Option<Vec<Vec<u8>>>, ProxyError> {
    let connection_names_upgrade = named_by_connection_header(request, "upgrade");

    let mut protocols = Vec::new();

    for header in request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("upgrade"))
    {
        protocols.extend(parse_upgrade_protocols(&header.value).map_err(|message| {
            ProxyError::InvalidClientBody {
                message: message.to_owned(),
            }
        })?);
    }

    if protocols.is_empty() {
        if connection_names_upgrade {
            return Err(ProxyError::InvalidClientBody {
                message: "Connection names Upgrade without an Upgrade header".to_owned(),
            });
        }

        return Ok(None);
    }

    if !connection_names_upgrade {
        return Err(ProxyError::InvalidClientBody {
            message: "Upgrade header requires Connection: Upgrade".to_owned(),
        });
    }

    Ok(Some(protocols))
}

fn parse_upgrade_protocols(value: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut protocols = Vec::new();

    for protocol in value.split(|byte| *byte == b',') {
        let protocol = trim_optional_whitespace(protocol);

        if protocol.is_empty() {
            return Err("Upgrade header contains an empty protocol");
        }

        let slash = protocol.iter().position(|byte| *byte == b'/');

        match slash {
            Some(index) => {
                let name = &protocol[..index];
                let version = &protocol[index + 1..];

                if name.is_empty()
                    || version.is_empty()
                    || version.contains(&b'/')
                    || !name.iter().copied().all(is_token_byte)
                    || !version.iter().copied().all(is_token_byte)
                {
                    return Err("Upgrade header contains an invalid protocol");
                }
            }
            None => {
                if !protocol.iter().copied().all(is_token_byte) {
                    return Err("Upgrade header contains an invalid protocol");
                }
            }
        }

        protocols.push(protocol.to_vec());
    }

    if protocols.is_empty() {
        return Err("Upgrade header contains no protocols");
    }

    Ok(protocols)
}

fn validate_switching_protocols_response(
    response_head: &[u8],
    requested_protocols: &[Vec<u8>],
) -> Result<(), ProxyError> {
    if !response_header_contains_token(response_head, b"connection", b"upgrade") {
        return Err(ProxyError::InvalidUpstreamResponse {
            message: "101 response is missing Connection: Upgrade".to_owned(),
        });
    }

    let selected_protocols = response_upgrade_protocols(response_head)?;

    if selected_protocols.is_empty() {
        return Err(ProxyError::InvalidUpstreamResponse {
            message: "101 response is missing an Upgrade protocol".to_owned(),
        });
    }

    for selected in &selected_protocols {
        if !requested_protocols
            .iter()
            .any(|requested| upgrade_protocols_match(requested, selected))
        {
            return Err(ProxyError::InvalidUpstreamResponse {
                message: "101 response selected an unrequested Upgrade protocol".to_owned(),
            });
        }
    }

    Ok(())
}

fn response_upgrade_protocols(response_head: &[u8]) -> Result<Vec<Vec<u8>>, ProxyError> {
    let mut protocols = Vec::new();

    for line in response_head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if line.is_empty() {
            continue;
        }

        let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            ProxyError::InvalidUpstreamResponse {
                message: "malformed response header".to_owned(),
            }
        })?;

        if !line[..separator].eq_ignore_ascii_case(b"upgrade") {
            continue;
        }

        protocols.extend(
            parse_upgrade_protocols(&line[separator + 1..]).map_err(|message| {
                ProxyError::InvalidUpstreamResponse {
                    message: message.to_owned(),
                }
            })?,
        );
    }

    Ok(protocols)
}

fn upgrade_protocols_match(left: &[u8], right: &[u8]) -> bool {
    let (left_name, left_version) = split_upgrade_protocol(left);
    let (right_name, right_version) = split_upgrade_protocol(right);

    left_name.eq_ignore_ascii_case(right_name) && left_version == right_version
}

fn split_upgrade_protocol(protocol: &[u8]) -> (&[u8], Option<&[u8]>) {
    match protocol.iter().position(|byte| *byte == b'/') {
        Some(index) => (&protocol[..index], Some(&protocol[index + 1..])),
        None => (protocol, None),
    }
}

fn request_accepts_trailers(request: &http::Request) -> bool {
    if !named_by_connection_header(request, "te") {
        return false;
    }

    request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("te"))
        .any(|header| {
            header
                .value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|coding| coding.eq_ignore_ascii_case(b"trailers"))
        })
}

fn validate_trailer_header_value(value: &[u8]) -> Result<(), &'static str> {
    let mut field_count = 0;

    for field_name in value.split(|byte| *byte == b',') {
        let field_name = trim_optional_whitespace(field_name);

        if field_name.is_empty() || !field_name.iter().copied().all(is_token_byte) {
            return Err("Trailer header contains invalid field name");
        }

        if is_forbidden_trailer_name(field_name) {
            return Err("Trailer header contains forbidden field name");
        }

        field_count += 1;
    }

    if field_count == 0 {
        return Err("Trailer header contains no field names");
    }

    Ok(())
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
        io::{self, Cursor, Read, Write},
        net::{IpAddr, TcpListener},
        thread,
    };

    use crate::{config, http};

    use super::{
        ProxyError, exchange, sanitize_response_head, serialize_request_head,
        stream_chunked_request_body, stream_chunked_response_body,
        stream_close_delimited_response_body,
    };

    struct FragmentedReader {
        data: Vec<u8>,
        position: usize,
        max_chunk: usize,
    }

    impl FragmentedReader {
        fn new(data: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                data,
                position: 0,
                max_chunk,
            }
        }
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.position == self.data.len() {
                return Ok(0);
            }

            let remaining = self.data.len() - self.position;
            let bytes_read = remaining.min(buffer.len()).min(self.max_chunk);

            buffer[..bytes_read]
                .copy_from_slice(&self.data[self.position..self.position + bytes_read]);

            self.position += bytes_read;

            Ok(bytes_read)
        }
    }

    struct TestClient {
        request_body: Vec<u8>,
        request_position: usize,
        response: Vec<u8>,
        bytes_read: usize,
    }

    impl TestClient {
        fn new(request_body: Vec<u8>) -> Self {
            Self {
                request_body,
                request_position: 0,
                response: Vec::new(),
                bytes_read: 0,
            }
        }
    }

    impl Read for TestClient {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.request_position == self.request_body.len() {
                return Ok(0);
            }

            let remaining = self.request_body.len() - self.request_position;
            let bytes_read = remaining.min(buffer.len());

            buffer[..bytes_read].copy_from_slice(
                &self.request_body[self.request_position..self.request_position + bytes_read],
            );

            self.request_position += bytes_read;
            self.bytes_read += bytes_read;

            Ok(bytes_read)
        }
    }

    impl Write for TestClient {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.response.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

        assert!(!serialized.contains("X-Remove: nope"));
        assert!(!serialized.contains("X-Forwarded-For: spoofed"));
        assert!(!serialized.contains("Connection: keep-alive"));
        assert!(!serialized.contains("Connection: close"));
    }

    #[test]
    fn sanitizes_response_connection_headers() {
        let response = sanitize_response_head(
            b"HTTP/1.1 200 OK\r\n\
Content-Length: 2\r\n\
Connection: keep-alive, X-Hop\r\n\
Keep-Alive: timeout=5\r\n\
X-Hop: remove-me\r\n\
X-End-To-End: keep-me\r\n\
\r\n",
            Some(b"close"),
            false,
            false,
        )
        .unwrap();

        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 2\r\n"));
        assert!(response.contains("X-End-To-End: keep-me\r\n"));
        assert!(response.contains("Connection: close\r\n"));

        assert!(!response.contains("Connection: keep-alive"));
        assert!(!response.contains("Keep-Alive:"));
        assert!(!response.contains("X-Hop:"));
    }

    #[test]
    fn serializes_upgrade_request_for_upstream() {
        let request = http::parse_request_with_consumed(
            b"GET /socket HTTP/1.1\r\n\
Host: example.test\r\n\
Connection: keep-alive, Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let serialized = serialize_request_head(&request, IpAddr::from([127, 0, 0, 1])).unwrap();

        let serialized = String::from_utf8(serialized).unwrap();

        assert!(serialized.contains("Upgrade: websocket\r\n"));
        assert!(serialized.contains("Connection: Upgrade\r\n"));

        assert!(!serialized.contains("Connection: keep-alive"));
    }

    #[test]
    fn rejects_upgrade_without_connection_option() {
        let request = http::parse_request_with_consumed(
            b"GET /socket HTTP/1.1\r\n\
Host: example.test\r\n\
Upgrade: websocket\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let result = serialize_request_head(&request, IpAddr::from([127, 0, 0, 1]));

        assert!(matches!(result, Err(ProxyError::InvalidClientBody { .. })));
    }

    #[test]
    fn serializes_chunked_request_for_upstream() {
        let request = http::parse_request_with_consumed(
            b"POST /chunked HTTP/1.1\r\n\
Host: example.test\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: X-End\r\n\
Connection: TE\r\n\
TE: trailers, gzip;q=0.5\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let serialized = serialize_request_head(&request, IpAddr::from([127, 0, 0, 1])).unwrap();

        let serialized = String::from_utf8(serialized).unwrap();

        assert!(serialized.contains("Transfer-Encoding: chunked\r\n"));
        assert!(serialized.contains("Trailer: X-End\r\n"));
        assert!(serialized.contains("TE: trailers\r\n"));
        assert!(serialized.contains("Connection: TE\r\n"));

        assert!(!serialized.contains("gzip"));
        assert!(!serialized.contains("Content-Length:"));
    }

    #[test]
    fn rejects_forbidden_request_trailer_declaration() {
        let request = http::parse_request_with_consumed(
            b"POST /chunked HTTP/1.1\r\n\
Host: example.test\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: Content-Length\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let result = serialize_request_head(&request, IpAddr::from([127, 0, 0, 1]));

        assert!(matches!(result, Err(ProxyError::InvalidClientBody { .. })));
    }

    #[test]
    fn streams_fragmented_chunked_body_with_trailer() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-End: yes\r\n\r\n";
        let next_request = b"GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";

        let mut buffered = Vec::new();
        buffered.extend_from_slice(body);
        buffered.extend_from_slice(next_request);

        let mut client = FragmentedReader::new(Vec::new(), 2);
        let mut upstream = Vec::new();

        let remaining = stream_chunked_request_body(&mut client, &mut upstream, &buffered).unwrap();

        assert_eq!(upstream, body);
        assert_eq!(remaining, next_request);
    }

    #[test]
    fn rejects_malformed_chunk_size() {
        let mut client = Cursor::new(b"potato\r\nhello\r\n0\r\n\r\n".to_vec());
        let mut upstream = Vec::new();

        let result = stream_chunked_request_body(&mut client, &mut upstream, &[]);

        assert!(matches!(result, Err(ProxyError::InvalidClientBody { .. })));
    }

    #[test]
    fn streams_fragmented_chunked_response_with_trailer() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-End: yes\r\n\r\n";
        let buffered = &body[..4];
        let mut upstream = FragmentedReader::new(body[4..].to_vec(), 2);
        let mut client = Vec::new();

        stream_chunked_response_body(&mut upstream, &mut client, buffered).unwrap();

        assert_eq!(client, body);
    }

    #[test]
    fn rejects_forbidden_response_trailer_declaration() {
        let result = sanitize_response_head(
            b"HTTP/1.1 200 OK\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: Content-Length\r\n\
\r\n",
            None,
            true,
            false,
        );

        assert!(matches!(
            result,
            Err(ProxyError::InvalidUpstreamResponse { .. })
        ));
    }

    #[test]
    fn streams_close_delimited_response_without_buffering_whole_body() {
        let mut upstream = FragmentedReader::new(b"llo world".to_vec(), 2);
        let mut client = Vec::new();

        stream_close_delimited_response_body(&mut upstream, &mut client, b"he").unwrap();

        assert_eq!(client, b"hello world");
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
            assert!(!request.contains("Connection: close\r\n"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 15\r\n\
Connection: close, X-Upstream-Hop\r\n\
Keep-Alive: timeout=5\r\n\
X-Upstream-Hop: remove-me\r\n\
X-End-To-End: keep-me\r\n\
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

        let mut client = Cursor::new(Vec::new());

        let result = exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        assert!(!result.client_reusable);

        let response = client.into_inner();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

        assert!(
            response
                .windows(b"Connection: close\r\n".len())
                .any(|window| window == b"Connection: close\r\n")
        );

        assert!(
            response
                .windows(b"X-End-To-End: keep-me\r\n".len())
                .any(|window| window == b"X-End-To-End: keep-me\r\n")
        );

        assert!(
            !response
                .windows(b"Keep-Alive: timeout=5\r\n".len())
                .any(|window| window == b"Keep-Alive: timeout=5\r\n")
        );

        assert!(
            !response
                .windows(b"X-Upstream-Hop: remove-me\r\n".len())
                .any(|window| window == b"X-Upstream-Hop: remove-me\r\n")
        );

        assert!(response.ends_with(b"upstream works\n"));
    }

    #[test]
    fn forwards_valid_upgrade_handshake() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];

            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let bytes_read = stream.read(&mut chunk).unwrap();

                assert!(bytes_read > 0);

                request.extend_from_slice(&chunk[..bytes_read]);
            }

            assert!(
                request
                    .windows(b"Upgrade: websocket\r\n".len())
                    .any(|window| window == b"Upgrade: websocket\r\n")
            );

            assert!(
                request
                    .windows(b"Connection: Upgrade\r\n".len())
                    .any(|window| window == b"Connection: Upgrade\r\n")
            );

            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
X-Handshake: yes\r\n\
\r\n\
UPGRADE-READY\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request = http::parse_request_with_consumed(
            b"GET /socket HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let mut client = Cursor::new(Vec::new());

        let result = exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        assert!(!result.client_reusable);

        let response = client.into_inner();

        assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));

        assert!(
            response
                .windows(b"Connection: Upgrade\r\n".len())
                .any(|window| window == b"Connection: Upgrade\r\n")
        );

        assert!(
            response
                .windows(b"Upgrade: websocket\r\n".len())
                .any(|window| window == b"Upgrade: websocket\r\n")
        );

        assert!(response.ends_with(b"UPGRADE-READY\n"));
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

        let mut client = Cursor::new(Vec::new());

        let result = exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        );

        upstream_thread.join().unwrap();

        assert!(matches!(result, Err(ProxyError::ResponseStarted { .. })));
    }

    #[test]
    fn forwards_chunked_upstream_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = [0_u8; 1024];

            let _ = stream.read(&mut request).unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: X-End\r\n\
TE: trailers\r\n\
Connection: close\r\n\
\r\n\
4\r\nWiki\r\n\
5\r\npedia\r\n\
0\r\n\
X-End: yes\r\n\
\r\n",
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

        let mut client = Cursor::new(Vec::new());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        let response = client.into_inner();

        assert!(
            response
                .windows(b"Transfer-Encoding: chunked\r\n".len())
                .any(|window| window == b"Transfer-Encoding: chunked\r\n")
        );

        assert!(
            response
                .windows(b"Trailer: X-End\r\n".len())
                .any(|window| window == b"Trailer: X-End\r\n")
        );

        assert!(
            !response
                .windows(b"TE: trailers\r\n".len())
                .any(|window| window == b"TE: trailers\r\n")
        );

        assert!(response.ends_with(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-End: yes\r\n\r\n"));
    }

    #[test]
    fn head_response_does_not_require_a_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = [0_u8; 1024];

            let _ = stream.read(&mut request).unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 999\r\n\
Connection: close\r\n\
\r\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request =
            http::parse_request_with_consumed(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap()
                .0;

        let mut client = Cursor::new(Vec::new());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        let response = client.into_inner();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn no_content_response_does_not_forward_a_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = [0_u8; 1024];

            let _ = stream.read(&mut request).unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\n\
Connection: close\r\n\
\r\n\
this-must-not-be-forwarded",
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

        let mut client = Cursor::new(Vec::new());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        let response = client.into_inner();

        assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        assert!(!response.ends_with(b"this-must-not-be-forwarded"));
        assert!(response.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn forwards_interim_response_before_final_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut request = [0_u8; 1024];

            let _ = stream.read(&mut request).unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\n\
Link: </style.css>; rel=preload\r\n\
\r\n\
HTTP/1.1 200 OK\r\n\
Content-Length: 2\r\n\
Connection: close\r\n\
\r\n\
OK",
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

        let mut client = Cursor::new(Vec::new());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        let response = client.into_inner();

        assert!(response.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));

        assert!(
            response
                .windows(b"HTTP/1.1 200 OK\r\n".len())
                .any(|window| window == b"HTTP/1.1 200 OK\r\n")
        );

        assert!(response.ends_with(b"OK"));
    }

    #[test]
    fn waits_for_100_continue_before_sending_request_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let mut request_head = Vec::new();
            let mut chunk = [0_u8; 512];

            while !request_head.windows(4).any(|window| window == b"\r\n\r\n") {
                let bytes_read = stream.read(&mut chunk).unwrap();
                assert!(bytes_read > 0);
                request_head.extend_from_slice(&chunk[..bytes_read]);
            }

            assert!(
                request_head
                    .windows(b"Expect: 100-continue\r\n".len())
                    .any(|window| window == b"Expect: 100-continue\r\n")
            );

            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
            stream.flush().unwrap();

            let mut body = [0_u8; 5];
            stream.read_exact(&mut body).unwrap();

            assert_eq!(&body, b"hello");

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 2\r\n\
Connection: close\r\n\
\r\n\
OK",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request = http::parse_request_with_consumed(
            b"POST /continue HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
Expect: 100-continue\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let mut client = TestClient::new(b"hello".to_vec());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        assert_eq!(client.bytes_read, 5);
        assert!(
            client
                .response
                .starts_with(b"HTTP/1.1 100 Continue\r\n\r\n")
        );

        assert!(
            client
                .response
                .windows(b"HTTP/1.1 200 OK\r\n".len())
                .any(|window| window == b"HTTP/1.1 200 OK\r\n")
        );

        assert!(client.response.ends_with(b"OK"));
    }

    #[test]
    fn final_response_before_continue_does_not_consume_request_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let mut request_head = Vec::new();
            let mut chunk = [0_u8; 512];

            while !request_head.windows(4).any(|window| window == b"\r\n\r\n") {
                let bytes_read = stream.read(&mut chunk).unwrap();
                assert!(bytes_read > 0);
                request_head.extend_from_slice(&chunk[..bytes_read]);
            }

            stream
                .write_all(
                    b"HTTP/1.1 417 Expectation Failed\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\
\r\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let route = configuration.route_for_host("localhost").unwrap();

        let request = http::parse_request_with_consumed(
            b"POST /rejected HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
Expect: 100-continue\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let mut client = TestClient::new(b"hello".to_vec());

        exchange(
            route,
            &request,
            &mut client,
            &[],
            IpAddr::from([127, 0, 0, 1]),
        )
        .unwrap();

        upstream_thread.join().unwrap();

        assert_eq!(client.bytes_read, 0);
        assert!(
            client
                .response
                .starts_with(b"HTTP/1.1 417 Expectation Failed\r\n")
        );
    }
}
