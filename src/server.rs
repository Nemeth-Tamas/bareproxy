use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
};

use crate::{config, http, proxy};

pub const DEV_LISTEN_ADDR: &str = "127.0.0.1:8080";

const READ_CHUNK_SIZE: usize = 4096;

#[cfg(test)]
const RESPONSE_BODY: &str = "BareProxy is alive.\n";

pub fn bind_listener() -> io::Result<TcpListener> {
    TcpListener::bind(DEV_LISTEN_ADDR)
}

pub fn serve_one(listener: &TcpListener, configuration: &config::Config) -> io::Result<()> {
    let (mut stream, peer_addr) = listener.accept()?;
    println!("Accepted connection from {peer_addr}");

    match handle_connection(&mut stream, configuration) {
        Ok(()) => Ok(()),
        Err(error) if is_client_disconnect(&error) => {
            println!("Client {peer_addr} disconnected: {error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn handle_connection(stream: &mut TcpStream, configuration: &config::Config) -> io::Result<()> {
    let Some(received) = read_request_head(stream)? else {
        println!("Client disconnected before sending a request");
        return Ok(());
    };

    let ReceivedRequest {
        request,
        buffered_body,
        bytes_read,
    } = received;

    println!("Read {bytes_read} bytes while receiving request headers");

    if !buffered_body.is_empty() {
        println!("Buffered body prefix: {} bytes", buffered_body.len());
    }

    println!(
        "Request: {} {} {}",
        request.method, request.target, request.version
    );

    if let Some(host) = request.host() {
        println!("Host: {host}");
    }

    if let Some(content_length) = request.content_length {
        println!("Content-Length: {content_length}");
    }

    if request.has_transfer_encoding {
        println!("Transfer-Encoding: present");
    }

    println!(
        "Connection persistence: {}",
        if request.keep_alive {
            "keep-alive"
        } else {
            "close"
        }
    );

    let route = match select_route(&request, configuration) {
        Ok(route) => route,
        Err(status) => {
            let body = format!("{}\n", status.reason_phrase());
            return write_text_response(stream, status, &body);
        }
    };

    println!("Matched route: {route}");

    if request.has_transfer_encoding || request.content_length.unwrap_or(0) > 0 {
        return write_text_response(
            stream,
            http::StatusCode::BadRequest,
            "Request body proxying is not available yet.\n",
        );
    }

    let client_ip = stream.peer_addr()?.ip();

    match proxy::exchange(route, &request, client_ip) {
        Ok(response) => {
            stream.write_all(&response)?;
            stream.flush()?;

            let _ = stream.shutdown(Shutdown::Both);

            Ok(())
        }
        Err(error) => {
            eprintln!("BareProxy upstream error: {error}");

            write_text_response(stream, http::StatusCode::BadGateway, "Bad Gateway\n")
        }
    }
}

struct ReceivedRequest {
    request: http::Request,
    buffered_body: Vec<u8>,
    bytes_read: usize,
}

fn read_request_head(reader: &mut impl Read) -> io::Result<Option<ReceivedRequest>> {
    let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);
    let mut chunk = [0_u8; READ_CHUNK_SIZE];

    loop {
        match http::parse_request_with_consumed(&buffer) {
            Ok((request, bytes_consumed)) => {
                let buffered_body = buffer[bytes_consumed..].to_vec();

                return Ok(Some(ReceivedRequest {
                    request,
                    buffered_body,
                    bytes_read: buffer.len(),
                }));
            }
            Err(http::ParseError::IncompleteHeaders) => {}
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }

        if buffer.len() >= http::MAX_REQUEST_HEAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers exceed maximum size",
            ));
        }

        let remaining_capacity = http::MAX_REQUEST_HEAD_SIZE - buffer.len();
        let read_limit = remaining_capacity.min(chunk.len());
        let bytes_read = reader.read(&mut chunk[..read_limit])?;

        if bytes_read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }

            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client disconnected before completing HTTP request headers",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn select_route<'a>(
    request: &http::Request,
    configuration: &'a config::Config,
) -> Result<&'a config::Route, http::StatusCode> {
    let host = request.host().ok_or(http::StatusCode::BadRequest)?;

    match configuration.route_for_host(host) {
        Ok(route) => Ok(route),
        Err(config::RouteLookupError::InvalidHost) => Err(http::StatusCode::BadRequest),
        Err(config::RouteLookupError::NotFound(_)) => Err(http::StatusCode::NotFound),
    }
}

fn write_text_response(
    stream: &mut TcpStream,
    status: http::StatusCode,
    body: &str,
) -> io::Result<()> {
    let response = build_text_response(status, body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    stream.write_all(&response)?;
    stream.flush()?;

    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
}

fn build_text_response(
    status: http::StatusCode,
    body: &str,
) -> Result<Vec<u8>, http::ResponseError> {
    let response = http::Response::new(status, body.as_bytes().to_vec())
        .with_header("Content-Type", b"text/plain; charset=utf-8")?
        .with_header(
            "Server",
            format!("BareProxy/{}", env!("CARGO_PKG_VERSION")).as_bytes(),
        )?
        .with_header("Connection", b"close")?;

    response.serialize()
}

#[cfg(test)]
fn build_response() -> Result<Vec<u8>, http::ResponseError> {
    build_text_response(http::StatusCode::Ok, RESPONSE_BODY)
}

fn is_client_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        thread,
    };

    use crate::{config, http};

    use super::{RESPONSE_BODY, build_response, read_request_head, select_route, serve_one};

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

    #[test]
    fn response_is_valid_http_11_success() {
        assert!(
            build_response()
                .unwrap()
                .starts_with(b"HTTP/1.1 200 OK\r\n")
        );
    }

    #[test]
    fn response_has_correct_content_length() {
        let response = String::from_utf8(build_response().unwrap()).unwrap();

        assert!(response.contains(&format!("Content-Length: {}\r\n", RESPONSE_BODY.len())));
    }

    #[test]
    fn response_has_bareproxy_server_header() {
        let response = String::from_utf8(build_response().unwrap()).unwrap();

        assert!(response.contains(&format!(
            "Server: BareProxy/{}\r\n",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn response_closes_connection() {
        let response = String::from_utf8(build_response().unwrap()).unwrap();

        assert!(response.contains("Connection: close\r\n"));
    }

    #[test]
    fn response_contains_expected_body() {
        assert!(
            build_response()
                .unwrap()
                .ends_with(RESPONSE_BODY.as_bytes())
        );
    }

    #[test]
    fn reads_fragmented_request_headers() {
        let mut reader = FragmentedReader::new(
            b"GET /fragmented HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            3,
        );

        let received = read_request_head(&mut reader).unwrap().unwrap();

        assert_eq!(received.request.method, "GET");
        assert_eq!(received.request.target, "/fragmented");
        assert_eq!(received.request.host(), Some("localhost"));
        assert!(received.buffered_body.is_empty());
    }

    #[test]
    fn preserves_body_bytes_received_with_headers() {
        let mut reader = FragmentedReader::new(
            b"POST /body HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
            usize::MAX,
        );

        let received = read_request_head(&mut reader).unwrap().unwrap();

        assert_eq!(received.request.content_length, Some(5));
        assert_eq!(received.buffered_body, b"hello".to_vec());
    }

    #[test]
    fn missing_host_is_bad_request() {
        let request = http::parse_request_with_consumed(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap()
            .0;
        let configuration = config::parse("localhost -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            select_route(&request, &configuration),
            Err(http::StatusCode::BadRequest)
        );
    }

    #[test]
    fn unknown_host_is_not_found() {
        let request =
            http::parse_request_with_consumed(b"GET / HTTP/1.1\r\nHost: missing.test\r\n\r\n")
                .unwrap()
                .0;

        let configuration = config::parse("localhost -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            select_route(&request, &configuration),
            Err(http::StatusCode::NotFound)
        );
    }

    #[test]
    fn configured_host_selects_route() {
        let request =
            http::parse_request_with_consumed(b"GET / HTTP/1.1\r\nHost: LOCALHOST:8080\r\n\r\n")
                .unwrap()
                .0;

        let configuration = config::parse("localhost -> 127.0.0.1:3000").unwrap();

        assert!(select_route(&request, &configuration).is_ok());
    }

    #[test]
    fn proxies_get_request_end_to_end() {
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

            assert!(request.starts_with("GET /proxied HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost\r\n"));
            assert!(request.contains("X-Forwarded-Proto: http\r\n"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 16\r\n\
Connection: close\r\n\
\r\n\
hello upstream!\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let bare_thread = thread::spawn(move || {
            serve_one(&bare_listener, &configuration).unwrap();
        });

        let mut client = TcpStream::connect(bare_address).unwrap();

        client
            .write_all(
                b"GET /proxied HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"hello upstream!\n"));
    }
}
