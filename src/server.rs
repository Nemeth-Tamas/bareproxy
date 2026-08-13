use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
};

use crate::http;

pub const DEV_LISTEN_ADDR: &str = "127.0.0.1:8080";

const READ_CHUNK_SIZE: usize = 4096;
const RESPONSE_BODY: &str = "BareProxy is alive.\n";

pub fn bind_listener() -> io::Result<TcpListener> {
    TcpListener::bind(DEV_LISTEN_ADDR)
}

pub fn serve_one(listener: &TcpListener) -> io::Result<()> {
    let (mut stream, peer_addr) = listener.accept()?;
    println!("Accepted connection from {peer_addr}");

    match handle_connection(&mut stream) {
        Ok(()) => Ok(()),
        Err(error) if is_client_disconnect(&error) => {
            println!("Client {peer_addr} disconnected: {error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn handle_connection(stream: &mut TcpStream) -> io::Result<()> {
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

    let response = build_response();

    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
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

fn build_response() -> String {
    format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Server: BareProxy/{}\r\n",
            "Connection: close\r\n",
            "\r\n",
            "{}"
        ),
        RESPONSE_BODY.len(),
        env!("CARGO_PKG_VERSION"),
        RESPONSE_BODY
    )
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
    use std::io::{self, Read};

    use super::{RESPONSE_BODY, build_response, read_request_head};

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
        assert!(build_response().starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn response_has_correct_content_length() {
        assert!(build_response().contains(&format!("Content-Length: {}\r\n", RESPONSE_BODY.len())));
    }

    #[test]
    fn response_has_bareproxy_server_header() {
        assert!(build_response().contains(&format!(
            "Server: BareProxy/{}\r\n",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn response_closes_connection() {
        assert!(build_response().contains("Connection: close\r\n"));
    }

    #[test]
    fn response_contains_expected_body() {
        assert!(build_response().ends_with(RESPONSE_BODY));
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
}
