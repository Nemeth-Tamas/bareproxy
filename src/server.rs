use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
};

pub const DEV_LISTEN_ADDR: &str = "127.0.0.1:8080";

const REQUEST_BUFFER_SIZE: usize = 8192;
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
    let mut request = [0_u8; REQUEST_BUFFER_SIZE];
    let bytes_read = stream.read(&mut request)?;

    if bytes_read == 0 {
        println!("Client disconnected before sending a request");
        return Ok(());
    }

    println!("Read {bytes_read} request bytes");

    let response = build_response();

    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
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
    use super::{RESPONSE_BODY, build_response};

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
}
