use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{config, http, proxy};

pub const DEV_LISTEN_ADDR: &str = "127.0.0.1:8080";

const READ_CHUNK_SIZE: usize = 4096;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(25);

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
const SIGINT: i32 = 2;

#[cfg(test)]
const RESPONSE_BODY: &str = "BareProxy is alive.\n";

#[derive(Default)]
struct ServerCounters {
    requests: AtomicUsize,
    errors: AtomicUsize,
}

impl ServerCounters {
    fn record_request(&self) -> usize {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_error(&self) -> usize {
        self.errors.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn snapshot(&self) -> (usize, usize) {
        (
            self.requests.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
}

#[cfg(unix)]
extern "C" fn handle_sigint(_: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_shutdown_handler() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

    unsafe {
        let _ = signal(SIGINT, handle_sigint as usize);
    }
}

#[cfg(not(unix))]
fn install_shutdown_handler() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

pub fn bind_listener() -> io::Result<TcpListener> {
    TcpListener::bind(DEV_LISTEN_ADDR)
}

pub fn serve(listener: TcpListener, configuration: &config::Config) -> io::Result<()> {
    install_shutdown_handler();

    serve_until(listener, configuration, &SHUTDOWN_REQUESTED)
}

fn serve_until(
    listener: TcpListener,
    configuration: &config::Config,
    shutdown_requested: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;

    let active_connections = Arc::new(AtomicUsize::new(0));
    let counters = Arc::new(ServerCounters::default());
    let mut workers = Vec::new();

    while !shutdown_requested.load(Ordering::Acquire) {
        match accept_and_spawn(&listener, configuration, &active_connections, &counters) {
            Ok(Some(worker)) => workers.push(worker),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(SHUTDOWN_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }

        reap_finished_workers(&mut workers);
    }

    println!(
        "INFO event=shutdown_begin active={} workers={}",
        active_connections.load(Ordering::SeqCst),
        workers.len()
    );

    drop(listener);

    println!("INFO event=listener_stop reason=shutdown");

    reap_finished_workers(&mut workers);

    if !workers.is_empty() {
        println!(
            "INFO event=shutdown_drain active={} workers={}",
            active_connections.load(Ordering::SeqCst),
            workers.len()
        );
    }

    for worker in workers {
        if worker.join().is_err() {
            eprintln!("ERROR event=worker_panic phase=shutdown_drain");
        }
    }

    let (requests_total, errors_total) = counters.snapshot();

    println!(
        "INFO event=shutdown_complete requests_total={requests_total} errors_total={errors_total}"
    );

    Ok(())
}

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    while let Some(index) = workers.iter().position(JoinHandle::is_finished) {
        let worker = workers.swap_remove(index);

        if worker.join().is_err() {
            eprintln!("ERROR event=worker_panic phase=runtime_reap");
        }
    }
}

#[cfg(test)]
pub fn serve_one(listener: &TcpListener, configuration: &config::Config) -> io::Result<()> {
    let counters = ServerCounters::default();
    let (stream, peer_addr) = listener.accept()?;
    println!("INFO event=connection_accept peer={peer_addr}");

    handle_accepted_connection(stream, peer_addr, configuration, &counters)
}

fn accept_and_spawn(
    listener: &TcpListener,
    configuration: &config::Config,
    active_connections: &Arc<AtomicUsize>,
    counters: &Arc<ServerCounters>,
) -> io::Result<Option<JoinHandle<()>>> {
    let (mut stream, peer_addr) = listener.accept()?;

    let active = active_connections.load(Ordering::SeqCst);
    let maximum = configuration.max_connections();

    if active >= maximum {
        println!(
            "WARN event=connection_reject peer={peer_addr} reason=connection_limit active={active} maximum={maximum}"
        );

        if let Err(error) = write_text_response(
            &mut stream,
            http::StatusCode::ServiceUnavailable,
            "Service Unavailable\n",
        ) {
            eprintln!(
                "ERROR event=response_failure peer={peer_addr} context=overload error={error}"
            );
        }

        return Ok(None);
    }

    let configuration = configuration.clone();
    let active_connections = Arc::clone(active_connections);
    let counters = Arc::clone(counters);

    let active = active_connections.fetch_add(1, Ordering::SeqCst) + 1;

    println!("INFO event=connection_accept peer={peer_addr} active={active} maximum={maximum}");

    Ok(Some(thread::spawn(move || {
        let result = handle_accepted_connection(stream, peer_addr, &configuration, &counters);

        let active = active_connections.fetch_sub(1, Ordering::SeqCst) - 1;

        if let Err(error) = result {
            eprintln!("ERROR event=connection_failure peer={peer_addr} error={error}");
        }

        let (requests_total, errors_total) = counters.snapshot();

        println!(
            "INFO event=connection_close peer={peer_addr} active={active} maximum={maximum} requests_total={requests_total} errors_total={errors_total}"
        );
    })))
}

fn handle_accepted_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    configuration: &config::Config,
    counters: &ServerCounters,
) -> io::Result<()> {
    let idle_timeout = Duration::from_secs(configuration.client_idle_timeout_seconds());

    stream.set_read_timeout(Some(idle_timeout))?;

    match handle_connection(&mut stream, configuration, counters) {
        Ok(()) => Ok(()),
        Err(error) if is_client_idle_timeout(&error) => {
            println!(
                "WARN event=client_idle_timeout peer={peer_addr} timeout_seconds={}",
                configuration.client_idle_timeout_seconds()
            );

            let _ = stream.shutdown(Shutdown::Both);

            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let errors_total = counters.record_error();

            eprintln!(
                "WARN event=protocol_error peer={peer_addr} phase=request_head error={error} errors_total={errors_total}"
            );

            write_text_response(&mut stream, http::StatusCode::BadRequest, "Bad Request\n")
        }
        Err(error) if is_client_disconnect(&error) => {
            println!("INFO event=client_disconnect peer={peer_addr} error={error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    configuration: &config::Config,
    counters: &ServerCounters,
) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    let mut buffered = Vec::new();
    let mut proxy_session = proxy::Session::new(configuration.upstream_timeout_seconds());

    loop {
        let Some(received) = read_request_head(stream, &buffered)? else {
            println!("INFO event=client_disconnect peer={peer_addr} phase=before_request");
            return Ok(());
        };

        let ReceivedRequest {
            request,
            buffered_body,
            bytes_read,
        } = received;

        let requests_total = counters.record_request();

        println!(
            "INFO event=request peer={peer_addr} method={} target={} version={} host={} content_length={:?} transfer_encoding={} persistence={} head_bytes={} buffered_bytes={} requests_total={requests_total}",
            request.method,
            request.target,
            request.version,
            request.host().unwrap_or("-"),
            request.content_length,
            request.has_transfer_encoding,
            if request.keep_alive {
                "keep-alive"
            } else {
                "close"
            },
            bytes_read,
            buffered_body.len()
        );

        let route = match select_route(&request, configuration) {
            Ok(route) => route,
            Err(status) => {
                let errors_total = counters.record_error();

                eprintln!(
                    "WARN event=protocol_error peer={peer_addr} phase=route status={} reason={} errors_total={errors_total}",
                    status.code(),
                    status.reason_phrase()
                );

                let body = format!("{}\n", status.reason_phrase());
                return write_text_response(stream, status, &body);
            }
        };

        println!("INFO event=route_selected peer={peer_addr} route=\"{route}\"");

        let client_ip = peer_addr.ip();

        match proxy_session.exchange(route, &request, stream, &buffered_body, client_ip) {
            Ok(result) if result.upgraded => {
                println!("INFO event=upgrade_tunnel_start peer={peer_addr}");

                match proxy_session.tunnel_upgraded(stream, result.buffered_client_bytes) {
                    Ok(()) => {
                        println!("INFO event=upgrade_tunnel_close peer={peer_addr}");
                    }
                    Err(error) => {
                        let errors_total = counters.record_error();

                        eprintln!(
                            "ERROR event=upgrade_tunnel_failure peer={peer_addr} error={error} errors_total={errors_total}"
                        );
                    }
                }

                let _ = stream.shutdown(Shutdown::Both);

                return Ok(());
            }
            Ok(result) if request.keep_alive && result.client_reusable => {
                buffered = result.buffered_client_bytes;

                if !buffered.is_empty() {
                    println!(
                        "INFO event=request_buffer_preserved peer={peer_addr} bytes={}",
                        buffered.len()
                    );
                }

                println!("INFO event=connection_keep_alive peer={peer_addr}");
                continue;
            }
            Ok(result) => {
                if request.keep_alive && !result.client_reusable {
                    println!(
                        "INFO event=connection_close_required peer={peer_addr} reason=upstream_not_reusable"
                    );
                }

                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(proxy::ProxyError::InvalidClientBody { message }) => {
                let errors_total = counters.record_error();

                eprintln!(
                    "WARN event=protocol_error peer={peer_addr} phase=request_body error={message} errors_total={errors_total}"
                );

                return write_text_response(stream, http::StatusCode::BadRequest, "Bad Request\n");
            }
            Err(proxy::ProxyError::ClientRead { kind, message }) => {
                return Err(io::Error::new(kind, message));
            }
            Err(proxy::ProxyError::ResponseStarted { message }) => {
                let errors_total = counters.record_error();

                eprintln!(
                    "ERROR event=upstream_failure peer={peer_addr} phase=response_stream error={message} errors_total={errors_total}"
                );

                let _ = stream.shutdown(Shutdown::Both);

                return Ok(());
            }
            Err(error) if error.is_upstream_timeout() => {
                let errors_total = counters.record_error();

                eprintln!(
                    "ERROR event=upstream_failure peer={peer_addr} kind=timeout error={error} errors_total={errors_total}"
                );

                return write_text_response(
                    stream,
                    http::StatusCode::GatewayTimeout,
                    "Gateway Timeout\n",
                );
            }
            Err(error) => {
                let errors_total = counters.record_error();

                eprintln!(
                    "ERROR event=upstream_failure peer={peer_addr} error={error} errors_total={errors_total}"
                );

                return write_text_response(stream, http::StatusCode::BadGateway, "Bad Gateway\n");
            }
        }
    }
}

struct ReceivedRequest {
    request: http::Request,
    buffered_body: Vec<u8>,
    bytes_read: usize,
}

fn read_request_head(
    reader: &mut impl Read,
    buffered_prefix: &[u8],
) -> io::Result<Option<ReceivedRequest>> {
    let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE.max(buffered_prefix.len()));
    buffer.extend_from_slice(buffered_prefix);

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

fn is_client_idle_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
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
    use std::{
        io::{self, Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use crate::{config, http};

    use super::{
        RESPONSE_BODY, ServerCounters, accept_and_spawn, build_response, read_request_head,
        select_route, serve_one, serve_until,
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

        let received = read_request_head(&mut reader, &[]).unwrap().unwrap();

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

        let received = read_request_head(&mut reader, &[]).unwrap().unwrap();

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
    fn duplicate_host_is_bad_request() {
        let request = http::parse_request_with_consumed(
            b"GET / HTTP/1.1\r\n\
Host: localhost\r\n\
Host: attacker.test\r\n\
\r\n",
        )
        .unwrap()
        .0;

        let configuration = config::parse("localhost -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            select_route(&request, &configuration),
            Err(http::StatusCode::BadRequest)
        );
    }

    #[test]
    fn malformed_host_is_bad_request() {
        let request = http::parse_request_with_consumed(
            b"GET / HTTP/1.1\r\n\
Host: user@localhost\r\n\
\r\n",
        )
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

    #[test]
    fn proxies_post_body_end_to_end() {
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

                let complete = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .is_some_and(|header_end| request.len() >= header_end + 4 + 5);

                if complete {
                    break;
                }
            }

            assert!(request.starts_with(b"POST /body HTTP/1.1\r\n"));
            assert!(
                request
                    .windows(b"Content-Length: 5\r\n".len())
                    .any(|window| window == b"Content-Length: 5\r\n")
            );
            assert!(request.ends_with(b"hello"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 10\r\n\
Connection: close\r\n\
\r\n\
got hello\n",
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
                b"POST /body HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
Connection: close\r\n\
\r\n\
he",
            )
            .unwrap();

        client.write_all(b"llo").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"got hello\n"));
    }

    #[test]
    fn slow_client_does_not_block_another_client() {
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

            assert!(request.starts_with(b"GET /fast HTTP/1.1\r\n"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 13\r\n\
Connection: close\r\n\
\r\n\
second works\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();
        let active_connections = Arc::new(AtomicUsize::new(0));
        let counters = Arc::new(ServerCounters::default());

        let active_for_server = Arc::clone(&active_connections);

        let bare_thread = thread::spawn(move || {
            let first = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters,
            )
            .unwrap()
            .unwrap();

            let second = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters,
            )
            .unwrap()
            .unwrap();

            first.join().unwrap();
            second.join().unwrap();
        });

        let mut slow_client = TcpStream::connect(bare_address).unwrap();

        slow_client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n")
            .unwrap();

        let mut fast_client = TcpStream::connect(bare_address).unwrap();

        fast_client
            .write_all(
                b"GET /fast HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        fast_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        fast_client.read_to_end(&mut response).unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"second works\n"));

        slow_client.shutdown(Shutdown::Both).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert_eq!(active_connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn serves_two_sequential_requests_on_one_client_connection() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let responses: [&[u8]; 2] = [
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 5\r\n\
\r\n\
first",
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 6\r\n\
\r\n\
second",
            ];

            let targets: [&[u8]; 2] = [b"GET /first HTTP/1.1\r\n", b"GET /second HTTP/1.1\r\n"];

            for (expected_target, response) in targets.into_iter().zip(responses) {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];

                loop {
                    let bytes_read = stream.read(&mut chunk).unwrap();

                    assert!(bytes_read > 0);

                    request.extend_from_slice(&chunk[..bytes_read]);

                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                assert!(request.starts_with(expected_target));

                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            }
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
                b"GET /first HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n",
            )
            .unwrap();

        let expected_first = b"HTTP/1.1 200 OK\r\n\
Content-Length: 5\r\n\
\r\n\
first";

        let mut first_response = vec![0_u8; expected_first.len()];
        client.read_exact(&mut first_response).unwrap();

        assert_eq!(first_response, expected_first);

        client
            .write_all(
                b"GET /second HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        let mut second_response = Vec::new();
        client.read_to_end(&mut second_response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert_eq!(
            second_response,
            b"HTTP/1.1 200 OK\r\n\
Content-Length: 6\r\n\
\r\n\
second"
        );
    }

    #[test]
    fn preserves_pipelined_request_after_fixed_length_body() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let expected_requests: [&[u8]; 2] =
                [b"POST /first HTTP/1.1\r\n", b"GET /second HTTP/1.1\r\n"];

            let responses: [&[u8]; 2] = [
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 5\r\n\
\r\n\
first",
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 6\r\n\
\r\n\
second",
            ];

            for (expected_request, response) in expected_requests.into_iter().zip(responses) {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];

                loop {
                    let bytes_read = stream.read(&mut chunk).unwrap();

                    assert!(bytes_read > 0);

                    request.extend_from_slice(&chunk[..bytes_read]);

                    let complete = if expected_request.starts_with(b"POST") {
                        request
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .is_some_and(|header_end| request.len() >= header_end + 4 + 5)
                    } else {
                        request.windows(4).any(|window| window == b"\r\n\r\n")
                    };

                    if complete {
                        break;
                    }
                }

                assert!(request.starts_with(expected_request));

                if expected_request.starts_with(b"POST") {
                    assert!(request.ends_with(b"hello"));
                }

                stream.write_all(response).unwrap();
                stream.flush().unwrap();
            }
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
                b"POST /first HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 5\r\n\
\r\n\
hello\
GET /second HTTP/1.1\r\n\
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

        assert_eq!(
            response
                .windows(b"HTTP/1.1 200 OK\r\n".len())
                .filter(|window| *window == b"HTTP/1.1 200 OK\r\n")
                .count(),
            2
        );

        assert!(response.ends_with(b"second"));
    }

    #[test]
    fn rejects_connection_when_limit_is_reached() {
        let configuration = config::parse(
            "max_connections = 1\n\
localhost -> 127.0.0.1:3000",
        )
        .unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let active_connections = Arc::new(AtomicUsize::new(0));
        let counters = Arc::new(ServerCounters::default());
        let active_for_server = Arc::clone(&active_connections);

        let bare_thread = thread::spawn(move || {
            let first = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters,
            )
            .unwrap()
            .unwrap();

            let rejected = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters,
            )
            .unwrap();

            assert!(rejected.is_none());

            first.join().unwrap();
        });

        let mut slow_client = TcpStream::connect(bare_address).unwrap();

        slow_client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n")
            .unwrap();

        let mut rejected_client = TcpStream::connect(bare_address).unwrap();

        let mut response = Vec::new();
        rejected_client.read_to_end(&mut response).unwrap();

        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response.ends_with(b"Service Unavailable\n"));

        slow_client.shutdown(Shutdown::Both).unwrap();

        bare_thread.join().unwrap();

        assert_eq!(active_connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn closes_idle_client_after_configured_timeout() {
        let configuration = config::parse(
            "client_idle_timeout_seconds = 1\n\
localhost -> 127.0.0.1:3000",
        )
        .unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let bare_thread = thread::spawn(move || {
            serve_one(&bare_listener, &configuration).unwrap();
        });

        let mut client = TcpStream::connect(bare_address).unwrap();

        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n")
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();

        assert!(response.is_empty());
    }

    #[test]
    fn returns_gateway_timeout_when_upstream_stalls() {
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

            thread::sleep(Duration::from_millis(1500));
        });

        let configuration = config::parse(&format!(
            "upstream_timeout_seconds = 1\n\
localhost -> 127.0.0.1:{upstream_port}"
        ))
        .unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let bare_thread = thread::spawn(move || {
            serve_one(&bare_listener, &configuration).unwrap();
        });

        let mut client = TcpStream::connect(bare_address).unwrap();

        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        client
            .write_all(
                b"GET /stall HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 504 Gateway Timeout\r\n"));
        assert!(response.ends_with(b"Gateway Timeout\n"));
    }

    #[test]
    fn tunnels_upgraded_connection_with_half_close() {
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
\r\n",
                )
                .unwrap();

            stream.flush().unwrap();

            let mut tunneled = Vec::new();
            stream.read_to_end(&mut tunneled).unwrap();

            assert_eq!(tunneled, b"PING");

            stream.write_all(b"PONG").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
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
                b"GET /socket HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n\
PING",
            )
            .unwrap();

        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

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

        assert!(response.ends_with(b"PONG"));
    }

    #[test]
    fn tunnels_websocket_text_frames() {
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

            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;

            let mut websocket_bytes = request[header_end..].to_vec();

            assert!(
                request[..header_end]
                    .windows(b"Upgrade: websocket\r\n".len())
                    .any(|window| window == b"Upgrade: websocket\r\n")
            );

            assert!(
                request[..header_end]
                    .windows(b"Connection: Upgrade\r\n".len())
                    .any(|window| window == b"Connection: Upgrade\r\n")
            );

            assert!(
                request[..header_end]
                    .windows(b"Sec-WebSocket-Version: 13\r\n".len())
                    .any(|window| window == b"Sec-WebSocket-Version: 13\r\n")
            );

            assert!(
                request[..header_end]
                    .windows(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".len())
                    .any(|window| { window == b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" })
            );

            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
\r\n",
                )
                .unwrap();

            stream.flush().unwrap();

            while websocket_bytes.len() < 11 {
                let bytes_read = stream.read(&mut chunk).unwrap();

                assert!(bytes_read > 0);

                websocket_bytes.extend_from_slice(&chunk[..bytes_read]);
            }

            assert_eq!(websocket_bytes[0], 0x81);
            assert_eq!(websocket_bytes[1], 0x85);

            let masking_key = &websocket_bytes[2..6];
            let masked_payload = &websocket_bytes[6..11];

            let payload: Vec<u8> = masked_payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ masking_key[index % 4])
                .collect();

            assert_eq!(payload, b"hello");

            stream.write_all(b"\x81\x05world").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
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
                b"GET /socket HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n\
\x81\x85\x01\x02\x03\x04igohn",
            )
            .unwrap();

        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        let response_head_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;

        let response_head = &response[..response_head_end];
        let websocket_frame = &response[response_head_end..];

        assert!(response_head.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));

        assert!(
            response_head
                .windows(b"Connection: Upgrade\r\n".len())
                .any(|window| window == b"Connection: Upgrade\r\n")
        );

        assert!(
            response_head
                .windows(b"Upgrade: websocket\r\n".len())
                .any(|window| window == b"Upgrade: websocket\r\n")
        );

        assert!(
            response_head
                .windows(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n".len())
                .any(|window| {
                    window == b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                })
        );

        assert_eq!(websocket_frame, b"\x81\x05world");
    }

    #[test]
    fn rejects_ambiguous_framing_before_contacting_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        upstream_listener.set_nonblocking(true).unwrap();

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
                b"POST /smuggle HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 4\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
0\r\n\
\r\n",
            )
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(response.ends_with(b"Bad Request\n"));

        match upstream_listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("ambiguous request reached the upstream"),
            Err(error) => panic!("unexpected upstream accept error: {error}"),
        }
    }

    #[test]
    fn rejects_upstream_header_injection() {
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

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 2\r\n\
X-Safe: yes\nX-Injected: nope\r\n\
\r\n\
OK",
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
                b"GET /injection HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(response.ends_with(b"Bad Gateway\n"));

        assert!(
            !response
                .windows(b"X-Injected: nope\r\n".len())
                .any(|window| window == b"X-Injected: nope\r\n")
        );

        assert!(
            !response
                .windows(b"X-Safe: yes\r\n".len())
                .any(|window| window == b"X-Safe: yes\r\n")
        );
    }

    #[test]
    fn failed_request_does_not_terminate_listener() {
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

            assert!(request.starts_with(b"GET /still-alive HTTP/1.1\r\n"));

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 6\r\n\
Connection: close\r\n\
\r\n\
ALIVE\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let active_connections = Arc::new(AtomicUsize::new(0));
        let counters = Arc::new(ServerCounters::default());

        let active_for_server = Arc::clone(&active_connections);
        let counters_for_server = Arc::clone(&counters);

        let bare_thread = thread::spawn(move || {
            let failed = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters_for_server,
            )
            .unwrap()
            .unwrap();

            let successful = accept_and_spawn(
                &bare_listener,
                &configuration,
                &active_for_server,
                &counters_for_server,
            )
            .unwrap()
            .unwrap();

            failed.join().unwrap();
            successful.join().unwrap();
        });

        let mut bad_client = TcpStream::connect(bare_address).unwrap();

        bad_client
            .write_all(
                b"POST /bad HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 4\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
0\r\n\
\r\n",
            )
            .unwrap();

        let mut bad_response = Vec::new();
        bad_client.read_to_end(&mut bad_response).unwrap();

        assert!(bad_response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

        let mut good_client = TcpStream::connect(bare_address).unwrap();

        good_client
            .write_all(
                b"GET /still-alive HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        let mut good_response = Vec::new();
        good_client.read_to_end(&mut good_response).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(good_response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(good_response.ends_with(b"ALIVE\n"));

        assert_eq!(counters.snapshot(), (1, 1));
        assert_eq!(active_connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn graceful_shutdown_stops_listener_and_finishes_active_request() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (release_upstream_tx, release_upstream_rx) = mpsc::channel();

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();

            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];

            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let bytes_read = stream.read(&mut chunk).unwrap();

                assert!(bytes_read > 0);

                request.extend_from_slice(&chunk[..bytes_read]);
            }

            assert!(request.starts_with(b"GET /drain HTTP/1.1\r\n"));

            request_seen_tx.send(()).unwrap();

            release_upstream_rx.recv().unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
Content-Length: 8\r\n\
Connection: close\r\n\
\r\n\
DRAINED\n",
                )
                .unwrap();
        });

        let configuration =
            config::parse(&format!("localhost -> 127.0.0.1:{upstream_port}")).unwrap();

        let bare_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bare_address = bare_listener.local_addr().unwrap();

        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let shutdown_for_server = Arc::clone(&shutdown_requested);

        let (server_done_tx, server_done_rx) = mpsc::channel();

        let bare_thread = thread::spawn(move || {
            serve_until(bare_listener, &configuration, &shutdown_for_server).unwrap();

            server_done_tx.send(()).unwrap();
        });

        let mut client = TcpStream::connect(bare_address).unwrap();

        client
            .write_all(
                b"GET /drain HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: close\r\n\
\r\n",
            )
            .unwrap();

        request_seen_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        shutdown_requested.store(true, Ordering::Release);

        thread::sleep(Duration::from_millis(100));

        assert_eq!(server_done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));

        let deadline = Instant::now() + Duration::from_secs(2);

        loop {
            match TcpStream::connect(bare_address) {
                Err(_) => break,
                Ok(stream) => drop(stream),
            }

            assert!(
                Instant::now() < deadline,
                "listener remained open during graceful shutdown"
            );

            thread::sleep(Duration::from_millis(20));
        }

        release_upstream_tx.send(()).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        server_done_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        bare_thread.join().unwrap();
        upstream_thread.join().unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"DRAINED\n"));
    }
}
