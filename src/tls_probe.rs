use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use crate::{
    tls::{
        self, CiphertextRecordDecoder, ContentType, HandshakeDeframer, PlaintextRecordDecoder,
        TLS_CIPHERTEXT_FRAGMENT_LIMIT, TLS_LEGACY_RECORD_VERSION, TLS_RECORD_HEADER_SIZE,
        Tls13ApplicationEvent, Tls13ApplicationState, Tls13ServerFirstFlight, TlsCiphertextRecord,
        TlsPlaintextRecord,
    },
    tls_identity::{TlsIdentity, TlsIdentityStore},
};

pub const DEV_TLS_PROBE_ADDR: &str = "127.0.0.1:8443";

const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROBE_HTTP_REQUEST: usize = 32 * 1024;

pub fn run(certificate_path: &str, private_key_path: &str) -> io::Result<()> {
    let identity = TlsIdentity::load_pem_files(certificate_path, private_key_path)?;

    let identities = TlsIdentityStore::new(vec![identity])?;

    let listener = TcpListener::bind(DEV_TLS_PROBE_ADDR)?;

    println!(
        "INFO event=tls_probe_listener_start address={DEV_TLS_PROBE_ADDR} identities={}",
        identities.identities().len()
    );
    io::stdout().flush()?;

    let (mut stream, peer_addr) = listener.accept()?;

    stream.set_read_timeout(Some(PROBE_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_IO_TIMEOUT))?;

    println!("INFO event=tls_probe_connection_accept peer={peer_addr}");

    handle_connection(&mut stream, &identities)?;

    println!("INFO event=tls_probe_complete peer={peer_addr}");

    Ok(())
}

fn handle_connection(stream: &mut TcpStream, identities: &TlsIdentityStore) -> io::Result<()> {
    let client_hello1 = read_client_hello(stream, false)?;

    let parsed_client_hello =
        tls::parse_client_hello(&client_hello1).map_err(|error| invalid_data(error.to_string()))?;

    let compatibility_mode = !parsed_client_hello.legacy_session_id().is_empty();

    let server_name = parsed_client_hello
        .server_name()
        .ok_or_else(|| invalid_data("TLS probe ClientHello contains no SNI hostname"))?;

    let identity = identities.select(server_name).ok_or_else(|| {
        invalid_data(format!(
            "TLS probe has no certificate identity matching SNI hostname {server_name}"
        ))
    })?;

    println!("INFO event=tls_probe_identity_selected server_name={server_name}");

    let first_flight = tls::negotiate_tls13_server_first_flight(&client_hello1)
        .map_err(|error| invalid_data(error.to_string()))?;

    let mut flight = match first_flight {
        Tls13ServerFirstFlight::ServerHello(flight) => {
            write_handshake_message(stream, flight.server_hello())?;

            if compatibility_mode {
                write_compatibility_change_cipher_spec(stream)?;
            }

            println!("INFO event=tls_probe_server_hello path=direct");

            flight
        }
        Tls13ServerFirstFlight::HelloRetry(retry) => {
            write_handshake_message(stream, retry.hello_retry_request())?;

            if compatibility_mode {
                write_compatibility_change_cipher_spec(stream)?;
            }

            println!(
                "INFO event=tls_probe_hello_retry selected_group=0x{:04x}",
                retry.selected_group()
            );

            let client_hello2 = read_client_hello(stream, true)?;

            let flight = retry
                .continue_with_client_hello(&client_hello2)
                .map_err(|error| invalid_data(error.to_string()))?;

            write_handshake_message(stream, flight.server_hello())?;

            println!("INFO event=tls_probe_server_hello path=retry");

            flight
        }
    };

    let authentication = flight
        .authenticate_server(identity.certificate_chain(), identity.signing_key())
        .map_err(|error| invalid_data(error.to_string()))?;

    write_ciphertext_record(stream, flight.encrypted_extensions_record())?;

    write_ciphertext_records(stream, authentication.certificate_records())?;
    write_ciphertext_records(stream, authentication.certificate_verify_records())?;
    write_ciphertext_records(stream, authentication.finished_records())?;

    let client_finished = read_client_finished_record(stream)?;

    let mut application_state = flight
        .complete_handshake(&[client_finished])
        .map_err(|error| invalid_data(error.to_string()))?;

    let negotiated_alpn = application_state
        .negotiated_alpn()
        .and_then(|protocol| std::str::from_utf8(protocol).ok())
        .unwrap_or("-");

    println!("INFO event=tls_probe_handshake_complete alpn={negotiated_alpn}");

    let request = read_http_request(stream, &mut application_state)?;

    if !request.starts_with(b"GET / HTTP/1.1\r\n") {
        return Err(invalid_data("TLS probe expected an HTTP/1.1 GET request"));
    }

    println!(
        "INFO event=tls_probe_request_received bytes={}",
        request.len()
    );

    let response = b"HTTP/1.1 200 OK\r\n\
Content-Length: 24\r\n\
Content-Type: text/plain\r\n\
Connection: close\r\n\
\r\n\
BareProxy TLS probe OK.\n";

    let response_record = application_state
        .encrypt_application_data_record(response)
        .map_err(|error| invalid_data(error.to_string()))?;

    write_ciphertext_record(stream, &response_record)?;

    let close_notify = application_state
        .encrypt_close_notify()
        .map_err(|error| invalid_data(error.to_string()))?;

    write_ciphertext_record(stream, &close_notify)?;

    println!(
        "INFO event=tls_probe_response_sent bytes={}",
        response.len()
    );

    Ok(())
}

fn read_client_hello(
    stream: &mut TcpStream,
    allow_compatibility_change_cipher_spec: bool,
) -> io::Result<Vec<u8>> {
    let mut deframer = HandshakeDeframer::new();

    loop {
        let wire = read_wire_record(stream)?;

        if wire[0] == ContentType::ChangeCipherSpec as u8 {
            if !allow_compatibility_change_cipher_spec {
                return Err(invalid_data(
                    "unexpected change_cipher_spec before the first ClientHello",
                ));
            }

            let record = decode_plaintext_record(&wire)?;

            if record.content_type() != ContentType::ChangeCipherSpec {
                return Err(invalid_data(
                    "invalid TLS compatibility change_cipher_spec record",
                ));
            }

            println!("INFO event=tls_probe_compatibility_ccs_received");

            continue;
        }

        if wire[0] != ContentType::Handshake as u8 {
            return Err(invalid_data(format!(
                "expected plaintext ClientHello record, got TLS content type {}",
                wire[0]
            )));
        }

        let record = decode_plaintext_record(&wire)?;

        if allow_compatibility_change_cipher_spec
            && record.legacy_record_version() != TLS_LEGACY_RECORD_VERSION
        {
            return Err(invalid_data(format!(
                "second ClientHello record version must be 0x{TLS_LEGACY_RECORD_VERSION:04x}"
            )));
        }

        let messages = deframer
            .push_record(&record)
            .map_err(|error| invalid_data(error.to_string()))?;

        if messages.len() > 1 {
            return Err(invalid_data(
                "TLS probe received multiple handshake messages while waiting for ClientHello",
            ));
        }

        if let Some(message) = messages.into_iter().next() {
            deframer
                .require_message_boundary()
                .map_err(|error| invalid_data(error.to_string()))?;

            return Ok(message);
        }
    }
}

fn read_client_finished_record(stream: &mut TcpStream) -> io::Result<TlsCiphertextRecord> {
    loop {
        let wire = read_wire_record(stream)?;

        if wire[0] == ContentType::ChangeCipherSpec as u8 {
            let record = decode_plaintext_record(&wire)?;

            if record.content_type() != ContentType::ChangeCipherSpec {
                return Err(invalid_data(
                    "invalid TLS compatibility change_cipher_spec record",
                ));
            }

            println!("INFO event=tls_probe_compatibility_ccs_received");

            continue;
        }

        if wire[0] != ContentType::ApplicationData as u8 {
            return Err(invalid_data(format!(
                "expected protected client Finished record, got TLS content type {}",
                wire[0]
            )));
        }

        return decode_ciphertext_record(&wire);
    }
}

fn read_http_request(
    stream: &mut TcpStream,
    application_state: &mut Tls13ApplicationState,
) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();

    loop {
        let wire = read_wire_record(stream)?;

        if wire[0] != ContentType::ApplicationData as u8 {
            return Err(invalid_data(format!(
                "expected protected application-data record, got TLS content type {}",
                wire[0]
            )));
        }

        let record = decode_ciphertext_record(&wire)?;

        let event = application_state
            .receive_protected_record(&record)
            .map_err(|error| invalid_data(error.to_string()))?;

        match event {
            Tls13ApplicationEvent::ApplicationData(fragment) => {
                request.extend_from_slice(&fragment);
            }
            Tls13ApplicationEvent::CloseNotify => {
                return Err(invalid_data(
                    "client sent close_notify before the TLS probe HTTP request",
                ));
            }
            Tls13ApplicationEvent::UserCanceled => {
                return Err(invalid_data(
                    "client canceled the TLS connection before the probe request",
                ));
            }
            Tls13ApplicationEvent::FatalAlert(description) => {
                return Err(invalid_data(format!(
                    "client sent fatal TLS alert {description:?}"
                )));
            }
            Tls13ApplicationEvent::IgnoredAfterCloseNotify => {
                return Err(invalid_data(
                    "TLS probe received application data after close_notify",
                ));
            }
        }

        if request.len() > MAX_PROBE_HTTP_REQUEST {
            return Err(invalid_data(format!(
                "TLS probe HTTP request exceeded {MAX_PROBE_HTTP_REQUEST} bytes"
            )));
        }

        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
}

fn write_handshake_message(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let record = TlsPlaintextRecord::new(ContentType::Handshake, message.to_vec())
        .map_err(|error| invalid_data(error.to_string()))?;

    let wire = record
        .serialize()
        .map_err(|error| invalid_data(error.to_string()))?;

    stream.write_all(&wire)?;
    stream.flush()
}

fn write_compatibility_change_cipher_spec(stream: &mut TcpStream) -> io::Result<()> {
    let record = TlsPlaintextRecord::new(ContentType::ChangeCipherSpec, vec![0x01])
        .map_err(|error| invalid_data(error.to_string()))?;

    let wire = record
        .serialize()
        .map_err(|error| invalid_data(error.to_string()))?;

    stream.write_all(&wire)?;
    stream.flush()?;

    println!("INFO event=tls_probe_compatibility_ccs_sent");

    Ok(())
}

fn write_ciphertext_records(
    stream: &mut TcpStream,
    records: &[TlsCiphertextRecord],
) -> io::Result<()> {
    for record in records {
        stream.write_all(&record.serialize())?;
    }

    stream.flush()
}

fn write_ciphertext_record(stream: &mut TcpStream, record: &TlsCiphertextRecord) -> io::Result<()> {
    stream.write_all(&record.serialize())?;
    stream.flush()
}

fn read_wire_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; TLS_RECORD_HEADER_SIZE];

    stream.read_exact(&mut header)?;

    let fragment_length = usize::from(u16::from_be_bytes([header[3], header[4]]));

    if fragment_length > TLS_CIPHERTEXT_FRAGMENT_LIMIT {
        return Err(invalid_data(format!(
            "TLS probe received oversized record fragment of {fragment_length} bytes"
        )));
    }

    let mut wire = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + fragment_length);

    wire.extend_from_slice(&header);
    wire.resize(TLS_RECORD_HEADER_SIZE + fragment_length, 0);

    stream.read_exact(&mut wire[TLS_RECORD_HEADER_SIZE..])?;

    Ok(wire)
}

fn decode_plaintext_record(wire: &[u8]) -> io::Result<TlsPlaintextRecord> {
    let mut decoder = PlaintextRecordDecoder::new();

    let mut records = decoder
        .push(wire)
        .map_err(|error| invalid_data(error.to_string()))?;

    if records.len() != 1 || decoder.buffered_len() != 0 {
        return Err(invalid_data(
            "TLS probe expected exactly one complete plaintext record",
        ));
    }

    Ok(records
        .pop()
        .expect("validated one-record plaintext decode"))
}

fn decode_ciphertext_record(wire: &[u8]) -> io::Result<TlsCiphertextRecord> {
    let mut decoder = CiphertextRecordDecoder::new();

    let mut records = decoder
        .push(wire)
        .map_err(|error| invalid_data(error.to_string()))?;

    if records.len() != 1 || decoder.buffered_len() != 0 {
        return Err(invalid_data(
            "TLS probe expected exactly one complete ciphertext record",
        ));
    }

    Ok(records
        .pop()
        .expect("validated one-record ciphertext decode"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
