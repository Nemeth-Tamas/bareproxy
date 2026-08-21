use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};

use crate::tls::{
    self, CiphertextRecordDecoder, ContentType, HandshakeDeframer, PlaintextRecordDecoder,
    TLS_CIPHERTEXT_FRAGMENT_LIMIT, TLS_RECORD_HEADER_SIZE, Tls13ClientHelloFlight, TlsAlert,
    TlsCiphertextRecord, TlsPlaintextRecord,
};

const CLIENT_PROBE_IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run(server_name: &str, address: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(address)?;

    stream.set_read_timeout(Some(CLIENT_PROBE_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_PROBE_IO_TIMEOUT))?;

    let client = Tls13ClientHelloFlight::new(server_name)
        .map_err(|error| invalid_data(error.to_string()))?;

    let client_hello_record =
        TlsPlaintextRecord::new(ContentType::Handshake, client.client_hello().to_vec())
            .map_err(|error| invalid_data(error.to_string()))?;

    let wire = client_hello_record
        .serialize()
        .map_err(|error| invalid_data(error.to_string()))?;

    stream.write_all(&wire)?;
    stream.flush()?;

    println!(
        "INFO event=tls_client_hello_sent server_name={server_name} address={address} bytes={}",
        client.client_hello().len()
    );

    let server_hello = read_server_hello(&mut stream)?;

    let mut handshake = client
        .receive_server_hello(&server_hello)
        .map_err(|error| invalid_data(error.to_string()))?;

    println!(
        "INFO event=tls_client_server_hello server_name={server_name} cipher_suite=0x{:04x} group=0x{:04x}",
        tls::TLS_CHACHA20_POLY1305_SHA256,
        tls::TLS_GROUP_SECP256R1
    );

    let encrypted_handshake = read_first_protected_server_record(&mut stream)?;

    let decrypted = handshake
        .decrypt_server_handshake_record(&encrypted_handshake)
        .map_err(|error| invalid_data(error.to_string()))?;

    let transcript_hash = handshake.transcript_hash();

    println!(
        "INFO event=tls_client_handshake_keys_ready server_name={server_name} decrypted_handshake_bytes={} transcript_prefix={:02x}{:02x}{:02x}{:02x}",
        decrypted.fragment().len(),
        transcript_hash[0],
        transcript_hash[1],
        transcript_hash[2],
        transcript_hash[3]
    );

    Ok(())
}

fn read_server_hello(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut deframer = HandshakeDeframer::new();

    loop {
        let wire = read_wire_record(stream)?;

        match wire[0] {
            value if value == ContentType::Handshake as u8 => {
                let record = decode_plaintext_record(&wire)?;

                let messages = deframer
                    .push_record(&record)
                    .map_err(|error| invalid_data(error.to_string()))?;

                if messages.len() > 1 {
                    return Err(invalid_data(
                        "TLS server sent multiple plaintext handshake messages while waiting for ServerHello",
                    ));
                }

                if let Some(message) = messages.into_iter().next() {
                    deframer
                        .require_message_boundary()
                        .map_err(|error| invalid_data(error.to_string()))?;

                    return Ok(message);
                }
            }
            value if value == ContentType::Alert as u8 => {
                let record = decode_plaintext_record(&wire)?;

                return Err(alert_error(&record));
            }
            value => {
                return Err(invalid_data(format!(
                    "expected plaintext TLS ServerHello record, got content type {value}"
                )));
            }
        }
    }
}

fn read_first_protected_server_record(stream: &mut TcpStream) -> io::Result<TlsCiphertextRecord> {
    loop {
        let wire = read_wire_record(stream)?;

        match wire[0] {
            value if value == ContentType::ChangeCipherSpec as u8 => {
                let record = decode_plaintext_record(&wire)?;

                if record.content_type() != ContentType::ChangeCipherSpec {
                    return Err(invalid_data(
                        "invalid TLS compatibility change_cipher_spec record",
                    ));
                }

                println!("INFO event=tls_client_compatibility_ccs_received");
            }
            value if value == ContentType::ApplicationData as u8 => {
                return decode_ciphertext_record(&wire);
            }
            value if value == ContentType::Alert as u8 => {
                let record = decode_plaintext_record(&wire)?;

                return Err(alert_error(&record));
            }
            value => {
                return Err(invalid_data(format!(
                    "expected protected TLS handshake record, got content type {value}"
                )));
            }
        }
    }
}

fn read_wire_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; TLS_RECORD_HEADER_SIZE];

    stream.read_exact(&mut header)?;

    let fragment_length = usize::from(u16::from_be_bytes([header[3], header[4]]));

    if fragment_length > TLS_CIPHERTEXT_FRAGMENT_LIMIT {
        return Err(invalid_data(format!(
            "TLS record fragment is {fragment_length} bytes, exceeding the {}-byte transport limit",
            TLS_CIPHERTEXT_FRAGMENT_LIMIT
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
            "expected exactly one complete TLS plaintext record",
        ));
    }

    Ok(records.remove(0))
}

fn decode_ciphertext_record(wire: &[u8]) -> io::Result<TlsCiphertextRecord> {
    let mut decoder = CiphertextRecordDecoder::new();

    let mut records = decoder
        .push(wire)
        .map_err(|error| invalid_data(error.to_string()))?;

    if records.len() != 1 || decoder.buffered_len() != 0 {
        return Err(invalid_data(
            "expected exactly one complete TLS ciphertext record",
        ));
    }

    Ok(records.remove(0))
}

fn alert_error(record: &TlsPlaintextRecord) -> io::Error {
    match TlsAlert::parse(record.fragment()) {
        Ok(alert) => invalid_data(format!(
            "TLS peer sent plaintext alert level={} description={:?}",
            alert.level(),
            alert.description()
        )),
        Err(error) => invalid_data(error.to_string()),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
