#!/usr/bin/env python3

import base64
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TLS_PROBE_ADDRESS = "127.0.0.1:8443"

P256_GROUP_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)

HTTP_REQUEST = (
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Connection: close\r\n"
    "\r\n"
)


def require_command(name):
    path = shutil.which(name)

    if path is None:
        print(f"FAIL: required command not found: {name}")
        sys.exit(1)

    return path


def generate_p256_private_scalar():
    while True:
        private_bytes = secrets.token_bytes(32)
        value = int.from_bytes(private_bytes, "big")

        if 0 < value < P256_GROUP_ORDER:
            return private_bytes


def encode_sec1_p256_private_key(private_bytes):
    # RFC 5915:
    # ECPrivateKey ::= SEQUENCE {
    #     version        INTEGER { ecPrivkeyVer1(1) },
    #     privateKey     OCTET STRING,
    #     parameters [0] ECParameters
    # }
    #
    # prime256v1 / secp256r1 OID:
    # 1.2.840.10045.3.1.7
    der = (
        bytes.fromhex("30310201010420")
        + private_bytes
        + bytes.fromhex("a00a06082a8648ce3d030107")
    )

    encoded = base64.b64encode(der).decode("ascii")

    lines = [
        encoded[index:index + 64]
        for index in range(0, len(encoded), 64)
    ]

    return (
        "-----BEGIN EC PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END EC PRIVATE KEY-----\n"
    )


def generate_certificate_material(openssl, directory):
    directory = Path(directory)

    private_bytes = generate_p256_private_scalar()

    key_pem = directory / "localhost-key.pem"
    key_hex = directory / "localhost-key.hex"
    cert_pem = directory / "localhost-cert.pem"
    cert_der = directory / "localhost-cert.der"

    key_pem.write_text(
        encode_sec1_p256_private_key(private_bytes),
        encoding="ascii",
    )

    key_hex.write_text(private_bytes.hex() + "\n", encoding="ascii")

    try:
        os.chmod(key_pem, 0o600)
        os.chmod(key_hex, 0o600)
    except OSError:
        pass

    subprocess.run(
        [
            openssl,
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_pem),
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-out",
            str(cert_pem),
        ],
        cwd=ROOT,
        check=True,
    )

    subprocess.run(
        [
            openssl,
            "x509",
            "-in",
            str(cert_pem),
            "-outform",
            "DER",
            "-out",
            str(cert_der),
        ],
        cwd=ROOT,
        check=True,
    )

    return cert_pem, cert_der, key_hex


def wait_for_probe(server, server_lines, ready_event):
    deadline = time.monotonic() + 5.0

    while time.monotonic() < deadline:
        if ready_event.is_set():
            return True

        if server.poll() is not None:
            return False

        time.sleep(0.05)

    return False


def run_probe_case(
    name,
    binary,
    openssl,
    cert_pem,
    cert_der,
    key_hex,
    groups,
    expect_retry,
):
    print()
    print(f"=== {name} ===")
    print(f"groups: {groups}")

    server = subprocess.Popen(
        [
            str(binary),
            "--tls-probe",
            str(cert_der),
            str(key_hex),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    server_lines = []
    ready_event = threading.Event()

    def collect_server_output():
        if server.stdout is None:
            return

        for line in server.stdout:
            server_lines.append(line)

            if "event=tls_probe_listener_start" in line:
                ready_event.set()

    collector = threading.Thread(
        target=collect_server_output,
        daemon=True,
    )

    collector.start()

    if not wait_for_probe(server, server_lines, ready_event):
        if server.poll() is None:
            server.kill()

        server.wait(timeout=2)
        collector.join(timeout=1)

        print("FAIL: BareProxy TLS probe did not become ready")
        print("".join(server_lines))

        return False

    command = [
        openssl,
        "s_client",
        "-connect",
        TLS_PROBE_ADDRESS,
        "-servername",
        "localhost",
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        groups,
        "-alpn",
        "http/1.1",
        "-CAfile",
        str(cert_pem),
        "-verify_return_error",
        "-verify_hostname",
        "localhost",
        "-brief",
        "-ign_eof",
    ]

    try:
        client = subprocess.run(
            command,
            cwd=ROOT,
            input=HTTP_REQUEST,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=2)
        collector.join(timeout=1)

        print("FAIL: openssl s_client timed out")
        print("".join(server_lines))

        return False

    try:
        server_return_code = server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server_return_code = server.wait(timeout=2)

    collector.join(timeout=1)

    client_output = client.stdout
    server_output = "".join(server_lines)

    checks = [
        ("OpenSSL exit code", client.returncode == 0),
        ("BareProxy exit code", server_return_code == 0),
        (
            "TLS 1.3 negotiated",
            "Protocol version: TLSv1.3" in client_output
            or "Protocol  : TLSv1.3" in client_output,
        ),
        (
            "ChaCha20-Poly1305 negotiated",
            "TLS_CHACHA20_POLY1305_SHA256" in client_output,
        ),
        (
            "certificate verified",
            "Verification: OK" in client_output
            or "Verify return code: 0 (ok)" in client_output,
        ),
        (
            "HTTP application data round-tripped",
            "BareProxy TLS probe OK." in client_output,
        ),
        (
            "HTTP/1.1 ALPN selected",
            "event=tls_probe_handshake_complete alpn=http/1.1"
            in server_output,
        ),
        (
            "expected HRR path",
            (
                "event=tls_probe_hello_retry" in server_output
                if expect_retry
                else "event=tls_probe_server_hello path=direct"
                in server_output
            ),
        ),
    ]

    passed = True

    for description, result in checks:
        marker = "PASS" if result else "FAIL"

        print(f"{marker}: {description}")

        if not result:
            passed = False

    if not passed:
        print()
        print("--- BareProxy output ---")
        print(server_output.rstrip())

        print()
        print("--- openssl s_client output ---")
        print(client_output.rstrip())

    return passed


def main():
    cargo = require_command("cargo")
    openssl = require_command("openssl")

    print("BareProxy TLS 1.3 interoperability test")
    print(
        subprocess.run(
            [openssl, "version"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    )

    print()
    print("=== build ===")

    subprocess.run(
        [cargo, "build"],
        cwd=ROOT,
        check=True,
    )

    binary_name = "bareproxy.exe" if os.name == "nt" else "bareproxy"
    binary = ROOT / "target" / "debug" / binary_name

    if not binary.exists():
        print(f"FAIL: expected BareProxy binary was not produced: {binary}")
        return 1

    with tempfile.TemporaryDirectory(prefix="bareproxy-tls-interop-") as directory:
        cert_pem, cert_der, key_hex = generate_certificate_material(
            openssl,
            directory,
        )

        direct_passed = run_probe_case(
            name="direct P-256 handshake",
            binary=binary,
            openssl=openssl,
            cert_pem=cert_pem,
            cert_der=cert_der,
            key_hex=key_hex,
            groups="P-256",
            expect_retry=False,
        )

        retry_passed = run_probe_case(
            name="HelloRetryRequest handshake",
            binary=binary,
            openssl=openssl,
            cert_pem=cert_pem,
            cert_der=cert_der,
            key_hex=key_hex,
            groups="X25519:P-256",
            expect_retry=True,
        )

    print()
    print("=== result ===")

    if direct_passed and retry_passed:
        print("PASS: BareProxy interoperates with OpenSSL TLS 1.3 on both paths :D")
        return 0

    print("FAIL: at least one TLS interoperability path failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())