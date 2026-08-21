#!/usr/bin/env python3

import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from tls_interop import (
    ROOT,
    encode_sec1_p256_private_key,
    generate_p256_private_scalar,
    require_command,
)


SERVER_NAME = "client.localhost"
CIPHER_SUITE = "TLS_CHACHA20_POLY1305_SHA256"


def generate_identity(openssl, directory):
    directory = Path(directory)

    key_path = directory / "server-key.pem"
    cert_path = directory / "server-cert.pem"

    key_path.write_text(
        encode_sec1_p256_private_key(
            generate_p256_private_scalar()
        ),
        encoding="ascii",
    )

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    subprocess.run(
        [
            openssl,
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-sha256",
            "-days",
            "1",
            "-subj",
            f"/CN={SERVER_NAME}",
            "-addext",
            f"subjectAltName=DNS:{SERVER_NAME}",
            "-out",
            str(cert_path),
        ],
        cwd=ROOT,
        check=True,
    )

    return cert_path, key_path


def reserve_port():
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_listener(server, port):
    deadline = time.monotonic() + 3.0

    while time.monotonic() < deadline:
        if server.poll() is not None:
            return False

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.1,
            ):
                return True
        except OSError:
            time.sleep(0.05)

    return False


def run_probe(binary, server_name, port):
    return subprocess.run(
        [
            str(binary),
            "--tls-client-probe",
            server_name,
            f"127.0.0.1:{port}",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )


def print_check(description, passed):
    marker = "PASS" if passed else "FAIL"
    print(f"{marker}: {description}")
    return passed


def main():
    cargo = require_command("cargo")
    openssl = require_command("openssl")

    print("BareProxy TLS 1.3 client interoperability test")
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

    binary_name = (
        "bareproxy.exe"
        if os.name == "nt"
        else "bareproxy"
    )

    binary = ROOT / "target" / "debug" / binary_name

    if not binary.exists():
        print(
            "FAIL: expected BareProxy binary "
            f"was not produced: {binary}"
        )
        return 1

    with tempfile.TemporaryDirectory(
        prefix="bareproxy-client-interop-"
    ) as directory:
        directory = Path(directory)

        cert_path, key_path = generate_identity(
            openssl,
            directory,
        )

        port = reserve_port()

        server = subprocess.Popen(
            [
                openssl,
                "s_server",
                "-accept",
                f"127.0.0.1:{port}",
                "-cert",
                str(cert_path),
                "-key",
                str(key_path),
                "-cert2",
                str(cert_path),
                "-key2",
                str(key_path),
                "-servername",
                SERVER_NAME,
                "-servername_fatal",
                "-tls1_3",
                "-ciphersuites",
                CIPHER_SUITE,
                "-groups",
                "P-256",
                "-alpn",
                "http/1.1",
                "-quiet",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            if not wait_for_listener(server, port):
                print(
                    "FAIL: OpenSSL TLS server "
                    "did not become ready"
                )

                if server.poll() is None:
                    server.kill()

                output, _ = server.communicate(timeout=2)

                if output:
                    print(output.rstrip())

                return 1

            print()
            print("=== matching SNI ===")

            correct = run_probe(
                binary,
                SERVER_NAME,
                port,
            )

            correct_passed = True

            correct_passed &= print_check(
                "BareProxy client probe exit code",
                correct.returncode == 0,
            )

            correct_passed &= print_check(
                "ClientHello sent matching SNI",
                (
                    "event=tls_client_hello_sent "
                    f"server_name={SERVER_NAME}"
                )
                in correct.stdout,
            )

            correct_passed &= print_check(
                "real OpenSSL ServerHello parsed",
                "event=tls_client_server_hello"
                in correct.stdout,
            )

            correct_passed &= print_check(
                "ChaCha20-Poly1305 selected",
                "cipher_suite=0x1303"
                in correct.stdout,
            )

            correct_passed &= print_check(
                "P-256 selected",
                "group=0x0017"
                in correct.stdout,
            )

            correct_passed &= print_check(
                "handshake traffic keys decrypt OpenSSL",
                "event=tls_client_handshake_keys_ready"
                in correct.stdout,
            )

            server_alive = server.poll() is None

            print()
            print("=== mismatched SNI ===")

            mismatch = run_probe(
                binary,
                "wrong.localhost",
                port,
            )

            mismatch_passed = True

            mismatch_passed &= print_check(
                "OpenSSL server remained available",
                server_alive,
            )

            mismatch_passed &= print_check(
                "fatal SNI mismatch rejected",
                mismatch.returncode != 0,
            )

            mismatch_passed &= print_check(
                "BareProxy received unrecognized_name",
                "UnrecognizedName" in mismatch.stdout,
            )

            passed = (
                correct_passed
                and mismatch_passed
            )

            if not passed:
                print()
                print("--- matching probe output ---")
                print(correct.stdout.rstrip())

                print()
                print("--- mismatched probe output ---")
                print(mismatch.stdout.rstrip())

        finally:
            if server.poll() is None:
                server.terminate()

            try:
                server_output, _ = server.communicate(
                    timeout=2
                )
            except subprocess.TimeoutExpired:
                server.kill()
                server_output, _ = server.communicate(
                    timeout=2
                )

    print()
    print("=== result ===")

    if passed:
        print(
            "PASS: BareProxy sent SNI, parsed an OpenSSL "
            "TLS 1.3 ServerHello, and derived working "
            "handshake traffic keys :D"
        )
        return 0

    if server_output:
        print()
        print("--- OpenSSL server output ---")
        print(server_output.rstrip())

    print("FAIL: TLS client interoperability failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())