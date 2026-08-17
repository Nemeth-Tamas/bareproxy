#!/usr/bin/env python3

import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from tls_interop import (
    HTTP_REQUEST,
    ROOT,
    encode_sec1_p256_private_key,
    generate_p256_private_scalar,
    require_command,
    wait_for_probe,
)


TLS_PROBE_ADDRESS = "127.0.0.1:8443"


def generate_identity(openssl, directory, hostname):
    directory = Path(directory)

    private_bytes = generate_p256_private_scalar()

    stem = hostname.replace(".", "-")

    key_pem = directory / f"{stem}-key.pem"
    cert_pem = directory / f"{stem}-cert.pem"

    key_pem.write_text(
        encode_sec1_p256_private_key(private_bytes),
        encoding="ascii",
    )

    try:
        os.chmod(key_pem, 0o600)
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
            f"/CN={hostname}",
            "-addext",
            f"subjectAltName=DNS:{hostname}",
            "-out",
            str(cert_pem),
        ],
        cwd=ROOT,
        check=True,
    )

    return cert_pem, key_pem


def wait_for_server_event(server, server_lines, needle):
    deadline = time.monotonic() + 3.0

    while time.monotonic() < deadline:
        if any(needle in line for line in server_lines):
            return True

        if server.poll() is not None:
            return False

        time.sleep(0.05)

    return False


def run_client(openssl, ca_bundle, hostname, groups):
    command = [
        openssl,
        "s_client",
        "-connect",
        TLS_PROBE_ADDRESS,
        "-servername",
        hostname,
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        groups,
        "-alpn",
        "http/1.1",
        "-CAfile",
        str(ca_bundle),
        "-verify_return_error",
        "-verify_hostname",
        hostname,
        "-brief",
        "-ign_eof",
    ]

    return subprocess.run(
        command,
        cwd=ROOT,
        input=HTTP_REQUEST,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )


def print_checks(checks):
    passed = True

    for description, result in checks:
        marker = "PASS" if result else "FAIL"

        print(f"{marker}: {description}")

        if not result:
            passed = False

    return passed


def main():
    cargo = require_command("cargo")
    openssl = require_command("openssl")

    print("BareProxy configured multi-SNI TLS interoperability test")
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

    with tempfile.TemporaryDirectory(
        prefix="bareproxy-sni-interop-"
    ) as directory:
        directory = Path(directory)

        alpha_cert, alpha_key = generate_identity(
            openssl,
            directory,
            "alpha.localhost",
        )

        beta_cert, beta_key = generate_identity(
            openssl,
            directory,
            "beta.localhost",
        )

        ca_bundle = directory / "trusted-certs.pem"

        ca_bundle.write_text(
            alpha_cert.read_text(encoding="ascii")
            + beta_cert.read_text(encoding="ascii"),
            encoding="ascii",
        )

        config_path = directory / "bareproxy-sni.conf"

        config_path.write_text(
            "tls_identity = "
            f"{alpha_cert.name} | {alpha_key.name}\n"
            "tls_identity = "
            f"{beta_cert.name} | {beta_key.name}\n"
            "alpha.localhost -> 127.0.0.1:3000\n"
            "beta.localhost -> 127.0.0.1:3001\n",
            encoding="utf-8",
        )

        server = subprocess.Popen(
            [
                str(binary),
                "--tls-config-probe",
                str(config_path),
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

        if not wait_for_probe(
            server,
            server_lines,
            ready_event,
        ):
            if server.poll() is None:
                server.kill()

            server.wait(timeout=2)
            collector.join(timeout=1)

            print("FAIL: configured TLS probe did not become ready")
            print("".join(server_lines))

            return 1

        print()
        print("=== alpha.localhost / direct P-256 ===")

        alpha = run_client(
            openssl,
            ca_bundle,
            "alpha.localhost",
            "P-256",
        )

        alpha_event = wait_for_server_event(
            server,
            server_lines,
            "event=tls_probe_identity_selected server_name=alpha.localhost",
        )

        alpha_passed = print_checks(
            [
                ("OpenSSL exit code", alpha.returncode == 0),
                (
                    "alpha certificate verified for alpha.localhost",
                    "Verification: OK" in alpha.stdout
                    or "Verify return code: 0 (ok)" in alpha.stdout,
                ),
                (
                    "alpha identity selected by SNI",
                    alpha_event,
                ),
                (
                    "encrypted HTTP round-tripped",
                    "BareProxy TLS probe OK." in alpha.stdout,
                ),
                (
                    "direct ServerHello path used",
                    wait_for_server_event(
                        server,
                        server_lines,
                        "event=tls_probe_server_hello path=direct",
                    ),
                ),
            ]
        )

        print()
        print("=== beta.localhost / HelloRetryRequest ===")

        beta = run_client(
            openssl,
            ca_bundle,
            "beta.localhost",
            "X25519:P-256",
        )

        beta_event = wait_for_server_event(
            server,
            server_lines,
            "event=tls_probe_identity_selected server_name=beta.localhost",
        )

        beta_passed = print_checks(
            [
                ("OpenSSL exit code", beta.returncode == 0),
                (
                    "beta certificate verified for beta.localhost",
                    "Verification: OK" in beta.stdout
                    or "Verify return code: 0 (ok)" in beta.stdout,
                ),
                (
                    "beta identity selected by SNI",
                    beta_event,
                ),
                (
                    "encrypted HTTP round-tripped",
                    "BareProxy TLS probe OK." in beta.stdout,
                ),
                (
                    "HelloRetryRequest path used",
                    wait_for_server_event(
                        server,
                        server_lines,
                        "event=tls_probe_hello_retry",
                    ),
                ),
            ]
        )

        print()
        print("=== unknown.localhost / rejection ===")

        unknown = run_client(
            openssl,
            ca_bundle,
            "unknown.localhost",
            "P-256",
        )

        rejected_event = wait_for_server_event(
            server,
            server_lines,
            (
                "event=tls_probe_sni_rejected "
                "server_name=unknown.localhost "
                "alert=unrecognized_name"
            ),
        )

        unknown_passed = print_checks(
            [
                (
                    "OpenSSL rejected the handshake",
                    unknown.returncode != 0,
                ),
                (
                    "BareProxy emitted unrecognized_name",
                    rejected_event,
                ),
            ]
        )

        server.terminate()

        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=2)

        collector.join(timeout=1)

        passed = alpha_passed and beta_passed and unknown_passed

        if not passed:
            print()
            print("--- BareProxy output ---")
            print("".join(server_lines).rstrip())

            print()
            print("--- alpha OpenSSL output ---")
            print(alpha.stdout.rstrip())

            print()
            print("--- beta OpenSSL output ---")
            print(beta.stdout.rstrip())

            print()
            print("--- unknown OpenSSL output ---")
            print(unknown.stdout.rstrip())

    print()
    print("=== result ===")

    if passed:
        print(
            "PASS: one BareProxy TLS socket served two configured "
            "SNI certificates and rejected an unknown name :D"
        )
        return 0

    print("FAIL: configured multi-SNI interoperability failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())