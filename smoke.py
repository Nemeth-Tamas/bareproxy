#!/usr/bin/env python3

import argparse
import http.server
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

LISTEN_ADDRESS = ("127.0.0.1", 8080)
REQUEST_TIMEOUT_SECONDS = 2.0
RELOAD_SETTLE_SECONDS = 0.25


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run BareProxy's long-running Milestone 10 smoke test."
    )
    parser.add_argument(
        "duration",
        nargs="?",
        type=int,
        default=60,
        help="mixed-load duration in seconds (default: 60)",
    )
    parser.add_argument(
        "concurrency",
        nargs="?",
        type=int,
        default=8,
        help="concurrent workload workers, 1..64 (default: 8)",
    )

    args = parser.parse_args()

    if args.duration < 6:
        parser.error("duration must be at least 6 seconds")

    if not 1 <= args.concurrency <= 64:
        parser.error("concurrency must be between 1 and 64")

    return args


def assert_listen_port_is_free():
    probe = socket.socket()

    try:
        probe.bind(LISTEN_ADDRESS)
    except OSError as error:
        raise RuntimeError(
            f"{LISTEN_ADDRESS[0]}:{LISTEN_ADDRESS[1]} is unavailable: {error}"
        )
    finally:
        probe.close()


def make_backend(label):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = f"{label}\n".encode()

            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()

            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        Handler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server, thread


def write_config(path, upstream_port):
    path.write_text(
        "max_connections = 128\n"
        "client_idle_timeout_seconds = 30\n"
        "upstream_timeout_seconds = 10\n"
        "\n"
        f"localhost -> 127.0.0.1:{upstream_port}\n",
        encoding="utf-8",
    )


def exchange(request):
    with socket.create_connection(
        LISTEN_ADDRESS,
        timeout=REQUEST_TIMEOUT_SECONDS,
    ) as sock:
        sock.settimeout(REQUEST_TIMEOUT_SECONDS)
        sock.sendall(request)

        response = bytearray()

        while True:
            chunk = sock.recv(4096)

            if not chunk:
                return bytes(response)

            response.extend(chunk)


def parse_response(response):
    head, separator, body = response.partition(b"\r\n\r\n")

    if not separator:
        raise RuntimeError(
            f"response has no header terminator: {response!r}"
        )

    return head, body


def request_backend_body(path="/smoke-sanity"):
    response = exchange(
        (
            f"GET {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
    )

    head, body = parse_response(response)

    if not (
        head.startswith(b"HTTP/1.0 200 ")
        or head.startswith(b"HTTP/1.1 200 ")
    ):
        raise RuntimeError(
            f"unexpected success response: {response!r}"
        )

    if body not in (b"OLD\n", b"NEW\n"):
        raise RuntimeError(
            f"unexpected backend body: {body!r}"
        )

    return body.decode().strip()


def wait_for_listener(process, timeout=5.0):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                "BareProxy exited during startup "
                f"with code {process.returncode}"
            )

        try:
            with socket.create_connection(
                LISTEN_ADDRESS,
                timeout=0.2,
            ):
                return
        except OSError:
            time.sleep(0.05)

    raise RuntimeError(
        "BareProxy listener did not become reachable"
    )


def wait_for_body(
    process,
    expected,
    sanity_counter,
    timeout=5.0,
):
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"BareProxy exited while waiting for {expected}"
            )

        try:
            body = request_backend_body()
            sanity_counter[0] += 1

            if body == expected:
                return
        except (OSError, RuntimeError) as error:
            last_error = error

        time.sleep(0.05)

    raise RuntimeError(
        f"timed out waiting for backend body {expected}; "
        f"last error: {last_error}"
    )


def run_workload(
    duration,
    concurrency,
    counts,
    failures,
):
    lock = threading.Lock()
    stop = threading.Event()
    deadline = time.monotonic() + duration

    def worker(worker_id):
        sequence = 0

        while (
            time.monotonic() < deadline
            and not stop.is_set()
        ):
            try:
                body = request_backend_body(
                    f"/smoke/{worker_id}/{sequence}"
                )

                with lock:
                    counts["valid"] += 1

                    if body == "OLD":
                        counts["old"] += 1
                    else:
                        counts["new"] += 1

                if sequence % 10 == 0:
                    response = exchange(
                        b"POST /smoke-bad HTTP/1.1\r\n"
                        b"Host: localhost\r\n"
                        b"Content-Length: 4\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"Connection: close\r\n"
                        b"\r\n"
                        b"0\r\n"
                        b"\r\n"
                    )

                    if not response.startswith(
                        b"HTTP/1.1 400 Bad Request\r\n"
                    ):
                        raise RuntimeError(
                            "malformed request was not rejected: "
                            f"{response!r}"
                        )

                    with lock:
                        counts["bad"] += 1

                sequence += 1
                time.sleep(0.05)

            except Exception as error:
                with lock:
                    failures.append(
                        f"worker {worker_id}: {error}"
                    )

                stop.set()
                return

    threads = [
        threading.Thread(
            target=worker,
            args=(worker_id,),
        )
        for worker_id in range(concurrency)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()


def parse_shutdown_counters(log_text):
    summaries = [
        line
        for line in log_text.splitlines()
        if "INFO event=shutdown_complete" in line
    ]

    if not summaries:
        raise RuntimeError(
            "shutdown_complete log line not found"
        )

    summary = summaries[-1]

    requests = re.search(
        r"requests_total=(\d+)",
        summary,
    )

    errors = re.search(
        r"errors_total=(\d+)",
        summary,
    )

    if requests is None or errors is None:
        raise RuntimeError(
            f"could not parse shutdown counters: {summary}"
        )

    return (
        int(requests.group(1)),
        int(errors.group(1)),
    )


def stop_process(process):
    if process is None or process.poll() is not None:
        return

    process.terminate()

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def main():
    args = parse_args()

    root = Path(__file__).resolve().parent

    assert_listen_port_is_free()

    print("==> building BareProxy")

    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=root,
        check=True,
    )

    old_server, old_thread = make_backend("OLD")
    new_server, new_thread = make_backend("NEW")

    process = None
    log_file = None

    try:
        old_port = old_server.server_address[1]
        new_port = new_server.server_address[1]

        with tempfile.TemporaryDirectory(
            prefix="bareproxy-smoke-"
        ) as temp_dir:
            temp = Path(temp_dir)

            config_path = (
                temp / "bareproxy-smoke.conf"
            )

            log_path = (
                temp / "bareproxy.log"
            )

            write_config(
                config_path,
                old_port,
            )

            print("==> starting BareProxy")

            log_file = log_path.open(
                "w",
                encoding="utf-8",
            )

            process = subprocess.Popen(
                [
                    str(
                        root
                        / "target"
                        / "debug"
                        / "bareproxy"
                    ),
                    "--config",
                    str(config_path),
                ],
                cwd=root,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )

            wait_for_listener(process)

            sanity_requests = [0]

            wait_for_body(
                process,
                "OLD",
                sanity_requests,
            )

            print(
                "==> proving invalid reload is rejected"
            )

            config_path.write_text(
                "this is intentionally invalid "
                "smoke-test garbage :D\n",
                encoding="utf-8",
            )

            process.send_signal(
                signal.SIGHUP
            )

            time.sleep(
                RELOAD_SETTLE_SECONDS
            )

            wait_for_body(
                process,
                "OLD",
                sanity_requests,
            )

            print(
                f"==> running {args.duration}s "
                "mixed workload "
                f"with concurrency={args.concurrency}"
            )

            counts = {
                "valid": 0,
                "bad": 0,
                "old": 0,
                "new": 0,
            }

            failures = []

            workload = threading.Thread(
                target=run_workload,
                args=(
                    args.duration,
                    args.concurrency,
                    counts,
                    failures,
                ),
            )

            workload.start()

            time.sleep(
                max(
                    1.0,
                    args.duration / 3.0,
                )
            )

            if not workload.is_alive():
                raise RuntimeError(
                    "workload stopped before reload phase"
                )

            if process.poll() is not None:
                raise RuntimeError(
                    "BareProxy exited during workload"
                )

            print(
                "==> reloading to NEW backend "
                "while workload is active"
            )

            write_config(
                config_path,
                new_port,
            )

            process.send_signal(
                signal.SIGHUP
            )

            wait_for_body(
                process,
                "NEW",
                sanity_requests,
            )

            workload.join()

            if failures:
                raise RuntimeError(
                    "; ".join(failures)
                )

            if counts["valid"] == 0:
                raise RuntimeError(
                    "workload completed without "
                    "successful requests"
                )

            if counts["bad"] == 0:
                raise RuntimeError(
                    "workload completed without "
                    "malformed-request checks"
                )

            if (
                counts["old"] == 0
                or counts["new"] == 0
            ):
                raise RuntimeError(
                    "workload did not span both configs: "
                    f"old={counts['old']} "
                    f"new={counts['new']}"
                )

            if process.poll() is not None:
                raise RuntimeError(
                    "BareProxy did not survive "
                    "the mixed workload"
                )

            wait_for_body(
                process,
                "NEW",
                sanity_requests,
            )

            print(
                "==> requesting graceful shutdown"
            )

            process.send_signal(
                signal.SIGINT
            )

            try:
                return_code = process.wait(
                    timeout=10
                )
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(
                    "BareProxy did not finish "
                    "graceful shutdown"
                ) from error

            if return_code != 0:
                raise RuntimeError(
                    "BareProxy exited with code "
                    f"{return_code}"
                )

            log_file.close()
            log_file = None

            log_text = log_path.read_text(
                encoding="utf-8"
            )

            if (
                "WARN event=config_reload_rejected"
                not in log_text
            ):
                raise RuntimeError(
                    "invalid reload rejection "
                    "was not logged"
                )

            if (
                "INFO event=config_reload "
                not in log_text
            ):
                raise RuntimeError(
                    "successful reload "
                    "was not logged"
                )

            (
                actual_requests,
                actual_errors,
            ) = parse_shutdown_counters(
                log_text
            )

            expected_requests = (
                counts["valid"]
                + sanity_requests[0]
            )

            expected_errors = (
                counts["bad"]
            )

            if (
                actual_requests
                != expected_requests
            ):
                raise RuntimeError(
                    "request counter mismatch: "
                    f"expected={expected_requests} "
                    f"actual={actual_requests}"
                )

            if (
                actual_errors
                != expected_errors
            ):
                raise RuntimeError(
                    "error counter mismatch: "
                    f"expected={expected_errors} "
                    f"actual={actual_errors}"
                )

            print()
            print("SMOKE PASS")

            print(
                f"duration_seconds={args.duration} "
                f"concurrency={args.concurrency}"
            )

            print(
                f"valid_requests={counts['valid']} "
                f"malformed_requests={counts['bad']}"
            )

            print(
                f"old_backend_responses={counts['old']} "
                f"new_backend_responses={counts['new']}"
            )

            print(
                f"requests_total={actual_requests} "
                f"errors_total={actual_errors}"
            )

    except Exception:
        print(
            "SMOKE FAIL",
            file=sys.stderr,
        )

        if log_file is not None:
            log_file.flush()

        stop_process(process)

        if log_file is not None:
            log_file.close()
            log_file = None

        raise

    finally:
        stop_process(process)

        if log_file is not None:
            log_file.close()

        for server, thread in (
            (old_server, old_thread),
            (new_server, new_thread),
        ):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    main()