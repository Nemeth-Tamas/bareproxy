# BareProxy

BareProxy is a deliberately dependency-free Rust reverse proxy being built from the protocol level upward.

The long-term goal is automatic HTTPS using ACME, including BareProxy's own HTTP, TLS 1.3, certificate, and ACME implementations without third-party Rust crates.

## Development environment

BareProxy is developed primarily under Windows 11 using WSL.

The initial development listener is:

```text
127.0.0.1:8080
```

WSL is the primary target during early development. Native Windows support is planned later without changing the dependency-free architecture.

## Localhost smoke test

Start a local upstream from WSL:

```bash
python3 -m http.server 3000
```

Start BareProxy in another terminal:

```bash
cargo run
```

Then request the configured `localhost` route:

```bash
curl http://127.0.0.1:8080/ -H 'Host: localhost'
```

BareProxy should proxy the response from the local upstream.

## Long-running runtime smoke test

Milestone 10 includes an automated WSL/Linux smoke harness that exercises sustained concurrent requests, malformed-request rejection, configuration reload, runtime counters, and graceful shutdown.

Run the default 60-second test with eight concurrent workers:

```bash
python3 smoke.py
```

The duration and concurrency can be overridden:

```bash
python3 smoke.py 300 16
```

The harness creates temporary upstream servers and configuration files automatically and cleans them up when complete.

A successful run ends with a summary similar to:

```text
SMOKE PASS
duration_seconds=60 concurrency=8
valid_requests=6127 malformed_requests=618
old_backend_responses=2058 new_backend_responses=4069
requests_total=6131 errors_total=618
```

## Development gates

Every development slice must pass:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Run BareProxy with:

```bash
cargo run
```

CLI help:

```bash
cargo run -- --help
```

Use a custom configuration path:

```bash
cargo run -- --config custom.conf
```

## Dependency policy

BareProxy intentionally keeps Cargo's `[dependencies]` section empty.

Protocol parsing, networking, TLS, cryptographic primitives, certificate handling, and ACME support are intended to be implemented using Rust's standard library and direct operating-system facilities where necessary.

See `TODO.md` for the full development roadmap.