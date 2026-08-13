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

Start BareProxy from WSL:

```bash
cargo run
```

Then, from Windows PowerShell:

```powershell
curl.exe http://localhost:8080/
```

The response body should be:

```text
BareProxy is alive.
```

During Milestone 1, BareProxy intentionally serves one connection and then exits. A persistent accept loop is introduced in the next development phase.

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