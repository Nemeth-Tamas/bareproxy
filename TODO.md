# BareProxy TODO

BareProxy is a deliberately dependency-free Rust reverse proxy with automatic HTTPS.

The project starts as a tiny HTTP/1.1 reverse proxy and grows toward automatic ACME certificate issuance and TLS without third-party Rust crates.

## Project rules

* [ ] Keep `[dependencies]` empty.
* [ ] Prefer Rust `std` implementations over external libraries.
* [ ] Target Linux/WSL first.
* [ ] Keep Windows-native support possible where practical.
* [ ] Use HTTP/1.1 as the initial HTTP protocol.
* [ ] Use TLS 1.3 as the initial TLS protocol.
* [ ] Do not add HTTP/2 or HTTP/3 until the HTTP/1.1 + TLS + ACME path is complete.
* [ ] Keep configuration intentionally small and human-readable.
* [ ] Reject malformed or ambiguous protocol input rather than attempting clever recovery.
* [ ] Add tests alongside protocol parsers and cryptographic primitives.
* [ ] Keep each development slice small enough to test independently.

---

# Milestone 0 — Project foundation

Goal: establish the executable, error handling, testing conventions, and tiny internal architecture without prematurely building a framework.

* [x] Replace the Cargo-generated hello-world executable.
* [x] Add a BareProxy startup banner.
* [x] Define the first top-level application error type using only `std`.
* [x] Return meaningful process exit codes for startup failures.
* [x] Add basic command-line argument handling without a CLI crate.
* [x] Support `--help`.
* [x] Support `--version`.
* [x] Reject unknown command-line options.
* [x] Decide the default configuration file location.
* [x] Add a test module and first unit test.
* [x] Establish strict formatting/test/Clippy gates.
* [x] Document the WSL-first development environment.

**Milestone complete when:** BareProxy starts cleanly, reports useful errors, passes strict gates, and still has zero dependencies.

---

# Milestone 1 — Bare TCP HTTP server

Goal: prove BareProxy can accept real connections using only `std::net`.

* [x] Bind a `TcpListener`.
* [x] Default development listener to `127.0.0.1:8080`.
* [x] Print the bound address during startup.
* [x] Accept one incoming TCP connection.
* [x] Read bytes from the client.
* [x] Return a hard-coded valid HTTP/1.1 response.
* [x] Return a correct `Content-Length`.
* [x] Return a useful `Server` header.
* [x] Close the connection cleanly.
* [x] Handle client disconnects without crashing the process.
* [x] Handle listener errors explicitly.
* [x] Add a minimal localhost smoke-test procedure.

**Milestone complete when:** a Windows browser or `curl` can reach BareProxy running inside WSL through localhost.

---

# Milestone 2 — HTTP/1.1 request parser

Goal: understand incoming HTTP requests ourselves instead of treating them as arbitrary bytes.

* [x] Create an HTTP request representation.
* [x] Parse the request line.
* [x] Parse the HTTP method.
* [x] Parse the request target.
* [x] Parse the HTTP version.
* [x] Parse header names.
* [x] Parse header values.
* [x] Treat header names case-insensitively where required.
* [x] Detect the end of the header section.
* [x] Reject malformed request lines.
* [x] Reject malformed headers.
* [x] Reject unsupported HTTP versions.
* [x] Add a maximum request-line size.
* [x] Add a maximum individual header size.
* [x] Add a maximum total header size.
* [x] Add a maximum header count.
* [x] Parse `Host`.
* [x] Parse `Content-Length`.
* [x] Detect `Transfer-Encoding`.
* [x] Detect connection persistence semantics.
* [x] Handle partial TCP reads correctly.
* [x] Preserve unread bytes after the header parser finishes.
* [x] Add parser tests for valid requests.
* [x] Add parser tests for fragmented requests.
* [x] Add parser tests for invalid requests.
* [x] Add parser tests for size-limit failures.

**Milestone complete when:** BareProxy can reliably turn arbitrary fragmented TCP input into a validated HTTP/1.1 request header.

---

# Milestone 3 — HTTP response infrastructure

Goal: generate proper responses for BareProxy itself.

* [x] Create an HTTP response representation.
* [x] Implement status-code serialization.
* [x] Implement response-header serialization.
* [x] Implement body serialization.
* [x] Generate `400 Bad Request`.
* [x] Generate `404 Not Found`.
* [x] Generate `405 Method Not Allowed` where appropriate.
* [x] Generate `413 Content Too Large` or equivalent limit responses where applicable.
* [x] Generate `431 Request Header Fields Too Large`.
* [x] Generate `500 Internal Server Error`.
* [x] Generate `502 Bad Gateway`.
* [x] Generate `503 Service Unavailable`.
* [x] Ensure generated responses contain correct lengths.
* [x] Ensure generated responses cannot accidentally create malformed headers.
* [x] Add serialization tests.

**Milestone complete when:** every BareProxy-originated HTTP error can be generated consistently.

---

# Milestone 4 — Configuration file

Goal: describe proxy routes without recompiling BareProxy.

Initial configuration should stay intentionally boring.

* [x] Define the BareProxy configuration syntax.
* [x] Support comments.
* [x] Support blank lines.
* [x] Support one hostname mapped to one upstream.
* [x] Parse hostname values.
* [x] Parse upstream host/IP values.
* [x] Parse upstream ports.
* [x] Validate port ranges.
* [x] Normalize hostnames.
* [x] Reject duplicate routes.
* [x] Reject malformed configuration.
* [x] Include configuration line numbers in errors.
* [x] Load configuration at startup.
* [x] Reject startup when configuration is invalid.
* [x] Add configuration parser tests.
* [x] Add `--config <path>`.
* [x] Define a sensible default config filename.

Possible early syntax:

```text
example.test -> 127.0.0.1:3000
api.example.test -> 127.0.0.1:4000
```

**Milestone complete when:** routes can be changed entirely through a small text configuration file.

---

# Milestone 5 — Host routing

Goal: select an upstream based on the HTTP `Host` header.

* [x] Match an incoming `Host` against configured routes.
* [x] Correctly handle `Host` values containing a port.
* [x] Normalize hostname casing.
* [x] Reject requests without `Host` where HTTP/1.1 requires it.
* [x] Return `404` for unknown hosts.
* [x] Prevent ambiguous duplicate hostname mappings.
* [x] Add route lookup tests.
* [x] Add tests for host casing.
* [x] Add tests for explicit host ports.

**Milestone complete when:** multiple local hostnames can reach different upstream applications through one BareProxy listener.

---

# Milestone 6 — Basic reverse proxy

Goal: proxy a normal HTTP request to a real upstream server.

* [x] Open a TCP connection to the selected upstream.
* [x] Serialize the incoming request toward the upstream.
* [x] Preserve the method.
* [x] Preserve the request target.
* [x] Preserve ordinary request headers.
* [x] Rewrite or normalize connection-specific headers where required.
* [x] Add or update `Host` according to defined BareProxy behavior.
* [x] Add `X-Forwarded-For`.
* [x] Add `X-Forwarded-Host`.
* [x] Add `X-Forwarded-Proto`.
* [x] Send the request body upstream.
* [x] Read the upstream response.
* [x] Forward the upstream response to the client.
* [x] Handle upstream connection refusal.
* [x] Handle upstream disconnects.
* [x] Return `502 Bad Gateway` when appropriate.
* [x] Add an end-to-end proxy test using a local test upstream.

**Milestone complete when:** `browser -> BareProxy -> local HTTP application` works end to end.

---

# Milestone 7 — HTTP body framing and streaming

Goal: proxy real traffic without buffering entire messages in memory.

* [x] Stream fixed-length request bodies using `Content-Length`.
* [x] Stream fixed-length response bodies.
* [x] Parse chunked transfer coding.
* [x] Forward chunked request bodies safely.
* [x] Forward chunked response bodies safely.
* [x] Handle the terminating zero-size chunk.
* [x] Handle trailer sections.
* [x] Reject malformed chunk sizes.
* [x] Reject conflicting `Content-Length` values.
* [x] Reject unsafe `Content-Length` + `Transfer-Encoding` combinations.
* [x] Handle responses with no body.
* [x] Handle `HEAD` responses correctly.
* [x] Handle informational `1xx` responses where required.
* [x] Avoid unbounded body buffering.
* [x] Add fragmented-body tests.
* [x] Add chunked-body tests.
* [x] Add malformed framing tests.

**Milestone complete when:** large uploads and downloads can pass through BareProxy with bounded memory usage.

---

# Milestone 8 — Persistent connections and concurrency

Goal: stop behaving like a single-request toy server.

* [x] Support HTTP/1.1 client keep-alive.
* [x] Parse multiple requests on one connection.
* [x] Preserve buffered bytes between requests.
* [x] Support upstream keep-alive where safe.
* [x] Decide when upstream connections may be reused.
* [x] Close connections when protocol rules require it.
* [x] Handle multiple clients concurrently.
* [x] Begin with a straightforward thread-per-client model.
* [x] Ensure one slow client cannot block all other clients.
* [x] Track active connection count.
* [x] Add a configurable connection limit.
* [x] Reject excessive connections gracefully.
* [x] Add idle read timeouts where the platform permits.
* [x] Add upstream connection timeouts where practical.
* [x] Test several simultaneous clients.
* [x] Test multiple sequential requests over one client connection.

**Milestone complete when:** BareProxy can serve normal multi-client localhost traffic continuously.

---

# Milestone 9 — Proxy protocol correctness

Goal: handle the annoying corners needed for a trustworthy HTTP reverse proxy.

* [x] Implement hop-by-hop header removal.
* [x] Correctly process the `Connection` header's named hop-by-hop headers.
* [x] Handle `TE`.
* [x] Handle `Trailer`.
* [x] Handle `Upgrade`.
* [x] Support HTTP protocol upgrade tunnelling.
* [x] Support WebSocket upgrade traffic.
* [x] Switch upgraded connections into bidirectional byte tunnelling.
* [x] Correctly handle half-closed TCP streams where possible.
* [x] Prevent request smuggling through ambiguous framing.
* [x] Prevent header injection using CR/LF validation.
* [x] Reject malformed authority/host syntax.
* [x] Add request-smuggling regression tests.
* [x] Add upgrade tests.
* [x] Add WebSocket smoke testing.

**Milestone complete when:** BareProxy behaves predictably with ordinary applications and common HTTP/1.1 upgrade traffic.

---

# Milestone 10 — Runtime robustness

Goal: make BareProxy something that can stay running.

* [x] Add structured human-readable log messages without a logging crate.
* [x] Log listener startup.
* [x] Log accepted requests.
* [x] Log selected upstreams.
* [x] Log upstream failures.
* [x] Log protocol errors without dumping sensitive body data.
* [x] Add graceful Ctrl+C/SIGINT handling where possible.
* [x] Add graceful listener shutdown.
* [x] Allow active requests to finish during shutdown.
* [x] Add configuration reload support.
* [x] Validate replacement configuration before activating it.
* [x] Swap routing configuration without dropping active requests.
* [x] Ensure one failed request cannot terminate the server.
* [x] Add basic counters for requests and errors.
* [x] Add long-running smoke testing.

**Milestone complete when:** BareProxy can run for extended periods, reload configuration, and fail individual requests without failing the process.

---

# Milestone 11 — Cryptographic foundation

Goal: build the primitives required for TLS and ACME without crates.

This is where BareProxy stops being a reasonable weekend project.

* [x] Create dedicated crypto modules with intentionally narrow APIs.
* [x] Obtain cryptographically secure random bytes on Linux/WSL.
* [x] Read entropy from the OS rather than creating a pseudo-random generator.
* [x] Define a future abstraction for Windows secure randomness.
* [x] Implement constant-time byte comparison where secrets require it.
* [x] Implement hexadecimal encoding/decoding utilities.
* [x] Implement standard Base64 encoding.
* [x] Implement URL-safe Base64 without padding.
* [x] Add RFC/test-vector coverage for Base64.
* [x] Implement SHA-256.
* [x] Test SHA-256 against published vectors.
* [x] Implement HMAC-SHA256.
* [x] Test HMAC-SHA256 against published vectors.
* [x] Implement HKDF-Extract with SHA-256.
* [x] Implement HKDF-Expand with SHA-256.
* [x] Implement TLS 1.3 HKDF label expansion.
* [x] Test HKDF against published vectors.
* [x] Ensure secret-bearing temporary buffers are minimized.
* [x] Document every implemented cryptographic primitive and its source RFC/specification.

**Milestone complete when:** SHA-256/HMAC/HKDF/Base64 functionality passes known external test vectors.

---

# Milestone 12 — ChaCha20-Poly1305 AEAD

Goal: implement one TLS 1.3 application cipher suite completely.

Initial target:

```text
TLS_CHACHA20_POLY1305_SHA256
```

* [x] Implement ChaCha20 quarter-round.
* [x] Implement ChaCha20 block generation.
* [x] Implement ChaCha20 stream encryption.
* [x] Verify ChaCha20 against RFC test vectors.
* [x] Implement Poly1305 field arithmetic.
* [x] Implement Poly1305 authentication.
* [x] Verify Poly1305 against RFC test vectors.
* [x] Implement ChaCha20-Poly1305 AEAD.
* [x] Implement additional authenticated data handling.
* [x] Implement nonce construction.
* [x] Verify AEAD against RFC test vectors.
* [x] Reject modified authentication tags.
* [x] Ensure decryption never releases unauthenticated plaintext.
* [x] Add boundary-length tests.

**Milestone complete when:** our AEAD implementation exactly matches published ChaCha20-Poly1305 vectors.

---

# Milestone 13 — P-256 elliptic-curve cryptography

Goal: obtain the key-exchange and signing primitives needed for TLS, certificates, and ACME.

* [x] Implement fixed-width 256-bit integer storage.
* [x] Implement limb addition.
* [x] Implement limb subtraction.
* [x] Implement multiplication.
* [x] Implement modular reduction.
* [x] Implement modular inversion.
* [x] Implement scalar arithmetic modulo the P-256 group order.
* [x] Implement P-256 field arithmetic.
* [x] Represent curve points safely.
* [x] Validate curve points.
* [x] Implement point addition.
* [x] Implement point doubling.
* [x] Implement scalar multiplication.
* [x] Implement generator multiplication.
* [x] Implement SEC1 uncompressed point encoding.
* [x] Implement SEC1 point decoding.
* [x] Reject invalid points.
* [x] Implement P-256 ECDH.
* [x] Implement ECDSA signing with SHA-256.
* [x] Implement ECDSA verification with SHA-256.
* [x] Use deterministic or securely randomized ECDSA nonces.
* [x] Prevent zero/invalid signature components.
* [x] Add published P-256 arithmetic test vectors.
* [x] Add published ECDH test vectors.
* [x] Add published ECDSA test vectors.

**Milestone complete when:** P-256 key agreement and signatures interoperate with independently generated test vectors.

---

# Milestone 14 — DER, PEM, keys, and CSRs

Goal: speak enough ASN.1/X.509 machinery to request and store real certificates.

* [x] Implement minimal ASN.1 DER length encoding.
* [x] Implement minimal ASN.1 DER integer encoding.
* [x] Implement sequence encoding.
* [x] Implement set encoding where needed.
* [x] Implement object identifier encoding.
* [x] Implement bit-string encoding.
* [x] Implement octet-string encoding.
* [x] Implement context-specific tagged values needed by our structures.
* [x] Implement the corresponding bounded DER parser.
* [x] Reject non-canonical or malformed DER where relevant.
* [x] Implement PEM encoding.
* [x] Implement PEM decoding.
* [x] Encode a P-256 private key.
* [x] Encode a P-256 public key/SPKI structure.
* [x] Persist private keys with restrictive filesystem permissions.
* [x] Build PKCS#10 certificate signing requests.
* [x] Encode Subject Alternative Name DNS entries.
* [x] Sign CSRs using ECDSA/SHA-256.
* [x] Parse enough X.509 certificate structure to inspect issued certificates.
* [x] Extract certificate validity dates.
* [x] Extract DNS Subject Alternative Names.
* [x] Extract public-key information.
* [x] Parse certificate chains supplied as PEM.
* [x] Add DER malformed-input tests.
* [x] Compare generated CSRs against an independent parser such as OpenSSL during development.

**Milestone complete when:** BareProxy can generate a standards-valid private key and CSR for a hostname.

---

# Milestone 15 — TLS 1.3 record protocol

Goal: implement TLS framing before attempting the entire handshake.

* [x] Implement TLS plaintext record parsing.
* [x] Implement TLS plaintext record serialization.
* [x] Enforce record-size limits.
* [x] Support handshake record types.
* [x] Support alert record types.
* [x] Support application-data record types.
* [x] Handle fragmented TLS records.
* [x] Handle multiple messages inside one record.
* [x] Implement encrypted TLS 1.3 record construction.
* [x] Implement encrypted record decryption.
* [x] Implement per-direction sequence numbers.
* [x] Construct TLS 1.3 AEAD nonces correctly.
* [x] Authenticate record headers as additional data.
* [x] Handle TLS inner content types.
* [x] Reject bad AEAD tags.
* [x] Reject sequence-number overflow.
* [x] Add record-layer unit tests.

**Milestone complete when:** encrypted and plaintext TLS records round-trip correctly through our parser.

---

# Milestone 16 — TLS 1.3 server handshake

Goal: establish HTTPS with a manually supplied certificate before touching ACME.

* [x] Parse `ClientHello`.
* [x] Parse supported TLS versions.
* [x] Require TLS 1.3.
* [x] Parse SNI.
* [x] Parse supported groups.
* [x] Parse key-share extensions.
* [x] Parse supported signature algorithms.
* [x] Parse offered cipher suites.
* [x] Recognize `TLS_CHACHA20_POLY1305_SHA256`.
* [x] Negotiate P-256 key exchange.
* [x] Produce `HelloRetryRequest` when P-256 is supported but not initially shared.
* [x] Generate an ephemeral server key.
* [x] Produce `ServerHello`.
* [x] Maintain the TLS transcript hash.
* [x] Derive TLS handshake secrets using HKDF.
* [x] Produce `EncryptedExtensions`.
* [x] Process ALPN sufficiently to select HTTP/1.1 when offered.
* [x] Produce the TLS `Certificate` message.
* [x] Produce `CertificateVerify`.
* [x] Produce server `Finished`.
* [x] Verify client `Finished`.
* [x] Derive application traffic secrets.
* [x] Transition into encrypted application data.
* [x] Support TLS alerts.
* [x] Support `close_notify`.
* [x] Reject unsupported cipher suites cleanly.
* [x] Reject unsupported curves cleanly.
* [x] Reject malformed handshake messages.
* [x] Compare handshake behavior against real browser/OpenSSL clients.

**Milestone complete when:** Firefox/Chrome/`openssl s_client` can establish TLS 1.3 with BareProxy using a manually trusted certificate.

---

# Milestone 17 — HTTPS virtual hosts and SNI

Goal: select the correct certificate and proxy route during TLS setup.

* [x] Map SNI hostnames to configured sites.
* [x] Select certificates by SNI.
* [x] Reject or safely handle unknown SNI names.
* [x] Keep certificate material separate from route configuration.
* [x] Allow multiple certificates in memory.
* [x] Load configured PEM certificate/key identities at startup.
* [x] Serve different certificates from one listening socket.
* [x] Make TLS connection state available to the HTTP layer.
* [x] Set `X-Forwarded-Proto: https`.
* [x] Preserve ordinary host-based proxy routing inside TLS.
* [x] Add multi-domain localhost tests.
* [ ] Promote the configured TLS path from the development probe to the normal HTTPS listener.

**Milestone complete when:** multiple HTTPS names can share port 443 and route to different upstreams.

---

# Milestone 18 — Minimal TLS client

Goal: BareProxy must itself make secure HTTPS requests before it can communicate safely with an ACME server.

* [ ] Reuse the TLS record layer in client mode.
* [ ] Produce a TLS 1.3 `ClientHello`.
* [ ] Send SNI.
* [ ] Offer P-256 key exchange.
* [ ] Offer the implemented cipher suite.
* [ ] Parse `ServerHello`.
* [ ] Derive client/server handshake secrets.
* [ ] Parse `EncryptedExtensions`.
* [ ] Parse the remote certificate chain.
* [ ] Verify `CertificateVerify`.
* [ ] Verify server `Finished`.
* [ ] Produce client `Finished`.
* [ ] Exchange encrypted application data.
* [ ] Implement minimal HTTPS GET.
* [ ] Implement minimal HTTPS POST.
* [ ] Implement HTTP response-body reading for ACME traffic.
* [ ] Handle redirects only according to explicit security rules.
* [ ] Add HTTPS-client interoperability tests.

**Milestone complete when:** BareProxy can perform an HTTPS request to a controlled external TLS 1.3 server using its own TLS implementation.

---

# Milestone 19 — Certificate-chain validation

Goal: make the TLS client safe enough to trust the ACME endpoint.

* [ ] Locate the Linux/WSL system CA certificate bundle.
* [ ] Parse trusted root certificates.
* [ ] Build a certificate chain from leaf to trusted root.
* [ ] Validate certificate validity periods.
* [ ] Validate DNS hostname/SAN matching.
* [ ] Enforce CA/basic-constraints rules.
* [ ] Enforce key-usage constraints needed for server authentication.
* [ ] Verify ECDSA certificate signatures.
* [ ] Implement the RSA public-key arithmetic needed for certificate signature verification.
* [ ] Implement RSA PKCS#1 v1.5 SHA-256 signature verification if required by encountered chains.
* [ ] Implement RSA-PSS SHA-256 verification if required by encountered chains.
* [ ] Reject unknown critical X.509 extensions.
* [ ] Reject untrusted roots.
* [ ] Reject expired certificates.
* [ ] Reject hostname mismatches.
* [ ] Reject malformed chains.
* [ ] Add known-good chain tests.
* [ ] Add known-bad chain tests.

**Milestone complete when:** BareProxy can securely validate the certificate of an ACME HTTPS endpoint against the operating-system trust store.

---

# Milestone 20 — ACME protocol foundation

Goal: implement the RFC 8555 primitives without requesting a certificate yet.

* [ ] Define an ACME directory representation.
* [ ] Fetch the ACME directory.
* [ ] Parse the required directory URLs.
* [ ] Implement the minimal JSON serializer required for ACME.
* [ ] Implement the minimal JSON parser required for ACME responses.
* [ ] Properly escape JSON strings.
* [ ] Reject malformed or excessive JSON input.
* [ ] Generate an ACME account P-256 key.
* [ ] Persist the ACME account key.
* [ ] Generate a JWK representation of the public key.
* [ ] Calculate the JWK thumbprint.
* [ ] Implement ACME Base64URL encoding rules.
* [ ] Construct JWS protected headers.
* [ ] Construct JWS payloads.
* [ ] Sign JWS objects using ES256.
* [ ] Fetch ACME replay nonces.
* [ ] Track replay nonces.
* [ ] Recover from `badNonce`.
* [ ] Parse ACME problem documents.
* [ ] Produce readable ACME protocol errors.
* [ ] Add unit tests for JWK/JWS serialization.

**Milestone complete when:** BareProxy can produce standards-valid signed ACME JWS requests.

---

# Milestone 21 — ACME account management

Goal: create and reuse an ACME account.

* [ ] Implement `newAccount`.
* [ ] Support Terms of Service agreement state.
* [ ] Support an optional account contact email.
* [ ] Persist the ACME account URL/KID.
* [ ] Reload an existing account after restart.
* [ ] Distinguish JWK-authenticated requests from KID-authenticated requests.
* [ ] Handle an already-existing account.
* [ ] Handle ACME account errors cleanly.
* [ ] Test against an ACME staging environment.
* [ ] Ensure production ACME cannot be accidentally spammed during automated tests.

**Milestone complete when:** BareProxy can create and persist an ACME staging account and reuse it after restart.

---

# Milestone 22 — ACME certificate orders

Goal: create and inspect certificate orders.

* [ ] Build ACME identifier arrays for DNS hostnames.
* [ ] Implement `newOrder`.
* [ ] Parse the order URL.
* [ ] Parse authorization URLs.
* [ ] Parse the finalize URL.
* [ ] Fetch authorization objects.
* [ ] Parse authorization status.
* [ ] Parse available challenges.
* [ ] Locate an `http-01` challenge.
* [ ] Parse challenge tokens.
* [ ] Calculate HTTP-01 key authorization values.
* [ ] Track order state.
* [ ] Handle invalid orders.
* [ ] Handle already-valid authorizations.
* [ ] Support more than one hostname in a certificate order.
* [ ] Add staging-environment integration tests.

**Milestone complete when:** BareProxy can open an ACME order and determine exactly which HTTP-01 challenges must be satisfied.

---

# Milestone 23 — HTTP-01 challenge serving

Goal: allow the ACME CA to validate domain ownership.

* [ ] Reserve `/.well-known/acme-challenge/` inside the HTTP router.
* [ ] Match challenge tokens exactly.
* [ ] Serve challenge key-authorization content.
* [ ] Use the required content/body format.
* [ ] Keep challenge routes separate from normal proxy routes.
* [ ] Prevent arbitrary filesystem access through challenge URLs.
* [ ] Support several simultaneous pending challenges.
* [ ] Expire challenge state after use.
* [ ] Keep port 80 available for HTTP-01 validation.
* [ ] Ensure ordinary HTTP requests continue proxying during validation.
* [ ] Trigger the ACME challenge after the route is active.
* [ ] Poll authorization state according to ACME responses.
* [ ] Respect `Retry-After` where supplied.
* [ ] Detect validation failure.
* [ ] Remove challenge state after completion/failure.
* [ ] Add local challenge-serving tests.

**Milestone complete when:** an external ACME staging server can successfully validate a hostname served by BareProxy.

---

# Milestone 24 — ACME finalize and certificate retrieval

Goal: turn a validated order into an actual certificate.

* [ ] Generate a site private key.
* [ ] Persist the site private key securely.
* [ ] Generate a CSR containing all ordered DNS names.
* [ ] Send the CSR to the ACME finalize endpoint.
* [ ] Poll the order until valid or failed.
* [ ] Retrieve the certificate URL.
* [ ] Download the issued certificate chain.
* [ ] Parse the returned PEM chain.
* [ ] Verify that the certificate contains the requested hostnames.
* [ ] Verify that the certificate public key matches our private key.
* [ ] Inspect certificate validity dates.
* [ ] Persist the certificate atomically.
* [ ] Persist the chain atomically.
* [ ] Never overwrite a working certificate with malformed new material.
* [ ] Load the issued certificate into the TLS server.
* [ ] Complete a real TLS handshake using the ACME staging certificate.

**Milestone complete when:** BareProxy obtains a real staging certificate and immediately serves it over TLS.

---

# Milestone 25 — Automatic HTTPS orchestration

Goal: reach the actual BareProxy headline feature.

* [ ] Detect configured hostnames requiring certificates.
* [ ] Detect already-valid certificates on startup.
* [ ] Detect missing certificates.
* [ ] Detect certificates approaching expiry.
* [ ] Automatically begin ACME orders for missing certificates.
* [ ] Keep HTTP available while issuance is pending.
* [ ] Install newly issued certificates without restarting BareProxy.
* [ ] Start HTTPS automatically once a certificate becomes available.
* [ ] Redirect ordinary port-80 traffic to HTTPS.
* [ ] Exempt ACME HTTP-01 challenge paths from redirects.
* [ ] Generate correct permanent/temporary redirect responses according to policy.
* [ ] Prevent redirect loops.
* [ ] Keep independently failing domains from blocking healthy domains.
* [ ] Log automatic HTTPS state clearly.
* [ ] Distinguish staging and production ACME configuration.
* [ ] Require deliberate configuration before using a production CA during development.

**Milestone complete when:** adding a hostname + upstream to the config is enough for BareProxy to obtain its certificate and begin serving HTTPS automatically.

---

# Milestone 26 — Certificate renewal

Goal: make automatic HTTPS stay automatic.

* [ ] Define a renewal window before certificate expiry.
* [ ] Calculate renewal timing from the actual certificate lifetime.
* [ ] Add jitter so many certificates do not renew simultaneously.
* [ ] Schedule renewals while BareProxy is running.
* [ ] Detect required renewals at startup.
* [ ] Reuse valid ACME authorizations where permitted by the CA.
* [ ] Perform a fresh challenge when required.
* [ ] Obtain replacement certificates.
* [ ] Validate replacement certificates before activation.
* [ ] Atomically persist replacements.
* [ ] Hot-swap certificates for new TLS connections.
* [ ] Allow existing TLS connections to finish using their old state.
* [ ] Retry transient ACME failures with backoff.
* [ ] Avoid tight retry loops.
* [ ] Preserve the currently valid certificate after failed renewal.
* [ ] Escalate logging as expiration approaches.
* [ ] Test renewal using deliberately short-lived test certificates where possible.

**Milestone complete when:** BareProxy can run continuously across a certificate renewal without operator intervention or downtime.

---

# Milestone 27 — Certificate and ACME state storage

Goal: survive process restarts safely.

* [ ] Define a BareProxy state directory.
* [ ] Store ACME account material separately from site certificates.
* [ ] Store private keys with restrictive permissions.
* [ ] Use atomic temporary-file + rename writes.
* [ ] Flush important state before rename where appropriate.
* [ ] Detect truncated/corrupted state.
* [ ] Never silently regenerate an ACME account because one file failed to parse.
* [ ] Never silently replace a valid site key after recoverable errors.
* [ ] Support rebuilding derived metadata from certificate files.
* [ ] Ensure logs never print private keys.
* [ ] Ensure configuration errors never dump secret material.
* [ ] Document backup requirements.
* [ ] Add restart persistence tests.

**Milestone complete when:** restarting BareProxy preserves ACME identity, certificates, private keys, and renewal state.

---

# Milestone 28 — TLS and ACME security hardening

Goal: stop our homemade crypto stack from being quite as terrifying.

* [ ] Audit all cryptographic input length assumptions.
* [ ] Audit integer overflow behavior.
* [ ] Audit parser allocation limits.
* [ ] Audit secret-dependent branches.
* [ ] Audit secret-dependent memory accesses.
* [ ] Audit nonce generation.
* [ ] Audit ephemeral key generation.
* [ ] Audit ECDSA nonce handling.
* [ ] Audit TLS transcript construction.
* [ ] Audit key schedule derivation.
* [ ] Audit sequence-number handling.
* [ ] Audit AEAD nonce uniqueness.
* [ ] Audit X.509 hostname matching.
* [ ] Audit wildcard handling if wildcards are ever supported.
* [ ] Audit certificate-chain construction.
* [ ] Fuzz parsers with generated malformed input using an internal dependency-free harness.
* [ ] Run TLS interoperability tests against multiple independent clients.
* [ ] Run external TLS scanners against a controlled deployment.
* [ ] Confirm TLS 1.2 and older are refused.
* [ ] Confirm unsupported cipher suites are refused.
* [ ] Confirm invalid certificates are refused by BareProxy's TLS client.
* [ ] Document implemented TLS limitations prominently.

**Milestone complete when:** the supported protocol subset is explicit, heavily tested, and independently interoperable.

---

# Milestone 29 — Production-ish proxy behavior

Goal: improve BareProxy after the headline automatic-HTTPS path works.

* [ ] Add configurable upstream connect timeout.
* [ ] Add configurable client idle timeout.
* [ ] Add configurable upstream idle timeout.
* [ ] Add maximum request-body controls.
* [ ] Add graceful overload behavior.
* [ ] Add upstream health checks.
* [ ] Support multiple upstreams per hostname.
* [ ] Add round-robin load balancing.
* [ ] Skip unhealthy upstreams.
* [ ] Add passive failure detection.
* [ ] Add retry policy for safe/idempotent requests.
* [ ] Avoid automatically replaying unsafe request bodies.
* [ ] Add configurable access logs.
* [ ] Add basic request-duration measurements.
* [ ] Add transferred-byte counters.
* [ ] Add health/status endpoint.
* [ ] Make administrative endpoints opt-in and localhost-only by default.

**Milestone complete when:** BareProxy can reasonably front several ordinary services for extended periods.

---

# Milestone 30 — Configuration reload and live certificate management

Goal: make routine changes boring.

* [ ] Detect configuration changes or accept an explicit reload signal.
* [ ] Parse new configuration independently of active state.
* [ ] Validate all routes before activation.
* [ ] Determine added hostnames.
* [ ] Determine removed hostnames.
* [ ] Determine changed upstreams.
* [ ] Begin certificate acquisition for newly added HTTPS hosts.
* [ ] Preserve certificates for unchanged hosts.
* [ ] Stop routing removed hosts.
* [ ] Define whether removed certificates remain stored.
* [ ] Atomically swap routing tables.
* [ ] Atomically swap certificate maps.
* [ ] Keep active connections alive during reload.
* [ ] Report reload success/failure clearly.

**Milestone complete when:** routes can be changed without restarting the proxy.

---

# Milestone 31 — Windows-native portability

Goal: make BareProxy useful outside WSL without changing its architecture.

* [ ] Build natively on Windows.
* [ ] Abstract platform-specific secure-random generation.
* [ ] Use Windows CSPRNG through direct system API/FFI where required.
* [ ] Locate an appropriate Windows trust source for TLS-client verification.
* [ ] Define Windows state/config directory behavior.
* [ ] Handle Windows filesystem permission differences.
* [ ] Handle Windows signal/shutdown behavior.
* [ ] Verify localhost listeners.
* [ ] Verify public port 80 binding.
* [ ] Verify public port 443 binding.
* [ ] Test Windows Firewall interactions/document requirements.
* [ ] Verify certificate issuance natively on Windows.
* [ ] Keep Linux/WSL behavior unchanged.

**Milestone complete when:** the same dependency-free BareProxy executable can provide automatic HTTPS natively on Windows.

---

# Milestone 32 — Stretch goals

Only after the core proxy + automatic TLS path is stable.

* [ ] Wildcard route matching.
* [ ] Wildcard certificates through DNS-01.
* [ ] Pluggable DNS-01 providers without compromising the zero-crate goal.
* [ ] Multiple ACME certificate authorities.
* [ ] ACME External Account Binding.
* [ ] On-Demand TLS with strict abuse protections.
* [ ] Automatic local-development CA.
* [ ] Locally trusted development certificates.
* [ ] Static-file serving.
* [ ] Response compression.
* [ ] Basic authentication.
* [ ] Header manipulation rules.
* [ ] Request path rewrites.
* [ ] HTTP request matching rules.
* [ ] Upstream load balancing policies.
* [ ] Metrics endpoint.
* [ ] Unix domain socket upstreams.
* [ ] HTTP CONNECT support if genuinely useful.
* [ ] HTTP/2.
* [ ] HTTP/3/QUIC.
* [ ] OCSP stapling if applicable to issued certificates.
* [ ] TLS session resumption.
* [ ] TLS key updates.
* [ ] Additional TLS 1.3 cipher suites.
* [ ] IPv6 listener and upstream testing.
* [ ] Dual-stack ACME validation testing.

---

# First usable releases

## v0.1 — Bare HTTP proxy

Target milestones:

* [ ] Milestones 0–10 complete.
* [ ] HTTP/1.1 reverse proxy works reliably.
* [ ] Host-based routing works.
* [ ] Streaming bodies work.
* [ ] WebSocket upgrades work.
* [ ] Configuration reload works.
* [ ] Zero dependencies.

## v0.2 — Manual HTTPS

Target milestones:

* [ ] Milestones 11–19 complete.
* [ ] BareProxy's own TLS 1.3 implementation interoperates with real clients.
* [ ] HTTPS works using manually supplied certificates.
* [ ] BareProxy has a validating HTTPS client.
* [ ] Zero dependencies.

## v0.3 — Automatic HTTPS

Target milestones:

* [ ] Milestones 20–28 complete.
* [ ] ACME account creation works.
* [ ] HTTP-01 validation works.
* [ ] Certificates are automatically issued.
* [ ] Certificates are automatically installed.
* [ ] HTTP redirects to HTTPS.
* [ ] Certificates renew automatically.
* [ ] Restart persistence works.
* [ ] Zero dependencies.

## v1.0 — BareProxy

Target:

* [ ] Milestones 0–30 complete.
* [ ] Long-running HTTP/HTTPS proxy operation is stable.
* [ ] Automatic HTTPS requires no manual certificate handling.
* [ ] Certificate renewal causes no downtime.
* [ ] Common HTTP/1.1 applications and WebSockets work correctly.
* [ ] Security limitations are explicitly documented.
* [ ] External interoperability/security testing has been performed.
* [ ] `[dependencies]` remains empty.

---

# Definition of victory

A new BareProxy configuration entry should eventually be able to express, in roughly one line:

```text
example.com -> 127.0.0.1:3000
```

From that, BareProxy should be able to:

* [ ] listen on ports 80 and 443;
* [ ] route requests for `example.com`;
* [ ] obtain an ACME certificate automatically;
* [ ] answer the HTTP-01 challenge itself;
* [ ] persist the certificate and private key;
* [ ] establish TLS 1.3 using its own TLS implementation;
* [ ] redirect normal HTTP traffic to HTTPS;
* [ ] proxy HTTPS requests to `127.0.0.1:3000`;
* [ ] renew the certificate before expiration;
* [ ] hot-swap the renewed certificate;
* [ ] recover all required state after restart;
* [ ] accomplish all of the above with an empty Cargo `[dependencies]` section.

At that point we are allowed to stare at the repository and question why we did this.
