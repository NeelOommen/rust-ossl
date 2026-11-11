# rust-ossl

A safe Rust wrapper over OpenSSL 3.x, aimed at full TLS (client and server, TLS 1.2 and 1.3).

The workspace has two crates:

- **`ossl-sys`**: raw FFI. bindgen output plus hand-written Rust ports of the function-like C macros bindgen skips (`src/macros.rs`). No logic, no safety guarantees. No C shim unless a macro cannot be expressed in Rust.
- **`ossl`**: the safe API. RAII types that free what they own, `Result`-based errors, explicit ownership rules, and panic-safe callbacks (a panic never unwinds across the FFI boundary).

Status: early work in progress. Nothing here is stable or ready for use yet. Planning lives in [`plan.md`](plan.md), per-unit progress in [`work.md`](work.md), and the per-item procedure in [`migration_process.md`](migration_process.md).

Requires OpenSSL 3.x (found via `pkg-config` or `OPENSSL_DIR`).

## Contract

What the safe API (`ossl`) guarantees today. This section grows as more units land; anything not listed here is not implemented yet.

### Errors (`ossl::errors`)

- Fallible calls report failure through `ErrorStack`, a snapshot of the calling thread's OpenSSL error queue. It implements `Display` and `std::error::Error`.
- `ErrorStack::get()` drains the queue (oldest first, queue is empty afterwards). `ErrorStack::clear()` empties it. `errors()` and `is_empty()` inspect a drained stack.
- The queue is **per thread**. Clear it before an OpenSSL call whose failure you read from it, and drain it right after the failure, on the same thread.
- `OsslError` is one queue entry: `code()` (raw packed code), `library()` and `reason()` (`Option<&'static str>`, `None` when OpenSSL has no string for the code), and `message()` (the full `error:XXXXXXXX:lib::reason` line, as an owned `String`).

### Raw layer (`ossl-sys`)

- Ported macros: `OPENSSL_free`, `OPENSSL_clear_free`, `BIO_should_retry` / `BIO_should_read` / `BIO_should_write`, `BIO_get_mem_data`, `BIO_pending`, `BIO_wpending`, `SSL_CTX_set_mode`, `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_max_proto_version`, `SSL_set_tlsext_host_name`, `SSL_CTX_set_tlsext_servername_callback`, `SSL_CTX_set_tlsext_servername_arg`, `SSL_CTX_add_extra_chain_cert`.
- Every port is `unsafe`, documents its `# Safety` requirements, and has a test asserting its observable effect.

### Conventions

- Every `unsafe` block in `ossl` carries a `// SAFETY:` comment naming the invariant it relies on.
- Interior NUL in a string passed to C is rejected, never truncated.
- Every `extern "C"` callback is wrapped in `catch_unwind`.
- `SslContext` will be `Send + Sync` once built; `Ssl` will be `Send` only.

## License

See [`LICENSE`](LICENSE).
