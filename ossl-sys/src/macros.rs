//! Rust ports of function-like C macros that bindgen cannot see.
//! Each port is a thin wrapper over an exported fn + a bindgen constant.

use crate::{BIO_ctrl, BIO_test_flags, CRYPTO_clear_free, CRYPTO_free, SSL_CTX_callback_ctrl, SSL_CTX_ctrl, SSL_ctrl, TLSEXT_NAMETYPE_host_name, BIO, BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_WPENDING, BIO_FLAGS_READ, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, SSL, SSL_CTRL_EXTRA_CHAIN_CERT, SSL_CTRL_MODE, SSL_CTRL_SET_MAX_PROTO_VERSION, SSL_CTRL_SET_MIN_PROTO_VERSION, SSL_CTRL_SET_TLSEXT_HOSTNAME, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, SSL_CTX};
use std::ffi::c_void;
use std::os::raw;

/// Port of `OPENSSL_free(addr)`.
///
/// # Safety
/// `ptr` must be null, or a pointer allocated by OpenSSL's allocator that has
/// not already been freed.
#[inline]
pub unsafe fn OPENSSL_free(ptr: *mut c_void) {
    CRYPTO_free(ptr, c"".as_ptr(), 0)
}

/// Port of `OPENSSL_clear_free(addr, num)`: zeroes `num` bytes, then frees.
///
/// # Safety
/// Same as [`OPENSSL_free`], and `num` must not exceed the size of the allocation.
#[inline]
pub unsafe fn OPENSSL_clear_free(ptr: *mut c_void, num: usize) {
    CRYPTO_clear_free(ptr, num, c"".as_ptr(), 0)
}

/// Port of `SSL_CTX_set_min_proto_version(ctx, version)`. Returns 1 on success, 0 on failure.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`, and no other thread may be configuring it concurrently.
#[inline]
pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION as raw::c_int, version, std::ptr::null_mut())
}

/// Port of `SSL_CTX_set_max_proto_version(ctx, version)`. Returns 1 on success, 0 on failure.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`, and no other thread may be configuring it concurrently.
#[inline]
pub unsafe fn SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION as raw::c_int, version, std::ptr::null_mut())
}

/// Port of `SSL_CTX_set_mode(ctx, op)`. Returns the mode bitmask after `op` is OR-ed in.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`, and no other thread may be configuring it concurrently.
#[inline]
pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE as raw::c_int, op, std::ptr::null_mut())
}

/// Port of `SSL_set_tlsext_host_name(s, name)`: sets the SNI host name sent in the
/// ClientHello. Returns 1 on success, 0 on failure.
///
/// # Safety
/// `s` must be a valid, live `SSL*`. `name` must point to a valid NUL-terminated string;
/// OpenSSL copies it, so it only needs to live for the duration of the call.
#[inline]
pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *const raw::c_char) -> raw::c_long {
    SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME as raw::c_int,
             TLSEXT_NAMETYPE_host_name as raw::c_long, name as *mut raw::c_void)
}

/// Port of `BIO_should_retry(a)`. Non-zero if the last I/O on `a` should be retried.
///
/// # Safety
/// `a` must be a valid, live `BIO*`.
#[inline]
pub unsafe fn BIO_should_retry(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY as raw::c_int)
}

/// Port of `BIO_should_read(a)`. Non-zero if the retry condition is "wants to read".
///
/// # Safety
/// `a` must be a valid, live `BIO*`.
#[inline]
pub unsafe fn BIO_should_read(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_READ as raw::c_int)
}

/// Port of `BIO_should_write(a)`. Non-zero if the retry condition is "wants to write".
///
/// # Safety
/// `a` must be a valid, live `BIO*`.
#[inline]
pub unsafe fn BIO_should_write(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_WRITE as raw::c_int)
}

/// Port of `BIO_get_mem_data(b, pp)`. Stores a pointer to the memory BIO's buffer in `*pp`
/// and returns its length.
///
/// # Safety
/// `b` must be a valid memory BIO. `pp` must be a valid `char **` (a `*mut *mut c_char`
/// cast to `*mut c_void`). The pointer written to `*pp` points INTO the BIO: never free it,
/// and do not use it after the BIO is written to, read from, or freed.
#[inline]
pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut c_void) -> raw::c_long {
    BIO_ctrl(b, BIO_CTRL_INFO as raw::c_int, 0, pp)
}

/// Port of `BIO_pending(b)`: number of bytes buffered and readable from `b`.
///
/// # Safety
/// `b` must be a valid, live `BIO*`.
#[inline]
pub unsafe fn BIO_pending(b: *mut BIO) -> raw::c_int {
    BIO_ctrl(b, BIO_CTRL_PENDING as raw::c_int, 0, std::ptr::null_mut()) as raw::c_int
}

/// Port of `BIO_wpending(b)`: number of bytes buffered and waiting to be written out of `b`.
///
/// # Safety
/// `b` must be a valid, live `BIO*`.
#[inline]
pub unsafe fn BIO_wpending(b: *mut BIO) -> raw::c_int {
    BIO_ctrl(b, BIO_CTRL_WPENDING as raw::c_int, 0, std::ptr::null_mut()) as raw::c_int
}

/// Server-name (SNI) callback: `int cb(SSL *s, int *al, void *arg)`.
/// Return one of the `SSL_TLSEXT_ERR_*` values.
pub type ServernameCb = unsafe extern "C" fn(s: *mut SSL, al: *mut raw::c_int, arg: *mut c_void) -> raw::c_int;

/// Port of `SSL_CTX_set_tlsext_servername_callback(ctx, cb)`. `None` disables SNI handling.
/// Returns 1 on success.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`. `cb`, if set, must be sound to call from OpenSSL
/// during a handshake on any thread using `ctx`, and must never unwind (panic) out of the
/// `extern "C"` boundary.
#[inline]
pub unsafe fn SSL_CTX_set_tlsext_servername_callback(ctx: *mut SSL_CTX, c_fn: Option<ServernameCb>) -> raw::c_long {
    // Same cast as the C macro's `(void (*)(void))cb`. Option<fn> is one nullable pointer, so None stays NULL.
    let cb: Option<unsafe extern "C" fn()> = std::mem::transmute(c_fn);
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB as raw::c_int, cb)
}

/// Port of `SSL_CTX_set_tlsext_servername_arg(ctx, arg)`: the `arg` passed to the servername
/// callback. Returns 1 on success.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`. OpenSSL stores `arg` without copying it, so whatever
/// it points to must stay valid (and be safe to access from handshake threads) for as long as
/// the callback can run.
#[inline]
pub unsafe fn SSL_CTX_set_tlsext_servername_arg(ctx: *mut SSL_CTX, arg: *mut c_void) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG as raw::c_int, 0, arg)
}

/// Port of `SSL_CTX_add_extra_chain_cert(ctx, x509)`. Returns 1 on success, 0 on failure.
///
/// # Safety
/// `ctx` must be a valid, live `SSL_CTX*`. `x509` must be a valid `X509*`. **Ownership of
/// `x509` transfers to `ctx` on success** (it is not up-ref'd and is freed with the `SSL_CTX`),
/// so the caller must not free it or use it after `ctx` is freed. On failure the caller still
/// owns it.
#[inline]
pub unsafe fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut c_void) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT as raw::c_int, 0, x509)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::ffi::CStr;
    use std::ptr::null_mut;

    // ---- small RAII helpers so a failed assert doesn't leak ----------------------------

    struct Ctx(*mut SSL_CTX);
    impl Drop for Ctx {
        fn drop(&mut self) {
            unsafe { SSL_CTX_free(self.0) }
        }
    }
    fn ctx_with(method: *const SSL_METHOD) -> Ctx {
        let p = unsafe { SSL_CTX_new(method) };
        assert!(!p.is_null());
        Ctx(p)
    }

    struct Conn(*mut SSL);
    impl Drop for Conn {
        fn drop(&mut self) {
            unsafe { SSL_free(self.0) }
        }
    }

    struct Bio(*mut BIO);
    impl Drop for Bio {
        fn drop(&mut self) {
            unsafe {
                BIO_free(self.0);
            }
        }
    }
    fn mem_bio() -> Bio {
        let p = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!p.is_null());
        Bio(p)
    }

    // ---- OPENSSL_free / OPENSSL_clear_free ---------------------------------------------

    #[test]
    fn free_releases_openssl_allocation() {
        unsafe {
            let p = CRYPTO_malloc(64, c"".as_ptr(), 0);
            assert!(!p.is_null());
            OPENSSL_free(p);
        }
    }

    #[test]
    fn free_null_is_noop() {
        // OpenSSL documents OPENSSL_free(NULL) as a no-op.
        unsafe { OPENSSL_free(std::ptr::null_mut()) }
    }

    #[test]
    fn clear_free_zeroes_then_frees() {
        unsafe {
            let p = CRYPTO_zalloc(32, c"".as_ptr(), 0) as *mut u8;
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0xAB, 32);
            OPENSSL_clear_free(p.cast(), 32);
        }
    }

    // ---- SSL_CTX_set_{min,max}_proto_version -------------------------------------------

    #[test]
    fn proto_version_bounds_read_back() {
        let ctx = ctx_with(unsafe { TLS_client_method() });
        unsafe {
            assert_eq!(SSL_CTX_set_min_proto_version(ctx.0, TLS1_2_VERSION as _), 1);
            assert_eq!(SSL_CTX_set_max_proto_version(ctx.0, TLS1_3_VERSION as _), 1);
            let min = SSL_CTX_ctrl(ctx.0, SSL_CTRL_GET_MIN_PROTO_VERSION as _, 0, null_mut());
            let max = SSL_CTX_ctrl(ctx.0, SSL_CTRL_GET_MAX_PROTO_VERSION as _, 0, null_mut());
            assert_eq!(min, TLS1_2_VERSION as _);
            assert_eq!(max, TLS1_3_VERSION as _);
        }
    }

    #[test]
    fn proto_version_rejects_garbage() {
        let ctx = ctx_with(unsafe { TLS_client_method() });
        unsafe {
            assert_eq!(SSL_CTX_set_min_proto_version(ctx.0, 0x1234), 0);
            assert_eq!(SSL_CTX_set_max_proto_version(ctx.0, 0x1234), 0);
        }
    }

    // ---- SSL_CTX_set_mode --------------------------------------------------------------

    #[test]
    fn set_mode_returns_mode_with_bit_set() {
        let ctx = ctx_with(unsafe { TLS_client_method() });
        let bit = SSL_MODE_ENABLE_PARTIAL_WRITE as raw::c_long;
        unsafe {
            let mode = SSL_CTX_set_mode(ctx.0, bit);
            assert_ne!(mode & bit, 0);
        }
    }

    // ---- SSL_set_tlsext_host_name ------------------------------------------------------

    #[test]
    fn host_name_is_stored_on_ssl() {
        let ctx = ctx_with(unsafe { TLS_client_method() });
        unsafe {
            let ssl = Conn(SSL_new(ctx.0));
            assert!(!ssl.0.is_null());
            assert_eq!(SSL_set_tlsext_host_name(ssl.0, c"example.test".as_ptr()), 1);
            let got = SSL_get_servername(ssl.0, TLSEXT_NAMETYPE_host_name as raw::c_int);
            assert!(!got.is_null());
            assert_eq!(CStr::from_ptr(got).to_str().unwrap(), "example.test");
        }
    }

    // ---- BIO_should_{retry,read,write} -------------------------------------------------

    #[test]
    fn bio_should_flags_follow_set_flags() {
        let bio = mem_bio();
        unsafe {
            assert_eq!(BIO_should_retry(bio.0), 0);
            assert_eq!(BIO_should_read(bio.0), 0);
            assert_eq!(BIO_should_write(bio.0), 0);

            BIO_set_flags(bio.0, (BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ) as raw::c_int);
            assert_ne!(BIO_should_retry(bio.0), 0);
            assert_ne!(BIO_should_read(bio.0), 0);
            assert_eq!(BIO_should_write(bio.0), 0);

            BIO_clear_flags(bio.0, (BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ) as raw::c_int);
            BIO_set_flags(bio.0, (BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_WRITE) as raw::c_int);
            assert_ne!(BIO_should_retry(bio.0), 0);
            assert_eq!(BIO_should_read(bio.0), 0);
            assert_ne!(BIO_should_write(bio.0), 0);
        }
    }

    // ---- BIO_get_mem_data --------------------------------------------------------------

    #[test]
    fn bio_get_mem_data_exposes_buffer() {
        let bio = mem_bio();
        unsafe {
            assert_eq!(BIO_write(bio.0, b"hello".as_ptr().cast(), 5), 5);
            let mut p: *mut raw::c_char = null_mut();
            let len = BIO_get_mem_data(bio.0, (&mut p as *mut *mut raw::c_char).cast());
            assert_eq!(len, 5);
            assert!(!p.is_null());
            assert_eq!(std::slice::from_raw_parts(p as *const u8, 5), b"hello");
            // `p` points into the BIO: we must NOT free it, the BIO's Drop does.
        }
    }

    // ---- BIO_pending / BIO_wpending ----------------------------------------------------

    #[test]
    fn bio_pending_and_wpending_on_a_bio_pair() {
        unsafe {
            let (mut a, mut b) = (null_mut(), null_mut());
            assert_eq!(BIO_new_bio_pair(&mut a, 0, &mut b, 0), 1);
            let (a, b) = (Bio(a), Bio(b));

            assert_eq!(BIO_pending(a.0), 0);
            assert_eq!(BIO_wpending(a.0), 0);

            assert_eq!(BIO_write(a.0, b"abc".as_ptr().cast(), 3), 3);
            // `a` has 3 bytes waiting to go out; `b` has 3 bytes ready to read; `a` has none to read.
            assert_eq!(BIO_wpending(a.0), 3);
            assert_eq!(BIO_pending(b.0), 3);
            assert_eq!(BIO_pending(a.0), 0);
        }
    }

    // ---- SSL_CTX_add_extra_chain_cert --------------------------------------------------

    #[test]
    fn extra_chain_cert_is_added_and_owned_by_ctx() {
        let ctx = ctx_with(unsafe { TLS_server_method() });
        unsafe {
            let x = X509_new();
            assert!(!x.is_null());
            assert_eq!(SSL_CTX_add_extra_chain_cert(ctx.0, x.cast()), 1);

            let mut chain: *mut c_void = null_mut();
            let r = SSL_CTX_ctrl(
                ctx.0,
                SSL_CTRL_GET_EXTRA_CHAIN_CERTS as raw::c_int,
                0,
                (&mut chain as *mut *mut c_void).cast(),
            );
            assert_eq!(r, 1);
            assert_eq!(OPENSSL_sk_num(chain as *const OPENSSL_STACK), 1);
            // Ownership moved to ctx: no X509_free(x). Dropping `ctx` frees it; a double free
            // here would crash the test.
        }
    }

    // ---- servername callback + arg + host_name + proto bounds, end to end ----------------

    struct Seen {
        calls: u32,
        host: String,
    }

    unsafe extern "C" fn sni_cb(s: *mut SSL, _al: *mut raw::c_int, arg: *mut c_void) -> raw::c_int {
        let seen = &mut *(arg as *mut Seen);
        seen.calls += 1;
        let h = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name as raw::c_int);
        if !h.is_null() {
            seen.host = CStr::from_ptr(h).to_string_lossy().into_owned();
        }
        SSL_TLSEXT_ERR_OK as raw::c_int
    }

    /// Move everything readable on `from` into `to`.
    unsafe fn shuttle(from: *mut BIO, to: *mut BIO) {
        let mut buf = [0u8; 4096];
        loop {
            let n = BIO_read(from, buf.as_mut_ptr().cast(), buf.len() as raw::c_int);
            if n <= 0 {
                break;
            }
            assert_eq!(BIO_write(to, buf.as_ptr().cast(), n), n);
        }
    }

    #[test]
    fn servername_callback_and_arg_fire_during_handshake() {
        // Declared first so it outlives everything that can call back into it.
        let mut seen = Seen { calls: 0, host: String::new() };

        unsafe {
            let server_ctx = ctx_with(TLS_server_method());
            let client_ctx = ctx_with(TLS_client_method());

            assert_eq!(
                SSL_CTX_use_certificate_file(
                    server_ctx.0,
                    concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/dummy_cert.pem\0").as_ptr().cast(),
                    SSL_FILETYPE_PEM as raw::c_int,
                ),
                1
            );
            assert_eq!(
                SSL_CTX_use_PrivateKey_file(
                    server_ctx.0,
                    concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/dummy_key.pem\0").as_ptr().cast(),
                    SSL_FILETYPE_PEM as raw::c_int,
                ),
                1
            );

            // Force TLS 1.3 on both sides through the ported min-version macro.
            assert_eq!(SSL_CTX_set_min_proto_version(server_ctx.0, TLS1_3_VERSION as _), 1);
            assert_eq!(SSL_CTX_set_min_proto_version(client_ctx.0, TLS1_3_VERSION as _), 1);

            assert_eq!(SSL_CTX_set_tlsext_servername_callback(server_ctx.0, Some(sni_cb)), 1);
            assert_eq!(
                SSL_CTX_set_tlsext_servername_arg(server_ctx.0, (&mut seen as *mut Seen).cast()),
                1
            );

            // Wire two SSLs together through BIO pairs; we shuttle bytes between the "network" ends.
            let (mut c_ssl_end, mut c_net) = (null_mut(), null_mut());
            let (mut s_ssl_end, mut s_net) = (null_mut(), null_mut());
            assert_eq!(BIO_new_bio_pair(&mut c_ssl_end, 0, &mut c_net, 0), 1);
            assert_eq!(BIO_new_bio_pair(&mut s_ssl_end, 0, &mut s_net, 0), 1);
            let (c_net, s_net) = (Bio(c_net), Bio(s_net));

            let client = Conn(SSL_new(client_ctx.0));
            let server = Conn(SSL_new(server_ctx.0));
            assert!(!client.0.is_null() && !server.0.is_null());
            // SSL_set_bio takes ownership of the BIOs (same BIO for read and write is fine).
            SSL_set_bio(client.0, c_ssl_end, c_ssl_end);
            SSL_set_bio(server.0, s_ssl_end, s_ssl_end);

            assert_eq!(SSL_set_tlsext_host_name(client.0, c"example.test".as_ptr()), 1);

            let mut done = false;
            for _ in 0..100 {
                if SSL_is_init_finished(client.0) != 1 {
                    SSL_connect(client.0);
                }
                if SSL_is_init_finished(server.0) != 1 {
                    SSL_accept(server.0);
                }
                shuttle(c_net.0, s_net.0);
                shuttle(s_net.0, c_net.0);
                if SSL_is_init_finished(client.0) == 1 && SSL_is_init_finished(server.0) == 1 {
                    done = true;
                    break;
                }
            }
            assert!(done, "handshake did not complete");

            assert_eq!(SSL_version(client.0), TLS1_3_VERSION as raw::c_int);
        }

        assert_eq!(seen.calls, 1, "servername callback should fire exactly once");
        assert_eq!(seen.host, "example.test", "callback saw the SNI host sent by the client");
    }
}