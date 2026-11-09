//! Rust ports of function-like C macros that bindgen cannot see.
//! Each port is a thin wrapper over an exported fn + a bindgen constant.

use crate::{BIO_ctrl, BIO_test_flags, CRYPTO_clear_free, CRYPTO_free, SSL_CTX_ctrl, SSL_ctrl, TLSEXT_NAMETYPE_host_name, BIO, BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_WPENDING, BIO_FLAGS_READ, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, SSL, SSL_CTRL_MODE, SSL_CTRL_SET_MAX_PROTO_VERSION, SSL_CTRL_SET_MIN_PROTO_VERSION, SSL_CTRL_SET_TLSEXT_HOSTNAME, SSL_CTX};
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

#[inline]
pub unsafe fn OPENSSL_clear_free(ptr: *mut c_void, num: usize) {
    CRYPTO_clear_free(ptr, num, c"".as_ptr(), 0)
}

#[inline]
pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION as raw::c_int, version, std::ptr::null_mut())
}

#[inline]
pub unsafe fn SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION as raw::c_int, version, std::ptr::null_mut())
}

#[inline]
pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: raw::c_long) -> raw::c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE as raw::c_int, op, std::ptr::null_mut())
}

#[inline]
pub unsafe fn SSL_set_tlsext_host_name(s: *mut SSL, name: *mut c_void) -> raw::c_long {
    SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME as raw::c_int,
             TLSEXT_NAMETYPE_host_name as raw::c_long, name)
}

#[inline]
pub unsafe fn BIO_should_retry(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY as raw::c_int)
}

#[inline]
pub unsafe fn BIO_should_read(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_READ as raw::c_int)
}

#[inline]
pub unsafe fn BIO_should_write(a: *const BIO) -> raw::c_int {
    BIO_test_flags(a, BIO_FLAGS_WRITE as raw::c_int)
}

#[inline]
pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut c_void) -> raw::c_long {
    BIO_ctrl(b, BIO_CTRL_INFO as raw::c_int, 0, pp)
}

#[inline]
pub unsafe fn BIO_pending(b: *mut BIO) -> raw::c_int {
    BIO_ctrl(b, BIO_CTRL_PENDING as raw::c_int, 0, std::ptr::null_mut()) as raw::c_int
}

#[inline]
pub unsafe fn BIO_wpending(b: *mut BIO) -> raw::c_int {
    BIO_ctrl(b, BIO_CTRL_WPENDING as raw::c_int, 0, std::ptr::null_mut()) as raw::c_int
}