//! Rust ports of function-like C macros that bindgen cannot see.
//! Each port is a thin wrapper over an exported fn + a bindgen constant.

use std::ffi::c_void;
use std::os::raw;
use crate::{CRYPTO_clear_free, CRYPTO_free, SSL_CTX_ctrl, SSL_CTX};

/// Port of `OPENSSL_free(addr)`.
///
/// # Safety
/// `ptr` must be null, or a pointer allocated by OpenSSL's allocator that has
/// not already been freed.
#[inline]
pub unsafe fn OPENSSL_free(ptr: *mut c_void) {
    CRYPTO_free(ptr, c"".as_ptr(), 0);
}

#[inline]
pub unsafe fn OPENSSL_clear_free(ptr: *mut c_void, num: usize) {
    CRYPTO_clear_free(ptr, num, c"".as_ptr(), 0);
}

#[inline]
pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: raw::c_long, ) {
    SSL_CTX_ctrl(ctx, raw::c_int::from(123), version, std::ptr::null_mut());
}