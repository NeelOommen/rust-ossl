//! Raw OpenSSL 3.x FFI. No logic here: bindgen output plus Rust ports of
//! function-like C macros (see `macros.rs`). Safe API lives in the `ossl` crate.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::all)]

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;

pub mod macros;
#[allow(unused_imports)]
pub use macros::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn links_and_reports_openssl_3() {
        let v = unsafe { CStr::from_ptr(OpenSSL_version(OPENSSL_VERSION as _)) };
        let v = v.to_str().unwrap();
        assert!(v.starts_with("OpenSSL 3."), "got {v}");
    }

    #[test]
    fn can_create_and_free_ctx() {
        unsafe {
            let ctx = SSL_CTX_new(TLS_client_method());
            assert!(!ctx.is_null());
            SSL_CTX_free(ctx);
        }
    }
}
