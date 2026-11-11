use std::error::Error;
use std::ffi::CStr;
use std::fmt::Display;
use std::os::raw;
use ossl_sys::{ERR_error_string_n, ERR_lib_error_string, ERR_reason_error_string};

#[derive(Debug)]
pub struct OsslError {
    code: raw::c_ulong
}

impl OsslError {
    pub fn new(_code: raw::c_ulong) -> OsslError {
        OsslError {
            code: _code
        }
    }

    pub fn code(&self) -> raw::c_ulong {
        self.code
    }

    pub fn library(&self) -> Option<&'static str> {
        // SAFETY: any code is accepted; returns NULL or a pointer to a static string.
        let p = unsafe { ERR_lib_error_string(self.code) };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is non-null and points to a static NUL-terminated string.
        unsafe { CStr::from_ptr(p) }.to_str().ok()
    }

    pub fn message(&self) -> String {
        let mut buf = [0 as raw::c_char;256];
        // SAFETY: buf is valid for buf.len() bytes; OpenSSL writes at most that many
        // and always NUL-terminates.
        unsafe { ERR_error_string_n(self.code, buf.as_mut_ptr(), buf.len()) };
        // SAFETY: buf is NUL-terminated by the call above and lives through this expression.
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    }

    pub fn reason(&self) -> Option<&'static str> {
        // SAFETY: any code is accepted; returns NULL or a pointer to a static string.
        let p = unsafe { ERR_reason_error_string(self.code) };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is non-null and points to a static NUL-terminated string.
        unsafe { CStr::from_ptr(p) }.to_str().ok()
    }
}

impl Display for OsslError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OSSL Error=> code: {}, message: {}", self.code, self.message())
    }
}
impl Error for OsslError {}