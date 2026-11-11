use std::error::Error;
use std::ffi::c_ulong;
use std::fmt::Display;
use ossl_sys::{ERR_clear_error, ERR_get_error};
use crate::errors::error::OsslError;

/// Snapshot of the calling thread's OpenSSL error queue.
///
/// The queue is per-thread: call [`ErrorStack::clear`] before an OpenSSL call whose
/// failure you read from it, and [`ErrorStack::get`] right after the failure.
///
/// See also: `ERR_get_error(3)`, `ERR_clear_error(3)`.
#[derive(Debug)]
pub struct ErrorStack{
    error_list: Vec<OsslError>
}

impl ErrorStack {
    /// Drain the thread's error queue into an `ErrorStack`. The queue is empty afterwards.
    pub fn get() -> Self {
        let mut err_list: Vec<OsslError> = Vec::new();

        loop {
            // SAFETY: ERR_get_error has no arguments or preconditions; it pops the
            // oldest entry of the calling thread's queue, or returns 0 when empty.
            let err_code: c_ulong = unsafe { ERR_get_error() };
            if err_code == 0 { break; }
            err_list.push(OsslError::new(err_code));
        }

        ErrorStack{
            error_list: err_list
        }
    }

    /// Empty the thread's error queue.
    pub fn clear() {
        // SAFETY: ERR_clear_error has no arguments or preconditions; it only
        // empties the calling thread's error queue.
        unsafe { ERR_clear_error(); }
    }

    /// The drained errors, oldest first.
    pub fn errors(&self) -> &[OsslError] {
        &self.error_list
    }

    pub fn is_empty(&self) -> bool {
        self.error_list.is_empty()
    }
}

impl Display for ErrorStack {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.error_list.is_empty() {
            return write!(f, "OSSL error stack: empty");
        }
        write!(f, "OSSL error stack ({}):", self.error_list.len())?;
        for e in &self.error_list {
            write!(f, "\n  {}", e.message())?;
        }
        Ok(())
    }
}

impl Error for ErrorStack {}

#[cfg(test)]
mod tests {
    use super::*;
    use ossl_sys::{BIO_free, BIO_new_mem_buf, PEM_read_bio_X509};
    use std::ptr;
    use crate::errors::error::OsslError;

    /// Push one real error on this thread's queue: parse garbage as a PEM cert.
    fn push_error() {
        let junk = b"not a pem";
        // SAFETY: junk outlives the BIO; len matches; the BIO is freed before return.
        // PEM_read_bio_X509 returns NULL on garbage and queues PEM errors.
        unsafe {
            let bio = BIO_new_mem_buf(junk.as_ptr() as *const _, junk.len() as _);
            assert!(!bio.is_null());
            let x = PEM_read_bio_X509(bio, ptr::null_mut(), None, ptr::null_mut());
            assert!(x.is_null());
            BIO_free(bio);
        }
    }

    #[test]
    fn get_on_empty_queue_is_empty() {
        ErrorStack::clear();
        let s = ErrorStack::get();
        assert!(s.is_empty());
        assert_eq!(s.errors().len(), 0);
    }

    #[test]
    fn get_drains_queue_without_trailing_zero_entry() {
        ErrorStack::clear();
        push_error();
        let s = ErrorStack::get();
        assert!(!s.is_empty());
        assert!(s.errors().iter().all(|e| e.code() != 0));
        // queue is drained
        assert!(ErrorStack::get().is_empty());
    }

    #[test]
    fn clear_empties_queue() {
        push_error();
        ErrorStack::clear();
        assert!(ErrorStack::get().is_empty());
    }

    #[test]
    fn error_has_message_and_display() {
        ErrorStack::clear();
        push_error();
        let s = ErrorStack::get();
        let e = &s.errors()[0];
        assert!(!e.message().is_empty());
        assert!(e.library().is_some());
        assert!(format!("{}", s).contains(&e.message()));
        assert!(format!("{}", e).contains(&e.message()));
    }

    #[test]
    fn queue_is_per_thread() {
        ErrorStack::clear();
        push_error();
        let other = std::thread::spawn(|| ErrorStack::get().is_empty()).join().unwrap();
        assert!(other);
        assert!(!ErrorStack::get().is_empty());
    }

    #[test]
    fn send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ErrorStack>();
        assert_send_sync::<OsslError>();
    }

    #[test]
    fn moves_across_threads() {
        ErrorStack::clear();
        push_error();
        let s = ErrorStack::get();
        let n = s.errors().len();
        let back = std::thread::spawn(move || s).join().unwrap();
        assert_eq!(back.errors().len(), n);
        assert!(!back.errors()[0].message().is_empty());
    }

    #[test]
    fn implements_std_error() {
        fn takes_err(_: Box<dyn std::error::Error>) {}
        takes_err(Box::new(ErrorStack::get()));
    }
}
