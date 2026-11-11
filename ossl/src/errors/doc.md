OpenSSL error reporting: [`ErrorStack`] and [`OsslError`].

OpenSSL records failures in a **per-thread error queue**. Most calls report only "failed"
through their return value; the reason sits in the queue. This module drains that queue
into Rust values.

# Types

| Type | What it is | Wraps |
|---|---|---|
| [`ErrorStack`] | Snapshot of the calling thread's queue. Returned in `Err(..)` by fallible calls. Implements `Display` and `std::error::Error`. | `ERR_get_error(3)`, `ERR_clear_error(3)` |
| [`OsslError`] | One queue entry (a packed `unsigned long` code). | `ERR_lib_error_string(3)`, `ERR_reason_error_string(3)`, `ERR_error_string_n(3)` |

# Using the queue

The queue is per thread, so:

1. Call [`ErrorStack::clear`] before an OpenSSL call whose failure you read from the queue.
   Stale errors from earlier calls otherwise show up in the result.
2. Call [`ErrorStack::get`] right after the failure, **on the same thread**, before making
   any other OpenSSL call.

```ignore
ErrorStack::clear();
let r = unsafe { ossl_sys::SSL_CTX_set_cipher_list(ctx, list.as_ptr()) };
if r != 1 {
    return Err(ErrorStack::get());
}
```

[`ErrorStack::get`] pops every entry (oldest first), so the queue is empty afterwards.
[`ErrorStack::errors`] and [`ErrorStack::is_empty`] inspect the result.

# Reading one error

| Method | Returns | Notes |
|---|---|---|
| [`OsslError::code`] | raw packed code | Same value `ERR_get_error` returned. Never 0 for entries from an [`ErrorStack`]. |
| [`OsslError::library`] | `Option<&'static str>` | Subsystem, e.g. `"PEM routines"`. `None` if OpenSSL has no string for the code. |
| [`OsslError::reason`] | `Option<&'static str>` | Short cause, e.g. `"no start line"`. `None` if OpenSSL has no string for the code. |
| [`OsslError::message`] | `String` | Full line, `error:XXXXXXXX:library::reason`. If no strings are registered, it contains the numeric code instead. |

`library` and `reason` borrow OpenSSL's static string tables, so they cost no allocation.
`message` is formatted into a 256-byte buffer and returned owned (OpenSSL truncates
longer text and always NUL-terminates).

# Thread safety

[`ErrorStack`] and [`OsslError`] are plain data (`Vec` of integers), so they are `Send +
Sync` and can be moved off the thread that produced them. The *queue* they come from is
not shared: another thread's failures never appear in your `get()`.

# Not covered yet

- File, line, function and extra text per entry (`ERR_get_error_all(3)`).
- An `ErrorStack` constructor for errors that do not come from OpenSSL (for example an
  interior NUL in a string argument).

See also: `ERR_get_error(3)`, `ERR_error_string(3)`, `ERR_clear_error(3)`.
