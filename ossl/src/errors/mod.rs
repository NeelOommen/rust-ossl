#![doc = include_str!("doc.md")]

pub mod error;
pub mod error_stack;

pub use error::OsslError;
pub use error_stack::ErrorStack;
