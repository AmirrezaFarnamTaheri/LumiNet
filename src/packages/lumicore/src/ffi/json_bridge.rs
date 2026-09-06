//! Shared legacy JSON/string FFI admission and panic envelope.
//!
//! The binary FFI has its own versioned envelope. This module intentionally owns
//! only the retained C-string/JSON compatibility exports so raw pointer handling,
//! UTF-8 validation, JSON admission, and panic containment stay behind one seam.

use super::str_to_c_char;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug)]
pub(crate) enum JsonInputError {
    NullPointer,
    InvalidUtf8,
    InvalidJson(String),
}

impl fmt::Display for JsonInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullPointer => f.write_str("null C string pointer"),
            Self::InvalidUtf8 => f.write_str("input is not valid UTF-8"),
            Self::InvalidJson(err) => write!(f, "invalid JSON: {err}"),
        }
    }
}

/// Copies a NUL-terminated C string into owned Rust memory immediately.
///
/// # Safety
/// `ptr` must either be null or point to a readable NUL-terminated byte string
/// for the duration of this call. No borrow of the foreign allocation escapes.
pub(crate) unsafe fn read_c_string_owned(ptr: *const c_char) -> Result<String, JsonInputError> {
    if ptr.is_null() {
        return Err(JsonInputError::NullPointer);
    }
    let bytes = CStr::from_ptr(ptr).to_bytes();
    let text = std::str::from_utf8(bytes).map_err(|_| JsonInputError::InvalidUtf8)?;
    Ok(text.to_owned())
}

/// Copies and deserializes one legacy JSON input value.
///
/// # Safety
/// `ptr` must satisfy [`read_c_string_owned`]'s pointer contract.
pub(crate) unsafe fn parse_json_input<T: DeserializeOwned>(
    ptr: *const c_char,
) -> Result<T, JsonInputError> {
    let owned = read_c_string_owned(ptr)?;
    serde_json::from_str(&owned).map_err(|err| JsonInputError::InvalidJson(err.to_string()))
}

pub(crate) fn json_error_string(error: impl fmt::Display) -> String {
    json!({ "error": error.to_string() }).to_string()
}

pub(crate) fn json_error(error: impl fmt::Display) -> *mut c_char {
    str_to_c_char(&json_error_string(error))
}

/// Contains panics inside legacy pointer-returning C exports.
pub(crate) fn catch_json_ffi<F>(operation: F) -> *mut c_char
where
    F: FnOnce() -> *mut c_char,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => json_error("internal Rust panic"),
    }
}
