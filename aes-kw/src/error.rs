use core::fmt;

/// Result type with the `aes-kw` crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Errors emitted from the wrap and unwrap operations.
#[derive(Debug)]
pub enum Error {
    /// Input data length invalid.
    InvalidDataLength,
    /// Invalid kek size.
    InvalidKekSize(usize),
    /// Output buffer size invalid.
    InvalidOutputSize {
        /// Expected size in bytes.
        expected: usize,
    },
    /// Integrity check did not pass.
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidDataLength => write!(f, "data must be a multiple of 64 bits"),
            Error::InvalidKekSize(actual_size) => {
                write!(f, "invalid aes kek size: {}", actual_size)
            }
            Error::InvalidOutputSize { expected } => {
                write!(f, "invalid output buffer size: expected {}", expected)
            }
            Error::IntegrityCheckFailed => {
                write!(f, "integrity check failed")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
