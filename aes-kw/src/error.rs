use core::fmt;

/// Errors emitted from the wrap and unwrap operations.
#[derive(Debug)]
pub enum Error {
    /// Input data length invalid.
    InvalidDataLength,
    /// Invalid kek size.
    InvalidKekSize(usize),
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
            Error::IntegrityCheckFailed => {
                write!(f, "integrity check failed")
            }
        }
    }
}

impl std::error::Error for Error {}
