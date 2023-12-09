use std::fmt;

/// Errors that may occur when using this crate
#[derive(Debug)]
pub enum Argon2Error {
    /// Indicates that the user of a type or function has specified an invalid parameter or
    /// set of parameters
    InvalidParameter(&'static str),

    /// Indicates that a provided hash was expected to be valid, but is invalid. This
    /// normally occurs when a hash is improperly formatted.
    InvalidHash(&'static str),

    /// An error that is unhandled by the crate, but is recognized by the C argon2 library
    CLibError(String),
}

impl std::error::Error for Argon2Error {}

impl fmt::Display for Argon2Error {
    /// Turn an `Argon2Error` into a descriptive string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Argon2Error::InvalidParameter(msg) => {
                write!(f, "Argon2Error: Invalid parameter: {}", msg)
            }
            Argon2Error::InvalidHash(msg) => write!(f, "Argon2Error: Invalid hash: {}", msg),
            Argon2Error::CLibError(msg) => {
                write!(f, "Argon2Error: Error from C library: {}", msg)
            }
        }
    }
}
