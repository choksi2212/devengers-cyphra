//! Error types for VedDB client

use thiserror::Error;

/// Error type for VedDB client operations
#[derive(Debug, Error)]
pub enum Error {
    /// Network or connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Server returned an error
    #[error("Server error: {0}")]
    Server(String),

    /// Operation timed out
    #[error("Operation timed out: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/Deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid argument provided
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Key not found
    #[error("Key not found")]
    KeyNotFound,

    /// Connection pool exhausted
    #[error("Connection pool exhausted")]
    PoolExhausted,

    /// Invalid response from server
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Authentication failed
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Not connected to server
    #[error("Not connected")]
    NotConnected,

    /// Operation not supported
    #[error("Operation not supported")]
    NotSupported,

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Other errors
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a connection error
    pub fn connection<S: Into<String>>(msg: S) -> Self {
        Error::Connection(msg.into())
    }

    /// Create a protocol error
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Error::Protocol(msg.into())
    }

    /// Create a server error
    pub fn server<S: Into<String>>(msg: S) -> Self {
        Error::Server(msg.into())
    }

    /// Create an invalid argument error
    pub fn invalid_argument<S: Into<String>>(msg: S) -> Self {
        Error::InvalidArgument(msg.into())
    }

    /// Create an invalid response error
    pub fn invalid_response<S: Into<String>>(msg: S) -> Self {
        Error::InvalidResponse(msg.into())
    }

    /// Create a TLS error
    pub fn tls<S: Into<String>>(msg: S) -> Self {
        Error::Tls(msg.into())
    }

    /// Create an other error
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
