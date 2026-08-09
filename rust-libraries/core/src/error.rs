use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
    
    #[error("Device not found")]
    DeviceNotFound,
    
    #[error("Message not found")]
    MessageNotFound,
    
    #[error("Session not found")]
    SessionNotFound,
    
    #[error("Key expired or revoked")]
    KeyExpired,
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, Error>;
