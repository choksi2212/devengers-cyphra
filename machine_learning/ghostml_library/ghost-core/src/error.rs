//! Error types for GhostML
//! 
//! Comprehensive error handling for all ML operations

use thiserror::Error;

/// Result type for GhostML operations
pub type Result<T> = std::result::Result<T, GhostError>;

/// GhostML error types
#[derive(Error, Debug)]
pub enum GhostError {
    #[error("Shape mismatch: expected {expected}, got {actual}")]
    ShapeMismatch {
        expected: String,
        actual: String,
    },

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Not fitted: model must be fitted before prediction")]
    NotFitted,

    #[error("Convergence failed: {0}")]
    ConvergenceError(String),

    #[error("Numerical instability: {0}")]
    NumericalError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Dimension error: {0}")]
    DimensionError(String),

    #[error("Index out of bounds: {0}")]
    IndexError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl GhostError {
    /// Create a shape mismatch error
    pub fn shape_mismatch<S1: ToString, S2: ToString>(expected: S1, actual: S2) -> Self {
        Self::ShapeMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }

    /// Create an invalid parameter error
    pub fn invalid_parameter<S: ToString>(msg: S) -> Self {
        Self::InvalidParameter(msg.to_string())
    }

    /// Create a numerical error
    pub fn numerical<S: ToString>(msg: S) -> Self {
        Self::NumericalError(msg.to_string())
    }
}
