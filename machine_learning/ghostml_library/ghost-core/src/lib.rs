//! # GhostML Core
//! 
//! **The Foundation of Lightning-Fast Machine Learning**
//! 
//! Built from scratch to prove doubters wrong. Every line optimized for speed and accuracy.
//! Enterprise-grade, production-ready, hackathon-winning ML library.
//! 
//! ## Features
//! - Zero-copy operations where possible
//! - SIMD-optimized computations
//! - Parallel processing with Rayon
//! - Type-safe matrix operations
//! - Numerical stability guarantees

pub mod matrix;
pub mod activations;
pub mod losses;
pub mod optimizers;
pub mod metrics;
pub mod error;
pub mod types;

pub use error::{GhostError, Result};
pub use types::*;

// Re-export commonly used items
pub use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis};
pub use rayon::prelude::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize GhostML with optimal settings
pub fn init() {
    // Rayon automatically uses all available cores
    // No explicit initialization needed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
