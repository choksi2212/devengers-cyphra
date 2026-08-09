//! Common types used throughout GhostML

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};

/// Floating point type used throughout the library
pub type Float = f64;

/// Feature matrix type (samples × features)
pub type Features = Array2<Float>;

/// Target vector type
pub type Target = Array1<Float>;

/// Target matrix type (for multi-output)
pub type TargetMatrix = Array2<Float>;

/// Prediction vector type
pub type Predictions = Array1<Float>;

/// Probability matrix type (samples × classes)
pub type Probabilities = Array2<Float>;

/// Activation function type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Activation {
    /// Linear activation: f(x) = x
    Linear,
    /// Sigmoid activation: f(x) = 1 / (1 + e^(-x))
    Sigmoid,
    /// Hyperbolic tangent: f(x) = tanh(x)
    Tanh,
    /// Rectified Linear Unit: f(x) = max(0, x)
    ReLU,
    /// Leaky ReLU: f(x) = max(αx, x)
    LeakyReLU(Float),
    /// Exponential Linear Unit
    ELU(Float),
    /// Softmax (for output layer)
    Softmax,
}

/// Loss function type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Loss {
    /// Mean Squared Error
    MSE,
    /// Mean Absolute Error
    MAE,
    /// Binary Cross-Entropy
    BinaryCrossEntropy,
    /// Categorical Cross-Entropy
    CategoricalCrossEntropy,
    /// Hinge Loss (for SVM)
    Hinge,
    /// Huber Loss
    Huber(Float),
}

/// Optimizer type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum OptimizerType {
    /// Stochastic Gradient Descent
    SGD { learning_rate: Float },
    /// SGD with Momentum
    Momentum { learning_rate: Float, momentum: Float },
    /// Adaptive Moment Estimation (Adam)
    Adam {
        learning_rate: Float,
        beta1: Float,
        beta2: Float,
        epsilon: Float,
    },
    /// RMSprop
    RMSprop {
        learning_rate: Float,
        decay: Float,
        epsilon: Float,
    },
    /// AdaGrad
    AdaGrad {
        learning_rate: Float,
        epsilon: Float,
    },
}

/// Splitting criterion for decision trees
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitCriterion {
    /// Gini impurity (classification)
    Gini,
    /// Entropy / Information Gain (classification)
    Entropy,
    /// Mean Squared Error (regression)
    MSE,
    /// Mean Absolute Error (regression)
    MAE,
}

/// Sampling strategy for imbalanced learning
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SamplingStrategy {
    /// Oversample minority class to match majority
    Auto,
    /// Oversample to specific ratio
    Ratio(Float),
    /// Oversample to specific count
    Count(usize),
}

/// Random state for reproducibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomState {
    pub seed: u64,
}

impl RandomState {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }
}

impl Default for RandomState {
    fn default() -> Self {
        Self { seed: 42 }
    }
}
