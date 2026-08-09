//! GhostML Hyperparameter Optimization

pub mod grid_search;
pub mod random_search;

pub use grid_search::*;
pub use random_search::*;

use ghost_core::{Float, Result};
use std::collections::HashMap;

pub type ParamGrid = HashMap<String, Vec<Float>>;
pub type ParamSet = HashMap<String, Float>;

pub trait Estimator {
    fn fit(&mut self, X: &ndarray::Array2<Float>, y: &ndarray::Array1<Float>) -> Result<()>;
    fn score(&self, X: &ndarray::Array2<Float>, y: &ndarray::Array1<Float>) -> Float;
    fn set_params(&mut self, params: &ParamSet);
}
