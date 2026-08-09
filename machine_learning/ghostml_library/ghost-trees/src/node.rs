//! Tree node structure

use ghost_core::Float;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub is_leaf: bool,
    pub feature_idx: Option<usize>,
    pub threshold: Option<Float>,
    pub value: Option<Float>,
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,
    pub n_samples: usize,
    pub impurity: Float,
}

impl Node {
    pub fn leaf(value: Float, n_samples: usize, impurity: Float) -> Self {
        Self {
            is_leaf: true,
            feature_idx: None,
            threshold: None,
            value: Some(value),
            left: None,
            right: None,
            n_samples,
            impurity,
        }
    }
    
    pub fn split(
        feature_idx: usize,
        threshold: Float,
        left: Node,
        right: Node,
        n_samples: usize,
        impurity: Float,
    ) -> Self {
        Self {
            is_leaf: false,
            feature_idx: Some(feature_idx),
            threshold: Some(threshold),
            value: None,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            n_samples,
            impurity,
        }
    }
}
