//! Decision Tree Regressor implementation using CART algorithm

use ghost_core::{Float, Result, GhostError, SplitCriterion, Array1, Array2, Axis};
use crate::{Node, get_splitter};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTreeRegressor {
    max_depth: usize,
    min_samples_split: usize,
    min_samples_leaf: usize,
    max_features: Option<usize>,
    criterion: SplitCriterion,
    tree: Option<Node>,
    n_features: Option<usize>,
}

impl DecisionTreeRegressor {
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            min_samples_split: 2,
            min_samples_leaf: 1,
            max_features: None,
            criterion: SplitCriterion::MSE,  // Default to MSE for regression
            tree: None,
            n_features: None,
        }
    }
    
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
    
    pub fn min_samples_split(mut self, min_samples: usize) -> Self {
        self.min_samples_split = min_samples;
        self
    }
    
    pub fn min_samples_leaf(mut self, min_samples: usize) -> Self {
        self.min_samples_leaf = min_samples;
        self
    }
    
    pub fn criterion(mut self, criterion: SplitCriterion) -> Self {
        self.criterion = criterion;
        self
    }
    
    /// Compute mean of target values (for regression)
    fn mean_value(y: &Array1<Float>) -> Float {
        if y.is_empty() {
            return 0.0;
        }
        y.mean().unwrap_or(0.0)
    }
    
    fn find_best_split(
        &self,
        X: &Array2<Float>,
        y: &Array1<Float>,
        feature_indices: &[usize],
    ) -> Option<(usize, Float, Float)> {
        let splitter = get_splitter(self.criterion);
        
        let results: Vec<_> = feature_indices.par_iter()
            .filter_map(|&feature_idx| {
                let feature_values = X.column(feature_idx);
                let mut thresholds: Vec<Float> = feature_values.iter().cloned().collect();
                thresholds.sort_by(|a, b| a.partial_cmp(b).unwrap());
                thresholds.dedup();
                
                let mut best_score = Float::INFINITY;
                let mut best_threshold = 0.0;
                
                for &threshold in &thresholds {
                    let (left_mask, right_mask): (Vec<_>, Vec<_>) = (0..X.nrows())
                        .partition(|&i| feature_values[i] <= threshold);
                    
                    if left_mask.len() < self.min_samples_leaf || 
                       right_mask.len() < self.min_samples_leaf {
                        continue;
                    }
                    
                    let y_left = y.select(Axis(0), &left_mask);
                    let y_right = y.select(Axis(0), &right_mask);
                    
                    let score = splitter.split_score(&y_left, &y_right);
                    
                    if score < best_score {
                        best_score = score;
                        best_threshold = threshold;
                    }
                }
                
                if best_score < Float::INFINITY {
                    Some((feature_idx, best_threshold, best_score))
                } else {
                    None
                }
            })
            .collect();
        
        results.into_iter()
            .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap())
            .map(|(feat, thresh, score)| (feat, thresh, score))
    }
    
    fn build_tree(
        &self,
        X: &Array2<Float>,
        y: &Array1<Float>,
        depth: usize,
        feature_indices: &[usize],
    ) -> Node {
        let n_samples = y.len();
        let splitter = get_splitter(self.criterion);
        let impurity = splitter.impurity(y);
        
        // Stopping criteria
        if depth >= self.max_depth ||
           n_samples < self.min_samples_split ||
           impurity < 1e-7 {
            let value = Self::mean_value(y);  // Use mean for regression
            return Node::leaf(value, n_samples, impurity);
        }
        
        // Find best split
        if let Some((feature_idx, threshold, _)) = 
            self.find_best_split(X, y, feature_indices) {
            
            let feature_values = X.column(feature_idx);
            let (left_indices, right_indices): (Vec<_>, Vec<_>) = (0..X.nrows())
                .partition(|&i| feature_values[i] <= threshold);
            
            if left_indices.is_empty() || right_indices.is_empty() {
                let value = Self::mean_value(y);
                return Node::leaf(value, n_samples, impurity);
            }
            
            let X_left = X.select(Axis(0), &left_indices);
            let y_left = y.select(Axis(0), &left_indices);
            let X_right = X.select(Axis(0), &right_indices);
            let y_right = y.select(Axis(0), &right_indices);
            
            let left_node = self.build_tree(&X_left, &y_left, depth + 1, feature_indices);
            let right_node = self.build_tree(&X_right, &y_right, depth + 1, feature_indices);
            
            Node::split(feature_idx, threshold, left_node, right_node, n_samples, impurity)
        } else {
            let value = Self::mean_value(y);
            Node::leaf(value, n_samples, impurity)
        }
    }
    
    pub fn fit(&mut self, X: &Array2<Float>, y: &Array1<Float>) -> Result<&mut Self> {
        if X.nrows() != y.len() {
            return Err(GhostError::shape_mismatch(
                format!("{} samples", X.nrows()),
                format!("{} labels", y.len())
            ));
        }
        
        self.n_features = Some(X.ncols());
        
        let feature_indices: Vec<usize> = if let Some(max_feat) = self.max_features {
            use rand::seq::SliceRandom;
            let mut indices: Vec<usize> = (0..X.ncols()).collect();
            indices.shuffle(&mut rand::thread_rng());
            indices.truncate(max_feat);
            indices
        } else {
            (0..X.ncols()).collect()
        };
        
        self.tree = Some(self.build_tree(X, y, 0, &feature_indices));
        Ok(self)
    }
    
    fn predict_sample(&self, x: &Array1<Float>, node: &Node) -> Float {
        if node.is_leaf {
            return node.value.unwrap();
        }
        
        let feature_idx = node.feature_idx.unwrap();
        let threshold = node.threshold.unwrap();
        
        if x[feature_idx] <= threshold {
            self.predict_sample(x, node.left.as_ref().unwrap())
        } else {
            self.predict_sample(x, node.right.as_ref().unwrap())
        }
    }
    
    pub fn predict(&self, X: &Array2<Float>) -> Result<Array1<Float>> {
        let tree = self.tree.as_ref()
            .ok_or(GhostError::NotFitted)?;
        
        let predictions: Vec<Float> = X.axis_iter(Axis(0))
            .map(|row| self.predict_sample(&row.to_owned(), tree))
            .collect();
        
        Ok(Array1::from_vec(predictions))
    }
    
    pub fn feature_importances(&self) -> Result<Array1<Float>> {
        let tree = self.tree.as_ref()
            .ok_or(GhostError::NotFitted)?;
        
        let n_features = self.n_features.unwrap();
        let mut importances = vec![0.0; n_features];
        
        self.compute_feature_importances(tree, &mut importances);
        
        let total: Float = importances.iter().sum();
        if total > 0.0 {
            for imp in &mut importances {
                *imp /= total;
            }
        }
        
        Ok(Array1::from_vec(importances))
    }
    
    fn compute_feature_importances(&self, node: &Node, importances: &mut [Float]) {
        if node.is_leaf {
            return;
        }
        
        let feature_idx = node.feature_idx.unwrap();
        let n_samples = node.n_samples as Float;
        let impurity = node.impurity;
        
        let left = node.left.as_ref().unwrap();
        let right = node.right.as_ref().unwrap();
        
        let n_left = left.n_samples as Float;
        let n_right = right.n_samples as Float;
        
        let importance = n_samples * impurity -
                        n_left * left.impurity -
                        n_right * right.impurity;
        
        importances[feature_idx] += importance;
        
        self.compute_feature_importances(left, importances);
        self.compute_feature_importances(right, importances);
    }
    
    /// Save model to file using bincode
    pub fn save(&self, path: &str) -> Result<()> {
        let bytes = bincode::serialize(self)
            .map_err(|e| GhostError::SerializationError(format!("Serialization failed: {}", e)))?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
    
    /// Load model from file using bincode
    pub fn load(path: &str) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let model: Self = bincode::deserialize(&bytes)
            .map_err(|e| GhostError::SerializationError(format!("Deserialization failed: {}", e)))?;
        Ok(model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_tree_regressor() {
        // Simple regression test: y = 2*x1 + 3*x2
        let X = Array2::from_shape_vec((6, 2), vec![
            1.0, 1.0,
            2.0, 1.0,
            1.0, 2.0,
            3.0, 3.0,
            4.0, 2.0,
            2.0, 4.0,
        ]).unwrap();
        let y = Array1::from_vec(vec![5.0, 7.0, 8.0, 15.0, 14.0, 16.0]);
        
        let mut tree = DecisionTreeRegressor::new()
            .max_depth(5)
            .min_samples_split(2);
        
        tree.fit(&X, &y).unwrap();
        let predictions = tree.predict(&X).unwrap();
        
        assert_eq!(predictions.len(), y.len());
        
        // Check that predictions are continuous values (not just 0 or 1)
        for pred in predictions.iter() {
            assert!(*pred > 1.0);  // Should predict values in range of y
        }
    }
}
