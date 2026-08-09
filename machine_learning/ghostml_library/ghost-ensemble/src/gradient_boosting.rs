//! Gradient Boosting implementation

use ghost_core::{Float, Result, GhostError, Array1, Array2, Axis};
use ghost_trees::{DecisionTreeRegressor, Node};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientBoostingClassifier {
    n_estimators: usize,
    learning_rate: Float,
    max_depth: usize,
    min_samples_split: usize,
    subsample: Float,
    trees: Vec<DecisionTreeRegressor>,
    init_prediction: Float,
}

impl GradientBoostingClassifier {
    pub fn new(n_estimators: usize) -> Self {
        Self {
            n_estimators,
            learning_rate: 0.1,
            max_depth: 3,
            min_samples_split: 2,
            subsample: 1.0,
            trees: Vec::new(),
            init_prediction: 0.0,
        }
    }
    
    pub fn learning_rate(mut self, lr: Float) -> Self {
        self.learning_rate = lr;
        self
    }
    
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
    
    pub fn subsample(mut self, subsample: Float) -> Self {
        self.subsample = subsample.max(0.0).min(1.0);
        self
    }
    
    fn sigmoid(x: Float) -> Float {
        1.0 / (1.0 + (-x).exp())
    }
    
    fn log_loss_gradient(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        y_true - &y_pred.mapv(Self::sigmoid)
    }
    
    fn subsample_data(&self, X: &Array2<Float>, y: &Array1<Float>) 
        -> (Array2<Float>, Array1<Float>) {
        if self.subsample >= 1.0 {
            return (X.clone(), y.clone());
        }
        
        let n_samples = X.nrows();
        let n_subsample = (n_samples as Float * self.subsample) as usize;
        
        use rand::seq::SliceRandom;
        let mut indices: Vec<usize> = (0..n_samples).collect();
        indices.shuffle(&mut rand::thread_rng());
        indices.truncate(n_subsample);
        
        (X.select(Axis(0), &indices), y.select(Axis(0), &indices))
    }
    
    pub fn fit(&mut self, X: &Array2<Float>, y: &Array1<Float>) -> Result<&mut Self> {
        if X.nrows() != y.len() {
            return Err(GhostError::shape_mismatch(
                format!("{} samples", X.nrows()),
                format!("{} labels", y.len())
            ));
        }
        
        // Initialize with log-odds
        let n_pos = y.iter().filter(|&&label| label > 0.5).count() as Float;
        let n_neg = (y.len() as Float) - n_pos;
        self.init_prediction = (n_pos / (n_neg + 1e-10)).ln();
        
        // Current predictions (in log-odds space)
        let mut F = Array1::from_elem(y.len(), self.init_prediction);
        
        for i in 0..self.n_estimators {
            // Compute negative gradient (residuals)
            let residuals = Self::log_loss_gradient(y, &F);
            
            // Subsample data
            let (X_sub, residuals_sub) = self.subsample_data(X, &residuals);
            
            // Fit tree to residuals (use regressor for continuous residuals)
            let mut tree = DecisionTreeRegressor::new()
                .max_depth(self.max_depth)
                .min_samples_split(self.min_samples_split);
            
            tree.fit(&X_sub, &residuals_sub)?;
            
            // Update predictions
            let tree_predictions = tree.predict(X)?;
            F = F + &(tree_predictions * self.learning_rate);
            
            self.trees.push(tree);
            
            // Early stopping check (optional)
            if (i + 1) % 10 == 0 {
                let loss = self.compute_loss(y, &F);
                if loss < 1e-4 {
                    break;
                }
            }
        }
        
        Ok(self)
    }
    
    fn compute_loss(&self, y_true: &Array1<Float>, F: &Array1<Float>) -> Float {
        let y_pred = F.mapv(Self::sigmoid);
        let eps = 1e-15;
        
        -(y_true.iter().zip(y_pred.iter())
            .map(|(&y, &p)| {
                let p_clipped = p.max(eps).min(1.0 - eps);
                y * p_clipped.ln() + (1.0 - y) * (1.0 - p_clipped).ln()
            })
            .sum::<Float>() / y_true.len() as Float)
    }
    
    pub fn predict_proba(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if self.trees.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let mut F = Array1::from_elem(X.nrows(), self.init_prediction);
        
        for tree in &self.trees {
            let tree_pred = tree.predict(X)?;
            F = F + &(tree_pred * self.learning_rate);
        }
        
        let proba_class_1 = F.mapv(Self::sigmoid);
        let proba_class_0 = 1.0 - &proba_class_1;
        
        let mut probabilities = Array2::zeros((X.nrows(), 2));
        for i in 0..X.nrows() {
            probabilities[[i, 0]] = proba_class_0[i];
            probabilities[[i, 1]] = proba_class_1[i];
        }
        
        Ok(probabilities)
    }
    
    pub fn predict(&self, X: &Array2<Float>) -> Result<Array1<Float>> {
        let probabilities = self.predict_proba(X)?;
        
        let predictions: Vec<Float> = (0..X.nrows())
            .map(|i| if probabilities[[i, 1]] > 0.5 { 1.0 } else { 0.0 })
            .collect();
        
        Ok(Array1::from_vec(predictions))
    }
    
    pub fn feature_importances(&self) -> Result<Array1<Float>> {
        if self.trees.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let all_importances: Vec<Array1<Float>> = self.trees.iter()
            .map(|tree| tree.feature_importances().unwrap())
            .collect();
        
        let n_features = all_importances[0].len();
        let mut total_importances = Array1::zeros(n_features);
        
        for importances in &all_importances {
            total_importances = total_importances + importances;
        }
        
        let sum = total_importances.sum();
        if sum > 0.0 {
            total_importances /= sum;
        }
        
        Ok(total_importances)
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
    fn test_gradient_boosting() {
        let X = Array2::from_shape_vec((10, 2), vec![
            1.0, 1.0, 1.5, 1.5, 2.0, 2.0, 2.5, 2.5, 3.0, 3.0,
            5.0, 5.0, 5.5, 5.5, 6.0, 6.0, 6.5, 6.5, 7.0, 7.0,
        ]).unwrap();
        let y = Array1::from_vec(vec![0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0]);
        
        let mut gb = GradientBoostingClassifier::new(50)
            .learning_rate(0.1)
            .max_depth(3);
        
        gb.fit(&X, &y).unwrap();
        let predictions = gb.predict(&X).unwrap();
        
        assert_eq!(predictions.len(), y.len());
    }
}
