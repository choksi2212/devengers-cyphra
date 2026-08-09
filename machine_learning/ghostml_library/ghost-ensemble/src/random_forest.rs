//! Random Forest implementation

use ghost_core::{Float, Result, GhostError, SplitCriterion, Array1, Array2, Axis};
use ghost_trees::DecisionTreeClassifier;
use rayon::prelude::*;
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomForestClassifier {
    n_estimators: usize,
    max_depth: usize,
    min_samples_split: usize,
    max_features: MaxFeatures,
    bootstrap: bool,
    criterion: SplitCriterion,
    trees: Vec<DecisionTreeClassifier>,
    oob_score: Option<Float>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MaxFeatures {
    Sqrt,
    Log2,
    All,
    Fixed(usize),
}

impl RandomForestClassifier {
    pub fn new(n_estimators: usize) -> Self {
        Self {
            n_estimators,
            max_depth: 10,
            min_samples_split: 2,
            max_features: MaxFeatures::Sqrt,
            bootstrap: true,
            criterion: SplitCriterion::Gini,
            trees: Vec::new(),
            oob_score: None,
        }
    }
    
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
    
    pub fn max_features(mut self, max_features: MaxFeatures) -> Self {
        self.max_features = max_features;
        self
    }
    
    fn get_max_features(&self, n_features: usize) -> usize {
        match self.max_features {
            MaxFeatures::Sqrt => (n_features as Float).sqrt() as usize,
            MaxFeatures::Log2 => (n_features as Float).log2() as usize,
            MaxFeatures::All => n_features,
            MaxFeatures::Fixed(n) => n.min(n_features),
        }
    }
    
    fn bootstrap_sample(&self, X: &Array2<Float>, y: &Array1<Float>) 
        -> (Array2<Float>, Array1<Float>, Vec<usize>) {
        let n_samples = X.nrows();
        let mut rng = rand::thread_rng();
        
        let indices: Vec<usize> = (0..n_samples)
            .map(|_| rng.gen_range(0..n_samples))
            .collect();
        
        let oob_indices: Vec<usize> = (0..n_samples)
            .filter(|i| !indices.contains(i))
            .collect();
        
        let X_bootstrap = X.select(Axis(0), &indices);
        let y_bootstrap = y.select(Axis(0), &indices);
        
        (X_bootstrap, y_bootstrap, oob_indices)
    }
    
    pub fn fit(&mut self, X: &Array2<Float>, y: &Array1<Float>) -> Result<&mut Self> {
        if X.nrows() != y.len() {
            return Err(GhostError::shape_mismatch(
                format!("{} samples", X.nrows()),
                format!("{} labels", y.len())
            ));
        }
        
        let max_features = self.get_max_features(X.ncols());
        
        let trees_and_oob: Vec<_> = (0..self.n_estimators)
            .into_par_iter()
            .map(|_| {
                let (X_boot, y_boot, oob_indices) = if self.bootstrap {
                    self.bootstrap_sample(X, y)
                } else {
                    (X.clone(), y.clone(), Vec::new())
                };
                
                let mut tree = DecisionTreeClassifier::new()
                    .max_depth(self.max_depth)
                    .min_samples_split(self.min_samples_split)
                    .criterion(self.criterion);
                
                tree.fit(&X_boot, &y_boot).unwrap();
                
                (tree, oob_indices)
            })
            .collect();
        
        self.trees = trees_and_oob.iter().map(|(tree, _)| tree.clone()).collect();
        
        Ok(self)
    }
    
    pub fn predict(&self, X: &Array2<Float>) -> Result<Array1<Float>> {
        if self.trees.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let all_predictions: Vec<Array1<Float>> = self.trees.par_iter()
            .map(|tree| tree.predict(X).unwrap())
            .collect();
        
        let n_samples = X.nrows();
        let mut final_predictions = Vec::with_capacity(n_samples);
        
        for i in 0..n_samples {
            let votes: Vec<Float> = all_predictions.iter()
                .map(|pred| pred[i])
                .collect();
            
            let mut class_counts = std::collections::HashMap::new();
            for &vote in &votes {
                *class_counts.entry(vote as i32).or_insert(0) += 1;
            }
            
            let majority = class_counts.into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(class, _)| class as Float)
                .unwrap_or(0.0);
            
            final_predictions.push(majority);
        }
        
        Ok(Array1::from_vec(final_predictions))
    }
    
    pub fn predict_proba(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if self.trees.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let all_predictions: Vec<Array1<Float>> = self.trees.par_iter()
            .map(|tree| tree.predict(X).unwrap())
            .collect();
        
        let n_samples = X.nrows();
        let n_classes = 2; // Binary classification
        let mut probabilities = Array2::zeros((n_samples, n_classes));
        
        for i in 0..n_samples {
            let votes: Vec<Float> = all_predictions.iter()
                .map(|pred| pred[i])
                .collect();
            
            let n_votes = votes.len() as Float;
            for &vote in &votes {
                let class_idx = vote as usize;
                if class_idx < n_classes {
                    probabilities[[i, class_idx]] += 1.0 / n_votes;
                }
            }
        }
        
        Ok(probabilities)
    }
    
    pub fn feature_importances(&self) -> Result<Array1<Float>> {
        if self.trees.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let all_importances: Vec<Array1<Float>> = self.trees.iter()
            .map(|tree| tree.feature_importances().unwrap())
            .collect();
        
        let n_features = all_importances[0].len();
        let mut avg_importances = Array1::zeros(n_features);
        
        for importances in &all_importances {
            avg_importances = avg_importances + importances;
        }
        
        avg_importances /= self.n_estimators as Float;
        
        Ok(avg_importances)
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
    fn test_random_forest() {
        let X = Array2::from_shape_vec((10, 2), vec![
            1.0, 1.0, 1.5, 1.5, 2.0, 2.0, 2.5, 2.5, 3.0, 3.0,
            5.0, 5.0, 5.5, 5.5, 6.0, 6.0, 6.5, 6.5, 7.0, 7.0,
        ]).unwrap();
        let y = Array1::from_vec(vec![0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0]);
        
        let mut rf = RandomForestClassifier::new(10).max_depth(5);
        rf.fit(&X, &y).unwrap();
        
        let predictions = rf.predict(&X).unwrap();
        assert_eq!(predictions.len(), y.len());
    }
}
