//! Grid search for hyperparameter tuning

use crate::{Estimator, ParamGrid, ParamSet};
use ghost_core::{Float, Result, Array1, Array2};
use rayon::prelude::*;

pub struct GridSearchCV {
    param_grid: ParamGrid,
    cv: usize,
    best_params: Option<ParamSet>,
    best_score: Float,
}

impl GridSearchCV {
    pub fn new(param_grid: ParamGrid, cv: usize) -> Self {
        Self {
            param_grid,
            cv,
            best_params: None,
            best_score: Float::NEG_INFINITY,
        }
    }
    
    fn generate_param_combinations(&self) -> Vec<ParamSet> {
        let keys: Vec<String> = self.param_grid.keys().cloned().collect();
        let mut combinations = vec![ParamSet::new()];
        
        for key in &keys {
            let values = &self.param_grid[key];
            let mut new_combinations = Vec::new();
            
            for combo in &combinations {
                for &value in values {
                    let mut new_combo = combo.clone();
                    new_combo.insert(key.clone(), value);
                    new_combinations.push(new_combo);
                }
            }
            
            combinations = new_combinations;
        }
        
        combinations
    }
    
    pub fn fit<E: Estimator + Clone + Send + Sync>(
        &mut self,
        estimator: &E,
        X: &Array2<Float>,
        y: &Array1<Float>,
    ) -> Result<&mut Self> {
        let param_combinations = self.generate_param_combinations();
        
        let results: Vec<(ParamSet, Float)> = param_combinations.par_iter()
            .map(|params| {
                let score = self.cross_validate(estimator, X, y, params);
                (params.clone(), score)
            })
            .collect();
        
        for (params, score) in results {
            if score > self.best_score {
                self.best_score = score;
                self.best_params = Some(params);
            }
        }
        
        Ok(self)
    }
    
    fn cross_validate<E: Estimator + Clone>(
        &self,
        estimator: &E,
        X: &Array2<Float>,
        y: &Array1<Float>,
        params: &ParamSet,
    ) -> Float {
        let n_samples = X.nrows();
        
        // Shuffle indices before creating folds to avoid bias
        let mut indices: Vec<usize> = (0..n_samples).collect();
        use rand::seq::SliceRandom;
        indices.shuffle(&mut rand::thread_rng());
        
        let fold_size = n_samples / self.cv;
        let mut scores = Vec::new();
        
        for fold in 0..self.cv {
            let test_start = fold * fold_size;
            let test_end = if fold == self.cv - 1 { n_samples } else { (fold + 1) * fold_size };
            
            // Use shuffled indices
            let train_indices: Vec<usize> = indices[0..test_start]
                .iter()
                .chain(indices[test_end..n_samples].iter())
                .copied()
                .collect();
            let test_indices: Vec<usize> = indices[test_start..test_end].to_vec();
            
            let X_train = X.select(ndarray::Axis(0), &train_indices);
            let y_train = y.select(ndarray::Axis(0), &train_indices);
            let X_test = X.select(ndarray::Axis(0), &test_indices);
            let y_test = y.select(ndarray::Axis(0), &test_indices);
            
            let mut est = estimator.clone();
            est.set_params(params);
            est.fit(&X_train, &y_train).ok();
            
            let score = est.score(&X_test, &y_test);
            scores.push(score);
        }
        
        scores.iter().sum::<Float>() / scores.len() as Float
    }
    
    pub fn best_params(&self) -> Option<&ParamSet> {
        self.best_params.as_ref()
    }
    
    pub fn best_score(&self) -> Float {
        self.best_score
    }
}
