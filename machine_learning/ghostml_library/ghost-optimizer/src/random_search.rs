//! Random search for hyperparameter tuning

use crate::{Estimator, ParamGrid, ParamSet};
use ghost_core::{Float, Result, Array1, Array2};
use rand::Rng;

pub struct RandomizedSearchCV {
    param_distributions: ParamGrid,
    n_iter: usize,
    cv: usize,
    best_params: Option<ParamSet>,
    best_score: Float,
}

impl RandomizedSearchCV {
    pub fn new(param_distributions: ParamGrid, n_iter: usize, cv: usize) -> Self {
        Self {
            param_distributions,
            n_iter,
            cv,
            best_params: None,
            best_score: Float::NEG_INFINITY,
        }
    }
    
    fn sample_params(&self) -> ParamSet {
        let mut rng = rand::thread_rng();
        let mut params = ParamSet::new();
        
        for (key, values) in &self.param_distributions {
            let idx = rng.gen_range(0..values.len());
            params.insert(key.clone(), values[idx]);
        }
        
        params
    }
    
    pub fn fit<E: Estimator + Clone>(
        &mut self,
        estimator: &E,
        X: &Array2<Float>,
        y: &Array1<Float>,
    ) -> Result<&mut Self> {
        for _ in 0..self.n_iter {
            let params = self.sample_params();
            let score = self.cross_validate(estimator, X, y, &params);
            
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
