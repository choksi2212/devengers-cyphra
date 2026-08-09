//! Data splitting utilities

use ghost_core::{Float, Result, Array1, Array2};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::rngs::StdRng;

pub struct TrainTestSplit;

impl TrainTestSplit {
    pub fn split(
        X: &Array2<Float>,
        y: &Array1<Float>,
        test_size: Float,
        random_state: Option<u64>,
        stratify: bool,
    ) -> Result<(Array2<Float>, Array2<Float>, Array1<Float>, Array1<Float>)> {
        let n_samples = X.nrows();
        let n_test = (n_samples as Float * test_size) as usize;
        let n_train = n_samples - n_test;
        
        let mut indices: Vec<usize> = (0..n_samples).collect();
        
        if let Some(seed) = random_state {
            let mut rng = StdRng::seed_from_u64(seed);
            indices.shuffle(&mut rng);
        } else {
            let mut rng = rand::thread_rng();
            indices.shuffle(&mut rng);
        }
        
        let train_indices = &indices[..n_train];
        let test_indices = &indices[n_train..];
        
        let X_train = X.select(ndarray::Axis(0), train_indices);
        let X_test = X.select(ndarray::Axis(0), test_indices);
        let y_train = y.select(ndarray::Axis(0), train_indices);
        let y_test = y.select(ndarray::Axis(0), test_indices);
        
        Ok((X_train, X_test, y_train, y_test))
    }
}

pub struct KFold {
    n_splits: usize,
    shuffle: bool,
    random_state: Option<u64>,
}

impl KFold {
    pub fn new(n_splits: usize, shuffle: bool, random_state: Option<u64>) -> Self {
        Self { n_splits, shuffle, random_state }
    }
    
    pub fn split(&self, n_samples: usize) -> Vec<(Vec<usize>, Vec<usize>)> {
        let mut indices: Vec<usize> = (0..n_samples).collect();
        
        if self.shuffle {
            if let Some(seed) = self.random_state {
                let mut rng = StdRng::seed_from_u64(seed);
                indices.shuffle(&mut rng);
            } else {
                let mut rng = rand::thread_rng();
                indices.shuffle(&mut rng);
            }
        }
        
        let fold_size = n_samples / self.n_splits;
        let mut splits = Vec::new();
        
        for i in 0..self.n_splits {
            let test_start = i * fold_size;
            let test_end = if i == self.n_splits - 1 {
                n_samples
            } else {
                (i + 1) * fold_size
            };
            
            let test_indices: Vec<usize> = indices[test_start..test_end].to_vec();
            let train_indices: Vec<usize> = indices[..test_start].iter()
                .chain(indices[test_end..].iter())
                .cloned()
                .collect();
            
            splits.push((train_indices, test_indices));
        }
        
        splits
    }
}
