//! Random undersampling

use ghost_core::{Float, Result, GhostError, Array1, Array2, Axis};
use rand::seq::SliceRandom;

pub struct RandomUnderSampler;

impl RandomUnderSampler {
    pub fn fit_resample(
        X: &Array2<Float>,
        y: &Array1<Float>,
    ) -> Result<(Array2<Float>, Array1<Float>)> {
        let mut class_indices: std::collections::HashMap<i32, Vec<usize>> = 
            std::collections::HashMap::new();
        
        for (i, &label) in y.iter().enumerate() {
            class_indices.entry(label as i32)
                .or_insert_with(Vec::new)
                .push(i);
        }
        
        let min_count = class_indices.values().map(|v| v.len()).min().unwrap();
        
        let mut X_resampled = Vec::new();
        let mut y_resampled = Vec::new();
        
        let mut rng = rand::thread_rng();
        for (&class, indices) in &class_indices {
            let mut selected = indices.clone();
            selected.shuffle(&mut rng);
            selected.truncate(min_count);
            
            for &idx in &selected {
                X_resampled.push(X.row(idx).to_owned());
                y_resampled.push(class as Float);
            }
        }
        
        let X_result = ndarray::stack(Axis(0), &X_resampled.iter()
            .map(|r| r.view()).collect::<Vec<_>>())
            .map_err(|e| GhostError::DimensionError(e.to_string()))?;
        let y_result = Array1::from_vec(y_resampled);
        
        Ok((X_result, y_result))
    }
}
