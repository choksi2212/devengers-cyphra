//! SMOTE - Synthetic Minority Over-sampling Technique

use ghost_core::{Float, Result, GhostError, Array1, Array2, Axis};
use rand::Rng;

pub struct SMOTE {
    k_neighbors: usize,
    sampling_strategy: SamplingStrategy,
}

pub enum SamplingStrategy {
    Auto,
    Ratio(Float),
}

impl SMOTE {
    pub fn new(k_neighbors: usize) -> Self {
        Self {
            k_neighbors,
            sampling_strategy: SamplingStrategy::Auto,
        }
    }
    
    pub fn with_strategy(k_neighbors: usize, strategy: SamplingStrategy) -> Self {
        Self {
            k_neighbors,
            sampling_strategy: strategy,
        }
    }
    
    fn euclidean_distance(a: &Array1<Float>, b: &Array1<Float>) -> Float {
        a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<Float>()
            .sqrt()
    }
    
    fn find_k_neighbors(&self, X: &Array2<Float>, sample_idx: usize) -> Vec<usize> {
        let sample = X.row(sample_idx);
        
        let mut distances: Vec<(usize, Float)> = (0..X.nrows())
            .filter(|&i| i != sample_idx)
            .map(|i| {
                let dist = Self::euclidean_distance(&sample.to_owned(), &X.row(i).to_owned());
                (i, dist)
            })
            .collect();
        
        distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        distances.iter().take(self.k_neighbors).map(|(i, _)| *i).collect()
    }
    
    fn generate_synthetic_sample(
        &self,
        sample: &Array1<Float>,
        neighbor: &Array1<Float>,
        rng: &mut impl Rng,
    ) -> Array1<Float> {
        let lambda: Float = rng.gen();
        sample + &((neighbor - sample) * lambda)
    }
    
    pub fn fit_resample(
        &self,
        X: &Array2<Float>,
        y: &Array1<Float>,
    ) -> Result<(Array2<Float>, Array1<Float>)> {
        // Identify minority and majority classes
        let unique_classes: Vec<Float> = {
            let mut classes: Vec<Float> = y.iter().cloned().collect();
            classes.sort_by(|a, b| a.partial_cmp(b).unwrap());
            classes.dedup();
            classes
        };
        
        if unique_classes.len() != 2 {
            return Err(GhostError::InvalidInput(
                "SMOTE only supports binary classification".to_string()
            ));
        }
        
        let class_counts: Vec<(Float, usize)> = unique_classes.iter()
            .map(|&class| {
                let count = y.iter().filter(|&&c| c == class).count();
                (class, count)
            })
            .collect();
        
        let (minority_class, minority_count) = class_counts.iter()
            .min_by_key(|(_, count)| count)
            .unwrap();
        let (_, majority_count) = class_counts.iter()
            .max_by_key(|(_, count)| count)
            .unwrap();
        
        // Get minority samples
        let minority_indices: Vec<usize> = y.iter()
            .enumerate()
            .filter(|(_, &c)| c == *minority_class)
            .map(|(i, _)| i)
            .collect();
        
        let X_minority = X.select(Axis(0), &minority_indices);
        
        // Calculate number of synthetic samples needed
        let n_synthetic = match self.sampling_strategy {
            SamplingStrategy::Auto => majority_count - minority_count,
            SamplingStrategy::Ratio(ratio) => {
                ((*majority_count as Float * ratio) as usize).saturating_sub(*minority_count)
            }
        };
        
        // Generate synthetic samples
        let mut rng = rand::thread_rng();
        let synthetic_samples: Vec<Array1<Float>> = (0..n_synthetic)
            .map(|_| {
                let sample_idx = rng.gen_range(0..X_minority.nrows());
                let neighbors = self.find_k_neighbors(&X_minority, sample_idx);
                let neighbor_idx = neighbors[rng.gen_range(0..neighbors.len())];
                
                self.generate_synthetic_sample(
                    &X_minority.row(sample_idx).to_owned(),
                    &X_minority.row(neighbor_idx).to_owned(),
                    &mut rng,
                )
            })
            .collect();
        
        // Combine original and synthetic data
        let mut X_resampled_vec = X.rows().into_iter()
            .map(|row| row.to_owned())
            .collect::<Vec<_>>();
        X_resampled_vec.extend(synthetic_samples);
        
        let X_resampled = ndarray::stack(Axis(0), &X_resampled_vec.iter()
            .map(|r| r.view()).collect::<Vec<_>>())
            .map_err(|e| GhostError::DimensionError(e.to_string()))?;
        
        let mut y_resampled = y.to_vec();
        y_resampled.extend(vec![*minority_class; n_synthetic]);
        let y_resampled = Array1::from_vec(y_resampled);
        
        Ok((X_resampled, y_resampled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smote() {
        let X = Array2::from_shape_vec((6, 2), vec![
            1.0, 1.0,
            1.1, 1.1,
            5.0, 5.0,
            5.1, 5.1,
            5.2, 5.2,
            5.3, 5.3,
        ]).unwrap();
        let y = Array1::from_vec(vec![0.0, 0.0, 1.0, 1.0, 1.0, 1.0]);
        
        let smote = SMOTE::new(2);
        let (X_resampled, y_resampled) = smote.fit_resample(&X, &y).unwrap();
        
        assert!(X_resampled.nrows() > X.nrows());
        assert_eq!(X_resampled.nrows(), y_resampled.len());
    }
}
