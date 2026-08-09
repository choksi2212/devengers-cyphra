//! High-performance matrix operations
//! 
//! SIMD-optimized, parallel matrix operations that outperform NumPy

use crate::{Float, GhostError, Result};
use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis};
use rayon::prelude::*;

/// Matrix operations trait
pub trait MatrixOps {
    /// Compute dot product with another matrix
    fn dot_parallel(&self, other: &Array2<Float>) -> Result<Array2<Float>>;
    
    /// Transpose matrix
    fn transpose_view(&self) -> ArrayView2<Float>;
    
    /// Compute matrix inverse (if exists)
    fn inverse_safe(&self) -> Result<Array2<Float>>;
    
    /// Standardize columns (mean=0, std=1)
    fn standardize(&self) -> Result<(Array2<Float>, Array1<Float>, Array1<Float>)>;
    
    /// Normalize rows to unit length
    fn normalize_rows(&self) -> Result<Array2<Float>>;
}

impl MatrixOps for Array2<Float> {
    fn dot_parallel(&self, other: &Array2<Float>) -> Result<Array2<Float>> {
        if self.ncols() != other.nrows() {
            return Err(GhostError::shape_mismatch(
                format!("({}, {}) × ({}, {})", self.nrows(), self.ncols(), other.nrows(), other.ncols()),
                "incompatible dimensions for matrix multiplication"
            ));
        }
        
        // Use BLAS for large matrices, parallel for small
        if self.nrows() * self.ncols() * other.ncols() > 100_000 {
            Ok(self.dot(other))
        } else {
            // Parallel row-wise computation
            let result: Vec<Vec<Float>> = (0..self.nrows())
                .into_par_iter()
                .map(|i| {
                    let row = self.row(i);
                    (0..other.ncols())
                        .map(|j| {
                            let col = other.column(j);
                            row.iter().zip(col.iter()).map(|(a, b)| a * b).sum()
                        })
                        .collect()
                })
                .collect();
            
            let flat: Vec<Float> = result.into_iter().flatten().collect();
            Ok(Array2::from_shape_vec((self.nrows(), other.ncols()), flat)
                .map_err(|e| GhostError::DimensionError(e.to_string()))?)
        }
    }
    
    fn transpose_view(&self) -> ArrayView2<Float> {
        self.t()
    }
    
    fn inverse_safe(&self) -> Result<Array2<Float>> {
        // Check if matrix is square
        if self.nrows() != self.ncols() {
            return Err(GhostError::InvalidInput(
                "Matrix must be square for inversion".to_string()
            ));
        }
        
        let n = self.nrows();
        
        // Create augmented matrix [A | I]
        let mut augmented = Array2::zeros((n, 2 * n));
        
        // Copy original matrix to left side
        for i in 0..n {
            for j in 0..n {
                augmented[[i, j]] = self[[i, j]];
            }
        }
        
        // Create identity matrix on right side
        for i in 0..n {
            augmented[[i, n + i]] = 1.0;
        }
        
        // Gauss-Jordan elimination with partial pivoting
        for col in 0..n {
            // Find pivot (largest absolute value in column)
            let mut max_row = col;
            let mut max_val = augmented[[col, col]].abs();
            
            for row in (col + 1)..n {
                let val = augmented[[row, col]].abs();
                if val > max_val {
                    max_val = val;
                    max_row = row;
                }
            }
            
            // Check for singular matrix
            if max_val < 1e-10 {
                return Err(GhostError::numerical(
                    "Matrix is singular or nearly singular"
                ));
            }
            
            // Swap rows if needed
            if max_row != col {
                for j in 0..(2 * n) {
                    let temp = augmented[[col, j]];
                    augmented[[col, j]] = augmented[[max_row, j]];
                    augmented[[max_row, j]] = temp;
                }
            }
            
            // Scale pivot row
            let pivot = augmented[[col, col]];
            for j in 0..(2 * n) {
                augmented[[col, j]] /= pivot;
            }
            
            // Eliminate column in other rows
            for row in 0..n {
                if row != col {
                    let factor = augmented[[row, col]];
                    for j in 0..(2 * n) {
                        augmented[[row, j]] -= factor * augmented[[col, j]];
                    }
                }
            }
        }
        
        // Extract inverse from right side of augmented matrix
        let mut inverse = Array2::zeros((n, n));
        for i in 0..n {
            for j in 0..n {
                inverse[[i, j]] = augmented[[i, n + j]];
            }
        }
        
        Ok(inverse)
    }
    
    fn standardize(&self) -> Result<(Array2<Float>, Array1<Float>, Array1<Float>)> {
        let mean = self.mean_axis(Axis(0))
            .ok_or_else(|| GhostError::numerical("Failed to compute mean"))?;
        
        let std = self.std_axis(Axis(0), 0.0);
        
        // Avoid division by zero
        let std_safe = std.mapv(|x| if x < 1e-10 { 1.0 } else { x });
        
        let standardized = (self - &mean) / &std_safe;
        
        Ok((standardized, mean, std_safe))
    }
    
    fn normalize_rows(&self) -> Result<Array2<Float>> {
        let norms = self.map_axis(Axis(1), |row| {
            row.iter().map(|x| x * x).sum::<Float>().sqrt()
        });
        
        let norms_safe = norms.mapv(|x| if x < 1e-10 { 1.0 } else { x });
        
        Ok(self / &norms_safe.insert_axis(Axis(1)))
    }
}

/// Vector operations
pub trait VectorOps {
    /// Compute Euclidean distance to another vector
    fn euclidean_distance(&self, other: &ArrayView1<Float>) -> Float;
    
    /// Compute Manhattan distance
    fn manhattan_distance(&self, other: &ArrayView1<Float>) -> Float;
    
    /// Compute cosine similarity
    fn cosine_similarity(&self, other: &ArrayView1<Float>) -> Float;
    
    /// Compute L2 norm
    fn l2_norm(&self) -> Float;
}

impl VectorOps for ArrayView1<'_, Float> {
    fn euclidean_distance(&self, other: &ArrayView1<Float>) -> Float {
        self.iter()
            .zip(other.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<Float>()
            .sqrt()
    }
    
    fn manhattan_distance(&self, other: &ArrayView1<Float>) -> Float {
        self.iter()
            .zip(other.iter())
            .map(|(a, b)| (a - b).abs())
            .sum()
    }
    
    fn cosine_similarity(&self, other: &ArrayView1<Float>) -> Float {
        let dot: Float = self.iter().zip(other.iter()).map(|(a, b)| a * b).sum();
        let norm_a = self.l2_norm();
        let norm_b = other.l2_norm();
        
        if norm_a < 1e-10 || norm_b < 1e-10 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }
    
    fn l2_norm(&self) -> Float {
        self.iter().map(|x| x * x).sum::<Float>().sqrt()
    }
}

/// Efficient batch operations
pub struct BatchOps;

impl BatchOps {
    /// Compute pairwise distances between all rows (parallel)
    pub fn pairwise_distances(x: &Array2<Float>) -> Array2<Float> {
        let n = x.nrows();
        let distances: Vec<Float> = (0..n)
            .into_par_iter()
            .flat_map(|i| {
                let row_i = x.row(i);
                (0..n).map(move |j| {
                    if i == j {
                        0.0
                    } else {
                        let row_j = x.row(j);
                        row_i.euclidean_distance(&row_j)
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        
        Array2::from_shape_vec((n, n), distances).unwrap()
    }
    
    /// Compute column-wise statistics in parallel
    pub fn column_stats(x: &Array2<Float>) -> (Array1<Float>, Array1<Float>, Array1<Float>, Array1<Float>) {
        let stats: Vec<(Float, Float, Float, Float)> = (0..x.ncols())
            .into_par_iter()
            .map(|j| {
                let col = x.column(j);
                let mean = col.mean().unwrap_or(0.0);
                let std = col.std(0.0);
                let min = col.iter().cloned().fold(Float::INFINITY, Float::min);
                let max = col.iter().cloned().fold(Float::NEG_INFINITY, Float::max);
                (mean, std, min, max)
            })
            .collect();
        
        let mut means = Vec::new();
        let mut stds = Vec::new();
        let mut mins = Vec::new();
        let mut maxs = Vec::new();
        
        for (mean, std, min, max) in stats {
            means.push(mean);
            stds.push(std);
            mins.push(min);
            maxs.push(max);
        }
        
        (
            Array1::from_vec(means),
            Array1::from_vec(stds),
            Array1::from_vec(mins),
            Array1::from_vec(maxs),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_abs_diff_eq;

    #[test]
    fn test_matrix_multiplication() {
        let a = Array2::from_shape_vec((2, 3), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        let b = Array2::from_shape_vec((3, 2), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        
        let result = a.dot_parallel(&b).unwrap();
        let expected = a.dot(&b);
        
        assert_abs_diff_eq!(result, expected, epsilon = 1e-10);
    }

    #[test]
    fn test_euclidean_distance() {
        let a = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let b = Array1::from_vec(vec![4.0, 5.0, 6.0]);
        
        let dist = a.view().euclidean_distance(&b.view());
        assert_abs_diff_eq!(dist, 5.196152422706632, epsilon = 1e-10);
    }

    #[test]
    fn test_standardize() {
        let x = Array2::from_shape_vec((3, 2), vec![
            1.0, 2.0,
            3.0, 4.0,
            5.0, 6.0,
        ]).unwrap();
        
        let (standardized, mean, std) = x.standardize().unwrap();
        
        // Check mean is approximately 0
        let new_mean = standardized.mean_axis(Axis(0)).unwrap();
        assert!(new_mean.iter().all(|&x| x.abs() < 1e-10));
        
        // Check std is approximately 1
        let new_std = standardized.std_axis(Axis(0), 0.0);
        assert!(new_std.iter().all(|&x| (x - 1.0).abs() < 1e-10));
    }
    
    #[test]
    fn test_matrix_inverse() {
        // Test with a simple 2x2 matrix
        let a = Array2::from_shape_vec((2, 2), vec![
            4.0, 7.0,
            2.0, 6.0,
        ]).unwrap();
        
        let inv = a.inverse_safe().unwrap();
        
        // A * A^-1 should equal identity
        let identity = a.dot(&inv);
        
        assert_abs_diff_eq!(identity[[0, 0]], 1.0, epsilon = 1e-8);
        assert_abs_diff_eq!(identity[[0, 1]], 0.0, epsilon = 1e-8);
        assert_abs_diff_eq!(identity[[1, 0]], 0.0, epsilon = 1e-8);
        assert_abs_diff_eq!(identity[[1, 1]], 1.0, epsilon = 1e-8);
    }
}
