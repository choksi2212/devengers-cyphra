//! Feature selection methods

use ghost_core::{Float, Result, GhostError, Array1, Array2, Axis};
use rayon::prelude::*;

pub struct VarianceThreshold {
    threshold: Float,
    variances: Option<Array1<Float>>,
    selected_features: Option<Vec<usize>>,
}

impl VarianceThreshold {
    pub fn new(threshold: Float) -> Self {
        Self { threshold, variances: None, selected_features: None }
    }
    
    pub fn fit(&mut self, X: &Array2<Float>) -> Result<&mut Self> {
        let variances = X.var_axis(Axis(0), 0.0);
        let selected: Vec<usize> = variances.iter()
            .enumerate()
            .filter(|(_, &v)| v > self.threshold)
            .map(|(i, _)| i)
            .collect();
        
        self.variances = Some(variances);
        self.selected_features = Some(selected);
        Ok(self)
    }
    
    pub fn transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        let selected = self.selected_features.as_ref()
            .ok_or(GhostError::NotFitted)?;
        
        let selected_cols: Vec<Array1<Float>> = selected.iter()
            .map(|&i| X.column(i).to_owned())
            .collect();
        
        ndarray::stack(Axis(1), &selected_cols.iter()
            .map(|c| c.view()).collect::<Vec<_>>())
            .map_err(|e| GhostError::DimensionError(e.to_string()))
    }
    
    pub fn fit_transform(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
}

pub struct CorrelationFilter {
    threshold: Float,
    selected_features: Option<Vec<usize>>,
}

impl CorrelationFilter {
    pub fn new(threshold: Float) -> Self {
        Self { threshold, selected_features: None }
    }
    
    fn correlation_matrix(X: &Array2<Float>) -> Array2<Float> {
        let n_features = X.ncols();
        let mut corr = Array2::zeros((n_features, n_features));
        
        for i in 0..n_features {
            for j in i..n_features {
                let col_i = X.column(i);
                let col_j = X.column(j);
                
                let mean_i = col_i.mean().unwrap();
                let mean_j = col_j.mean().unwrap();
                
                let cov: Float = col_i.iter().zip(col_j.iter())
                    .map(|(a, b)| (a - mean_i) * (b - mean_j))
                    .sum::<Float>() / (col_i.len() as Float);
                
                let std_i = col_i.std(0.0);
                let std_j = col_j.std(0.0);
                
                let corr_val = if std_i < 1e-10 || std_j < 1e-10 {
                    0.0
                } else {
                    cov / (std_i * std_j)
                };
                
                corr[[i, j]] = corr_val;
                corr[[j, i]] = corr_val;
            }
        }
        corr
    }
    
    pub fn fit(&mut self, X: &Array2<Float>) -> Result<&mut Self> {
        let corr = Self::correlation_matrix(X);
        let n_features = X.ncols();
        
        let mut selected = Vec::new();
        let mut removed = vec![false; n_features];
        
        for i in 0..n_features {
            if removed[i] { continue; }
            selected.push(i);
            
            for j in (i + 1)..n_features {
                if !removed[j] && corr[[i, j]].abs() > self.threshold {
                    removed[j] = true;
                }
            }
        }
        
        self.selected_features = Some(selected);
        Ok(self)
    }
    
    pub fn transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        let selected = self.selected_features.as_ref()
            .ok_or(GhostError::NotFitted)?;
        
        let selected_cols: Vec<Array1<Float>> = selected.iter()
            .map(|&i| X.column(i).to_owned())
            .collect();
        
        ndarray::stack(Axis(1), &selected_cols.iter()
            .map(|c| c.view()).collect::<Vec<_>>())
            .map_err(|e| GhostError::DimensionError(e.to_string()))
    }
    
    pub fn fit_transform(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
}
