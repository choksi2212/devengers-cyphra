//! Scalers for data normalization

use ghost_core::{Float, Result, GhostError, Array1, Array2, Axis};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardScaler {
    mean: Option<Array1<Float>>,
    std: Option<Array1<Float>>,
    fitted: bool,
}

impl StandardScaler {
    pub fn new() -> Self {
        Self { mean: None, std: None, fitted: false }
    }
    
    pub fn fit(&mut self, X: &Array2<Float>) -> Result<&mut Self> {
        self.mean = Some(X.mean_axis(Axis(0)).ok_or_else(|| 
            GhostError::numerical("Failed to compute mean"))?);
        self.std = Some(X.std_axis(Axis(0), 0.0));
        self.fitted = true;
        Ok(self)
    }
    
    pub fn transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        let mean = self.mean.as_ref().unwrap();
        let std = self.std.as_ref().unwrap();
        let std_safe = std.mapv(|x| if x < 1e-10 { 1.0 } else { x });
        Ok((X - mean) / &std_safe)
    }
    
    pub fn fit_transform(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
    
    pub fn inverse_transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        let mean = self.mean.as_ref().unwrap();
        let std = self.std.as_ref().unwrap();
        Ok(X * std + mean)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinMaxScaler {
    min: Option<Array1<Float>>,
    max: Option<Array1<Float>>,
    feature_range: (Float, Float),
    fitted: bool,
}

impl MinMaxScaler {
    pub fn new(feature_range: (Float, Float)) -> Self {
        Self { min: None, max: None, feature_range, fitted: false }
    }
    
    pub fn fit(&mut self, X: &Array2<Float>) -> Result<&mut Self> {
        self.min = Some(X.map_axis(Axis(0), |col| 
            col.iter().cloned().fold(Float::INFINITY, Float::min)));
        self.max = Some(X.map_axis(Axis(0), |col| 
            col.iter().cloned().fold(Float::NEG_INFINITY, Float::max)));
        self.fitted = true;
        Ok(self)
    }
    
    pub fn transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        let min = self.min.as_ref().unwrap();
        let max = self.max.as_ref().unwrap();
        let range = max - min;
        let range_safe = range.mapv(|x| if x < 1e-10 { 1.0 } else { x });
        
        let (min_range, max_range) = self.feature_range;
        let scaled = (X - min) / &range_safe;
        Ok(scaled * (max_range - min_range) + min_range)
    }
    
    pub fn fit_transform(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobustScaler {
    median: Option<Array1<Float>>,
    iqr: Option<Array1<Float>>,
    fitted: bool,
}

impl RobustScaler {
    pub fn new() -> Self {
        Self { median: None, iqr: None, fitted: false }
    }
    
    /// Compute percentile with proper linear interpolation
    fn percentile(sorted: &[Float], p: Float) -> Float {
        if sorted.is_empty() {
            return 0.0;
        }
        if sorted.len() == 1 {
            return sorted[0];
        }
        
        let n = sorted.len();
        let rank = p * (n - 1) as Float;
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        let frac = rank - lower as Float;
        
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
    
    pub fn fit(&mut self, X: &Array2<Float>) -> Result<&mut Self> {
        self.median = Some(X.map_axis(Axis(0), |col| {
            let mut sorted = col.to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            Self::percentile(&sorted, 0.5)
        }));
        
        let q25 = X.map_axis(Axis(0), |col| {
            let mut sorted = col.to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            Self::percentile(&sorted, 0.25)
        });
        
        let q75 = X.map_axis(Axis(0), |col| {
            let mut sorted = col.to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            Self::percentile(&sorted, 0.75)
        });
        
        self.iqr = Some(&q75 - &q25);
        self.fitted = true;
        Ok(self)
    }
    
    pub fn transform(&self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        let median = self.median.as_ref().unwrap();
        let iqr = self.iqr.as_ref().unwrap();
        let iqr_safe = iqr.mapv(|x| if x < 1e-10 { 1.0 } else { x });
        Ok((X - median) / &iqr_safe)
    }
    
    pub fn fit_transform(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_abs_diff_eq;

    #[test]
    fn test_standard_scaler() {
        let X = Array2::from_shape_vec((3, 2), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        let mut scaler = StandardScaler::new();
        let X_scaled = scaler.fit_transform(&X).unwrap();
        
        let mean = X_scaled.mean_axis(Axis(0)).unwrap();
        assert!(mean.iter().all(|&x| x.abs() < 1e-10));
    }
}
