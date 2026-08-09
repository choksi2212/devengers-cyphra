//! Encoders for categorical data

use ghost_core::{Float, Result, GhostError, Array1, Array2};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelEncoder {
    classes: Option<Vec<String>>,
    class_to_idx: Option<HashMap<String, usize>>,
    fitted: bool,
}

impl LabelEncoder {
    pub fn new() -> Self {
        Self { classes: None, class_to_idx: None, fitted: false }
    }
    
    pub fn fit(&mut self, y: &[String]) -> Result<&mut Self> {
        let mut classes: Vec<String> = y.iter().cloned().collect();
        classes.sort();
        classes.dedup();
        
        let class_to_idx: HashMap<String, usize> = classes.iter()
            .enumerate()
            .map(|(idx, class)| (class.clone(), idx))
            .collect();
        
        self.classes = Some(classes);
        self.class_to_idx = Some(class_to_idx);
        self.fitted = true;
        Ok(self)
    }
    
    pub fn transform(&self, y: &[String]) -> Result<Array1<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        
        let class_to_idx = self.class_to_idx.as_ref().unwrap();
        let encoded: Vec<Float> = y.iter()
            .map(|label| {
                class_to_idx.get(label)
                    .map(|&idx| idx as Float)
                    .ok_or_else(|| GhostError::InvalidInput(
                        format!("Unknown label: {}", label)
                    ))
            })
            .collect::<Result<Vec<_>>>()?;
        
        Ok(Array1::from_vec(encoded))
    }
    
    pub fn fit_transform(&mut self, y: &[String]) -> Result<Array1<Float>> {
        self.fit(y)?;
        self.transform(y)
    }
    
    pub fn inverse_transform(&self, y: &Array1<Float>) -> Result<Vec<String>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        
        let classes = self.classes.as_ref().unwrap();
        let decoded: Vec<String> = y.iter()
            .map(|&idx| {
                let idx_usize = idx as usize;
                classes.get(idx_usize)
                    .cloned()
                    .ok_or_else(|| GhostError::IndexError(
                        format!("Index {} out of bounds", idx_usize)
                    ))
            })
            .collect::<Result<Vec<_>>>()?;
        
        Ok(decoded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneHotEncoder {
    categories: Option<Vec<Vec<String>>>,
    fitted: bool,
}

impl OneHotEncoder {
    pub fn new() -> Self {
        Self { categories: None, fitted: false }
    }
    
    pub fn fit(&mut self, X: &[Vec<String>]) -> Result<&mut Self> {
        if X.is_empty() {
            return Err(GhostError::InvalidInput("Empty input".to_string()));
        }
        
        let n_features = X[0].len();
        let mut categories = vec![Vec::new(); n_features];
        
        for sample in X {
            for (feat_idx, value) in sample.iter().enumerate() {
                if !categories[feat_idx].contains(value) {
                    categories[feat_idx].push(value.clone());
                }
            }
        }
        
        for cat in &mut categories {
            cat.sort();
        }
        
        self.categories = Some(categories);
        self.fitted = true;
        Ok(self)
    }
    
    pub fn transform(&self, X: &[Vec<String>]) -> Result<Array2<Float>> {
        if !self.fitted {
            return Err(GhostError::NotFitted);
        }
        
        let categories = self.categories.as_ref().unwrap();
        let n_samples = X.len();
        let n_features: usize = categories.iter().map(|c| c.len()).sum();
        
        let mut encoded = Array2::zeros((n_samples, n_features));
        
        for (sample_idx, sample) in X.iter().enumerate() {
            let mut col_offset = 0;
            for (feat_idx, value) in sample.iter().enumerate() {
                if let Some(cat_idx) = categories[feat_idx].iter().position(|c| c == value) {
                    encoded[[sample_idx, col_offset + cat_idx]] = 1.0;
                }
                col_offset += categories[feat_idx].len();
            }
        }
        
        Ok(encoded)
    }
    
    pub fn fit_transform(&mut self, X: &[Vec<String>]) -> Result<Array2<Float>> {
        self.fit(X)?;
        self.transform(X)
    }
}
