//! Splitting criteria for decision trees

use ghost_core::{Float, SplitCriterion, Array1};

pub trait Splitter: Send + Sync {
    fn impurity(&self, y: &Array1<Float>) -> Float;
    fn split_score(&self, y_left: &Array1<Float>, y_right: &Array1<Float>) -> Float;
}

pub fn get_splitter(criterion: SplitCriterion) -> Box<dyn Splitter> {
    match criterion {
        SplitCriterion::Gini => Box::new(GiniSplitter),
        SplitCriterion::Entropy => Box::new(EntropySplitter),
        SplitCriterion::MSE => Box::new(MSESplitter),
        SplitCriterion::MAE => Box::new(MAESplitter),
    }
}

pub struct GiniSplitter;

impl Splitter for GiniSplitter {
    fn impurity(&self, y: &Array1<Float>) -> Float {
        if y.is_empty() { return 0.0; }
        
        let n = y.len() as Float;
        let mut class_counts = std::collections::HashMap::new();
        
        for &label in y.iter() {
            *class_counts.entry(label as i32).or_insert(0) += 1;
        }
        
        let mut gini = 1.0;
        for &count in class_counts.values() {
            let p = count as Float / n;
            gini -= p * p;
        }
        gini
    }
    
    fn split_score(&self, y_left: &Array1<Float>, y_right: &Array1<Float>) -> Float {
        let n_left = y_left.len() as Float;
        let n_right = y_right.len() as Float;
        let n_total = n_left + n_right;
        
        if n_total == 0.0 { return Float::INFINITY; }
        
        let gini_left = self.impurity(y_left);
        let gini_right = self.impurity(y_right);
        
        (n_left / n_total) * gini_left + (n_right / n_total) * gini_right
    }
}

pub struct EntropySplitter;

impl Splitter for EntropySplitter {
    fn impurity(&self, y: &Array1<Float>) -> Float {
        if y.is_empty() { return 0.0; }
        
        let n = y.len() as Float;
        let mut class_counts = std::collections::HashMap::new();
        
        for &label in y.iter() {
            *class_counts.entry(label as i32).or_insert(0) += 1;
        }
        
        let mut entropy = 0.0;
        for &count in class_counts.values() {
            if count > 0 {
                let p = count as Float / n;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
    
    fn split_score(&self, y_left: &Array1<Float>, y_right: &Array1<Float>) -> Float {
        let n_left = y_left.len() as Float;
        let n_right = y_right.len() as Float;
        let n_total = n_left + n_right;
        
        if n_total == 0.0 { return Float::INFINITY; }
        
        let entropy_left = self.impurity(y_left);
        let entropy_right = self.impurity(y_right);
        
        (n_left / n_total) * entropy_left + (n_right / n_total) * entropy_right
    }
}

pub struct MSESplitter;

impl Splitter for MSESplitter {
    fn impurity(&self, y: &Array1<Float>) -> Float {
        if y.is_empty() { return 0.0; }
        
        let mean = y.mean().unwrap();
        y.iter().map(|&val| (val - mean).powi(2)).sum::<Float>() / y.len() as Float
    }
    
    fn split_score(&self, y_left: &Array1<Float>, y_right: &Array1<Float>) -> Float {
        let n_left = y_left.len() as Float;
        let n_right = y_right.len() as Float;
        let n_total = n_left + n_right;
        
        if n_total == 0.0 { return Float::INFINITY; }
        
        let mse_left = self.impurity(y_left);
        let mse_right = self.impurity(y_right);
        
        (n_left / n_total) * mse_left + (n_right / n_total) * mse_right
    }
}

pub struct MAESplitter;

impl Splitter for MAESplitter {
    fn impurity(&self, y: &Array1<Float>) -> Float {
        if y.is_empty() { return 0.0; }
        
        let median = {
            let mut sorted = y.to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            sorted[sorted.len() / 2]
        };
        
        y.iter().map(|&val| (val - median).abs()).sum::<Float>() / y.len() as Float
    }
    
    fn split_score(&self, y_left: &Array1<Float>, y_right: &Array1<Float>) -> Float {
        let n_left = y_left.len() as Float;
        let n_right = y_right.len() as Float;
        let n_total = n_left + n_right;
        
        if n_total == 0.0 { return Float::INFINITY; }
        
        let mae_left = self.impurity(y_left);
        let mae_right = self.impurity(y_right);
        
        (n_left / n_total) * mae_left + (n_right / n_total) * mae_right
    }
}
