//! Evaluation metrics

use crate::Float;
use ndarray::Array1;

pub struct Metrics;

impl Metrics {
    pub fn accuracy(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        y_true.iter().zip(y_pred.iter())
            .filter(|(t, p)| (*t - *p).abs() < 1e-10)
            .count() as Float / y_true.len() as Float
    }
    
    pub fn confusion_matrix(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> [[usize; 2]; 2] {
        let mut cm = [[0usize; 2]; 2];
        for (t, p) in y_true.iter().zip(y_pred.iter()) {
            let t_idx = if *t > 0.5 { 1 } else { 0 };
            let p_idx = if *p > 0.5 { 1 } else { 0 };
            cm[t_idx][p_idx] += 1;
        }
        cm
    }
    
    pub fn precision(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let cm = Self::confusion_matrix(y_true, y_pred);
        let tp = cm[1][1] as Float;
        let fp = cm[0][1] as Float;
        if tp + fp == 0.0 { 0.0 } else { tp / (tp + fp) }
    }
    
    pub fn recall(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let cm = Self::confusion_matrix(y_true, y_pred);
        let tp = cm[1][1] as Float;
        let fn_val = cm[1][0] as Float;
        if tp + fn_val == 0.0 { 0.0 } else { tp / (tp + fn_val) }
    }
    
    pub fn f1_score(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let p = Self::precision(y_true, y_pred);
        let r = Self::recall(y_true, y_pred);
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }
    
    pub fn roc_auc(y_true: &Array1<Float>, y_scores: &Array1<Float>) -> Float {
        let mut pairs: Vec<(Float, Float)> = y_true.iter()
            .zip(y_scores.iter())
            .map(|(t, s)| (*t, *s))
            .collect();
        pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        let n_pos = y_true.iter().filter(|&&x| x > 0.5).count() as Float;
        let n_neg = (y_true.len() as Float) - n_pos;
        
        if n_pos == 0.0 || n_neg == 0.0 { return 0.5; }
        
        let mut auc = 0.0;
        let mut tp = 0.0;
        for (label, _) in pairs {
            if label > 0.5 {
                tp += 1.0;
            } else {
                auc += tp;
            }
        }
        auc / (n_pos * n_neg)
    }
    
    pub fn mse(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let diff = y_true - y_pred;
        (&diff * &diff).mean().unwrap()
    }
    
    pub fn mae(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        (y_true - y_pred).mapv(|x| x.abs()).mean().unwrap()
    }
    
    pub fn r2_score(y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let ss_res = Self::mse(y_true, y_pred) * y_true.len() as Float;
        let y_mean = y_true.mean().unwrap();
        let ss_tot = y_true.mapv(|x| (x - y_mean).powi(2)).sum();
        if ss_tot == 0.0 { 0.0 } else { 1.0 - ss_res / ss_tot }
    }
}
