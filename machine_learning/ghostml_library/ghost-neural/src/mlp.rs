//! Multi-Layer Perceptron

use ghost_core::{Float, Result, GhostError, Activation, OptimizerType, Array1, Array2, Axis};
use ghost_core::optimizers::{get_optimizer, Optimizer};
use crate::layers::DenseLayer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MLPClassifier {
    layers: Vec<DenseLayer>,
    optimizer_type: OptimizerType,
    epochs: usize,
    batch_size: usize,
    
    #[serde(skip)]
    optimizers: Vec<Box<dyn Optimizer>>,
}

impl MLPClassifier {
    pub fn new(layer_sizes: &[usize], hidden_activation: Activation) -> Self {
        let mut layers = Vec::new();
        
        for i in 0..layer_sizes.len() - 1 {
            let activation = if i == layer_sizes.len() - 2 {
                Activation::Sigmoid
            } else {
                hidden_activation
            };
            
            layers.push(DenseLayer::new(layer_sizes[i], layer_sizes[i + 1], activation));
        }
        
        Self {
            layers,
            optimizer_type: OptimizerType::Adam {
                learning_rate: 0.001,
                beta1: 0.9,
                beta2: 0.999,
                epsilon: 1e-8,
            },
            epochs: 100,
            batch_size: 32,
            optimizers: Vec::new(),
        }
    }
    
    pub fn optimizer(mut self, optimizer: OptimizerType) -> Self {
        self.optimizer_type = optimizer;
        self
    }
    
    pub fn epochs(mut self, epochs: usize) -> Self {
        self.epochs = epochs;
        self
    }
    
    pub fn batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
    
    fn forward(&mut self, X: &Array2<Float>) -> Array2<Float> {
        let mut output = X.clone();
        for layer in &mut self.layers {
            output = layer.forward(&output);
        }
        output
    }
    
    fn backward(&mut self, grad_output: &Array2<Float>) -> Vec<(Array2<Float>, Array2<Float>)> {
        let mut grad = grad_output.clone();
        let mut gradients = Vec::new();
        
        for layer in self.layers.iter().rev() {
            let (grad_input, grad_weights, grad_biases) = layer.backward(&grad);
            gradients.push((grad_weights, grad_biases));
            grad = grad_input;
        }
        
        gradients.reverse();
        gradients
    }
    
    fn binary_cross_entropy_loss(&self, y_true: &Array2<Float>, y_pred: &Array2<Float>) -> Float {
        let eps = 1e-15;
        let y_pred_clipped = y_pred.mapv(|x| x.max(eps).min(1.0 - eps));
        
        -(y_true * &y_pred_clipped.mapv(|x| x.ln()) + 
          &(1.0 - y_true) * &(1.0 - &y_pred_clipped).mapv(|x| x.ln()))
            .mean().unwrap()
    }
    
    pub fn fit(&mut self, X: &Array2<Float>, y: &Array1<Float>) -> Result<&mut Self> {
        if X.nrows() != y.len() {
            return Err(GhostError::shape_mismatch(
                format!("{} samples", X.nrows()),
                format!("{} labels", y.len())
            ));
        }
        
        // Initialize optimizers
        self.optimizers = self.layers.iter()
            .map(|_| get_optimizer(self.optimizer_type))
            .collect();
        
        // Convert labels to one-hot (for binary: just reshape)
        let y_matrix = y.clone().insert_axis(Axis(1));
        
        let n_samples = X.nrows();
        let n_batches = (n_samples + self.batch_size - 1) / self.batch_size;
        
        for epoch in 0..self.epochs {
            let mut epoch_loss = 0.0;
            
            for batch_idx in 0..n_batches {
                let start = batch_idx * self.batch_size;
                let end = (start + self.batch_size).min(n_samples);
                
                let X_batch = X.slice(ndarray::s![start..end, ..]).to_owned();
                let y_batch = y_matrix.slice(ndarray::s![start..end, ..]).to_owned();
                
                // Forward pass
                let y_pred = self.forward(&X_batch);
                
                // Compute loss
                let loss = self.binary_cross_entropy_loss(&y_batch, &y_pred);
                epoch_loss += loss;
                
                // Backward pass
                let grad_output = &y_pred - &y_batch;
                let gradients = self.backward(&grad_output);
                
                // Update weights
                for (i, (grad_w, grad_b)) in gradients.iter().enumerate() {
                    self.optimizers[i].update(&mut self.layers[i].weights, grad_w);
                    self.optimizers[i].update(&mut self.layers[i].biases, grad_b);
                }
            }
            
            if (epoch + 1) % 10 == 0 {
                let avg_loss = epoch_loss / n_batches as Float;
                println!("Epoch {}/{}, Loss: {:.4}", epoch + 1, self.epochs, avg_loss);
            }
        }
        
        Ok(self)
    }
    
    pub fn predict_proba(&mut self, X: &Array2<Float>) -> Result<Array2<Float>> {
        if self.layers.is_empty() {
            return Err(GhostError::NotFitted);
        }
        
        let output = self.forward(X);
        
        let mut probabilities = Array2::zeros((X.nrows(), 2));
        for i in 0..X.nrows() {
            probabilities[[i, 1]] = output[[i, 0]];
            probabilities[[i, 0]] = 1.0 - output[[i, 0]];
        }
        
        Ok(probabilities)
    }
    
    pub fn predict(&mut self, X: &Array2<Float>) -> Result<Array1<Float>> {
        let probabilities = self.predict_proba(X)?;
        
        let predictions: Vec<Float> = (0..X.nrows())
            .map(|i| if probabilities[[i, 1]] > 0.5 { 1.0 } else { 0.0 })
            .collect();
        
        Ok(Array1::from_vec(predictions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlp() {
        let X = Array2::from_shape_vec((10, 2), vec![
            1.0, 1.0, 1.5, 1.5, 2.0, 2.0, 2.5, 2.5, 3.0, 3.0,
            5.0, 5.0, 5.5, 5.5, 6.0, 6.0, 6.5, 6.5, 7.0, 7.0,
        ]).unwrap();
        let y = Array1::from_vec(vec![0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0]);
        
        let mut mlp = MLPClassifier::new(&[2, 10, 1], Activation::ReLU)
            .epochs(50)
            .batch_size(5);
        
        mlp.fit(&X, &y).unwrap();
        let predictions = mlp.predict(&X).unwrap();
        
        assert_eq!(predictions.len(), y.len());
    }
}
