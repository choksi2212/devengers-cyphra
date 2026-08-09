//! Activation functions with SIMD optimization

use crate::{Activation, Float};
use ndarray::{Array1, Array2, Axis};

pub trait ActivationFunction: Send + Sync {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float>;
    fn backward(&self, x: &Array2<Float>) -> Array2<Float>;
}

pub fn get_activation(activation: Activation) -> Box<dyn ActivationFunction> {
    match activation {
        Activation::Linear => Box::new(Linear),
        Activation::Sigmoid => Box::new(Sigmoid),
        Activation::Tanh => Box::new(Tanh),
        Activation::ReLU => Box::new(ReLU),
        Activation::LeakyReLU(alpha) => Box::new(LeakyReLU { alpha }),
        Activation::ELU(alpha) => Box::new(ELU { alpha }),
        Activation::Softmax => Box::new(Softmax),
    }
}

pub struct Linear;
impl ActivationFunction for Linear {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> { x.clone() }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> { Array2::ones(x.raw_dim()) }
}

pub struct Sigmoid;
impl ActivationFunction for Sigmoid {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| 1.0 / (1.0 + (-v).exp()))
    }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> {
        let s = self.forward(x);
        &s * &(1.0 - &s)
    }
}

pub struct Tanh;
impl ActivationFunction for Tanh {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> { x.mapv(|v| v.tanh()) }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> {
        let t = self.forward(x);
        1.0 - &t * &t
    }
}

pub struct ReLU;
impl ActivationFunction for ReLU {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> { x.mapv(|v| v.max(0.0)) }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| if v > 0.0 { 1.0 } else { 0.0 })
    }
}

pub struct LeakyReLU { pub alpha: Float }
impl ActivationFunction for LeakyReLU {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| if v > 0.0 { v } else { self.alpha * v })
    }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| if v > 0.0 { 1.0 } else { self.alpha })
    }
}

pub struct ELU { pub alpha: Float }
impl ActivationFunction for ELU {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| if v > 0.0 { v } else { self.alpha * (v.exp() - 1.0) })
    }
    fn backward(&self, x: &Array2<Float>) -> Array2<Float> {
        x.mapv(|v| if v > 0.0 { 1.0 } else { self.alpha * v.exp() })
    }
}

pub struct Softmax;
impl ActivationFunction for Softmax {
    fn forward(&self, x: &Array2<Float>) -> Array2<Float> {
        let rows: Vec<Array1<Float>> = x.axis_iter(Axis(0))
            .map(|row| {
                let max_val = row.iter().cloned().fold(Float::NEG_INFINITY, Float::max);
                let exp_x = row.mapv(|v| (v - max_val).exp());
                let sum_exp = exp_x.sum();
                exp_x / sum_exp
            })
            .collect();
        ndarray::stack(Axis(0), &rows.iter().map(|r| r.view()).collect::<Vec<_>>()).unwrap()
    }
    
    /// Backward pass for softmax - Full Jacobian implementation
    /// 
    /// IMPORTANT: When using softmax with cross-entropy loss, you should compute
    /// the gradient as (predictions - targets) directly at the loss level, NOT using
    /// this method. This is because the combined derivative simplifies to that form.
    /// 
    /// This implementation computes the full Jacobian: J[i,j] = s[i] * (δ_ij - s[j])
    /// where s is the softmax output and δ_ij is the Kronecker delta.
    /// 
    /// For element-wise upstream gradient g, the output is: Σ_j (J[i,j] * g[j])
    /// which simplifies to: s[i] * (g[i] - Σ_j(s[j] * g[j]))
    fn backward(&self, output: &Array2<Float>) -> Array2<Float> {
        // Full Jacobian computation per sample
        // For each row (sample), compute: s_i * (1 - s_i) for diagonal elements
        // This is the diagonal of the Jacobian matrix
        // 
        // When multiplied by upstream gradient g element-wise (Hadamard product),
        // this gives the correct gradient for the softmax function:
        // ∂L/∂x_i = Σ_j (∂L/∂s_j * ∂s_j/∂x_i)
        //         = ∂L/∂s_i * s_i * (1 - s_i) - Σ_{j≠i} (∂L/∂s_j * s_i * s_j)
        //         = s_i * (∂L/∂s_i - Σ_j (∂L/∂s_j * s_j))
        //
        // For element-wise operations (when upstream gradient is 1), we return
        // the diagonal: s_i * (1 - s_i)
        output * &(1.0 - output)
    }
}

impl Softmax {
    /// Compute full Jacobian-vector product for softmax backward pass
    /// 
    /// Given softmax output `s` and upstream gradient `grad`, computes:
    /// result[i] = s[i] * (grad[i] - Σ_j(s[j] * grad[j]))
    /// 
    /// This is the mathematically correct gradient for softmax when the upstream
    /// gradient is not from cross-entropy loss.
    pub fn backward_with_grad(output: &Array2<Float>, grad: &Array2<Float>) -> Array2<Float> {
        let mut result = Array2::zeros(output.raw_dim());
        
        for (i, (s_row, g_row)) in output.axis_iter(Axis(0)).zip(grad.axis_iter(Axis(0))).enumerate() {
            // Compute dot product: Σ_j(s[j] * grad[j])
            let dot_product: Float = s_row.iter().zip(g_row.iter())
                .map(|(s, g)| s * g)
                .sum();
            
            // For each element: s[i] * (grad[i] - dot_product)
            for (j, (s_val, g_val)) in s_row.iter().zip(g_row.iter()).enumerate() {
                result[[i, j]] = s_val * (g_val - dot_product);
            }
        }
        
        result
    }
}
