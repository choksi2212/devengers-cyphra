//! Neural network layers

use ghost_core::{Float, Activation, Array2};
use ghost_core::activations::get_activation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenseLayer {
    pub weights: Array2<Float>,
    pub biases: Array2<Float>,
    pub activation: Activation,
    
    #[serde(skip)]
    pub input_cache: Option<Array2<Float>>,
    #[serde(skip)]
    pub z_cache: Option<Array2<Float>>,
}

impl DenseLayer {
    pub fn new(input_size: usize, output_size: usize, activation: Activation) -> Self {
        use ndarray_rand::RandomExt;
        use ndarray_rand::rand_distr::Normal;
        
        let scale = (2.0 / input_size as Float).sqrt();
        let weights = Array2::random((input_size, output_size), Normal::new(0.0, scale).unwrap());
        let biases = Array2::zeros((1, output_size));
        
        Self {
            weights,
            biases,
            activation,
            input_cache: None,
            z_cache: None,
        }
    }
    
    pub fn forward(&mut self, input: &Array2<Float>) -> Array2<Float> {
        self.input_cache = Some(input.clone());
        
        let z = input.dot(&self.weights) + &self.biases;
        self.z_cache = Some(z.clone());
        
        let activation_fn = get_activation(self.activation);
        activation_fn.forward(&z)
    }
    
    pub fn backward(&self, grad_output: &Array2<Float>) -> (Array2<Float>, Array2<Float>, Array2<Float>) {
        let input = self.input_cache.as_ref().unwrap();
        let z = self.z_cache.as_ref().unwrap();
        
        let activation_fn = get_activation(self.activation);
        let grad_activation = activation_fn.backward(z);
        let grad_z = grad_output * &grad_activation;
        
        let grad_weights = input.t().dot(&grad_z);
        let grad_biases = grad_z.sum_axis(ndarray::Axis(0)).insert_axis(ndarray::Axis(0));
        let grad_input = grad_z.dot(&self.weights.t());
        
        (grad_input, grad_weights, grad_biases)
    }
}
