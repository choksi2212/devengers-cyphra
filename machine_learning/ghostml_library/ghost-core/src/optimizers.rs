//! Optimizers for gradient descent

use crate::{Float, OptimizerType};
use ndarray::Array2;

pub trait Optimizer: Send + Sync {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>);
    fn reset(&mut self);
}

pub fn get_optimizer(opt_type: OptimizerType) -> Box<dyn Optimizer> {
    match opt_type {
        OptimizerType::SGD { learning_rate } => Box::new(SGD { learning_rate }),
        OptimizerType::Momentum { learning_rate, momentum } => 
            Box::new(Momentum { learning_rate, momentum, velocity: None }),
        OptimizerType::Adam { learning_rate, beta1, beta2, epsilon } =>
            Box::new(Adam { learning_rate, beta1, beta2, epsilon, m: None, v: None, t: 0 }),
        OptimizerType::RMSprop { learning_rate, decay, epsilon } =>
            Box::new(RMSprop { learning_rate, decay, epsilon, cache: None }),
        OptimizerType::AdaGrad { learning_rate, epsilon } =>
            Box::new(AdaGrad { learning_rate, epsilon, cache: None }),
    }
}

pub struct SGD { pub learning_rate: Float }
impl Optimizer for SGD {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>) {
        *params -= &(self.learning_rate * gradients);
    }
    fn reset(&mut self) {}
}

pub struct Momentum {
    pub learning_rate: Float,
    pub momentum: Float,
    pub velocity: Option<Array2<Float>>,
}
impl Optimizer for Momentum {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>) {
        if self.velocity.is_none() {
            self.velocity = Some(Array2::zeros(params.raw_dim()));
        }
        let v = self.velocity.as_mut().unwrap();
        *v = &*v * self.momentum + gradients * self.learning_rate;
        *params -= &*v;
    }
    fn reset(&mut self) { self.velocity = None; }
}

pub struct Adam {
    pub learning_rate: Float,
    pub beta1: Float,
    pub beta2: Float,
    pub epsilon: Float,
    pub m: Option<Array2<Float>>,
    pub v: Option<Array2<Float>>,
    pub t: usize,
}
impl Optimizer for Adam {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>) {
        if self.m.is_none() {
            self.m = Some(Array2::zeros(params.raw_dim()));
            self.v = Some(Array2::zeros(params.raw_dim()));
        }
        self.t += 1;
        let m = self.m.as_mut().unwrap();
        let v = self.v.as_mut().unwrap();
        
        *m = &*m * self.beta1 + &(gradients * (1.0 - self.beta1));
        *v = &*v * self.beta2 + &(gradients.mapv(|x| x * x) * (1.0 - self.beta2));
        
        let m_hat = &*m / (1.0 - self.beta1.powi(self.t as i32));
        let v_hat = &*v / (1.0 - self.beta2.powi(self.t as i32));
        
        *params -= &(self.learning_rate * &m_hat / &(v_hat.mapv(|x| x.sqrt()) + self.epsilon));
    }
    fn reset(&mut self) {
        self.m = None;
        self.v = None;
        self.t = 0;
    }
}

pub struct RMSprop {
    pub learning_rate: Float,
    pub decay: Float,
    pub epsilon: Float,
    pub cache: Option<Array2<Float>>,
}
impl Optimizer for RMSprop {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>) {
        if self.cache.is_none() {
            self.cache = Some(Array2::zeros(params.raw_dim()));
        }
        let cache = self.cache.as_mut().unwrap();
        *cache = &*cache * self.decay + &(gradients.mapv(|x| x * x) * (1.0 - self.decay));
        *params -= &(self.learning_rate * gradients / &(cache.mapv(|x| x.sqrt()) + self.epsilon));
    }
    fn reset(&mut self) { self.cache = None; }
}

pub struct AdaGrad {
    pub learning_rate: Float,
    pub epsilon: Float,
    pub cache: Option<Array2<Float>>,
}
impl Optimizer for AdaGrad {
    fn update(&mut self, params: &mut Array2<Float>, gradients: &Array2<Float>) {
        if self.cache.is_none() {
            self.cache = Some(Array2::zeros(params.raw_dim()));
        }
        let cache = self.cache.as_mut().unwrap();
        *cache += &gradients.mapv(|x| x * x);
        *params -= &(self.learning_rate * gradients / &(cache.mapv(|x| x.sqrt()) + self.epsilon));
    }
    fn reset(&mut self) { self.cache = None; }
}
