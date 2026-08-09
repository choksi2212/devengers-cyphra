//! Loss functions for training

use crate::{Float, Loss};
use ndarray::Array1;

pub trait LossFunction: Send + Sync {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float;
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float>;
}

pub fn get_loss(loss: Loss) -> Box<dyn LossFunction> {
    match loss {
        Loss::MSE => Box::new(MSE),
        Loss::MAE => Box::new(MAE),
        Loss::BinaryCrossEntropy => Box::new(BinaryCrossEntropy),
        Loss::CategoricalCrossEntropy => Box::new(CategoricalCrossEntropy),
        Loss::Hinge => Box::new(Hinge),
        Loss::Huber(delta) => Box::new(Huber { delta }),
    }
}

pub struct MSE;
impl LossFunction for MSE {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let diff = y_true - y_pred;
        (&diff * &diff).mean().unwrap()
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        2.0 * (y_pred - y_true) / (y_true.len() as Float)
    }
}

pub struct MAE;
impl LossFunction for MAE {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        (y_true - y_pred).mapv(|x| x.abs()).mean().unwrap()
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        (y_pred - y_true).mapv(|x| x.signum()) / (y_true.len() as Float)
    }
}

pub struct BinaryCrossEntropy;
impl LossFunction for BinaryCrossEntropy {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let eps = 1e-15;
        let y_pred_clipped = y_pred.mapv(|x| x.max(eps).min(1.0 - eps));
        -(y_true * &y_pred_clipped.mapv(|x| x.ln()) + 
          &(1.0 - y_true) * &(1.0 - &y_pred_clipped).mapv(|x| x.ln())).mean().unwrap()
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        let eps = 1e-15;
        let y_pred_clipped = y_pred.mapv(|x| x.max(eps).min(1.0 - eps));
        (y_pred_clipped - y_true) / (y_true.len() as Float)
    }
}

pub struct CategoricalCrossEntropy;
impl LossFunction for CategoricalCrossEntropy {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let eps = 1e-15;
        let y_pred_clipped = y_pred.mapv(|x| x.max(eps));
        -(y_true * &y_pred_clipped.mapv(|x| x.ln())).sum() / (y_true.len() as Float)
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        (y_pred - y_true) / (y_true.len() as Float)
    }
}

pub struct Hinge;
impl LossFunction for Hinge {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        (1.0 - y_true * y_pred).mapv(|x| x.max(0.0)).mean().unwrap()
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        (y_true * y_pred).mapv(|x| if x < 1.0 { -1.0 } else { 0.0 }) * y_true / (y_true.len() as Float)
    }
}

pub struct Huber { pub delta: Float }
impl LossFunction for Huber {
    fn compute(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Float {
        let diff = (y_true - y_pred).mapv(|x| x.abs());
        diff.mapv(|x| {
            if x <= self.delta {
                0.5 * x * x
            } else {
                self.delta * (x - 0.5 * self.delta)
            }
        }).mean().unwrap()
    }
    fn gradient(&self, y_true: &Array1<Float>, y_pred: &Array1<Float>) -> Array1<Float> {
        let diff = y_pred - y_true;
        diff.mapv(|x| {
            if x.abs() <= self.delta { x } else { self.delta * x.signum() }
        }) / (y_true.len() as Float)
    }
}
