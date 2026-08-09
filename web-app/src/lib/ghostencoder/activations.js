/**
 * GhostEncoder Activation Functions
 * Production-grade activation functions for neural networks
 * 
 * @module ghostencoder/activations
 * @author Ghost Key Team
 * @license MIT
 */

/**
 * ReLU (Rectified Linear Unit)
 * f(x) = max(0, x)
 */
export function relu(x) {
  return Math.max(0, x);
}

export function reluDerivative(x) {
  return x > 0 ? 1 : 0;
}

/**
 * Leaky ReLU
 * f(x) = x if x > 0, else alpha * x
 */
export function leakyRelu(x, alpha = 0.01) {
  return x > 0 ? x : alpha * x;
}

export function leakyReluDerivative(x, alpha = 0.01) {
  return x > 0 ? 1 : alpha;
}

/**
 * ELU (Exponential Linear Unit)
 * f(x) = x if x > 0, else alpha * (exp(x) - 1)
 */
export function elu(x, alpha = 1.0) {
  return x > 0 ? x : alpha * (Math.exp(x) - 1);
}

export function eluDerivative(x, alpha = 1.0) {
  return x > 0 ? 1 : alpha * Math.exp(x);
}

/**
 * SELU (Scaled Exponential Linear Unit)
 * Self-normalizing activation function
 */
export function selu(x) {
  const alpha = 1.6732632423543772848170429916717;
  const scale = 1.0507009873554804934193349852946;
  
  return scale * (x > 0 ? x : alpha * (Math.exp(x) - 1));
}

export function seluDerivative(x) {
  const alpha = 1.6732632423543772848170429916717;
  const scale = 1.0507009873554804934193349852946;
  
  return scale * (x > 0 ? 1 : alpha * Math.exp(x));
}

/**
 * Sigmoid
 * f(x) = 1 / (1 + exp(-x))
 */
export function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

export function sigmoidDerivative(x) {
  const s = sigmoid(x);
  return s * (1 - s);
}

/**
 * Tanh (Hyperbolic Tangent)
 * f(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))
 */
export function tanh(x) {
  return Math.tanh(x);
}

export function tanhDerivative(x) {
  const t = Math.tanh(x);
  return 1 - t * t;
}

/**
 * Swish (SiLU - Sigmoid Linear Unit)
 * f(x) = x * sigmoid(x)
 */
export function swish(x) {
  return x * sigmoid(x);
}

export function swishDerivative(x) {
  const s = sigmoid(x);
  return s + x * s * (1 - s);
}

/**
 * GELU (Gaussian Error Linear Unit)
 * f(x) ≈ 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3)))
 */
export function gelu(x) {
  const sqrt2OverPi = Math.sqrt(2 / Math.PI);
  return 0.5 * x * (1 + Math.tanh(sqrt2OverPi * (x + 0.044715 * Math.pow(x, 3))));
}

export function geluDerivative(x) {
  const sqrt2OverPi = Math.sqrt(2 / Math.PI);
  const x3 = Math.pow(x, 3);
  const inner = sqrt2OverPi * (x + 0.044715 * x3);
  const tanhInner = Math.tanh(inner);
  const sech2 = 1 - tanhInner * tanhInner;
  
  return 0.5 * (1 + tanhInner) + 0.5 * x * sech2 * sqrt2OverPi * (1 + 0.134145 * x * x);
}

/**
 * Mish
 * f(x) = x * tanh(softplus(x)) = x * tanh(ln(1 + exp(x)))
 */
export function mish(x) {
  return x * Math.tanh(Math.log(1 + Math.exp(x)));
}

export function mishDerivative(x) {
  const expX = Math.exp(x);
  const softplus = Math.log(1 + expX);
  const tanhSoftplus = Math.tanh(softplus);
  const sech2 = 1 - tanhSoftplus * tanhSoftplus;
  
  return tanhSoftplus + x * sech2 * expX / (1 + expX);
}

/**
 * Softplus
 * f(x) = ln(1 + exp(x))
 */
export function softplus(x) {
  return Math.log(1 + Math.exp(x));
}

export function softplusDerivative(x) {
  return sigmoid(x);
}

/**
 * Linear (Identity)
 * f(x) = x
 */
export function linear(x) {
  return x;
}

export function linearDerivative(x) {
  return 1;
}

/**
 * Get activation function by name
 */
export function getActivation(name) {
  const activations = {
    'relu': relu,
    'leaky_relu': leakyRelu,
    'elu': elu,
    'selu': selu,
    'sigmoid': sigmoid,
    'tanh': tanh,
    'swish': swish,
    'gelu': gelu,
    'mish': mish,
    'softplus': softplus,
    'linear': linear
  };
  
  return activations[name] || relu;
}

/**
 * Get activation derivative by name
 */
export function getActivationDerivative(name) {
  const derivatives = {
    'relu': reluDerivative,
    'leaky_relu': leakyReluDerivative,
    'elu': eluDerivative,
    'selu': seluDerivative,
    'sigmoid': sigmoidDerivative,
    'tanh': tanhDerivative,
    'swish': swishDerivative,
    'gelu': geluDerivative,
    'mish': mishDerivative,
    'softplus': softplusDerivative,
    'linear': linearDerivative
  };
  
  return derivatives[name] || reluDerivative;
}
