/**
 * GhostEncoder Tensor Module
 * Production-grade tensor operations for neural networks
 * Optimized for keystroke dynamics and biometric data
 * 
 * @module ghostencoder/tensor
 * @author Ghost Key Team
 * @license MIT
 */

export class Tensor {
  constructor(data, shape = null) {
    if (Array.isArray(data)) {
      this.data = new Float32Array(data.flat(Infinity));
      this.shape = shape || this.inferShape(data);
    } else if (data instanceof Float32Array) {
      this.data = data;
      this.shape = shape || [data.length];
    } else {
      throw new Error('Invalid tensor data');
    }
    
    this.size = this.data.length;
    this.ndim = this.shape.length;
  }

  /**
   * Infer shape from nested array
   * @private
   */
  inferShape(arr) {
    const shape = [];
    let current = arr;
    
    while (Array.isArray(current)) {
      shape.push(current.length);
      current = current[0];
    }
    
    return shape;
  }

  /**
   * Reshape tensor
   */
  reshape(newShape) {
    const newSize = newShape.reduce((a, b) => a * b, 1);
    if (newSize !== this.size) {
      throw new Error('Cannot reshape: size mismatch');
    }
    
    return new Tensor(this.data, newShape);
  }

  /**
   * Get element at index
   */
  get(...indices) {
    const index = this.computeIndex(indices);
    return this.data[index];
  }

  /**
   * Set element at index
   */
  set(value, ...indices) {
    const index = this.computeIndex(indices);
    this.data[index] = value;
  }

  /**
   * Compute flat index from multi-dimensional indices
   * @private
   */
  computeIndex(indices) {
    let index = 0;
    let stride = 1;
    
    for (let i = this.shape.length - 1; i >= 0; i--) {
      index += indices[i] * stride;
      stride *= this.shape[i];
    }
    
    return index;
  }

  /**
   * Matrix multiplication
   */
  matmul(other) {
    if (this.ndim !== 2 || other.ndim !== 2) {
      throw new Error('matmul requires 2D tensors');
    }
    
    const [m, k1] = this.shape;
    const [k2, n] = other.shape;
    
    if (k1 !== k2) {
      throw new Error('Incompatible shapes for matmul');
    }
    
    const result = new Float32Array(m * n);
    
    for (let i = 0; i < m; i++) {
      for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let k = 0; k < k1; k++) {
          sum += this.data[i * k1 + k] * other.data[k * n + j];
        }
        result[i * n + j] = sum;
      }
    }
    
    return new Tensor(result, [m, n]);
  }

  /**
   * Element-wise addition
   */
  add(other) {
    if (other instanceof Tensor) {
      if (this.size !== other.size) {
        throw new Error('Tensor size mismatch');
      }
      
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] + other.data[i];
      }
      
      return new Tensor(result, this.shape);
    } else {
      // Scalar addition
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] + other;
      }
      
      return new Tensor(result, this.shape);
    }
  }

  /**
   * Element-wise subtraction
   */
  subtract(other) {
    if (other instanceof Tensor) {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] - other.data[i];
      }
      
      return new Tensor(result, this.shape);
    } else {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] - other;
      }
      
      return new Tensor(result, this.shape);
    }
  }

  /**
   * Element-wise multiplication
   */
  multiply(other) {
    if (other instanceof Tensor) {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] * other.data[i];
      }
      
      return new Tensor(result, this.shape);
    } else {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] * other;
      }
      
      return new Tensor(result, this.shape);
    }
  }

  /**
   * Element-wise division
   */
  divide(other) {
    if (other instanceof Tensor) {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] / (other.data[i] + 1e-10);
      }
      
      return new Tensor(result, this.shape);
    } else {
      const result = new Float32Array(this.size);
      for (let i = 0; i < this.size; i++) {
        result[i] = this.data[i] / (other + 1e-10);
      }
      
      return new Tensor(result, this.shape);
    }
  }

  /**
   * Transpose (2D only)
   */
  transpose() {
    if (this.ndim !== 2) {
      throw new Error('transpose requires 2D tensor');
    }
    
    const [m, n] = this.shape;
    const result = new Float32Array(this.size);
    
    for (let i = 0; i < m; i++) {
      for (let j = 0; j < n; j++) {
        result[j * m + i] = this.data[i * n + j];
      }
    }
    
    return new Tensor(result, [n, m]);
  }

  /**
   * Sum along axis
   */
  sum(axis = null) {
    if (axis === null) {
      return this.data.reduce((a, b) => a + b, 0);
    }
    
    // Simplified: only support axis 0 for 2D
    if (this.ndim === 2 && axis === 0) {
      const [m, n] = this.shape;
      const result = new Float32Array(n);
      
      for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let i = 0; i < m; i++) {
          sum += this.data[i * n + j];
        }
        result[j] = sum;
      }
      
      return new Tensor(result, [n]);
    }
    
    throw new Error('Unsupported axis');
  }

  /**
   * Mean along axis
   */
  mean(axis = null) {
    if (axis === null) {
      return this.sum() / this.size;
    }
    
    if (this.ndim === 2 && axis === 0) {
      const sumTensor = this.sum(axis);
      return sumTensor.multiply(1 / this.shape[0]);
    }
    
    throw new Error('Unsupported axis');
  }

  /**
   * Apply function element-wise
   */
  apply(fn) {
    const result = new Float32Array(this.size);
    for (let i = 0; i < this.size; i++) {
      result[i] = fn(this.data[i]);
    }
    
    return new Tensor(result, this.shape);
  }

  /**
   * Clone tensor
   */
  clone() {
    return new Tensor(new Float32Array(this.data), [...this.shape]);
  }

  /**
   * Convert to array
   */
  toArray() {
    if (this.ndim === 1) {
      return Array.from(this.data);
    }
    
    if (this.ndim === 2) {
      const [m, n] = this.shape;
      const result = [];
      
      for (let i = 0; i < m; i++) {
        result.push(Array.from(this.data.slice(i * n, (i + 1) * n)));
      }
      
      return result;
    }
    
    return Array.from(this.data);
  }

  /**
   * Create tensor filled with zeros
   */
  static zeros(shape) {
    const size = shape.reduce((a, b) => a * b, 1);
    return new Tensor(new Float32Array(size), shape);
  }

  /**
   * Create tensor filled with ones
   */
  static ones(shape) {
    const size = shape.reduce((a, b) => a * b, 1);
    const data = new Float32Array(size).fill(1);
    return new Tensor(data, shape);
  }

  /**
   * Create tensor with random values (Xavier initialization)
   */
  static random(shape, scale = 1) {
    const size = shape.reduce((a, b) => a * b, 1);
    const data = new Float32Array(size);
    
    // Xavier initialization
    const limit = Math.sqrt(6 / (shape[0] + (shape[1] || shape[0])));
    
    for (let i = 0; i < size; i++) {
      data[i] = (Math.random() * 2 - 1) * limit * scale;
    }
    
    return new Tensor(data, shape);
  }

  /**
   * Create tensor with He initialization (for ReLU)
   */
  static heRandom(shape) {
    const size = shape.reduce((a, b) => a * b, 1);
    const data = new Float32Array(size);
    
    // He initialization
    const std = Math.sqrt(2 / shape[0]);
    
    for (let i = 0; i < size; i++) {
      // Box-Muller transform for normal distribution
      const u1 = Math.random();
      const u2 = Math.random();
      const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      data[i] = z * std;
    }
    
    return new Tensor(data, shape);
  }
}
