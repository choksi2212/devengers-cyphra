"""
GPU Utilities for GhostML
Detects CUDA availability and optimizes data for GPU processing
"""

import numpy as np
import sys

def detect_gpu():
    """Detect available GPU and CUDA"""
    try:
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
            cuda_version = torch.version.cuda
            return {
                'available': True,
                'name': gpu_name,
                'memory_gb': gpu_memory,
                'cuda_version': cuda_version,
                'device_count': torch.cuda.device_count()
            }
    except ImportError:
        pass
    
    return {'available': False}

def print_gpu_info():
    """Print GPU information"""
    gpu_info = detect_gpu()
    
    print("\n" + "="*70)
    print("🎮 GPU DETECTION")
    print("="*70)
    
    if gpu_info['available']:
        print(f"✅ CUDA GPU DETECTED!")
        print(f"   GPU Model:      {gpu_info['name']}")
        print(f"   GPU Memory:     {gpu_info['memory_gb']:.1f} GB")
        print(f"   CUDA Version:   {gpu_info['cuda_version']}")
        print(f"   Device Count:   {gpu_info['device_count']}")
        print(f"   Status:         Detected (not used by GhostML)")
    else:
        print("ℹ  No CUDA GPU detected - using CPU")
    
    print("   Note: GhostML is CPU-only, optimized with Rust + Rayon")
    print("="*70)
    
    return gpu_info

def optimize_for_gpu(X, batch_size=10000):
    """
    Optimize numpy array for GPU processing
    Converts to float32 and creates batches for efficient GPU transfer
    """
    # Convert to float32 (GPU optimized)
    if X.dtype != np.float32:
        X = X.astype(np.float32)
    
    # Ensure C-contiguous for faster GPU transfer
    if not X.flags['C_CONTIGUOUS']:
        X = np.ascontiguousarray(X)
    
    return X

def create_gpu_batches(X, y=None, batch_size=10000):
    """Create batches optimized for GPU processing"""
    n_samples = X.shape[0]
    n_batches = (n_samples + batch_size - 1) // batch_size
    
    batches = []
    for i in range(n_batches):
        start_idx = i * batch_size
        end_idx = min((i + 1) * batch_size, n_samples)
        
        if y is not None:
            batches.append((X[start_idx:end_idx], y[start_idx:end_idx]))
        else:
            batches.append(X[start_idx:end_idx])
    
    return batches

def get_optimal_batch_size(gpu_memory_gb, n_features):
    """Calculate optimal batch size based on GPU memory"""
    if gpu_memory_gb >= 8:
        # RTX 4060 8GB - can handle large batches
        if n_features < 100:
            return 50000
        elif n_features < 500:
            return 20000
        else:
            return 10000
    elif gpu_memory_gb >= 6:
        return 8000
    else:
        return 5000

def print_training_config(gpu_info, X_shape, batch_size):
    """Print training configuration"""
    print("\n" + "="*70)
    print("⚙  TRAINING CONFIGURATION")
    print("="*70)
    print(f"Dataset Shape:      {X_shape[0]:,} samples × {X_shape[1]} features")
    print(f"Memory Required:    {X_shape[0] * X_shape[1] * 4 / 1024**3:.2f} GB")
    print(f"Batch Size:         {batch_size:,} samples")
    print(f"Number of Batches:  {(X_shape[0] + batch_size - 1) // batch_size}")
    
    print(f"Processing Mode:    CPU (Multi-threaded via Rayon)")
    print(f"Note:               GhostML is CPU-only, optimized with Rust + Rayon")
    
    print("="*70)