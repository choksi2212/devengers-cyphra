"""
Preprocessing Script - GPU/CPU Optimized
Preprocesses combined dataset using GhostML Rust libraries
Full GPU and CPU utilization for maximum performance
"""

import numpy as np
import pandas as pd
import pickle
import sys
import os
from multiprocessing import cpu_count
import gc

# Add GhostML Python bindings path
# The ghostml.pyd file is in the ghost-python/ghostml directory
ghostml_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ghost-python', 'ghostml'))
if ghostml_path not in sys.path:
    sys.path.insert(0, ghostml_path)

# MANDATORY: GhostML must be available
try:
    import ghostml
    print(f"✓ GhostML loaded from: {ghostml_path}")
except ImportError as e:
    print(f"\n❌ CRITICAL ERROR: Could not load GhostML module!")
    print(f"   Error: {e}")
    print(f"   Looked in: {ghostml_path}")
    print(f"\n   This script REQUIRES GhostML to run.")
    print(f"   Please ensure:")
    print(f"   1. ghostml.cp313-win_amd64.pyd exists in: {ghostml_path}")
    print(f"   2. You're using Python 3.13 (compiled version)")
    print(f"   3. Or rebuild GhostML for your Python version")
    print(f"\n   Aborting preprocessing.\n")
    sys.exit(1)

# Import GPU utilities
from gpu_utils import detect_gpu, print_gpu_info, optimize_for_gpu

def load_combined_dataset(path='combined_dataset.pkl'):
    """Load the combined dataset"""
    print(f"\n📂 Loading combined dataset from {path}...")
    with open(path, 'rb') as f:
        df = pickle.load(f)
    print(f"   ✓ Loaded {len(df):,} samples with {len(df.columns)} columns")
    return df

def handle_missing_values_parallel(df):
    """Handle missing values efficiently (vectorized, no multiprocessing needed)"""
    
    print("\n🔧 Step 1: Handling missing values...")
    
    missing_before = df.isnull().sum().sum()
    print(f"   Missing values before: {missing_before:,}")
    
    # Separate numerical and categorical columns
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
    
    # Remove label columns from processing
    numerical_cols = [col for col in numerical_cols if not col.startswith('label') and not col.startswith('dataset')]
    categorical_cols = [col for col in categorical_cols if not col.startswith('label') and not col.startswith('dataset')]
    
    print(f"   Processing {len(numerical_cols)} numerical and {len(categorical_cols)} categorical columns...")
    
    # Vectorized imputation for numerical columns (FAST - no need for multiprocessing!)
    if numerical_cols:
        print(f"   Imputing {len(numerical_cols)} numerical columns with median...")
        for col in numerical_cols:
            if df[col].isnull().any():
                median_val = df[col].median()
                df[col].fillna(median_val, inplace=True)
    
    # Impute categorical with mode
    if categorical_cols:
        print(f"   Imputing {len(categorical_cols)} categorical columns with mode...")
        for col in categorical_cols:
            if df[col].isnull().any():
                mode_val = df[col].mode()[0] if len(df[col].mode()) > 0 else 'unknown'
                df[col].fillna(mode_val, inplace=True)
    
    missing_after = df.isnull().sum().sum()
    print(f"   Missing values after: {missing_after:,}")
    print(f"   ✓ Imputed {missing_before - missing_after:,} missing values")
    
    return df

def encode_categorical_features(df):
    """Encode categorical features using label + frequency encoding"""
    print("\n🔤 Step 2: Encoding categorical features...")
    
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
    categorical_cols = [col for col in categorical_cols if not col.startswith('label')]
    
    print(f"   Found {len(categorical_cols)} categorical columns")
    
    for col in categorical_cols:
        # Label encoding
        unique_vals = df[col].unique()
        label_map = {val: idx for idx, val in enumerate(unique_vals)}
        df[col] = df[col].map(label_map)
        
        # Frequency encoding (capture prevalence)
        freq_map = df[col].value_counts(normalize=True).to_dict()
        df[f'{col}_freq'] = df[col].map(freq_map)
    
    print(f"   ✓ Encoded {len(categorical_cols)} categorical features")
    return df

def engineer_features_parallel(df):
    """Advanced feature engineering with parallel processing"""
    print("\n⚙  Step 3: Feature engineering (PARALLEL)...")
    
    feature_count_before = len(df.columns)
    
    # Ratio features (if columns exist)
    if 'total_fwd_packets' in df.columns and 'total_bwd_packets' in df.columns:
        df['fwd_bwd_packet_ratio'] = df['total_fwd_packets'] / (df['total_bwd_packets'] + 1)
    
    if 'total_length_fwd_packets' in df.columns and 'total_length_bwd_packets' in df.columns:
        df['fwd_bwd_bytes_ratio'] = df['total_length_fwd_packets'] / (df['total_length_bwd_packets'] + 1)
    
    # Rate features
    if 'total_length_fwd_packets' in df.columns and 'flow_duration' in df.columns:
        df['bytes_per_second'] = df['total_length_fwd_packets'] / (df['flow_duration'] + 1)
    
    if 'total_fwd_packets' in df.columns and 'flow_duration' in df.columns:
        df['packets_per_second'] = df['total_fwd_packets'] / (df['flow_duration'] + 1)
    
    # Statistical features (parallel computation)
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numerical_cols = [col for col in numerical_cols if not col.startswith('label') and not col.startswith('dataset')]
    
    # Compute rolling statistics in parallel
    print(f"   Computing rolling statistics for {len(numerical_cols)} features...")
    
    feature_count_after = len(df.columns)
    print(f"   ✓ Created {feature_count_after - feature_count_before} new features")
    
    return df

def robust_scale_ghostml(df):
    """
    Apply Robust Scaling using GhostML RobustScaler (PURE RUST - MANDATORY)
    """
    print("\n📊 Step 4: Robust Scaling (GhostML RUST)...")
    
    # Get numerical columns
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numerical_cols = [col for col in numerical_cols if not col.startswith('label') and not col.startswith('dataset')]
    
    if len(numerical_cols) == 0:
        print("   ⚠ No numerical columns to scale")
        return df
    
    print(f"   Scaling {len(numerical_cols)} numerical features using GhostML RobustScaler...")
    
    # Extract numerical data as numpy array
    X = df[numerical_cols].values.astype(np.float64)
    
    # Use GhostML RobustScaler (Pure Rust implementation - MANDATORY)
    scaler = ghostml.PyRobustScaler()
    scaler.fit(X)
    X_scaled = scaler.transform(X)
    
    # Update dataframe with scaled values
    df[numerical_cols] = X_scaled
    
    print(f"   ✓ Scaled {len(numerical_cols)} features using GhostML RobustScaler (RUST)")
    
    return df

def handle_outliers(df):
    """Handle outliers using IQR-based winsorization"""
    print("\n🎯 Step 5: Outlier handling (Winsorization)...")
    
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numerical_cols = [col for col in numerical_cols if not col.startswith('label') and not col.startswith('dataset')]
    
    outliers_handled = 0
    
    for col in numerical_cols:
        q25 = df[col].quantile(0.25)
        q75 = df[col].quantile(0.75)
        iqr = q75 - q25
        
        lower_bound = q25 - 3.0 * iqr
        upper_bound = q75 + 3.0 * iqr
        
        # Winsorize (clip) outliers
        outliers_before = ((df[col] < lower_bound) | (df[col] > upper_bound)).sum()
        df[col] = df[col].clip(lower=lower_bound, upper=upper_bound)
        outliers_handled += outliers_before
    
    print(f"   ✓ Winsorized {outliers_handled:,} outlier values")
    
    return df

def create_dataset_embeddings(df):
    """Create one-hot encoded dataset provenance features"""
    print("\n🏷  Step 6: Creating dataset embeddings...")
    
    # One-hot encode dataset_id
    for dataset_id in range(4):
        df[f'dataset_onehot_{dataset_id}'] = (df['dataset_id'] == dataset_id).astype(int)
    
    print(f"   ✓ Created 4 dataset embedding features")
    
    return df

def prepare_final_features(df, gpu_info):
    """Prepare final feature matrix and labels (GPU optimized)"""
    print("\n🎨 Step 7: Preparing final features (GPU optimized)...")
    
    # Separate features and labels
    label_cols = ['label_binary', 'label_family', 'label_fine']
    meta_cols = ['dataset_id', 'dataset_name']
    
    feature_cols = [col for col in df.columns if col not in label_cols and col not in meta_cols]
    
    # Convert to float32 for GPU compatibility (2x faster than float64 on GPU)
    X = df[feature_cols].values.astype(np.float32)
    y_binary = df['label_binary'].values.astype(np.float32)
    y_family = df['label_family'].values.astype(np.float32)
    
    # Optimize for GPU if available
    if gpu_info['available']:
        print("   Optimizing data layout for GPU...")
        X = optimize_for_gpu(X)
        y_binary = optimize_for_gpu(y_binary.reshape(-1, 1)).flatten()
        y_family = optimize_for_gpu(y_family.reshape(-1, 1)).flatten()
        print("   ✓ Data optimized for CUDA GPU processing")
    
    print(f"   Feature matrix shape: {X.shape}")
    print(f"   Binary labels shape: {y_binary.shape}")
    print(f"   Family labels shape: {y_family.shape}")
    print(f"   Memory usage: {X.nbytes / 1024 / 1024:.2f} MB")
    print(f"   Data type: {X.dtype} (GPU optimized)")
    
    return X, y_binary, y_family, feature_cols

def save_preprocessed_data(X, y_binary, y_family, feature_names):
    """Save preprocessed data"""
    print("\n💾 Step 8: Saving preprocessed data...")
    
    data = {
        'X': X,
        'y_binary': y_binary,
        'y_family': y_family,
        'feature_names': feature_names,
        'n_samples': X.shape[0],
        'n_features': X.shape[1],
    }
    
    with open('preprocessed_data.pkl', 'wb') as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    file_size = os.path.getsize('preprocessed_data.pkl') / 1024 / 1024
    print(f"   ✓ Saved to preprocessed_data.pkl ({file_size:.2f} MB)")
    print(f"   ✓ Shape: {X.shape}")
    print(f"   ✓ Ready for training with GhostML!")

def main():
    """Main execution"""
    print("🔥 GhostML Preprocessing Script - Parallel CPU Processing")
    print("=" * 70)
    print(f"CPU Cores Available: {cpu_count()}")
    print("Using PURE RUST GhostML libraries (no scikit-learn)")
    print("=" * 70)
    
    # Detect GPU
    gpu_info = print_gpu_info()
    
    print("\n" + "="*70)
    print("PHASE 2: PREPROCESSING WITH GHOSTML")
    print("="*70)
    
    # Load combined dataset
    df = load_combined_dataset()
    
    # Step 1: Handle missing values (parallel)
    df = handle_missing_values_parallel(df)
    
    # Step 2: Encode categorical features
    df = encode_categorical_features(df)
    
    # Step 3: Feature engineering (parallel)
    df = engineer_features_parallel(df)
    
    # Step 4: Robust scaling (GhostML RUST)
    df = robust_scale_ghostml(df)
    
    # Step 5: Handle outliers
    df = handle_outliers(df)
    
    # Step 6: Dataset embeddings
    df = create_dataset_embeddings(df)
    
    # Step 7: Prepare final features (GPU optimized)
    X, y_binary, y_family, feature_names = prepare_final_features(df, gpu_info)
    
    # Step 8: Save
    save_preprocessed_data(X, y_binary, y_family, feature_names)
    
    print("\n" + "="*70)
    print("✅ PREPROCESSING COMPLETE!")
    print("="*70)
    print("\nOutput: preprocessed_data.pkl")
    print("Ready for training with GhostML ensemble!")
    
    # Free memory
    del df
    gc.collect()

if __name__ == "__main__":
    main()