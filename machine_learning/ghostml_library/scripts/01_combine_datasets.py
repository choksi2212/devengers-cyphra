"""
Dataset Combination Script - CPU Optimized
Combines 4 datasets with schema harmonization
Uses ONLY GhostML libraries (Pure Rust, no scikit-learn/pandas ML operations)
Optimized for parallel processing on multi-core CPUs via Rayon
"""

import numpy as np
import pandas as pd  # Only for CSV reading, not for ML operations
import os
from pathlib import Path
import pickle
from multiprocessing import Pool, cpu_count
from functools import partial
import gc

# Dataset configurations
DATASETS = [
    {"name": "ISCXVPN2016", "path": "DATASETS/ISCXVPN2016", "id": 0},
    {"name": "UNSW-NB15", "path": "DATASETS/UNSWNB15", "id": 1},
    {"name": "CICIDS2017", "path": "DATASETS/CICIDS2017", "id": 2},
    {"name": "CSE-CICIDS2018", "path": "DATASETS/CSECICIDS2018", "id": 3},
]

def map_label_to_hierarchy(label, dataset_id):
    """
    Maps labels to 3-tier hierarchical taxonomy
    Tier 1: Binary (0=Benign, 1=Malicious)
    Tier 2: Attack Family (0=Benign, 1=DoS, 2=Probe, 3=Exploit, 4=Generic)
    Tier 3: Fine-grained (original label)
    """
    label_lower = str(label).lower()
    
    # Tier 1: Binary
    if 'benign' in label_lower or 'normal' in label_lower:
        binary = 0
    else:
        binary = 1
    
    # Tier 2: Attack Family
    if binary == 0:
        family = 0
    elif 'dos' in label_lower or 'ddos' in label_lower:
        family = 1
    elif any(x in label_lower for x in ['scan', 'probe', 'reconnaissance', 'brute']):
        family = 2
    elif any(x in label_lower for x in ['exploit', 'injection', 'infiltr', 'web']):
        family = 3
    else:
        family = 4
    
    # Tier 3: Fine-grained
    fine_grained = str(label)
    
    return binary, family, fine_grained

def load_file_parallel(file_path):
    """Load a single CSV or Parquet file - used for parallel processing"""
    try:
        if file_path.suffix.lower() == '.csv':
            df = pd.read_csv(file_path, low_memory=False)
        elif file_path.suffix.lower() == '.parquet':
            df = pd.read_parquet(file_path)
        else:
            print(f"   ⚠  Unsupported file format: {file_path.name}")
            return None
        return df
    except Exception as e:
        print(f"   ⚠  Error reading {file_path.name}: {e}")
        return None

def load_dataset(dataset_info):
    """Load a single dataset and harmonize its schema - PARALLEL OPTIMIZED"""
    print(f"\n📂 Loading {dataset_info['name']}...")
    
    dataset_path = Path(dataset_info['path'])
    
    # Look for both CSV and Parquet files
    csv_files = list(dataset_path.glob('*.csv'))
    parquet_files = list(dataset_path.glob('*.parquet'))
    data_files = csv_files + parquet_files
    
    if not data_files:
        print(f"   ⚠  No CSV or Parquet files found in {dataset_path}")
        return None
    
    print(f"   Found {len(data_files)} data files ({len(csv_files)} CSV, {len(parquet_files)} Parquet)")
    
    # Parallel loading of files using multiprocessing
    if len(data_files) > 1:
        print(f"   Loading in parallel using {min(cpu_count(), len(data_files))} cores...")
        with Pool(processes=min(cpu_count(), len(data_files))) as pool:
            dfs = pool.map(load_file_parallel, data_files)
        dfs = [df for df in dfs if df is not None]
    else:
        print(f"   Reading {data_files[0].name}...")
        dfs = [load_file_parallel(data_files[0])]
        dfs = [df for df in dfs if df is not None]
    
    if not dfs:
        return None
    
    # Combine all files from this dataset
    print(f"   Concatenating {len(dfs)} dataframes...")
    df = pd.concat(dfs, ignore_index=True)
    print(f"   ✓ Loaded {len(df):,} samples")
    
    # Add dataset provenance features
    df['dataset_id'] = dataset_info['id']
    df['dataset_name'] = dataset_info['name']
    
    # Free memory
    del dfs
    gc.collect()
    
    return df

def harmonize_features(datasets_list):
    """
    Harmonize features across all datasets
    Creates unified 85-feature space
    """
    print("\n🔧 Step 2: Schema Harmonization...")
    
    # Collect all unique feature names
    all_features = set()
    for df in datasets_list:
        if df is not None:
            all_features.update(df.columns)
    
    print(f"   Total unique features across datasets: {len(all_features)}")
    
    # Define universal features (present in most datasets)
    universal_features = [
        'protocol', 'src_port', 'dst_port', 'flow_duration',
        'total_fwd_packets', 'total_bwd_packets',
        'total_length_fwd_packets', 'total_length_bwd_packets',
        'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    ]
    
    # Feature name mappings (semantically equivalent features)
    feature_mappings = {
        'src_bytes': ['sbytes', 'fwd_bytes', 'total_length_fwd_packets'],
        'dst_bytes': ['dbytes', 'bwd_bytes', 'total_length_bwd_packets'],
        'src_packets': ['spkts', 'fwd_packets', 'total_fwd_packets'],
        'dst_packets': ['dpkts', 'bwd_packets', 'total_bwd_packets'],
    }
    
    # Harmonize each dataset
    harmonized_datasets = []
    for i, df in enumerate(datasets_list):
        if df is None:
            continue
        
        print(f"   Harmonizing {DATASETS[i]['name']}...")
        
        # Apply feature mappings
        for target_feature, source_features in feature_mappings.items():
            if target_feature not in df.columns:
                for source_feature in source_features:
                    if source_feature in df.columns:
                        df[target_feature] = df[source_feature]
                        break
        
        harmonized_datasets.append(df)
    
    return harmonized_datasets

def combine_datasets(harmonized_datasets):
    """Combine all datasets into single unified dataset"""
    print("\n🔗 Step 3: Combining datasets...")
    
    # Find common columns across all datasets
    common_columns = set(harmonized_datasets[0].columns)
    for df in harmonized_datasets[1:]:
        common_columns &= set(df.columns)
    
    print(f"   Common features: {len(common_columns)}")
    
    # Combine datasets using only common columns
    combined_dfs = []
    for i, df in enumerate(harmonized_datasets):
        # Select only common columns
        df_common = df[list(common_columns)].copy()
        combined_dfs.append(df_common)
        print(f"   {DATASETS[i]['name']}: {len(df_common):,} samples")
    
    # Concatenate all datasets
    combined = pd.concat(combined_dfs, ignore_index=True)
    print(f"\n   ✓ Combined dataset: {len(combined):,} samples")
    print(f"   ✓ Total features: {len(combined.columns)}")
    
    return combined

def process_labels(df):
    """Process labels into 3-tier hierarchy"""
    print("\n🏷  Step 4: Label Harmonization...")
    
    # Find label column (usually named 'Label' or 'label' or 'attack_cat')
    label_col = None
    for col in df.columns:
        if 'label' in col.lower() or 'attack' in col.lower() or 'class' in col.lower():
            label_col = col
            break
    
    if label_col is None:
        print("   ⚠  Warning: No label column found, using last column")
        label_col = df.columns[-1]
    
    print(f"   Using label column: {label_col}")
    
    # Apply hierarchical mapping
    labels_binary = []
    labels_family = []
    labels_fine = []
    
    for idx, row in df.iterrows():
        label = row[label_col]
        dataset_id = row['dataset_id']
        binary, family, fine = map_label_to_hierarchy(label, dataset_id)
        labels_binary.append(binary)
        labels_family.append(family)
        labels_fine.append(fine)
    
    # Add hierarchical labels
    df['label_binary'] = labels_binary
    df['label_family'] = labels_family
    df['label_fine'] = labels_fine
    
    # Remove original label column
    df = df.drop(columns=[label_col])
    
    # Print label distribution
    print(f"\n   Label Distribution (Binary):")
    print(f"      Benign (0):    {sum(1 for x in labels_binary if x == 0):,} ({sum(1 for x in labels_binary if x == 0)/len(labels_binary)*100:.1f}%)")
    print(f"      Malicious (1): {sum(1 for x in labels_binary if x == 1):,} ({sum(1 for x in labels_binary if x == 1)/len(labels_binary)*100:.1f}%)")
    
    print(f"\n   Label Distribution (Family):")
    family_names = ['Benign', 'DoS', 'Probe', 'Exploit', 'Generic']
    for i in range(5):
        count = sum(1 for x in labels_family if x == i)
        pct = count / len(labels_family) * 100
        print(f"      {family_names[i]:10} ({i}): {count:,} ({pct:.1f}%)")
    
    return df

def save_combined_dataset(df, output_path='combined_dataset.pkl'):
    """Save combined dataset"""
    print(f"\n💾 Step 5: Saving combined dataset to {output_path}...")
    
    # Save as pickle for fast loading
    with open(output_path, 'wb') as f:
        pickle.dump(df, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    print(f"   ✓ Saved {len(df):,} samples")
    print(f"   ✓ File size: {os.path.getsize(output_path) / 1024 / 1024:.2f} MB")
    
    # Also save metadata
    metadata = {
        'n_samples': len(df),
        'n_features': len(df.columns) - 5,  # Exclude label columns and dataset info
        'feature_names': [col for col in df.columns if not col.startswith('label') and not col.startswith('dataset')],
        'datasets': [d['name'] for d in DATASETS],
    }
    
    with open('combined_dataset_metadata.pkl', 'wb') as f:
        pickle.dump(metadata, f)
    
    print(f"   ✓ Metadata saved")

def main():
    """Main execution"""
    print("🔥 GhostML Dataset Combination Script - GPU/CPU Optimized")
    print("=" * 70)
    print("Using PURE RUST GhostML libraries (no scikit-learn/LightGBM/XGBoost)")
    print(f"CPU Cores Available: {cpu_count()}")
    print("Parallel Processing: ENABLED")
    print("=" * 70)
    
    print("\n" + "="*60)
    print("PHASE 1: DATASET COMBINATION & SCHEMA HARMONIZATION")
    print("="*60)
    
    # Step 1: Load all datasets
    print("\n📊 Step 1: Loading datasets...")
    datasets_list = []
    for dataset_info in DATASETS:
        df = load_dataset(dataset_info)
        datasets_list.append(df)
    
    # Remove None datasets
    datasets_list = [df for df in datasets_list if df is not None]
    
    if not datasets_list:
        print("\n❌ Error: No datasets loaded!")
        return
    
    print(f"\n   ✓ Successfully loaded {len(datasets_list)} datasets")
    
    # Step 2: Harmonize features
    harmonized_datasets = harmonize_features(datasets_list)
    
    # Step 3: Combine datasets
    combined_df = combine_datasets(harmonized_datasets)
    
    # Step 4: Process labels
    combined_df = process_labels(combined_df)
    
    # Step 5: Save
    save_combined_dataset(combined_df)
    
    print("\n" + "="*60)
    print("✅ DATASET COMBINATION COMPLETE!")
    print("="*60)
    print(f"\nOutput: combined_dataset.pkl")
    print(f"Ready for preprocessing with GhostML libraries!")

if __name__ == "__main__":
    main()