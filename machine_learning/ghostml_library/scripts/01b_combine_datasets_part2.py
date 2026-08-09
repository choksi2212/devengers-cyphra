"""
Dataset Combination Script - PART 2 (Memory Optimized)
Processes CICIDS2017 and CSE-CICIDS2018 datasets
Uses chunk-based processing to minimize memory usage
"""

import numpy as np
import pandas as pd
import os
from pathlib import Path
import pickle
from multiprocessing import Pool, cpu_count
import gc

# Part 2 Datasets (larger CICIDS datasets)
DATASETS_PART2 = [
    {"name": "CICIDS2017", "path": "DATASETS/CICIDS2017", "id": 2},
    {"name": "CSE-CICIDS2018", "path": "DATASETS/CSECICIDS2018", "id": 3},
]

# Chunk size for processing (rows at a time)
CHUNK_SIZE = 50000

def map_label_to_hierarchy(label, dataset_id):
    """
    Maps labels to 3-tier hierarchical taxonomy
    Tier 1: Binary (0=Benign, 1=Malicious)
    Tier 2: Attack Family (0=Benign, 1=DoS, 2=Probe, 3=Exploit, 4=Generic)
    Tier 3: Fine-grained (original label)
    """
    label_lower = str(label).lower().strip()
    
    # Tier 1: Binary
    if any(x in label_lower for x in ['benign', 'normal', 'background']):
        binary = 0
    else:
        binary = 1
    
    # Tier 2: Attack Family
    if binary == 0:
        family = 0
    elif any(x in label_lower for x in ['dos', 'ddos', 'slowloris', 'hulk', 'goldeneye', 'hoic']):
        family = 1  # DoS Family
    elif any(x in label_lower for x in ['scan', 'probe', 'reconnaissance', 'brute', 'ftp-', 'ssh-']):
        family = 2  # Probe/Reconnaissance Family
    elif any(x in label_lower for x in ['exploit', 'injection', 'infiltr', 'web', 'xss', 'sql']):
        family = 3  # Exploit/Intrusion Family
    else:
        family = 4  # Generic/Other
    
    # Tier 3: Fine-grained (preserve original)
    fine_grained = str(label).strip()
    
    return binary, family, fine_grained

def detect_label_column(df):
    """Automatically detect the label column"""
    for col in df.columns:
        col_lower = col.lower()
        if any(x in col_lower for x in ['label', 'attack', 'class', 'category']):
            return col
    return df.columns[-1]

def load_file_with_chunks(file_path, dataset_info):
    """Load a file in chunks to minimize memory usage"""
    print(f"   Loading {file_path.name} in chunks...")
    
    chunks = []
    chunk_count = 0
    
    try:
        if file_path.suffix.lower() == '.csv':
            # Load CSV in chunks
            for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False, encoding='utf-8', on_bad_lines='skip'):
                chunk_count += 1
                # Add dataset provenance
                chunk['dataset_id'] = dataset_info['id']
                chunk['dataset_name'] = dataset_info['name']
                chunks.append(chunk)
                
                if chunk_count % 5 == 0:
                    print(f"      Loaded {chunk_count * CHUNK_SIZE:,} rows...")
        
        elif file_path.suffix.lower() == '.parquet':
            df = pd.read_parquet(file_path)
            df['dataset_id'] = dataset_info['id']
            df['dataset_name'] = dataset_info['name']
            chunks.append(df)
        
        else:
            print(f"      ⚠  Unsupported file format: {file_path.name}")
            return None
        
        # Concatenate chunks
        if chunks:
            df = pd.concat(chunks, ignore_index=True)
            print(f"      ✓ Loaded {len(df):,} rows total")
            
            # Free memory
            del chunks
            gc.collect()
            
            return df
        
    except Exception as e:
        print(f"      ⚠  Error reading {file_path.name}: {e}")
        return None
    
    return None

def load_dataset(dataset_info):
    """Load a single dataset with memory optimization"""
    print(f"\n📂 Loading {dataset_info['name']}...")
    
    dataset_path = Path(dataset_info['path'])
    
    if not dataset_path.exists():
        print(f"   ⚠  Path not found: {dataset_path}")
        return None
    
    # Find data files
    csv_files = list(dataset_path.glob('*.csv'))
    parquet_files = list(dataset_path.glob('*.parquet'))
    data_files = csv_files + parquet_files
    
    if not data_files:
        print(f"   ⚠  No CSV or Parquet files found in {dataset_path}")
        return None
    
    print(f"   Found {len(data_files)} data files ({len(csv_files)} CSV, {len(parquet_files)} Parquet)")
    
    # Load files one by one (memory efficient)
    all_dfs = []
    for file_path in data_files:
        df = load_file_with_chunks(file_path, dataset_info)
        if df is not None:
            all_dfs.append(df)
    
    if not all_dfs:
        return None
    
    # Combine files from this dataset
    print(f"   Combining {len(all_dfs)} files...")
    combined_df = pd.concat(all_dfs, ignore_index=True)
    print(f"   ✓ Total samples: {len(combined_df):,}")
    
    # Free memory
    del all_dfs
    gc.collect()
    
    return combined_df

def harmonize_columns(df, dataset_name):
    """Standardize column names for this dataset"""
    print(f"   Harmonizing column names for {dataset_name}...")
    
    # Column name mappings (dataset-specific)
    column_mappings = {
        # CICIDS specific mappings
        'flow_duration': 'duration',
        'total_fwd_packets': 'fwd_packets',
        'total_bwd_packets': 'bwd_packets',
        'total_length_fwd_packets': 'fwd_bytes',
        'total_length_bwd_packets': 'bwd_bytes',
        'fwd_packet_length_max': 'fwd_pkt_len_max',
        'fwd_packet_length_min': 'fwd_pkt_len_min',
        'fwd_packet_length_mean': 'fwd_pkt_len_mean',
        'fwd_packet_length_std': 'fwd_pkt_len_std',
        'bwd_packet_length_max': 'bwd_pkt_len_max',
        'bwd_packet_length_min': 'bwd_pkt_len_min',
        'bwd_packet_length_mean': 'bwd_pkt_len_mean',
        'bwd_packet_length_std': 'bwd_pkt_len_std',
        ' destination port': 'dst_port',
        ' source port': 'src_port',
        'source port': 'src_port',
        'destination port': 'dst_port',
    }
    
    # Apply mappings
    df.rename(columns=column_mappings, inplace=True)
    
    # Lowercase and strip all column names
    df.columns = [col.lower().strip() for col in df.columns]
    
    return df

def process_labels(df, dataset_name):
    """Process labels into 3-tier hierarchy"""
    print(f"   Processing labels for {dataset_name}...")
    
    # Detect label column
    label_col = detect_label_column(df)
    print(f"      Using label column: '{label_col}'")
    
    # Get dataset ID
    dataset_id = df['dataset_id'].iloc[0]
    
    # Apply hierarchical mapping (vectorized for speed)
    print(f"      Mapping labels to hierarchy...")
    
    results = [map_label_to_hierarchy(label, dataset_id) for label in df[label_col]]
    
    df['label_binary'] = [r[0] for r in results]
    df['label_family'] = [r[1] for r in results]
    df['label_fine'] = [r[2] for r in results]
    
    # Print label distribution
    print(f"\n      Label Distribution (Binary):")
    benign_count = (df['label_binary'] == 0).sum()
    malicious_count = (df['label_binary'] == 1).sum()
    print(f"         Benign (0):    {benign_count:,} ({benign_count/len(df)*100:.1f}%)")
    print(f"         Malicious (1): {malicious_count:,} ({malicious_count/len(df)*100:.1f}%)")
    
    print(f"\n      Label Distribution (Family):")
    family_names = ['Benign', 'DoS', 'Probe', 'Exploit', 'Generic']
    for i in range(5):
        count = (df['label_family'] == i).sum()
        pct = count / len(df) * 100
        print(f"         {family_names[i]:10} ({i}): {count:,} ({pct:.1f}%)")
    
    # Remove original label column
    df = df.drop(columns=[label_col])
    
    return df

def save_partial_dataset(df, output_path):
    """Save partial dataset"""
    print(f"\n💾 Saving to {output_path}...")
    
    with open(output_path, 'wb') as f:
        pickle.dump(df, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    file_size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"   ✓ Saved {len(df):,} samples")
    print(f"   ✓ File size: {file_size_mb:.2f} MB")
    
    return file_size_mb

def main():
    """Main execution for Part 2"""
    print("=" * 70)
    print("🔥 DATASET COMBINATION - PART 2 (Memory Optimized)")
    print("=" * 70)
    print("Processing: CICIDS2017 + CSE-CICIDS2018")
    print(f"CPU Cores: {cpu_count()}")
    print(f"Chunk Size: {CHUNK_SIZE:,} rows")
    print("=" * 70)
    
    all_datasets = []
    
    # Load and process each dataset
    for dataset_info in DATASETS_PART2:
        print(f"\n{'='*60}")
        print(f"PROCESSING: {dataset_info['name']}")
        print(f"{'='*60}")
        
        # Step 1: Load dataset
        df = load_dataset(dataset_info)
        
        if df is None:
            print(f"   ⚠  Skipping {dataset_info['name']}")
            continue
        
        # Step 2: Harmonize column names
        df = harmonize_columns(df, dataset_info['name'])
        
        # Step 3: Process labels
        df = process_labels(df, dataset_info['name'])
        
        # Step 4: Save individual dataset
        output_file = f"combined_part2_{dataset_info['name'].lower().replace('-', '_')}.pkl"
        save_partial_dataset(df, output_file)
        
        # Add to list
        all_datasets.append(df)
        
        # Free memory
        gc.collect()
    
    if not all_datasets:
        print("\n❌ Error: No datasets processed!")
        return
    
    # Combine Part 2 datasets
    print(f"\n{'='*60}")
    print("COMBINING PART 2 DATASETS")
    print(f"{'='*60}")
    
    # Find common columns
    common_columns = set(all_datasets[0].columns)
    for df in all_datasets[1:]:
        common_columns &= set(df.columns)
    
    common_columns = list(common_columns)
    print(f"\nCommon columns across Part 2: {len(common_columns)}")
    
    # Combine using only common columns
    combined_dfs = []
    for df in all_datasets:
        df_common = df[common_columns].copy()
        combined_dfs.append(df_common)
    
    combined_part2 = pd.concat(combined_dfs, ignore_index=True)
    
    print(f"\n✓ Combined Part 2: {len(combined_part2):,} samples")
    print(f"✓ Features: {len(combined_part2.columns) - 5}")  # Exclude labels and dataset info
    
    # Save combined Part 2
    file_size = save_partial_dataset(combined_part2, 'combined_dataset_part2.pkl')
    
    # Save metadata
    metadata = {
        'part': 2,
        'datasets': [d['name'] for d in DATASETS_PART2],
        'n_samples': len(combined_part2),
        'n_features': len(combined_part2.columns) - 5,
        'common_columns': common_columns,
        'file_size_mb': file_size,
    }
    
    with open('combined_dataset_part2_metadata.pkl', 'wb') as f:
        pickle.dump(metadata, f)
    
    print(f"\n{'='*60}")
    print("✅ PART 2 COMPLETE!")
    print(f"{'='*60}")
    print(f"\nOutput: combined_dataset_part2.pkl ({file_size:.2f} MB)")
    print(f"Samples: {len(combined_part2):,}")
    print(f"Features: {len(combined_part2.columns) - 5}")
    print(f"\nNext: Run 01c_merge_all_parts.py to combine Part 1 + Part 2")

if __name__ == "__main__":
    main()

