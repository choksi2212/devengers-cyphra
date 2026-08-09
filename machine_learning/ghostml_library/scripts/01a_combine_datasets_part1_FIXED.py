"""
Dataset Combination Script - PART 1 (Memory Optimized) - FIXED VERSION
Processes ISCXVPN2016 and UNSW-NB15 datasets with PROPER column harmonization
Uses chunk-based processing to minimize memory usage
"""

import numpy as np
import pandas as pd
import os
from pathlib import Path
import pickle
from multiprocessing import Pool, cpu_count
import gc

# Part 1 Datasets (smaller ones first)
DATASETS_PART1 = [
    {"name": "ISCXVPN2016", "path": "DATASETS/ISCXVPN2016", "id": 0},
    {"name": "UNSW-NB15", "path": "DATASETS/UNSWNB15", "id": 1},
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

def harmonize_columns_comprehensive(df, dataset_name):
    """
    COMPREHENSIVE column harmonization - maps ALL dataset-specific names to common names
    """
    print(f"   Harmonizing columns for {dataset_name}...")
    print(f"      Original columns: {len(df.columns)}")
    
    # First, lowercase and strip all column names
    df.columns = [col.lower().strip() for col in df.columns]
    
    # Define comprehensive column mappings
    if 'ISCXVPN2016' in dataset_name:
        # ISCXVPN2016 has spaces in column names - map to standard names
        column_mappings = {
            # Basic flow info
            'protocol': 'protocol',
            'src port': 'src_port',
            'dst port': 'dst_port',
            'flow duration': 'duration',
            
            # Packet counts
            'tot fwd pkts': 'fwd_packets',
            'tot bwd pkts': 'bwd_packets',
            
            # Byte counts
            'totlen fwd pkts': 'fwd_bytes',
            'totlen bwd pkts': 'bwd_bytes',
            
            # Packet lengths
            'fwd pkt len max': 'fwd_pkt_len_max',
            'fwd pkt len min': 'fwd_pkt_len_min',
            'fwd pkt len mean': 'fwd_pkt_len_mean',
            'fwd pkt len std': 'fwd_pkt_len_std',
            'bwd pkt len max': 'bwd_pkt_len_max',
            'bwd pkt len min': 'bwd_pkt_len_min',
            'bwd pkt len mean': 'bwd_pkt_len_mean',
            'bwd pkt len std': 'bwd_pkt_len_std',
            
            # IAT (Inter-Arrival Time)
            'flow iat mean': 'flow_iat_mean',
            'flow iat std': 'flow_iat_std',
            'flow iat max': 'flow_iat_max',
            'flow iat min': 'flow_iat_min',
            'fwd iat mean': 'fwd_iat_mean',
            'fwd iat std': 'fwd_iat_std',
            'fwd iat max': 'fwd_iat_max',
            'fwd iat min': 'fwd_iat_min',
            'bwd iat mean': 'bwd_iat_mean',
            'bwd iat std': 'bwd_iat_std',
            'bwd iat max': 'bwd_iat_max',
            'bwd iat min': 'bwd_iat_min',
            
            # Flags
            'fin flag cnt': 'fin_flag_count',
            'syn flag cnt': 'syn_flag_count',
            'rst flag cnt': 'rst_flag_count',
            'psh flag cnt': 'psh_flag_count',
            'ack flag cnt': 'ack_flag_count',
            'urg flag cnt': 'urg_flag_count',
            
            # Rates
            'flow byts/s': 'flow_bytes_per_sec',
            'flow pkts/s': 'flow_pkts_per_sec',
            'fwd pkts/s': 'fwd_pkts_per_sec',
            'bwd pkts/s': 'bwd_pkts_per_sec',
            
            # Other
            'pkt len min': 'pkt_len_min',
            'pkt len max': 'pkt_len_max',
            'pkt len mean': 'pkt_len_mean',
            'pkt len std': 'pkt_len_std',
        }
    
    elif 'UNSW-NB15' in dataset_name:
        # UNSW-NB15 has short names - map to standard names
        column_mappings = {
            # Basic
            'proto': 'protocol',
            'service': 'service',
            'state': 'state',
            'dur': 'duration',
            
            # Packets
            'spkts': 'src_packets',
            'dpkts': 'dst_packets',
            
            # Bytes
            'sbytes': 'src_bytes',
            'dbytes': 'dst_bytes',
            
            # Rates/Loads
            'rate': 'rate',
            'sload': 'src_load',
            'dload': 'dst_load',
            
            # Loss
            'sloss': 'src_loss',
            'dloss': 'dst_loss',
            
            # Inter-packet times
            'sinpkt': 'src_inter_pkt_time',
            'dinpkt': 'dst_inter_pkt_time',
            
            # Jitter
            'sjit': 'src_jitter',
            'djit': 'dst_jitter',
            
            # Window sizes
            'swin': 'src_win',
            'dwin': 'dst_win',
            'stcpb': 'src_tcp_base',
            'dtcpb': 'dst_tcp_base',
            
            # TTL
            'sttl': 'src_ttl',
            'dttl': 'dst_ttl',
            
            # Mean
            'smean': 'src_mean',
            'dmean': 'dst_mean',
        }
    else:
        column_mappings = {}
    
    # Apply mappings
    df.rename(columns=column_mappings, inplace=True)
    
    # Create universal features from mapped columns
    # Map src/dst variations to fwd/bwd
    if 'src_packets' in df.columns and 'fwd_packets' not in df.columns:
        df['fwd_packets'] = df['src_packets']
    if 'dst_packets' in df.columns and 'bwd_packets' not in df.columns:
        df['bwd_packets'] = df['dst_packets']
    if 'src_bytes' in df.columns and 'fwd_bytes' not in df.columns:
        df['fwd_bytes'] = df['src_bytes']
    if 'dst_bytes' in df.columns and 'bwd_bytes' not in df.columns:
        df['bwd_bytes'] = df['dst_bytes']
    
    print(f"      After harmonization: {len(df.columns)} columns")
    
    return df

def create_universal_features(df, dataset_name):
    """Create universal features that should exist across all datasets"""
    print(f"   Creating universal features for {dataset_name}...")
    
    # Create total_packets if not exists
    if 'total_packets' not in df.columns and 'fwd_packets' in df.columns and 'bwd_packets' in df.columns:
        df['total_packets'] = df['fwd_packets'] + df['bwd_packets']
    
    # Create total_bytes if not exists
    if 'total_bytes' not in df.columns and 'fwd_bytes' in df.columns and 'bwd_bytes' in df.columns:
        df['total_bytes'] = df['fwd_bytes'] + df['bwd_bytes']
    
    # Create fwd_bwd_packet_ratio
    if 'fwd_bwd_packet_ratio' not in df.columns and 'fwd_packets' in df.columns and 'bwd_packets' in df.columns:
        df['fwd_bwd_packet_ratio'] = df['fwd_packets'] / (df['bwd_packets'] + 1)
    
    # Create fwd_bwd_byte_ratio
    if 'fwd_bwd_byte_ratio' not in df.columns and 'fwd_bytes' in df.columns and 'bwd_bytes' in df.columns:
        df['fwd_bwd_byte_ratio'] = df['fwd_bytes'] / (df['bwd_bytes'] + 1)
    
    # Average packet size
    if 'avg_pkt_size' not in df.columns and 'total_bytes' in df.columns and 'total_packets' in df.columns:
        df['avg_pkt_size'] = df['total_bytes'] / (df['total_packets'] + 1)
    
    return df

def load_file_with_chunks(file_path, dataset_info):
    """Load a file in chunks to minimize memory usage"""
    print(f"   Loading {file_path.name} in chunks...")
    
    chunks = []
    chunk_count = 0
    
    try:
        if file_path.suffix.lower() == '.csv':
            for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False):
                chunk_count += 1
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
        
        if chunks:
            df = pd.concat(chunks, ignore_index=True)
            print(f"      ✓ Loaded {len(df):,} rows total")
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
    
    csv_files = list(dataset_path.glob('*.csv'))
    parquet_files = list(dataset_path.glob('*.parquet'))
    data_files = csv_files + parquet_files
    
    if not data_files:
        print(f"   ⚠  No CSV or Parquet files found in {dataset_path}")
        return None
    
    print(f"   Found {len(data_files)} data files ({len(csv_files)} CSV, {len(parquet_files)} Parquet)")
    
    all_dfs = []
    for file_path in data_files:
        df = load_file_with_chunks(file_path, dataset_info)
        if df is not None:
            all_dfs.append(df)
    
    if not all_dfs:
        return None
    
    print(f"   Combining {len(all_dfs)} files...")
    combined_df = pd.concat(all_dfs, ignore_index=True)
    print(f"   ✓ Total samples: {len(combined_df):,}")
    
    del all_dfs
    gc.collect()
    
    return combined_df

def process_labels(df, dataset_name):
    """Process labels into 3-tier hierarchy"""
    print(f"   Processing labels for {dataset_name}...")
    
    label_col = detect_label_column(df)
    print(f"      Using label column: '{label_col}'")
    
    dataset_id = df['dataset_id'].iloc[0]
    
    print(f"      Mapping labels to hierarchy...")
    results = [map_label_to_hierarchy(label, dataset_id) for label in df[label_col]]
    
    df['label_binary'] = [r[0] for r in results]
    df['label_family'] = [r[1] for r in results]
    df['label_fine'] = [r[2] for r in results]
    
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
    """Main execution for Part 1"""
    print("=" * 70)
    print("🔥 DATASET COMBINATION - PART 1 (FIXED - Proper Harmonization)")
    print("=" * 70)
    print("Processing: ISCXVPN2016 + UNSW-NB15")
    print(f"CPU Cores: {cpu_count()}")
    print(f"Chunk Size: {CHUNK_SIZE:,} rows")
    print("=" * 70)
    
    all_datasets = []
    
    for dataset_info in DATASETS_PART1:
        print(f"\n{'='*60}")
        print(f"PROCESSING: {dataset_info['name']}")
        print(f"{'='*60}")
        
        df = load_dataset(dataset_info)
        
        if df is None:
            print(f"   ⚠  Skipping {dataset_info['name']}")
            continue
        
        # Comprehensive column harmonization
        df = harmonize_columns_comprehensive(df, dataset_info['name'])
        
        # Create universal features
        df = create_universal_features(df, dataset_info['name'])
        
        # Process labels
        df = process_labels(df, dataset_info['name'])
        
        # Save individual dataset
        output_file = f"combined_part1_{dataset_info['name'].lower().replace('-', '_')}.pkl"
        save_partial_dataset(df, output_file)
        
        all_datasets.append(df)
        gc.collect()
    
    if not all_datasets:
        print("\n❌ Error: No datasets processed!")
        return
    
    print(f"\n{'='*60}")
    print("COMBINING PART 1 DATASETS")
    print(f"{'='*60}")
    
    # Find common columns
    common_columns = set(all_datasets[0].columns)
    for df in all_datasets[1:]:
        common_columns &= set(df.columns)
    
    common_columns = list(common_columns)
    print(f"\nCommon columns across Part 1: {len(common_columns)}")
    print(f"Common feature columns (excluding labels/dataset info):")
    feature_cols = [col for col in common_columns if not col.startswith('label') and not col.startswith('dataset')]
    print(f"   {len(feature_cols)} features: {feature_cols[:10]}..." if len(feature_cols) > 10 else f"   {feature_cols}")
    
    # Combine using only common columns
    combined_dfs = []
    for df in all_datasets:
        df_common = df[common_columns].copy()
        combined_dfs.append(df_common)
    
    combined_part1 = pd.concat(combined_dfs, ignore_index=True)
    
    print(f"\n✓ Combined Part 1: {len(combined_part1):,} samples")
    print(f"✓ Features: {len(combined_part1.columns) - 5}")
    
    file_size = save_partial_dataset(combined_part1, 'combined_dataset_part1.pkl')
    
    metadata = {
        'part': 1,
        'datasets': [d['name'] for d in DATASETS_PART1],
        'n_samples': len(combined_part1),
        'n_features': len(combined_part1.columns) - 5,
        'common_columns': common_columns,
        'feature_columns': feature_cols,
        'file_size_mb': file_size,
    }
    
    with open('combined_dataset_part1_metadata.pkl', 'wb') as f:
        pickle.dump(metadata, f)
    
    print(f"\n{'='*60}")
    print("✅ PART 1 COMPLETE!")
    print(f"{'='*60}")
    print(f"\nOutput: combined_dataset_part1.pkl ({file_size:.2f} MB)")
    print(f"Samples: {len(combined_part1):,}")
    print(f"Features: {len(combined_part1.columns) - 5}")
    print(f"\nNext: Run 01b_combine_datasets_part2.py for CICIDS2017 + CSE-CICIDS2018")

if __name__ == "__main__":
    main()

