"""
Dataset Merge Script - Final Step (Memory Optimized)
Merges Part 1 (ISCXVPN2016 + UNSW-NB15) with Part 2 (CICIDS2017 + CSE-CICIDS2018)
Creates final unified dataset with all 4 datasets
"""

import numpy as np
import pandas as pd
import os
import pickle
import gc

def load_part(part_num):
    """Load a part dataset"""
    filename = f'combined_dataset_part{part_num}.pkl'
    metadata_filename = f'combined_dataset_part{part_num}_metadata.pkl'
    
    print(f"\n📂 Loading Part {part_num}...")
    
    if not os.path.exists(filename):
        print(f"   ❌ Error: {filename} not found!")
        print(f"   Please run 01{chr(96+part_num)}_combine_datasets_part{part_num}.py first")
        return None, None
    
    # Load metadata first
    with open(metadata_filename, 'rb') as f:
        metadata = pickle.load(f)
    
    print(f"   Metadata:")
    print(f"      Datasets: {', '.join(metadata['datasets'])}")
    print(f"      Samples: {metadata['n_samples']:,}")
    print(f"      Features: {metadata['n_features']}")
    print(f"      File size: {metadata['file_size_mb']:.2f} MB")
    
    # Load data
    with open(filename, 'rb') as f:
        df = pickle.load(f)
    
    print(f"   ✓ Loaded Part {part_num}: {len(df):,} samples")
    
    return df, metadata

def merge_parts(part1_df, part2_df):
    """Merge Part 1 and Part 2 datasets - KEEP ALL FEATURES"""
    print(f"\n🔗 Merging Part 1 + Part 2...")
    
    # Always keep label and dataset columns
    required_cols = ['dataset_id', 'dataset_name', 'label_binary', 'label_family', 'label_fine']
    
    # Get feature columns from both parts
    part1_features = set(part1_df.columns) - set(required_cols)
    part2_features = set(part2_df.columns) - set(required_cols)
    
    # Find common and unique features
    common_features = part1_features & part2_features
    part1_unique = part1_features - part2_features
    part2_unique = part2_features - part1_features
    
    print(f"   Part 1 features: {len(part1_features)}")
    print(f"   Part 2 features: {len(part2_features)}")
    print(f"   Common features: {len(common_features)}")
    print(f"   Part 1 unique: {len(part1_unique)}")
    print(f"   Part 2 unique: {len(part2_unique)}")
    
    # Combine ALL features (union, not intersection!)
    all_features = sorted(list(part1_features | part2_features))
    final_columns = required_cols + all_features
    
    print(f"   Total features in merged dataset: {len(all_features)}")
    print(f"   Merging datasets...")
    
    # Merge using concat with fill_value=0 for missing features
    # This is more memory efficient than adding columns then concatenating
    merged_df = pd.concat([part1_df, part2_df], ignore_index=True, sort=False)
    
    # Fill NaN values with 0 (for features that don't exist in one part)
    print(f"   Filling missing values with 0...")
    for col in all_features:
        if col in merged_df.columns:
            merged_df[col] = merged_df[col].fillna(0)
    
    # Reorder columns to ensure consistency
    merged_df = merged_df[final_columns]
    
    # Free original memory
    del part1_df, part2_df
    gc.collect()
    
    print(f"   ✓ Merged dataset: {len(merged_df):,} samples")
    print(f"   ✓ Total features: {len(all_features)}")
    
    return merged_df

def analyze_final_dataset(df):
    """Analyze and print statistics for final dataset"""
    print(f"\n📊 Final Dataset Analysis:")
    print(f"=" * 60)
    
    # Basic stats
    print(f"\n   Total Samples: {len(df):,}")
    print(f"   Total Features: {len(df.columns) - 5}")
    
    # Dataset distribution
    print(f"\n   Dataset Distribution:")
    for dataset_id in sorted(df['dataset_id'].unique()):
        dataset_name = df[df['dataset_id'] == dataset_id]['dataset_name'].iloc[0]
        count = (df['dataset_id'] == dataset_id).sum()
        pct = count / len(df) * 100
        print(f"      {dataset_name:15} (ID={dataset_id}): {count:,} ({pct:.1f}%)")
    
    # Binary label distribution
    print(f"\n   Binary Label Distribution:")
    benign_count = (df['label_binary'] == 0).sum()
    malicious_count = (df['label_binary'] == 1).sum()
    print(f"      Benign (0):    {benign_count:,} ({benign_count/len(df)*100:.1f}%)")
    print(f"      Malicious (1): {malicious_count:,} ({malicious_count/len(df)*100:.1f}%)")
    
    # Family label distribution
    print(f"\n   Family Label Distribution:")
    family_names = ['Benign', 'DoS', 'Probe', 'Exploit', 'Generic']
    for i in range(5):
        count = (df['label_family'] == i).sum()
        pct = count / len(df) * 100
        print(f"      {family_names[i]:10} ({i}): {count:,} ({pct:.1f}%)")
    
    # Fine-grained labels
    print(f"\n   Fine-grained Labels:")
    unique_labels = df['label_fine'].unique()
    print(f"      Total unique attack types: {len(unique_labels)}")
    print(f"      Top 10 most common:")
    top_labels = df['label_fine'].value_counts().head(10)
    for label, count in top_labels.items():
        pct = count / len(df) * 100
        print(f"         {str(label)[:30]:30} {count:,} ({pct:.1f}%)")
    
    # Memory usage
    memory_mb = df.memory_usage(deep=True).sum() / 1024 / 1024
    print(f"\n   Memory Usage: {memory_mb:.2f} MB")
    
    # Data types
    print(f"\n   Data Types:")
    dtype_counts = df.dtypes.value_counts()
    for dtype, count in dtype_counts.items():
        print(f"      {dtype}: {count} columns")
    
    # Missing values
    missing_total = df.isnull().sum().sum()
    print(f"\n   Missing Values: {missing_total:,}")
    if missing_total > 0:
        print(f"      Columns with missing values:")
        missing_cols = df.columns[df.isnull().any()].tolist()
        for col in missing_cols[:10]:  # Show first 10
            missing_count = df[col].isnull().sum()
            missing_pct = missing_count / len(df) * 100
            print(f"         {col}: {missing_count:,} ({missing_pct:.2f}%)")

def save_final_dataset(df, output_path='combined_dataset_final.pkl'):
    """Save final combined dataset"""
    print(f"\n💾 Saving final dataset to {output_path}...")
    
    with open(output_path, 'wb') as f:
        pickle.dump(df, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    file_size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"   ✓ Saved {len(df):,} samples")
    print(f"   ✓ File size: {file_size_mb:.2f} MB")
    
    # Save metadata
    metadata = {
        'datasets': ['ISCXVPN2016', 'UNSW-NB15', 'CICIDS2017', 'CSE-CICIDS2018'],
        'n_samples': len(df),
        'n_features': len(df.columns) - 5,
        'feature_names': [col for col in df.columns if not col.startswith('label') and not col.startswith('dataset')],
        'label_columns': ['label_binary', 'label_family', 'label_fine'],
        'dataset_columns': ['dataset_id', 'dataset_name'],
        'file_size_mb': file_size_mb,
        'binary_distribution': {
            'benign': int((df['label_binary'] == 0).sum()),
            'malicious': int((df['label_binary'] == 1).sum()),
        },
        'family_distribution': {
            'benign': int((df['label_family'] == 0).sum()),
            'dos': int((df['label_family'] == 1).sum()),
            'probe': int((df['label_family'] == 2).sum()),
            'exploit': int((df['label_family'] == 3).sum()),
            'generic': int((df['label_family'] == 4).sum()),
        },
    }
    
    metadata_path = output_path.replace('.pkl', '_metadata.pkl')
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    
    print(f"   ✓ Metadata saved to {metadata_path}")
    
    return file_size_mb

def verify_label_correctness(df):
    """Verify that labels are correctly assigned"""
    print(f"\n🔍 Verifying Label Correctness...")
    
    errors = []
    
    # Check 1: Binary label consistency with family
    binary_0_should_be_family_0 = df[df['label_binary'] == 0]['label_family'].unique()
    if len(binary_0_should_be_family_0) != 1 or binary_0_should_be_family_0[0] != 0:
        errors.append("ERROR: Benign samples (binary=0) have non-zero family labels!")
    
    # Check 2: Malicious samples should have family 1-4
    malicious_families = df[df['label_binary'] == 1]['label_family'].unique()
    if 0 in malicious_families:
        errors.append("ERROR: Malicious samples (binary=1) have family=0 (benign)!")
    
    # Check 3: No null labels
    if df['label_binary'].isnull().any():
        errors.append(f"ERROR: {df['label_binary'].isnull().sum()} null binary labels found!")
    if df['label_family'].isnull().any():
        errors.append(f"ERROR: {df['label_family'].isnull().sum()} null family labels found!")
    if df['label_fine'].isnull().any():
        errors.append(f"ERROR: {df['label_fine'].isnull().sum()} null fine-grained labels found!")
    
    # Check 4: Label ranges
    if df['label_binary'].min() < 0 or df['label_binary'].max() > 1:
        errors.append(f"ERROR: Binary labels out of range [0,1]: [{df['label_binary'].min()}, {df['label_binary'].max()}]")
    if df['label_family'].min() < 0 or df['label_family'].max() > 4:
        errors.append(f"ERROR: Family labels out of range [0,4]: [{df['label_family'].min()}, {df['label_family'].max()}]")
    
    # Print results
    if errors:
        print(f"   ❌ Found {len(errors)} label errors:")
        for error in errors:
            print(f"      {error}")
        return False
    else:
        print(f"   ✅ All label checks passed!")
        print(f"      ✓ Binary labels: consistent")
        print(f"      ✓ Family labels: consistent")
        print(f"      ✓ Fine-grained labels: present")
        print(f"      ✓ No null values")
        print(f"      ✓ Label ranges: valid")
        return True

def main():
    """Main execution for merging all parts"""
    print("=" * 70)
    print("🔥 FINAL MERGE - Combining All 4 Datasets")
    print("=" * 70)
    
    # Load Part 1
    part1_df, part1_metadata = load_part(1)
    if part1_df is None:
        return
    
    # Load Part 2
    part2_df, part2_metadata = load_part(2)
    if part2_df is None:
        return
    
    # Merge parts
    final_df = merge_parts(part1_df, part2_df)
    
    # Verify labels
    labels_ok = verify_label_correctness(final_df)
    
    # Analyze final dataset
    analyze_final_dataset(final_df)
    
    # Save final dataset
    file_size = save_final_dataset(final_df, 'combined_dataset_final.pkl')
    
    # Final summary
    print(f"\n{'='*60}")
    print("✅ FINAL MERGE COMPLETE!")
    print(f"{'='*60}")
    print(f"\nOutput: combined_dataset_final.pkl ({file_size:.2f} MB)")
    print(f"Samples: {len(final_df):,}")
    print(f"Features: {len(final_df.columns) - 5}")
    print(f"Datasets: 4 (ISCXVPN2016, UNSW-NB15, CICIDS2017, CSE-CICIDS2018)")
    print(f"\nLabels: {'✅ VERIFIED' if labels_ok else '❌ ERRORS FOUND'}")
    print(f"\nNext: Run 02_preprocess_dataset.py for preprocessing with GhostML libraries!")

if __name__ == "__main__":
    main()

