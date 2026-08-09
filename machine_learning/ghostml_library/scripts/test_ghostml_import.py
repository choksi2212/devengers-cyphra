"""
Test script to verify GhostML import
"""
import sys
import os

# Add GhostML path
ghostml_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ghost-python', 'ghostml'))
print(f"Adding to sys.path: {ghostml_path}")
print(f"Path exists: {os.path.exists(ghostml_path)}")

# Check for .pyd file
pyd_file = os.path.join(ghostml_path, 'ghostml.cp313-win_amd64.pyd')
print(f"\nLooking for: {pyd_file}")
print(f"File exists: {os.path.exists(pyd_file)}")

# List files in directory
print(f"\nFiles in {ghostml_path}:")
for item in os.listdir(ghostml_path):
    if item.endswith('.pyd') or item.endswith('.py'):
        full_path = os.path.join(ghostml_path, item)
        size = os.path.getsize(full_path) / 1024
        print(f"  - {item} ({size:.2f} KB)")

# Add to path and try import
sys.path.insert(0, ghostml_path)
print(f"\nsys.path[0]: {sys.path[0]}")

try:
    import ghostml
    print("\n✅ SUCCESS: GhostML imported!")
    print(f"   Module: {ghostml}")
    print(f"   File: {ghostml.__file__ if hasattr(ghostml, '__file__') else 'N/A'}")
    
    # Try to access some attributes
    if hasattr(ghostml, '__version__'):
        print(f"   Version: {ghostml.__version__}")
    
    # List available functions/classes
    print("\n   Available items:")
    for item in dir(ghostml):
        if not item.startswith('_'):
            print(f"      - {item}")
            
except ImportError as e:
    print(f"\n❌ ERROR: Could not import ghostml")
    print(f"   Error: {e}")
    print(f"\n   Python version: {sys.version}")
    print(f"   Expected: Python 3.13 (cp313)")

