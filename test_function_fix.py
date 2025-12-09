#!/usr/bin/env python3
"""
Test function extraction with the new adaptive retry logic.
Run this to verify the fix works correctly.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.tools.angr_functions import angr_extract_functions
from src.utils.logger import get_logger

logger = get_logger(__name__)


def test_function_extraction(binary_path: str):
    """Test function extraction with various complexity thresholds."""
    
    print("=" * 80)
    print(f"Testing function extraction: {binary_path}")
    print("=" * 80)
    
    # Test 1: Default threshold (should use blob detection logic)
    print("\n[TEST 1] Default threshold (auto-detected):")
    print("-" * 80)
    result1 = angr_extract_functions(binary_path, limit=100, min_complexity=None)
    
    if 'error' in result1:
        print(f"❌ Error: {result1['error']}")
    else:
        print(f"✅ Total functions in binary: {result1.get('total_functions', 'N/A')}")
        print(f"✅ Functions extracted: {len(result1.get('functions', []))}")
        print(f"✅ Filtered count: {result1.get('filtered_count', 0)}")
        print(f"✅ Complexity threshold: {result1.get('min_complexity_threshold', 'N/A')}")
        print(f"✅ Adaptive retry: {result1.get('adaptive_retry', False)}")
        
        if result1.get('functions'):
            print(f"\n📊 Top 5 functions by complexity:")
            for i, func in enumerate(result1['functions'][:5], 1):
                print(f"  {i}. {func['name']} - Complexity: {func['cyclomatic_complexity']} - Size: {func['size']} bytes")
    
    # Test 2: Explicit low threshold
    print("\n[TEST 2] Explicit low threshold (min_complexity=2):")
    print("-" * 80)
    result2 = angr_extract_functions(binary_path, limit=100, min_complexity=2)
    
    if 'error' in result2:
        print(f"❌ Error: {result2['error']}")
    else:
        print(f"✅ Functions extracted: {len(result2.get('functions', []))}")
        print(f"✅ Complexity threshold: {result2.get('min_complexity_threshold', 'N/A')}")
    
    # Test 3: High threshold (should trigger adaptive retry for blob binaries)
    print("\n[TEST 3] High threshold (min_complexity=10, should trigger retry for blobs):")
    print("-" * 80)
    result3 = angr_extract_functions(binary_path, limit=100, min_complexity=10)
    
    if 'error' in result3:
        print(f"❌ Error: {result3['error']}")
    else:
        print(f"✅ Functions extracted: {len(result3.get('functions', []))}")
        print(f"✅ Complexity threshold: {result3.get('min_complexity_threshold', 'N/A')}")
        print(f"✅ Adaptive retry: {result3.get('adaptive_retry', False)}")
    
    print("\n" + "=" * 80)
    print("Testing complete!")
    print("=" * 80)
    
    return result1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_function_fix.py <binary_path>")
        print("\nExample:")
        print("  python test_function_fix.py Data/P_2_S_8.bin")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"❌ Error: File not found: {binary_path}")
        sys.exit(1)
    
    test_function_extraction(binary_path)
