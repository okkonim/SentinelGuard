#!/usr/bin/env python3
"""
Test script to simulate mass encryption attack for ransomware detection testing
"""

import os
import time
from crypto import CryptoManager

def test_mass_encryption():
    """Test mass encryption detection"""
    crypto = CryptoManager()

    # Get test files
    test_dir = "./test_ransomware"
    if not os.path.exists(test_dir):
        print("Test directory not found. Run 'python ransomware_protection_system.py test' first")
        return

    files = [os.path.join(test_dir, f) for f in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, f))]

    print(f"Starting mass encryption test with {len(files)} files...")

    # Encrypt files quickly to trigger mass encryption detection
    for i, file_path in enumerate(files):
        if not file_path.endswith('.encrypted'):
            print(f"Encrypting {file_path}...")
            crypto.encrypt_file(file_path)
            time.sleep(0.5)  # Small delay between encryptions

    print("Mass encryption test completed")

if __name__ == "__main__":
    test_mass_encryption()
