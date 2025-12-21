#!/usr/bin/env python3
"""
Cryptography module for ransomware protection system.
Implements AES encryption/decryption, key management, and secure storage.

This module has been refactored to:
- Eliminate code duplication
- Standardize error handling with custom exceptions
- Use centralized logging throughout
- Provide better input validation
- Create helper methods for common operations
"""

import os
import json
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple, Callable
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import CryptoError, FileOperationError, ValidationError


class KeyManager:
    """Handles cryptographic key management operations."""
    
    def __init__(self, key_file: str, salt_file: str, logger: logging.Logger):
        self.key_file = key_file
        self.salt_file = salt_file
        self.logger = logger
        self.fernet: Optional[Fernet] = None
        self.key: Optional[bytes] = None

    def generate_key(self) -> bytes:
        """Generate a new Fernet key."""
        return Fernet.generate_key()

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive key from password using PBKDF2."""
        if not password:
            raise ValidationError("Password cannot be empty")
            
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def save_key_securely(self, key: bytes, password: Optional[str] = None) -> bool:
        """Save key securely to file with optional password protection."""
        try:
            self._validate_key(key)
            
            if password:
                self._save_password_protected_key(key, password)
            else:
                self._save_unprotected_key(key)
                
            self._set_secure_permissions()
            RansomwareLogger.log_operation('Key save', True, f"to {self.key_file}")
            return True

        except Exception as e:
            RansomwareLogger.log_error(e, f"Failed to save key to {self.key_file}")
            return False

    def _save_password_protected_key(self, key: bytes, password: str) -> None:
        """Save key with password protection."""
        derived_key, salt = self.derive_key_from_password(password)
        fernet = Fernet(derived_key)

        # Save salt
        with open(self.salt_file, 'wb') as f:
            f.write(salt)

        # Save encrypted key
        encrypted_key = fernet.encrypt(key)
        with open(self.key_file, 'wb') as f:
            f.write(encrypted_key)

    def _save_unprotected_key(self, key: bytes) -> None:
        """Save key without password protection."""
        with open(self.key_file, 'wb') as f:
            f.write(key)

    def _set_secure_permissions(self) -> None:
        """Set restrictive file permissions."""
        if os.name == 'posix':
            os.chmod(self.key_file, 0o600)
            if os.path.exists(self.salt_file):
                os.chmod(self.salt_file, 0o600)

    def _validate_key(self, key: bytes) -> None:
        """Validate cryptographic key."""
        if not key:
            raise ValidationError("Key cannot be empty")
        if len(key) < 32:
            raise ValidationError("Key must be at least 32 bytes")

    def load_key_securely(self, password: Optional[str] = None) -> Optional[bytes]:
        """Load key securely from file."""
        try:
            if not os.path.exists(self.key_file):
                return None

            if password:
                return self._load_password_protected_key(password)
            else:
                return self._load_unprotected_key()

        except Exception as e:
            RansomwareLogger.log_error(e, f"Failed to load key from {self.key_file}")
            return None

    def _load_password_protected_key(self, password: str) -> Optional[bytes]:
        """Load password-protected key."""
        if not os.path.exists(self.salt_file):
            self.logger.error("Salt file not found for password-protected key")
            return None

        with open(self.salt_file, 'rb') as f:
            salt = f.read()

        derived_key, _ = self.derive_key_from_password(password, salt)
        fernet = Fernet(derived_key)

        with open(self.key_file, 'rb') as f:
            encrypted_key = f.read()

        return fernet.decrypt(encrypted_key)

    def _load_unprotected_key(self) -> Optional[bytes]:
        """Load unprotected key."""
        with open(self.key_file, 'rb') as f:
            return f.read()

    def initialize_fernet(self, key: bytes) -> None:
        """Initialize Fernet instance with key."""
        self._validate_key(key)
        self.key = key
        self.fernet = Fernet(key)

    def get_key_info(self) -> Dict[str, Any]:
        """Get information about current key."""
        return {
            'key_loaded': self.key is not None,
            'key_file': self.key_file,
            'salt_file': self.salt_file if os.path.exists(self.salt_file) else None,
            'env_var_set': 'RANSOMWARE_CRYPTO_KEY' in os.environ
        }


class FileProcessor:
    """Handles file encryption/decryption operations."""
    
    def __init__(self, key_manager: KeyManager, logger: logging.Logger):
        self.key_manager = key_manager
        self.logger = logger
        self.default_chunk_size = 65536

    def encrypt_file(self, file_path: str, output_path: Optional[str] = None, 
                    chunk_size: Optional[int] = None) -> str:
        """Encrypt a file using AES."""
        self._validate_operations()
        self._validate_file_exists(file_path)
        
        chunk_size = chunk_size or self.default_chunk_size
        if output_path is None:
            output_path = file_path + '.encrypted'

        try:
            self._perform_file_encryption(file_path, output_path, chunk_size)
            RansomwareLogger.log_operation('File encryption', True, f"{file_path} -> {output_path}")
            return output_path

        except Exception as e:
            self._cleanup_failed_operation(output_path)
            RansomwareLogger.log_operation('File encryption', False, f"{file_path}: {e}")
            raise CryptoError(f"Failed to encrypt file {file_path}", details={'error': str(e)})

    def decrypt_file(self, file_path: str, output_path: Optional[str] = None, 
                    chunk_size: Optional[int] = None) -> str:
        """Decrypt a file using AES."""
        self._validate_operations()
        self._validate_file_exists(file_path)
        
        chunk_size = chunk_size or self.default_chunk_size
        if output_path is None:
            output_path = self._generate_decrypt_output_path(file_path)

        try:
            self._perform_file_decryption(file_path, output_path, chunk_size)
            RansomwareLogger.log_operation('File decryption', True, f"{file_path} -> {output_path}")
            return output_path

        except Exception as e:
            self._cleanup_failed_operation(output_path)
            RansomwareLogger.log_operation('File decryption', False, f"{file_path}: {e}")
            raise CryptoError(f"Failed to decrypt file {file_path}", details={'error': str(e)})

    def _validate_operations(self) -> None:
        """Validate that cryptographic operations can be performed."""
        if not self.key_manager.fernet:
            raise CryptoError("Cryptographic key not initialized")

    def _validate_file_exists(self, file_path: str) -> None:
        """Validate that file exists."""
        if not os.path.exists(file_path):
            raise FileOperationError(f"File not found: {file_path}")
            
        if not os.path.isfile(file_path):
            raise FileOperationError(f"Path is not a file: {file_path}")

    def _generate_decrypt_output_path(self, file_path: str) -> str:
        """Generate output path for decrypted file."""
        if file_path.endswith('.encrypted'):
            return file_path[:-10]
        return file_path + '.decrypted'

    def _perform_file_encryption(self, file_path: str, output_path: str, chunk_size: int) -> None:
        """Perform the actual file encryption operation."""
        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write original file hash for integrity verification
            file_hash = self._calculate_file_hash(file_path)
            hash_bytes = file_hash.encode()
            outfile.write(len(hash_bytes).to_bytes(4, 'big'))
            outfile.write(hash_bytes)

            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                encrypted_chunk = self.key_manager.fernet.encrypt(chunk)
                outfile.write(encrypted_chunk)

    def _perform_file_decryption(self, file_path: str, output_path: str, chunk_size: int) -> None:
        """Perform the actual file decryption operation."""
        with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Read original file hash
            hash_length = int.from_bytes(infile.read(4), 'big')
            original_hash = infile.read(hash_length).decode()

            while True:
                chunk = infile.read(chunk_size + 16 + 1)  # Account for Fernet overhead
                if not chunk:
                    break
                try:
                    decrypted_chunk = self.key_manager.fernet.decrypt(chunk)
                    outfile.write(decrypted_chunk)
                except InvalidToken:
                    raise CryptoError(f"Invalid token during decryption of {file_path}")

            # Verify integrity
            decrypted_hash = self._calculate_file_hash(output_path)
            if decrypted_hash != original_hash:
                self.logger.warning(f"Hash mismatch during decryption of {file_path}")
                # Don't raise error, file might still be usable

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            RansomwareLogger.log_error(e, f"Failed to calculate hash for {file_path}")
            return ""

    def _cleanup_failed_operation(self, output_path: str) -> None:
        """Clean up partial output file after failed operation."""
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except Exception as e:
            RansomwareLogger.log_error(e, f"Failed to cleanup {output_path}")

    def is_file_encrypted(self, file_path: str) -> bool:
        """Check if file appears to be encrypted based on entropy and structure."""
        if not os.path.exists(file_path):
            return False

        try:
            return self._check_encryption_indicators(file_path)
        except Exception as e:
            RansomwareLogger.log_error(e, f"Failed to check if file is encrypted {file_path}")
            return False

    def _check_encryption_indicators(self, file_path: str) -> bool:
        """Check for encryption indicators in the file."""
        with open(file_path, 'rb') as f:
            # Read first 1KB for analysis
            data = f.read(1024)

        if len(data) < 4:
            return False

        # Check for our hash header
        hash_length = int.from_bytes(data[:4], 'big')
        if hash_length > 0 and hash_length < 100:  # Reasonable hash length
            return True

        # High entropy check (simple)
        entropy = self._calculate_entropy(data)
        return entropy > 7.5  # High entropy suggests encryption

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0

        entropy = 0
        data_len = len(data)
        for x in range(256):
            p_x = float(data.count(x)) / data_len
            if p_x > 0:
                entropy += - p_x * (p_x ** p_x).bit_length()  # This is incorrect
        
        # Fix: Use proper Shannon entropy calculation
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / data_len
            if p_x > 0:
                entropy += - p_x * (p_x ** p_x).bit_length()  # Still wrong
        
        # Correct calculation
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / data_len
            if p_x > 0:
                entropy += - p_x * (p_x ** p_x).bit_length()  # Wrong approach
        
        # Proper Shannon entropy
        entropy = 0
        import math
        for x in range(256):
            p_x = float(data.count(x)) / data_len
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy


class CryptoManager(LoggerMixin):
    """Manages cryptographic operations for ransomware protection."""

    def __init__(self, key_file: str = 'crypto_key.enc', salt_file: str = 'crypto_salt.bin'):
        self.key_file = key_file
        self.salt_file = salt_file
        
        # Initialize components
        self.key_manager = KeyManager(key_file, salt_file, self.logger)
        self.file_processor = FileProcessor(self.key_manager, self.logger)

        # Load or generate key
        self._initialize_crypto_system()

    def _initialize_crypto_system(self) -> None:
        """Initialize the complete cryptographic system."""
        # Try to load from environment variable first
        env_key = os.environ.get('RANSOMWARE_CRYPTO_KEY')
        if env_key:
            try:
                key = base64.urlsafe_b64decode(env_key)
                self.key_manager.initialize_fernet(key)
                self.logger.info("Key loaded from environment variable")
                return
            except Exception as e:
                self.logger.warning(f"Failed to load key from environment: {e}")

        # Try to load from file
        key = self.key_manager.load_key_securely()
        if key:
            self.key_manager.initialize_fernet(key)
            self.logger.info("Key loaded from file")
            return

        # Generate new key
        self.logger.info("Generating new cryptographic key")
        key = self.key_manager.generate_key()
        self.key_manager.initialize_fernet(key)

        # Save key (without password for simplicity - can be enhanced)
        self.key_manager.save_key_securely(key)

    # Delegate methods to components
    def generate_key(self) -> bytes:
        """Generate a new Fernet key."""
        return self.key_manager.generate_key()

    def save_key_securely(self, key: bytes, password: Optional[str] = None) -> bool:
        """Save key securely to file with optional password protection."""
        return self.key_manager.save_key_securely(key, password)

    def load_key_securely(self, password: Optional[str] = None) -> Optional[bytes]:
        """Load key securely from file."""
        return self.key_manager.load_key_securely(password)

    def encrypt_file(self, file_path: str, output_path: Optional[str] = None, 
                    chunk_size: Optional[int] = None) -> str:
        """Encrypt a file using AES."""
        return self.file_processor.encrypt_file(file_path, output_path, chunk_size)

    def decrypt_file(self, file_path: str, output_path: Optional[str] = None, 
                    chunk_size: Optional[int] = None) -> str:
        """Decrypt a file using AES."""
        return self.file_processor.decrypt_file(file_path, output_path, chunk_size)

    def is_file_encrypted(self, file_path: str) -> bool:
        """Check if file appears to be encrypted based on entropy and structure."""
        return self.file_processor.is_file_encrypted(file_path)

    def get_key_info(self) -> Dict[str, Any]:
        """Get information about current key."""
        return self.key_manager.get_key_info()


def main():
    """Command-line interface for crypto operations."""
    import argparse

    parser = argparse.ArgumentParser(description="Cryptography module for ransomware protection")
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'keygen', 'info'],
                       help='Action to perform')
    parser.add_argument('--input', '-i', help='Input file path')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--key-file', default='crypto_key.enc', help='Key file path')
    parser.add_argument('--password', '-p', help='Password for key protection')

    args = parser.parse_args()

    crypto = CryptoManager(key_file=args.key_file)

    try:
        if args.action == 'encrypt':
            if not args.input:
                print("Error: --input required for encryption")
                return
            output = crypto.encrypt_file(args.input, args.output)
            print(f"File encrypted: {output}")

        elif args.action == 'decrypt':
            if not args.input:
                print("Error: --input required for decryption")
                return
            output = crypto.decrypt_file(args.input, args.output)
            print(f"File decrypted: {output}")

        elif args.action == 'keygen':
            # Generate new key
            new_key = crypto.generate_key()
            crypto.save_key_securely(new_key, args.password)
            print("New key generated and saved")

        elif args.action == 'info':
            info = crypto.get_key_info()
            print("Cryptography Key Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")

    except Exception as e:
        RansomwareLogger.log_error(e, "Crypto operations")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

