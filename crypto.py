#!/usr/bin/env python3
"""
Cryptography module for ransomware protection system
Implements AES encryption/decryption, key management, and secure storage
"""

import os
import json
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

class CryptoManager:
    """Manages cryptographic operations for ransomware protection"""

    def __init__(self, key_file='crypto_key.enc', salt_file='crypto_salt.bin'):
        self.key_file = key_file
        self.salt_file = salt_file
        self.fernet = None
        self.key = None

        # Load or generate key
        self.load_or_generate_key()

    def generate_key(self):
        """Generate a new Fernet key"""
        return Fernet.generate_key()

    def derive_key_from_password(self, password, salt=None):
        """Derive key from password using PBKDF2"""
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

    def save_key_securely(self, key, password=None):
        """Save key securely to file with optional password protection"""
        try:
            if password:
                # Encrypt key with password
                derived_key, salt = self.derive_key_from_password(password)
                fernet = Fernet(derived_key)

                # Save salt
                with open(self.salt_file, 'wb') as f:
                    f.write(salt)

                # Save encrypted key
                encrypted_key = fernet.encrypt(key)
                with open(self.key_file, 'wb') as f:
                    f.write(encrypted_key)
            else:
                # Save key directly (less secure)
                with open(self.key_file, 'wb') as f:
                    f.write(key)

            # Set restrictive permissions
            if os.name == 'posix':
                os.chmod(self.key_file, 0o600)
                if password:
                    os.chmod(self.salt_file, 0o600)

            logger.info(f"Key saved securely to {self.key_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save key: {e}")
            return False

    def load_key_securely(self, password=None):
        """Load key securely from file"""
        try:
            if not os.path.exists(self.key_file):
                return None

            if password:
                # Load encrypted key
                if not os.path.exists(self.salt_file):
                    logger.error("Salt file not found for password-protected key")
                    return None

                with open(self.salt_file, 'rb') as f:
                    salt = f.read()

                derived_key, _ = self.derive_key_from_password(password, salt)
                fernet = Fernet(derived_key)

                with open(self.key_file, 'rb') as f:
                    encrypted_key = f.read()

                key = fernet.decrypt(encrypted_key)
            else:
                # Load key directly
                with open(self.key_file, 'rb') as f:
                    key = f.read()

            return key

        except Exception as e:
            logger.error(f"Failed to load key: {e}")
            return None

    def load_or_generate_key(self):
        """Load existing key or generate new one"""
        # Try to load from environment variable first
        env_key = os.environ.get('RANSOMWARE_CRYPTO_KEY')
        if env_key:
            try:
                self.key = base64.urlsafe_b64decode(env_key)
                self.fernet = Fernet(self.key)
                logger.info("Key loaded from environment variable")
                return
            except Exception as e:
                logger.warning(f"Failed to load key from environment: {e}")

        # Try to load from file
        self.key = self.load_key_securely()
        if self.key:
            self.fernet = Fernet(self.key)
            logger.info("Key loaded from file")
            return

        # Generate new key
        logger.info("Generating new cryptographic key")
        self.key = self.generate_key()
        self.fernet = Fernet(self.key)

        # Save key (without password for simplicity - can be enhanced)
        self.save_key_securely(self.key)

    def encrypt_file(self, file_path, output_path=None, chunk_size=65536):
        """Encrypt a file using AES"""
        if not self.fernet:
            raise ValueError("Cryptographic key not initialized")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if output_path is None:
            output_path = file_path + '.encrypted'

        try:
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
                    encrypted_chunk = self.fernet.encrypt(chunk)
                    outfile.write(encrypted_chunk)

            logger.info(f"File encrypted: {file_path} -> {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to encrypt file {file_path}: {e}")
            # Clean up partial output file
            if os.path.exists(output_path):
                os.remove(output_path)
            raise

    def decrypt_file(self, file_path, output_path=None, chunk_size=65536):
        """Decrypt a file using AES"""
        if not self.fernet:
            raise ValueError("Cryptographic key not initialized")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if output_path is None:
            # Remove .encrypted extension if present
            if file_path.endswith('.encrypted'):
                output_path = file_path[:-10]
            else:
                output_path = file_path + '.decrypted'

        try:
            with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Read original file hash
                hash_length = int.from_bytes(infile.read(4), 'big')
                original_hash = infile.read(hash_length).decode()

                while True:
                    chunk = infile.read(chunk_size + 16 + 1)  # Account for Fernet overhead
                    if not chunk:
                        break
                    try:
                        decrypted_chunk = self.fernet.decrypt(chunk)
                        outfile.write(decrypted_chunk)
                    except InvalidToken:
                        logger.error(f"Invalid token during decryption of {file_path}")
                        raise ValueError("Invalid encryption key or corrupted file")

                # Verify integrity
                decrypted_hash = self._calculate_file_hash(output_path)
                if decrypted_hash != original_hash:
                    logger.warning(f"Hash mismatch during decryption of {file_path}")
                    # Don't raise error, file might still be usable

            logger.info(f"File decrypted: {file_path} -> {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to decrypt file {file_path}: {e}")
            # Clean up partial output file
            if os.path.exists(output_path):
                os.remove(output_path)
            raise

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""

    def is_file_encrypted(self, file_path):
        """Check if file appears to be encrypted based on entropy and structure"""
        if not os.path.exists(file_path):
            return False

        try:
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

        except Exception as e:
            logger.error(f"Failed to check if file is encrypted {file_path}: {e}")
            return False

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x ** p_x).bit_length()  # Approximation

        return entropy

    def get_key_info(self):
        """Get information about current key"""
        return {
            'key_loaded': self.key is not None,
            'key_file': self.key_file,
            'salt_file': self.salt_file if os.path.exists(self.salt_file) else None,
            'env_var_set': 'RANSOMWARE_CRYPTO_KEY' in os.environ
        }


def main():
    """Command-line interface for crypto operations"""
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
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
