import os
import tempfile
import time
from crypto import CryptoManager


def test_encrypt_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CryptoManager(key_file=os.path.join(tmpdir, 'test_key.enc'), salt_file=os.path.join(tmpdir, 'test_salt.bin'))
        key = cm.generate_key()
        cm.key_manager.initialize_fernet(key)

        orig_path = os.path.join(tmpdir, 'orig.txt')
        with open(orig_path, 'wb') as f:
            f.write(b'This is a test payload for encryption.\n' * 10)

        encrypted = cm.file_processor.encrypt_file(orig_path)
        assert os.path.exists(encrypted)

        decrypted = cm.file_processor.decrypt_file(encrypted)
        assert os.path.exists(decrypted)

        with open(decrypted, 'rb') as f:
            dec_content = f.read()
        with open(orig_path, 'rb') as f:
            orig_content = f.read()

        assert dec_content == orig_content

        # Cleanup
        os.remove(encrypted)
        os.remove(decrypted)


def test_decrypt_with_bad_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CryptoManager(key_file=os.path.join(tmpdir, 'test_key2.enc'), salt_file=os.path.join(tmpdir, 'test_salt2.bin'))
        key = cm.generate_key()
        cm.key_manager.initialize_fernet(key)

        orig_path = os.path.join(tmpdir, 'orig2.txt')
        with open(orig_path, 'wb') as f:
            f.write(b'Secret data')

        encrypted = cm.file_processor.encrypt_file(orig_path)

        # Re-initialize with different key
        other_key = cm.generate_key()
        cm.key_manager.initialize_fernet(other_key)

        failed = False
        try:
            cm.file_processor.decrypt_file(encrypted)
            failed = True
        except Exception:
            # Expected
            pass
        finally:
            os.remove(encrypted)

        assert not failed, "Decryption should have failed with wrong key"


def test_mass_encryption_smoke():
    """Smoke test: create several files and encrypt them rapidly"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CryptoManager(key_file=os.path.join(tmpdir, 'mass_key.enc'), salt_file=os.path.join(tmpdir, 'mass_salt.bin'))
        key = cm.generate_key()
        cm.key_manager.initialize_fernet(key)

        # Create test files
        files = []
        for i in range(5):
            p = os.path.join(tmpdir, f'testfile_{i}.txt')
            with open(p, 'w', encoding='utf-8') as f:
                f.write('Sensitive data ' * 20)
            files.append(p)

        # Encrypt quickly
        for p in files:
            enc = cm.file_processor.encrypt_file(p)
            assert os.path.exists(enc)
            # small delay
            time.sleep(0.1)

        # cleanup encrypted files
        for p in os.listdir(tmpdir):
            if p.endswith('.encrypted'):
                os.remove(os.path.join(tmpdir, p))

        assert True
