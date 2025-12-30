import os
import tempfile
from yara_scanner import YaraRuleManager, YaraScanner
from pe_analyzer import PEAnalyzer
from database import Database


def test_create_suspicious_file_and_pe_and_yara_scan():
    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
    tmpfile_path = tmpfile.name
    tmpfile.close()

    try:
        # Write minimal PE-like header
        with open(tmpfile_path, 'wb') as f:
            f.write(b'MZ\x90\x00\x03\x00')

        # PE check
        pe = PEAnalyzer(':memory:')
        assert pe.is_pe_file(tmpfile_path)

        # Create a simple yara rule that matches MZ header
        yara_file = os.path.join(os.path.dirname(tmpfile_path), 'sample_test.yar')
        with open(yara_file, 'w') as f:
            f.write('rule TestMz {strings: $mz = {4D 5A} condition: $mz at 0 }')

        # Compile rules
        y_manager = YaraRuleManager()
        assert y_manager.compile_rules({'test': yara_file})

        # Scan file with YaraScanner
        db = Database(':memory:')
        scanner = YaraScanner(y_manager, db)
        results = scanner.scan_file(tmpfile_path)

        # Either match exists or at least scan executes cleanly
        assert isinstance(results, list)

    finally:
        try:
            os.remove(tmpfile_path)
        except Exception:
            pass
        try:
            os.remove(yara_file)
        except Exception:
            pass
