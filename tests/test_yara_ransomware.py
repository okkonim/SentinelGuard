import os
import tempfile
from yara_scanner import YaraRuleManager
from database import Database


def test_yara_rules_compilation_and_db_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        yara_file = os.path.join(tmpdir, 'sample.yar')
        with open(yara_file, 'w') as f:
            f.write('rule TestRansom { strings: $mz = {4D 5A} condition: $mz at 0 }')

        y_manager = YaraRuleManager()
        assert y_manager.compile_rules({'sample': yara_file})

        # Simulate a YARA detection recording to DB
        db = Database(':memory:')
        db.insert_yara_event('sample.exe', 'TestRansom', 'YARA_RANSOMWARE_DETECTED', 'HIGH', 'details')
        events = db.query_events('yara_events', limit=10)
        assert len(events) >= 1
