import os
import json
import tempfile
from utils.logging_utils import RansomwareLogger
from database import Database


def test_imports():
    # Lightweight import smoke test
    # Importing modules to ensure they are available
    from firewall import Firewall
    from network_monitor import NetworkMonitor
    from process_monitor import ProcessMonitor
    from yara_scanner import YARAScanner
    from pe_analyzer import PEAnalyzer
    from crypto import CryptoManager
    from database import Database

    assert Firewall is not None
    assert NetworkMonitor is not None
    assert ProcessMonitor is not None
    assert YARAScanner is not None
    assert PEAnalyzer is not None
    assert CryptoManager is not None
    assert Database is not None


def test_constants():
    from utils.constants import SEVERITY_CRITICAL, EVENT_YARA_MATCH, PE_EXTENSIONS, SUSPICIOUS_IMPORTS

    assert isinstance(SEVERITY_CRITICAL, str)
    assert isinstance(EVENT_YARA_MATCH, str)
    assert isinstance(PE_EXTENSIONS, (list, tuple, set))
    assert isinstance(SUSPICIOUS_IMPORTS, (list, tuple, set))


def test_logging():
    # Ensure logger functions do not raise
    logger = RansomwareLogger.get_logger("test")
    RansomwareLogger.log_operation("test_operation", True, "test details")
    RansomwareLogger.log_security_event("TEST_EVENT", "Test security event", "INFO")
    try:
        raise ValueError("Test error")
    except ValueError as e:
        RansomwareLogger.log_error(e, "Test error context")
    assert True


def test_database():
    # Use in-memory DB
    db = Database(':memory:')
    db.insert_netsec_alert('TEST_ALERT', 'Test alert', 'LOW', 'Test details')
    alerts = db.query_events('netsec_alerts', 10)
    assert len(alerts) >= 1


def test_components():
    # Simple component instantiation smoke tests using temp config
    tmpcfg = {'database': {'name': ':memory:'}, 'logging': {'level': 'INFO'}}
    cfgfile = 'test_config.json'
    with open(cfgfile, 'w') as f:
        json.dump(tmpcfg, f)

    from network_monitor import NetworkMonitor
    from process_monitor import ProcessMonitor
    from yara_scanner import YARAScanner
    from pe_analyzer import PEAnalyzer
    from crypto import CryptoManager

    nm = NetworkMonitor(config=None, external_db=Database(':memory:'))
    pm = ProcessMonitor(config_path=cfgfile, db_name=':memory:')
    ys = YARAScanner(db_name=':memory:')
    pe = PEAnalyzer(db_name=':memory:', config_path=cfgfile)
    cm = CryptoManager(key_file='test_key.bin', salt_file='test_salt.bin')

    assert nm is not None
    assert pm is not None
    assert ys is not None
    assert pe is not None
    assert cm is not None

    os.remove(cfgfile)


def test_firewall_class():
    # Create minimal config file for Firewall
    cfg = {
        'database': {'name': 'test_firewall.db'},
        'logging': {'level': 'INFO', 'file': 'test.log'},
        'yara': {'rules_files': {}},
        'pe_analysis': {'enabled': True},
        'process_monitor': {'enabled': False},
        'network_monitor': {'enabled': False},
        'fim': {'enabled': False}
    }
    cfgfile = 'test_config.json'
    with open(cfgfile, 'w') as f:
        json.dump(cfg, f)

    from firewall import Firewall
    fw = Firewall(cfgfile)
    assert fw is not None

    # cleanup
    for fpath in ['test_firewall.db', 'test.log', cfgfile]:
        if os.path.exists(fpath):
            os.remove(fpath)

