import time
from process_monitor import ProcessMonitor


def test_heuristic_rule_vssadmin_triggers_alert():
    monitor = ProcessMonitor(config_path='config.json', db_name=':memory:')

    # Trigger startup check directly on ransomware_detector
    rd = monitor.ransomware_detector
    rd._check_startup_ransomware_behavior(1234, 'vssadmin.exe', 'C:\Windows\System32\vssadmin.exe')

    alerts = monitor.db.query_events('netsec_alerts', limit=10)
    assert any('RANSOMWARE_BEHAVIOR' in a[2] or 'RANSOMWARE' in (a[2] or '') for a in alerts)


def test_mass_file_operations_triggers_alert():
    monitor = ProcessMonitor(config_path='config.json', db_name=':memory:')

    pid = 5678
    name = 'suspicious_process.exe'

    # Simulate many write operations
    for i in range(monitor.ransomware_detector.file_io_threshold + 5):
        monitor.track_file_operation(pid, 'write', f'/tmp/file_{i}.txt')

    # Run detection
    monitor.ransomware_detector.detect_ransomware_behavior(pid, name, '/tmp/suspicious_process.exe', 'process_running')

    alerts = monitor.db.query_events('netsec_alerts', limit=10)
    assert any('MASS_FILE_OPERATIONS' in a[2] for a in alerts)


def test_multiple_file_types_triggers_alert():
    monitor = ProcessMonitor(config_path='config.json', db_name=':memory:')

    pid = 9012
    name = 'ransomware_sim.exe'

    file_extensions = ['.txt', '.doc', '.pdf', '.jpg', '.png', '.xlsx', '.pptx', '.zip', '.mp3', '.mp4', '.exe', '.dll']

    for i, ext in enumerate(file_extensions):
        monitor.track_file_operation(pid, 'write', f'/tmp/file_{i}{ext}')

    monitor.ransomware_detector.detect_ransomware_behavior(pid, name, '/tmp/ransomware_sim.exe', 'process_running')

    alerts = monitor.db.query_events('netsec_alerts', limit=20)
    assert any('MULTIPLE_FILE_TYPES' in a[2] for a in alerts)
