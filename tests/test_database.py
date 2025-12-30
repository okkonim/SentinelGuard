from database import Database


def test_correlation_detects_ransomware():
    db = Database(':memory:')

    # Insert events to simulate ransomware indicators
    db.insert_fim_event('/tmp/file1.txt', 'mass encryption detected', 'CRITICAL')
    db.insert_process_event(4242, 'badproc.exe', 'ransomware_behavior detected', 'CRITICAL')
    db.insert_netsec_alert('C_AND_C_CONNECTION', 'Connection to known C&C server', 'CRITICAL', 'details')

    attack_id = db.correlate_ransomware_events([], [], [])

    assert attack_id is not None
    recent = db.get_recent_ransomware_attacks(hours=1)
    assert len(recent) >= 1


def test_db_structure_smoke():
    db = Database(':memory:')

    # Basic inserts and queries
    db.insert_fim_event('/tmp/a.txt', 'modified', 'WARNING')
    db.insert_netsec_alert('TEST_ALERT', 'Test alert', 'LOW', 'details')

    fim = db.query_events('fim_events', limit=10)
    netsec = db.query_events('netsec_alerts', limit=10)

    assert len(fim) >= 1
    assert len(netsec) >= 1
