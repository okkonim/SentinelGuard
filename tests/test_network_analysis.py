import time
from database import Database


class NetworkSnifferCCDemo:
    def __init__(self):
        self.db = Database('firewall.db')

    def simulate_cc_connections(self):
        entries = [
            ('IRC_CNC_CONNECTION', 'Suspicious IRC C&C', 'HIGH', {'dest_ip': '185.220.101.45', 'dest_port': 6667}),
            ('SUSPICIOUS_EXTERNAL_CONNECTION', 'Tor exit node', 'MEDIUM', {'dest_ip': '199.87.154.22', 'dest_port': 443}),
        ]
        for etype, desc, sev, details in entries:
            self.db.insert_netsec_alert(etype, desc, sev, str(details))

    def simulate_dns_cc_detection(self):
        entries = [
            ('DNS_CNC_DETECTED', 'DNS-based C&C detected', 'HIGH', {'domain': 'c2.malware-control.xyz'}),
        ]
        for etype, desc, sev, details in entries:
            self.db.insert_netsec_alert(etype, desc, sev, str(details))


class NetworkAttackDemo:
    def __init__(self):
        self.db = Database('firewall.db')

    def simulate_syn_flood(self):
        details = {'attack_type': 'SYN_FLOOD', 'packets_per_second': 1500}
        self.db.insert_netsec_alert('NETWORK_ATTACK_SYN_FLOOD', 'SYN flood detected', 'CRITICAL', str(details))

    def simulate_icmp_flood(self):
        details = {'attack_type': 'ICMP_FLOOD', 'packets_per_second': 2000}
        self.db.insert_netsec_alert('NETWORK_ATTACK_ICMP_FLOOD', 'ICMP flood detected', 'HIGH', str(details))

    def simulate_combined_attacks(self):
        details = {'attacks': ['SYN', 'ICMP'], 'severity': 'CRITICAL'}
        self.db.insert_netsec_alert('NETWORK_ATTACK_COMBINED', 'Combined attack detected', 'CRITICAL', str(details))


def test_network_cc_demo_smoke():
    demo = NetworkSnifferCCDemo()
    demo.db = Database(':memory:')

    demo.simulate_cc_connections()
    demo.simulate_dns_cc_detection()

    # Check that netsec alerts were inserted
    alerts = demo.db.query_events('netsec_alerts', limit=20)
    assert len(alerts) >= 1


def test_network_attack_demo_smoke():
    demo = NetworkAttackDemo()
    demo.db = Database(':memory:')

    demo.simulate_syn_flood()
    demo.simulate_icmp_flood()
    demo.simulate_combined_attacks()

    alerts = demo.db.query_events('netsec_alerts', limit=20)
    assert len(alerts) >= 1
