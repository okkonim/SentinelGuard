"""Unified demo runner combining several existing demonstration scripts"""
import time
from tests.test_network_analysis import NetworkSnifferCCDemo, NetworkAttackDemo
from tests.test_pe_integration import PERansomwareDemo
from database import Database


class DatabaseStructureDemo:
    def __init__(self, db_path='firewall.db'):
        self.db = Database(db_path)

    def show_database_overview(self):
        print("Database tables overview (sample):")
        tables = ['fim_events', 'yara_events', 'pe_files', 'process_events', 'netsec_alerts']
        for t in tables:
            rows = self.db.query_events(t, limit=3)
            print(f" - {t}: {len(rows)} sample rows")


def run_all_demos():
    print("Running unified demos...\n")

    ns_demo = NetworkSnifferCCDemo()
    ns_demo.simulate_cc_connections()
    time.sleep(0.5)
    ns_demo.simulate_dns_cc_detection()
    time.sleep(0.5)

    na_demo = NetworkAttackDemo()
    na_demo.simulate_syn_flood()
    time.sleep(0.5)
    na_demo.simulate_icmp_flood()
    time.sleep(0.5)
    na_demo.simulate_combined_attacks()
    time.sleep(0.5)

    # PE/process demo (class-based)
    pe_demo = PERansomwareDemo()
    pe_demo.db = Database(':memory:')
    pe_demo.simulate_pe_ransomware_analysis()
    time.sleep(0.5)

    # Database structure
    db_demo = DatabaseStructureDemo(db_path=':memory:')
    db_demo.show_database_overview()
    time.sleep(0.5)

    print("All demos completed.")


if __name__ == '__main__':
    run_all_demos()
