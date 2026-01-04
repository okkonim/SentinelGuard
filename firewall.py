import argparse
import threading
import time
import json
import logging
import os
import sys
from datetime import datetime

from utils.logging_utils import RansomwareLogger
from utils.exceptions import RansomwareProtectionError, ConfigurationError
from utils.constants import *

from database import Database
from network_capture import NetworkCapture
from fim import FIM
from process_monitor import ProcessMonitor
from network_monitor import NetworkMonitor
from network_sniffer import NetworkSniffer
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer

from ransomware_protection_system import SystemManager

class Firewall:
    def __init__(self, config_path='config.json'):
        self.config_path = config_path
        self.logger = RansomwareLogger.get_logger(__name__)
        self.db = Database(DB_DEFAULT_NAME)
        self.network_capture = NetworkCapture(interface=NETWORK_INTERFACE, db_name=DB_DEFAULT_NAME)
        self._network_sniffer = None  # Lazy initialization
        self._fim = None  # Lazy initialization
        self._process_monitor = None  # Lazy initialization
        self.network_monitor = NetworkMonitor(config=None, external_db=self.db)
        self._yara_scanner = None  # Lazy initialization
        self._pe_analyzer = None  # Lazy initialization
        self._ransomware_protection = None  # Lazy initialization
        self.threads = []
        self.running = False
        self._config_loaded = False
        self.load_config()

    @property
    def yara_scanner(self):
        """Lazy initialization of YARA scanner."""
        if self._yara_scanner is None:
            self._yara_scanner = YARAScanner(db_name=DB_DEFAULT_NAME)
            # Compile rules if available in config
            if hasattr(self, '_config') and self._config:
                yara_rules = self._config.get('yara', {}).get('rules_files', {})
                if yara_rules:
                    self._yara_scanner.compile_rules(yara_rules)
        return self._yara_scanner

    @yara_scanner.setter
    def yara_scanner(self, value):
        self._yara_scanner = value

    @property
    def pe_analyzer(self):
        """Lazy initialization of PE analyzer."""
        if self._pe_analyzer is None:
            self._pe_analyzer = PEAnalyzer(db_name=DB_DEFAULT_NAME)
        return self._pe_analyzer

    @pe_analyzer.setter
    def pe_analyzer(self, value):
        self._pe_analyzer = value

    @property
    def fim(self):
        """Lazy initialization of FIM module."""
        if self._fim is None:
            self._fim = FIM(self.config_path)
        return self._fim

    @fim.setter
    def fim(self, value):
        self._fim = value

    @property
    def process_monitor(self):
        """Lazy initialization of process monitor."""
        if self._process_monitor is None:
            self._process_monitor = ProcessMonitor(config_path=self.config_path, db_name=DB_DEFAULT_NAME)
        return self._process_monitor

    @process_monitor.setter
    def process_monitor(self, value):
        self._process_monitor = value

    @property
    def network_sniffer(self):
        """Lazy initialization of network sniffer."""
        if self._network_sniffer is None:
            self._network_sniffer = NetworkSniffer(interface=NETWORK_INTERFACE, db_name=DB_DEFAULT_NAME, config_path=self.config_path)
        return self._network_sniffer

    @network_sniffer.setter
    def network_sniffer(self, value):
        self._network_sniffer = value

    @property
    def ransomware_protection(self):
        """Lazy initialization of ransomware protection system."""
        if self._ransomware_protection is None:
            self._ransomware_protection = SystemManager(config_path=self.config_path, db_name=DB_DEFAULT_NAME)
        return self._ransomware_protection

    @ransomware_protection.setter
    def ransomware_protection(self, value):
        self._ransomware_protection = value

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Logging configuration
            if not hasattr(self, '_config_loaded'):
                log_config = {
                    'level': config.get('logging', {}).get('level', LOG_LEVEL_DEFAULT),
                    'file': config.get('logging', {}).get('file', LOG_FILE_DEFAULT),
                    'format': config.get('logging', {}).get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                }
                
                # Configure logging only once
                RansomwareLogger()
                RansomwareLogger()._configure_logging(log_config)
                self._config_loaded = True
            
            self._config = config
                
            self.logger.info("Configuration loaded successfully")
            
        except FileNotFoundError:
            self.logger.error(f"Configuration file {self.config_path} not found")
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error in configuration file: {e}")
            raise ConfigurationError(f"Invalid JSON format in configuration file: {e}")
        except Exception as e:
            self.logger.error(f"Configuration loading error: {e}")
            raise RansomwareProtectionError(f"Failed to load configuration: {e}")

    def start(self):
        self.logger.info("Starting firewall...")
        print("Starting firewall prototype...")

        try:
            self.running = True

            # Prefer the central SystemManager to orchestrate modules to avoid duplicate starts
            if self.ransomware_protection:
                started = self.ransomware_protection.start_protection()
                if not started:
                    self.logger.error("SystemManager failed to start protection")
                    raise RansomwareProtectionError("Failed to start protection system via SystemManager")

                print("Protection system started via SystemManager. Press Ctrl+C to stop.")
                self.logger.info("Protection system started via SystemManager.")

                try:
                    while self.ransomware_protection.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.logger.info("KeyboardInterrupt received. Stopping firewall...")
                    self.stop()
            else:
                # Fallback: start modules individually if SystemManager is unavailable
                if self.network_sniffer:  # Will trigger lazy initialization
                    t1 = threading.Thread(target=self.network_sniffer.start_sniffing, daemon=True)
                    t1.start()
                    self.threads.append(t1)

                if self.fim:  # Will trigger lazy initialization
                    t2 = threading.Thread(target=self.fim.monitor, daemon=True)
                    t2.start()
                    self.threads.append(t2)

                if self.process_monitor:  # Will trigger lazy initialization
                    t3 = threading.Thread(target=self.process_monitor.monitor, daemon=True)
                    t3.start()
                    self.threads.append(t3)

                t4 = threading.Thread(target=self._run_continuous_network_monitoring, daemon=True)
                t4.start()
                self.threads.append(t4)

                print("Press Ctrl+C to stop.")
                self.logger.info("All modules started. Firewall is running.")

                try:
                    while self.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.logger.info("KeyboardInterrupt received. Stopping firewall...")
                    self.stop()

        except Exception as e:
            self.logger.error(f"Error starting firewall: {e}")
            raise RansomwareProtectionError(f"Failed to start firewall: {e}")

    def _run_continuous_network_monitoring(self):
        """Continuous network monitoring"""
        while self.running:
            try:
                # Perform quick scan every minute
                connections = self.network_monitor.get_network_connections()
                if connections:
                    patterns = self.network_monitor.analyze_traffic_patterns(connections)
                    if any(patterns.values()):
                        self.logger.warning(f"Suspicious patterns detected: {list(patterns.keys())}")
                
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in continuous monitoring: {e}")
                time.sleep(30)  # Wait 30 seconds on error

    def stop(self):
        self.logger.info("Stopping firewall...")
        print("Stopping firewall...")
        
        try:
            self.running = False

            # Prefer central shutdown via SystemManager if available
            if self.ransomware_protection:
                try:
                    self.ransomware_protection.stop_protection()
                except Exception as e:
                    self.logger.error(f"Error stopping SystemManager: {e}")

            # Fallback: stop individual modules
            if hasattr(self, '_network_sniffer') and self._network_sniffer:
                self.network_sniffer.stop_sniffing()

            if hasattr(self, '_fim') and self._fim:
                self.fim.stop()

            if hasattr(self, '_process_monitor') and self._process_monitor:
                self.process_monitor.stop()

            if hasattr(self, 'network_monitor') and self.network_monitor:
                # Network monitoring stops itself via running flag
                pass

            # Wait for threads to complete with timeout
            for t in self.threads:
                if t.is_alive():
                    t.join(timeout=5)

            # Close database
            if hasattr(self, 'db') and self.db:
                self.db.close()

            self.logger.info("Firewall stopped successfully")
            print("Firewall stopped.")

        except Exception as e:
            self.logger.error(f"Error stopping firewall: {e}")
            raise RansomwareProtectionError(f"Failed to stop firewall correctly: {e}")

    def view_logs(self, table, limit=10):
        events = self.db.query_events(table, limit)
        for event in events:
            print(event)

    def manual_scan(self, path):
        """Manual YARA scan of file or directory"""
        if not os.path.exists(path):
            print(f"Path {path} does not exist")
            return
            
        scanner = self.yara_scanner  # Triggers lazy initialization
        
        if os.path.isfile(path):
            results = scanner.scan_file(path)
        elif os.path.isdir(path):
            results = scanner.scan_directory(path)
        else:
            print(f"Path {path} is neither file nor directory")
            return
            
        if results:
            print(f"YARA scan results for {path}:")
            for result in results:
                print(f"  Rule: {result['rule_name']}, File: {result['file_path']}")
        else:
            print(f"No YARA matches found in {path}")

    def manual_pe_analysis(self, path):
        """Manual PE analysis of file with YARA integration"""
        if not os.path.isfile(path):
            print(f"File {path} does not exist")
            return

        pe_analyzer = self.pe_analyzer  # Triggers lazy initialization
        
        if not pe_analyzer.is_pe_file(path):
            print(f"File {path} is not a PE file")
            return

        print(f"Analyzing PE file: {path}")

        # Run YARA scan first
        scanner = self.yara_scanner  # Triggers lazy initialization
        yara_results = scanner.scan_file(path) if scanner.rule_manager.rules else []
        yara_matches = len(yara_results) > 0

        # Run PE analysis
        result = pe_analyzer.analyze_file(path)
        if result:
            print("PE Analysis Results:")
            print(f"  Architecture: {result['header'].get('architecture', 'Unknown')}")
            print(f"  Entry Point: 0x{result['header'].get('entry_point', 0):08x}")
            print(f"  SHA-256: {result['sha256'][:16]}...")
            print(f"  Sections: {len(result['sections'])}")
            for section in result['sections']:
                anomalies = f" [{section['anomalies']}]" if section['anomalies'] else ""
                print(f"    {section['name']}: entropy={section['entropy']:.2f}{anomalies}")
            suspicious_imports = [imp for imp in result['imports'] if imp['suspicious']]
            print(f"  Suspicious Imports: {len(suspicious_imports)}")
            for imp in suspicious_imports:
                print(f"    {imp['function']} ({imp['dll']})")

            # Determine threat level based on PE and YARA
            pe_suspicious = any(section['anomalies'] for section in result['sections']) or suspicious_imports
            threat_reasons = []

            if pe_suspicious:
                reasons = []
                if any(section['anomalies'] for section in result['sections']):
                    high_entropy_sections = [s['name'] for s in result['sections'] if 'high_entropy' in s['anomalies']]
                    if high_entropy_sections:
                        reasons.append(f"high entropy in sections: {', '.join(high_entropy_sections)}")
                    suspicious_names = [s['name'] for s in result['sections'] if 'suspicious_name' in s['anomalies']]
                    if suspicious_names:
                        reasons.append(f"suspicious section names: {', '.join(suspicious_names)}")
                if suspicious_imports:
                    reasons.append(f"suspicious imports: {', '.join([imp['function'] for imp in suspicious_imports])}")
                threat_reasons.append(f"PE Module: {', '.join(reasons)}")

            if yara_matches and not pe_suspicious:
                yara_rules = [r['rule_name'] for r in yara_results]
                threat_reasons.append(f"YARA Module (unknown threat): rules {', '.join(yara_rules)}")
            elif yara_matches and pe_suspicious:
                yara_rules = [r['rule_name'] for r in yara_results]
                threat_reasons.append(f"YARA Module: rules {', '.join(yara_rules)}")

            if threat_reasons:
                print(f"  Status: SUSPICIOUS")
                for reason in threat_reasons:
                    print(f"    - {reason}")
            else:
                print(f"  Status: CLEAN")
        else:
            print("PE analysis failed")

    def view_pe_reports(self, limit=10):
        """View PE analysis reports"""
        files = self.db.query_pe_files(limit)
        if files:
            print("Recent PE Files:")
            for file in files:
                print(f"  {file[2]}: {file[3]} ({file[4] or 'Unknown arch'})")
        else:
            print("No PE files analyzed yet.")

        sections = self.db.query_pe_sections(limit=limit)
        if sections:
            print(f"\nRecent PE Sections (last {limit}):")
            for section in sections:
                anomalies = f" [{section[7]}]" if section[7] else ""
                print(f"  File {section[1]}: {section[2]} entropy={section[6]:.2f}{anomalies}")
        else:
            print("No PE sections found.")

        imports = self.db.query_pe_imports(limit=limit)
        if imports:
            print(f"\nRecent PE Imports (last {limit}):")
            for imp in imports:
                suspicious = " [SUSPICIOUS]" if imp[4] else ""
                print(f"  File {imp[1]}: {imp[3]} ({imp[2]}){suspicious}")
        else:
            print("No PE imports found.")

    def view_yara_rules(self):
        """Display loaded YARA rules"""
        scanner = self.yara_scanner  # Triggers lazy initialization
        
        if scanner.rule_manager.rules:
            print("YARA rules loaded successfully")
            # Note: YARA Rules object doesn't expose rule names directly
            # We can show that rules are compiled from config
            print("Rules compiled from config.json")
        else:
            print("No YARA rules loaded")

    def reload_config(self):
        """Reload configuration and YARA rules"""
        self.load_config()
        self.fim.load_config()
        self.process_monitor.load_config()
        print("Configuration reloaded")

    def run_netsec_scan(self):
        """Run network monitoring scan"""
        print("Running network monitoring scan...")
        results = self.network_monitor.run_comprehensive_scan()
        print("Network monitoring scan completed.")
        return results

    def create_baseline(self):
        """Create network baseline"""
        print("Creating network baseline...")
        self.network_monitor.generate_baseline()
        print("Baseline created.")

    def compare_baseline(self):
        """Compare with baseline"""
        print("Comparing with baseline...")
        anomalies = self.network_monitor.compare_with_baseline()
        if anomalies:
            print("Anomalies found:")
            for anomaly in anomalies:
                print(f"  {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}")
        else:
            print("No anomalies found.")
        return anomalies

    def reload_rules(self):
        self.network_capture.reload_rules()
        self.reload_config()

    def start_network_sniffer_only(self):
        print("Starting hybrid network sniffer...")
        if self.network_sniffer.start_sniffing():
            print("Hybrid network sniffer started. Press Ctrl+C to stop.")
            try:
                input()
            except KeyboardInterrupt:
                pass
            self.network_sniffer.stop_sniffing()
        self.db.close()
        print("Hybrid network sniffer stopped.")

    def start_fim_only(self):
        print("Starting FIM module...")
        t = threading.Thread(target=self.fim.monitor)
        t.start()
        print("FIM module started. Press Ctrl+C to stop.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.fim.stop()
        t.join()
        self.db.close()
        print("FIM module stopped.")

    def start_process_only(self):
        print("Starting process monitoring module...")
        t = threading.Thread(target=self.process_monitor.monitor)
        t.start()
        print("Process monitoring module started. Press Ctrl+C to stop.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.process_monitor.stop()
        t.join()
        self.db.close()
        print("Process monitoring module stopped.")

    def start_netsec_only(self):
        print("Starting NetSec Sentinel module...")
        t = threading.Thread(target=self.network_monitor.start_monitoring)
        t.start()
        print("NetSec Sentinel module started. Press Ctrl+C to stop.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.network_monitor.stop_monitoring()
        t.join()
        self.db.close()
        print("NetSec Sentinel module stopped.")

def interactive_menu(firewall):
    while True:
        print("\n=== Software Firewall Prototype ===")
        print("1. Start all modules")
        print("2. Start hybrid network sniffer")
        print("3. Start FIM module")
        print("4. Start process monitoring module")
        print("5. Start network monitoring module")
        print("6. Start ransomware protection system")
        print("7. View logs")
        print("8. Reload rules")
        print("9. Network threat scan")
        print("10. Create baseline")
        print("11. Compare with baseline")
        print("12. Manual YARA scan")
        print("13. View YARA rules")
        print("14. PE file analysis")
        print("15. View PE reports")
        print("0. Exit")
        choice = input("Select option (0-15): ").strip()

        if choice == '1':
            firewall.start()
        elif choice == '2':
            firewall.start_network_sniffer_only()
        elif choice == '3':
            firewall.start_fim_only()
        elif choice == '4':
            firewall.start_process_only()
        elif choice == '5':
            firewall.start_netsec_only()
        elif choice == '6':
            print("Starting ransomware protection system...")
            protection_system = firewall.ransomware_protection  # Triggers lazy initialization
            
            # Start protection system
            if protection_system.start_protection():
                print("Ransomware protection system started. Press Ctrl+C to stop...")
                try:
                    while protection_system.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    protection_system.stop_protection()
            else:
                print("Error starting ransomware protection system.")
        elif choice == '7':
            table = input("Table (network_events, fim_events, process_events, netsec_alerts, yara_events): ").strip()
            if table in ['network_events', 'fim_events', 'process_events', 'netsec_alerts', 'yara_events']:
                limit = input("Number of records (default 10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                firewall.view_logs(table, limit)
            else:
                print("Invalid table.")
        elif choice == '8':
            firewall.reload_rules()
            print("Rules reloaded.")
        elif choice == '9':
            firewall.run_netsec_scan()
        elif choice == '10':
            firewall.create_baseline()
        elif choice == '11':
            firewall.compare_baseline()
        elif choice == '12':
            path = input("Path to file or directory for scanning: ").strip()
            if path:
                firewall.manual_scan(path)
            else:
                print("Path not specified.")
        elif choice == '13':
            firewall.view_yara_rules()
        elif choice == '14':
            path = input("Path to PE file for analysis: ").strip()
            if path:
                firewall.manual_pe_analysis(path)
            else:
                print("Path not specified.")
        elif choice == '15':
            limit = input("Number of records (default 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            firewall.view_pe_reports(limit)
        elif choice == '0':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    parser = argparse.ArgumentParser(
        description="Firewall / SentinelGuard command-line interface (primary project entry)",
        epilog="Usage examples:\n  python3 firewall.py start\n  python3 firewall.py logs --table fim_events --limit 20\n  python3 firewall.py scan --path /tmp/sample --limit 10\n\nTip: `ransomware_protection_system.py` is deprecated and will delegate to this CLI (it emits a DeprecationWarning).",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--config', '-c', default='config.json', help='Path to configuration file (default: config.json)')
    parser.add_argument('--db', '-d', default=DB_DEFAULT_NAME, help=f"Database file (default: {DB_DEFAULT_NAME})")
    parser.add_argument('--version', action='version', version='SentinelGuard 0.1')

    parser.add_argument('command', nargs='?', choices=['start', 'stop', 'logs', 'reload', 'netsec-scan', 'baseline', 'compare', 'start-sniffer', 'start-fim', 'start-process', 'start-netsec', 'start-ransomware', 'interactive', 'scan', 'rules', 'pe-analyze', 'pe-reports'], help="Command to execute")
    parser.add_argument('--table', choices=['network_events', 'fim_events', 'process_events', 'netsec_alerts', 'yara_events', 'ransomware_attacks'], help="Table for viewing logs")
    parser.add_argument('--limit', type=int, default=10, help="Number of log records to display")
    parser.add_argument('--path', help="Path for scanning (for scan command)")

    args = parser.parse_args()

    firewall = Firewall()

    if args.command == 'start':
        try:
            firewall.start()
            input()
            firewall.stop()
        except KeyboardInterrupt:
            firewall.stop()
    elif args.command == 'logs':
        if not args.table:
            print("Please specify --table")
            return
        firewall.view_logs(args.table, args.limit)
    elif args.command == 'reload':
        firewall.reload_rules()
    elif args.command == 'netsec-scan':
        firewall.run_netsec_scan()
    elif args.command == 'baseline':
        firewall.create_baseline()
    elif args.command == 'compare':
        firewall.compare_baseline()
    elif args.command == 'start-sniffer':
        firewall.start_network_sniffer_only()
    elif args.command == 'start-fim':
        firewall.start_fim_only()
    elif args.command == 'start-process':
        firewall.start_process_only()
    elif args.command == 'start-netsec':
        firewall.start_netsec_only()
    elif args.command == 'interactive' or args.command is None:
        interactive_menu(firewall)
    elif args.command == 'scan':
        if not args.path:
            print("Please specify --path for scanning")
            return
        firewall.manual_scan(args.path)
    elif args.command == 'rules':
        firewall.view_yara_rules()
    elif args.command == 'pe-analyze':
        if not args.path:
            print("Please specify --path for PE analysis")
            return
        firewall.manual_pe_analysis(args.path)
    elif args.command == 'pe-reports':
        firewall.view_pe_reports(args.limit)
    elif args.command == 'stop':
        firewall.stop()
    else:
        print("Invalid command")

if __name__ == "__main__":
    main()

