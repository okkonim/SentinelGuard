import psutil
import time
import json
import os
import logging
from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor processes for anomalies and trigger YARA scans."""
    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)
        self.check_interval = 5
        self.network_threshold = 1000000  # 1MB
        self.running = False
        # previous snapshot of processes: {pid: (name, exe_path, network_bytes)}
        self.prev_procs = {}
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            self.check_interval = config.get('process_monitor', {}).get('check_interval', 5)
            self.network_threshold = config.get('process_monitor', {}).get('network_threshold', 1000000)
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def get_process_network_usage(self, proc):
        try:
            # Use io_counters() for per-process I/O, but network monitoring is system-wide
            # For simplicity, we'll use a different approach or skip detailed network tracking
            # since psutil doesn't provide per-process network counters easily
            return 0  # Placeholder - network monitoring could be implemented differently
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0

    def monitor(self):
        self.running = True
        logger.info("Запуск мониторинга процессов")

        # Display current processes
        print("Текущие процессы:")
        print(f"{'PID':<10} {'PPID':<10} {'Имя':<20} {'Путь':<50} {'Аргументы'}")
        print("-" * 100)
        try:
            for proc in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe', 'cmdline']):
                try:
                    info = proc.info
                    pid = info.get('pid', 'N/A')
                    ppid = info.get('ppid', 'N/A')
                    name = info.get('name', 'N/A')
                    exe = info.get('exe', 'N/A')
                    cmdline = ' '.join(info.get('cmdline', [])) if info.get('cmdline') else 'N/A'
                    print(f"{pid:<10} {ppid:<10} {name:<20} {exe:<50} {cmdline}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            logger.exception('Failed to list processes')

        # Initial snapshot
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.pid
                    name = proc.info.get('name') or proc.name()
                    exe_path = proc.info.get('exe') or proc.exe()
                    network_bytes = self.get_process_network_usage(proc)
                    self.prev_procs[pid] = (name, exe_path, network_bytes)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            # Write a single startup event
            try:
                self.db.insert_process_event(0, 'ProcessMonitor', 'Process monitor started', 'INFO')
            except Exception:
                logger.exception('Failed to write initial process monitor event')
        except Exception:
            logger.exception('Failed to take initial process snapshot')

        while self.running:
            current = {}
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.pid
                        name = proc.info.get('name') or proc.name()
                        exe_path = proc.info.get('exe') or proc.exe()
                        network_bytes = self.get_process_network_usage(proc)
                        current[pid] = (name, exe_path, network_bytes)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Detect started processes
                started = {pid: data for pid, data in current.items() if pid not in self.prev_procs}
                # Detect terminated processes
                terminated = {pid: data for pid, data in self.prev_procs.items() if pid not in current}

                for pid, (name, exe_path, network_bytes) in started.items():
                    try:
                        self.db.insert_process_event(pid, name, 'process_started', 'INFO')
                        logger.info(f'Process started: {name} (PID {pid})')
                    except Exception:
                        logger.exception(f'Failed to insert process_started for PID {pid}')

                for pid, (name, exe_path, network_bytes) in terminated.items():
                    try:
                        self.db.insert_process_event(pid, name, 'process_terminated', 'WARNING')
                        logger.info(f'Process terminated: {name} (PID {pid})')
                    except Exception:
                        logger.exception(f'Failed to insert process_terminated for PID {pid}')

                # Detect anomalies - simplified for now (could be extended with other metrics)
                # For demonstration, we'll trigger on processes with suspicious names or paths
                for pid, (name, exe_path, current_network) in current.items():
                    if exe_path and ('temp' in exe_path.lower() or 'tmp' in exe_path.lower()):
                        self.handle_anomaly(pid, name, exe_path, "Suspicious executable location", 'WARNING')

                # update snapshot
                self.prev_procs = current

            except Exception:
                logger.exception('Error during process monitoring iteration')

            time.sleep(self.check_interval)

    def handle_anomaly(self, pid, name, exe_path, description, criticality):
        self.db.insert_process_event(pid, name, f'anomaly: {description}', criticality)
        print(f"Аномалия процесса: {name} (PID {pid}) - {description}")

        # Trigger PE analysis if exe is PE file
        if exe_path and os.path.exists(exe_path) and self.pe_analyzer.is_pe_file(exe_path):
            print(f"Запуск PE анализа для подозрительного процесса {name}: {exe_path}")
            pe_result = self.pe_analyzer.analyze_file(exe_path)
            if pe_result:
                # Check for PE anomalies
                pe_anomalies = []
                for section in pe_result['sections']:
                    if section['anomalies']:
                        pe_anomalies.append(f"Section {section['name']}: {section['anomalies']}")
                for imp in pe_result['imports']:
                    if imp['suspicious']:
                        pe_anomalies.append(f"Suspicious import: {imp['function']}")

                if pe_anomalies:
                    print(f"PE анализ подтвердил аномалии в {exe_path}: {pe_anomalies}")
                    self.db.insert_netsec_alert('PROCESS_PE_ANOMALY',
                                               f'Process {name} shows PE anomalies: {pe_anomalies}',
                                               'CRITICAL',
                                               f"Process: {name}, Exe: {exe_path}, PE anomalies: {pe_anomalies}")

        # Trigger YARA scan on exe
        if exe_path and os.path.exists(exe_path) and self.yara_scanner.rules:
            results = self.yara_scanner.scan_file(exe_path)
            if results:
                threat_type = "известная угроза"
                print(f"YARA обнаружил {threat_type} в {exe_path}: {[r['rule_name'] for r in results]}")
                for result in results:
                    self.db.insert_yara_event(exe_path, result['rule_name'], f'MATCH from anomaly - {threat_type}', 'CRITICAL', str(result))
            else:
                threat_type = "потенциальная неизвестная угроза"
                print(f"YARA не нашел сигнатур, но процесс {name} демонстрирует аномальное поведение - {threat_type}")
                self.db.insert_yara_event(exe_path, 'No Match', f'ANOMALY - {threat_type}', 'CRITICAL', f"Process anomaly: {description}")

    def stop(self):
        self.running = False
        logger.info('Остановка мониторинга процессов')
