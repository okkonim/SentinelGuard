import psutil
import time
import json
import os
import logging
from database import Database
from yara_scanner import YARAScanner

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor processes for anomalies and trigger YARA scans."""
    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
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
            net_io = proc.net_io_counters()
            return net_io.bytes_sent + net_io.bytes_recv if net_io else 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0

    def monitor(self):
        self.running = True
        logger.info("Запуск мониторинга процессов")

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

                # Detect anomalies
                for pid, (name, exe_path, current_network) in current.items():
                    if pid in self.prev_procs:
                        prev_name, prev_exe, prev_network = self.prev_procs[pid]
                        network_increase = current_network - prev_network
                        if network_increase > self.network_threshold:
                            self.handle_anomaly(pid, name, exe_path, f"High network usage: {network_increase} bytes", 'WARNING')

                # update snapshot
                self.prev_procs = current

            except Exception:
                logger.exception('Error during process monitoring iteration')

            time.sleep(self.check_interval)

    def handle_anomaly(self, pid, name, exe_path, description, criticality):
        self.db.insert_process_event(pid, name, f'anomaly: {description}', criticality)
        print(f"Аномалия процесса: {name} (PID {pid}) - {description}")
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
