
import psutil
import time
import json
import os
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer
from crypto import CryptoManager

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor processes for anomalies and trigger YARA scans."""

    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)
        self.crypto_manager = CryptoManager()
        self.check_interval = 5
        self.network_threshold = 1000000  # 1MB
        self.running = False

        # previous snapshot of processes: {pid: (name, exe_path, network_bytes)}
        self.prev_procs = {}

        # Ransomware detection settings
        self.vssadmin_suspicious = True
        self.file_extension_blacklist = []
        self.process_whitelist = []
        self.file_io_threshold = 100  # File operations per minute
        self.unique_extensions_threshold = 10  # Different file types per minute

        # File I/O tracking
        self.file_operations = defaultdict(list)  # pid -> [(timestamp, operation, file_path)]
        self.recent_processes = defaultdict(set)  # pid -> set of file extensions seen

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

            # Load ransomware detection settings
            ransomware_config = config.get('ransomware', {})
            self.vssadmin_suspicious = ransomware_config.get('vssadmin_suspicious', True)
            self.file_extension_blacklist = ransomware_config.get('file_extension_blacklist', [])
            self.process_whitelist = ransomware_config.get('process_whitelist', [])

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
                        # Check for ransomware-related processes
                        self._check_ransomware_behavior(pid, name, exe_path, 'started')
                    except Exception:
                        logger.exception(f'Failed to insert process_started for PID {pid}')

                for pid, (name, exe_path, network_bytes) in terminated.items():
                    try:
                        self.db.insert_process_event(pid, name, 'process_terminated', 'WARNING')
                        logger.info(f'Process terminated: {name} (PID {pid})')
                    except Exception:
                        logger.exception(f'Failed to insert process_terminated for PID {pid}')


                # Detect ransomware behavior in existing processes
                self._detect_ransomware_behavior(current)

                # Detect anomalies - simplified for now (could be extended with other metrics)
                # For demonstration, we'll trigger on processes with suspicious names or paths
                for pid, (name, exe_path, current_network) in current.items():
                    if exe_path and ('temp' in exe_path.lower() or 'tmp' in exe_path.lower()):
                        self.handle_anomaly(pid, name, exe_path, "Suspicious executable location", 'WARNING')

                # update snapshot
                self.prev_procs = current

                # Clean old file operations (older than 1 minute)
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(minutes=1)
                for pid in list(self.file_operations.keys()):
                    self.file_operations[pid] = [(t, op, path) for t, op, path in self.file_operations[pid] if t > cutoff_time]

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

    def _check_ransomware_behavior(self, pid, name, exe_path, event_type):
        """Check for ransomware-specific behavior when process starts"""
        current_time = datetime.now()

        # Check for vssadmin.exe (Volume Shadow Copy deletion)
        if self.vssadmin_suspicious and name.lower() == 'vssadmin.exe':
            self._handle_ransomware_alert(
                pid, name, exe_path,
                "Обнаружен vssadmin.exe - потенциальное удаление теневых копий",
                'CRITICAL',
                "RANSOMWARE_BEHAVIOR"
            )

        # Check for processes that shouldn't have network access
        if exe_path and ('notepad.exe' in name.lower() or 'calc.exe' in name.lower()):
            # This would need actual network monitoring to be effective
            pass

    def _detect_ransomware_behavior(self, current_processes):
        """Detect ransomware behavior in running processes"""
        current_time = datetime.now()

        # Monitor file operations (simplified - would need kernel-level monitoring)
        for pid, (name, exe_path, network_bytes) in current_processes.items():
            # Check for mass file operations
            if pid in self.file_operations:
                recent_ops = [op for t, op, path in self.file_operations[pid] if t > current_time - timedelta(minutes=1)]

                # Count file write operations
                write_ops = [op for op in recent_ops if op == 'write']
                if len(write_ops) > self.file_io_threshold:
                    self._handle_ransomware_alert(
                        pid, name, exe_path,
                        f"Массовая запись файлов: {len(write_ops)} операций за минуту",
                        'HIGH',
                        'MASS_FILE_OPERATIONS'
                    )

                # Check for multiple file extensions
                extensions = set()
                for t, op, path in self.file_operations[pid]:
                    if '.' in path:
                        ext = os.path.splitext(path)[1].lower()
                        extensions.add(ext)

                if len(extensions) > self.unique_extensions_threshold:
                    self._handle_ransomware_alert(
                        pid, name, exe_path,
                        f"Доступ к множеству типов файлов: {len(extensions)} расширений",
                        'MEDIUM',
                        'MULTIPLE_FILE_TYPES'
                    )

                # Check for blacklisted extensions
                for ext in extensions:
                    if ext in self.file_extension_blacklist:
                        self._handle_ransomware_alert(
                            pid, name, exe_path,
                            f"Доступ к файлам с подозрительным расширением: {ext}",
                            'HIGH',
                            'BLACKLISTED_EXTENSION'
                        )

    def _handle_ransomware_alert(self, pid, name, exe_path, description, severity, alert_type):
        """Handle detected ransomware behavior"""
        alert_message = f"Ransomware behavior detected: {description}"

        print(f"[{severity}] {alert_message}")
        print(f"  Process: {name} (PID {pid})")
        if exe_path:
            print(f"  Path: {exe_path}")

        # Log to database
        try:
            self.db.insert_netsec_alert(
                alert_type,
                alert_message,
                severity,
                json.dumps({
                    'pid': pid,
                    'process_name': name,
                    'exe_path': exe_path,
                    'timestamp': datetime.now().isoformat()
                })
            )

            # Log process event
            self.db.insert_process_event(pid, name, f'ransomware_behavior: {description}', severity)

        except Exception as e:
            logger.error(f"Failed to log ransomware alert: {e}")

        # Trigger PE analysis and YARA scan if process is executable
        if exe_path and os.path.exists(exe_path):
            if self.pe_analyzer.is_pe_file(exe_path):
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
                        print(f"  PE анализ подтвердил аномалии: {pe_anomalies}")

            # Trigger YARA scan
            if self.yara_scanner.rules:
                results = self.yara_scanner.scan_file(exe_path)
                if results:
                    print(f"  YARA обнаружил совпадения: {[r['rule_name'] for r in results]}")
                    for result in results:
                        self.db.insert_yara_event(exe_path, result['rule_name'], f'MATCH from ransomware behavior', 'CRITICAL', str(result))
                else:
                    print(f"  YARA не нашел сигнатур - потенциальная неизвестная угроза")

        # If critical, try to stop the process
        if severity == 'CRITICAL':
            try:
                process = psutil.Process(pid)
                process.terminate()
                print(f"  Процесс {name} (PID {pid}) принудительно остановлен")
                self.db.insert_process_event(pid, name, 'process_terminated_by_security', 'CRITICAL')
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"  Не удалось остановить процесс {name} (PID {pid}): {e}")

    def track_file_operation(self, pid, operation, file_path):
        """Track file operations for ransomware detection"""
        current_time = datetime.now()
        self.file_operations[pid].append((current_time, operation, file_path))

        # Track file extensions
        if '.' in file_path:
            ext = os.path.splitext(file_path)[1].lower()
            self.recent_processes[pid].add(ext)
