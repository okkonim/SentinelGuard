import hashlib
import os
import time
import json
from collections import defaultdict
from datetime import datetime, timedelta
from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer
from crypto import CryptoManager
import logging

logger = logging.getLogger(__name__)


class FIM:
    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)
        self.crypto_manager = CryptoManager()
        self.monitor_paths = []
        self.check_interval = 4
        self.file_hashes = {}
        self.running = False

        # Ransomware detection settings
        self.mass_encryption_threshold = 5
        self.encryption_time_window = 60
        self.encryption_events = []  # List of (timestamp, file_path)

        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            self.monitor_paths = config.get('fim', {}).get('monitor_paths', ['./'])
            self.check_interval = config.get('fim', {}).get('check_interval', 4)
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)

            # Load ransomware detection settings
            ransomware_config = config.get('ransomware', {})
            self.mass_encryption_threshold = ransomware_config.get('mass_encryption_threshold', 5)
            self.encryption_time_window = ransomware_config.get('encryption_time_window', 60)

        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.monitor_paths = ['./']

    def get_file_hash(self, file_path):
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None

    def initialize_hashes(self):
        for path in self.monitor_paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.file_hashes[file_path] = self.get_file_hash(file_path)
            elif os.path.isfile(path):
                self.file_hashes[path] = self.get_file_hash(path)

    def monitor(self):
        self.running = True
        self.initialize_hashes()
        print(f"Запуск FIM мониторинга для путей: {self.monitor_paths}")
        # Insert initial event
        try:
            self.db.insert_fim_event(','.join(self.monitor_paths), "FIM мониторинг запущен", 'INFO')
        except Exception as e:
            logger.exception(f"Failed to write initial FIM event: {e}")

        while self.running:
            time.sleep(self.check_interval)
            for path in self.monitor_paths:
                if os.path.isdir(path):
                    self.check_directory(path)
                elif os.path.isfile(path):
                    self.check_file(path)

    def check_directory(self, directory):
        current_files = set()
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                current_files.add(file_path)
                current_hash = self.get_file_hash(file_path)
                if file_path not in self.file_hashes:
                    # New file
                    self.handle_file_change(file_path, "Файл создан", 'INFO')
                    self.file_hashes[file_path] = current_hash
                elif self.file_hashes[file_path] != current_hash:
                    # Modified file
                    self.handle_file_change(file_path, "Файл изменен", 'CRITICAL')
                    self.file_hashes[file_path] = current_hash

        # Check for deleted files
        deleted_files = set(self.file_hashes.keys()) - current_files
        for file_path in deleted_files:
            if file_path.startswith(directory):
                self.db.insert_fim_event(file_path, "Файл удален", 'WARNING')
                del self.file_hashes[file_path]

    def check_file(self, file_path):
        current_hash = self.get_file_hash(file_path)
        if file_path not in self.file_hashes:
            self.handle_file_change(file_path, "Файл создан", 'INFO')
            self.file_hashes[file_path] = current_hash
        elif self.file_hashes[file_path] != current_hash:
            self.handle_file_change(file_path, "Файл изменен", 'CRITICAL')
            self.file_hashes[file_path] = current_hash

    def handle_file_change(self, file_path, event_type, criticality):
        self.db.insert_fim_event(file_path, event_type, criticality)
        print(f"FIM Оповещение: {event_type} для {file_path}")

        # Check if file appears to be encrypted
        is_encrypted = self.crypto_manager.is_file_encrypted(file_path)
        if is_encrypted and event_type == "Файл изменен":
            print(f"Обнаружено потенциальное шифрование файла: {file_path}")
            self._handle_encryption_detection(file_path)

        # Check if PE file and trigger PE analysis
        if self.pe_analyzer.is_pe_file(file_path):
            print(f"Запуск PE анализа для {file_path}")
            pe_result = self.pe_analyzer.analyze_file(file_path)
            if pe_result:
                # Check for anomalies
                has_anomalies = False
                for section in pe_result['sections']:
                    if section['anomalies']:
                        has_anomalies = True
                        break
                for imp in pe_result['imports']:
                    if imp['suspicious']:
                        has_anomalies = True
                        break

                if has_anomalies:
                    print(f"PE анализ обнаружил аномалии в {file_path}")
                    self.db.insert_netsec_alert('PE_ANOMALY', f'PE file anomalies detected in {file_path}', 'HIGH', str(pe_result))

        # Trigger YARA scan
        if self.yara_scanner.rules:
            results = self.yara_scanner.scan_file(file_path)
            if results:
                print(f"YARA обнаружил совпадения в {file_path}: {[r['rule_name'] for r in results]}")
                for result in results:
                    self.db.insert_yara_event(file_path, result['rule_name'], 'MATCH', 'CRITICAL', str(result))
            else:

                # No YARA matches but file changed - potential unknown threat
                if event_type == "Файл изменен":
                    print(f"YARA: нет совпадений в {file_path} - потенциальная неизвестная угроза")
                    self.db.insert_netsec_alert('UNKNOWN_THREAT', f'No YARA matches but file changed: {file_path}', 'MEDIUM', 'File modified without YARA detection')

    def _handle_encryption_detection(self, file_path):
        """Handle detected file encryption"""
        current_time = datetime.now()
        self.encryption_events.append((current_time, file_path))

        # Log encryption event to database
        self.db.insert_fim_event(file_path, "Файл зашифрован", 'CRITICAL')

        # Check for mass encryption
        self._check_mass_encryption()


    def _check_mass_encryption(self):
        """Check for mass encryption attack"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.encryption_time_window)

        # Clean old events
        self.encryption_events = [(t, f) for t, f in self.encryption_events if t > cutoff_time]

        # Count encryption events in time window
        encryption_count = len(self.encryption_events)

        if encryption_count >= self.mass_encryption_threshold:
            # Mass encryption detected
            affected_files = [f for _, f in self.encryption_events]
            file_list = ', '.join(affected_files[:5])  # Show first 5 files
            if encryption_count > 5:
                file_list += f" и еще {encryption_count - 5} файлов"

            alert_message = f"Массовое шифрование файлов обнаружено: {encryption_count} файлов за {self.encryption_time_window} секунд"
            details = f"Затронутые файлы: {file_list}"

            print(f"[КРИТИЧЕСКОЕ] {alert_message}")
            print(f"  Детали: {details}")

            # Log to database
            self.db.insert_netsec_alert(
                'MASS_ENCRYPTION',
                alert_message,
                'CRITICAL',
                json.dumps({
                    'affected_files': affected_files,
                    'count': encryption_count,
                    'time_window': self.encryption_time_window,
                    'timestamp': current_time.isoformat()
                })
            )

    def stop(self):
        self.running = False
        print("Остановка FIM мониторинга")
