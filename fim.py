import hashlib
import os
import time
import json
from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer
import logging

logger = logging.getLogger(__name__)

class FIM:
    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)
        self.monitor_paths = []
        self.check_interval = 4
        self.file_hashes = {}
        self.running = False
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

    def stop(self):
        self.running = False
        print("Остановка FIM мониторинга")
