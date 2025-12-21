#!/usr/bin/env python3
"""
File Integrity Monitoring (FIM) module for ransomware protection system.
Monitors file changes, detects encryption attempts, and triggers security analysis.

This module has been refactored to:
- Eliminate code duplication and long methods
- Separate concerns into focused classes
- Use centralized logging and error handling
- Provide better structure and maintainability
"""

import hashlib
import os
import time
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer
from crypto import CryptoManager
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import FileOperationError, SecurityAlert, ValidationError


class FileHashCalculator:
    """Handles file hashing operations."""
    
    def __init__(self, logger):
        self.logger = logger

    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        if not os.path.exists(file_path):
            return None
            
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error hashing file {file_path}")
            return None

    def validate_file_path(self, file_path: str) -> None:
        """Validate file path for operations."""
        if not file_path:
            raise ValidationError("File path cannot be empty")
        if not os.path.exists(file_path):
            raise FileOperationError(f"File not found: {file_path}")


class DirectoryScanner:
    """Handles directory scanning and file discovery."""
    
    def __init__(self, hash_calculator: FileHashCalculator, logger):
        self.hash_calculator = hash_calculator
        self.logger = logger

    def scan_directory(self, directory: str) -> Set[str]:
        """Scan directory and return set of file paths."""
        try:
            file_paths = set()
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_paths.add(file_path)
            return file_paths
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error scanning directory {directory}")
            return set()

    def scan_single_file(self, file_path: str) -> Set[str]:
        """Scan single file and return set with file path."""
        try:
            if os.path.isfile(file_path):
                return {file_path}
            return set()
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error scanning file {file_path}")
            return set()


class ThreatAnalyzer:
    """Handles threat analysis for files (PE analysis and YARA scanning)."""
    
    def __init__(self, db: Database, yara_scanner: YARAScanner, 
                 pe_analyzer: PEAnalyzer, logger):
        self.db = db
        self.yara_scanner = yara_scanner
        self.pe_analyzer = pe_analyzer
        self.logger = logger

    def analyze_file_threats(self, file_path: str, event_type: str) -> None:
        """Analyze file for security threats."""
        try:
            # Analyze PE files
            if self._is_pe_analysis_needed(file_path, event_type):
                self._perform_pe_analysis(file_path)
            
            # Perform YARA scanning
            self._perform_yara_scan(file_path, event_type)
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing threats for {file_path}")

    def _is_pe_analysis_needed(self, file_path: str, event_type: str) -> bool:
        """Determine if PE analysis is needed for the file."""
        return (event_type == "Файл изменен" and 
                self.pe_analyzer.is_pe_file(file_path))

    def _perform_pe_analysis(self, file_path: str) -> None:
        """Perform PE analysis on the file."""
        try:
            pe_result = self.pe_analyzer.analyze_file(file_path)
            if pe_result and self._has_pe_anomalies(pe_result):
                alert_message = f'PE file anomalies detected in {file_path}'
                RansomwareLogger.log_security_event('PE_ANOMALY', alert_message, 'HIGH', str(pe_result))
                self.db.insert_netsec_alert('PE_ANOMALY', alert_message, 'HIGH', str(pe_result))
        except Exception as e:
            RansomwareLogger.log_error(e, f"PE analysis error for {file_path}")

    def _has_pe_anomalies(self, pe_result: Dict[str, Any]) -> bool:
        """Check if PE analysis found anomalies."""
        # Check for anomalous sections
        for section in pe_result.get('sections', []):
            if section.get('anomalies'):
                return True
                
        # Check for suspicious imports
        for imp in pe_result.get('imports', []):
            if imp.get('suspicious'):
                return True
                
        return False

    def _perform_yara_scan(self, file_path: str, event_type: str) -> None:
        """Perform YARA scanning on the file."""
        try:
            if not self.yara_scanner.rule_manager.rules:
                return
                
            results = self.yara_scanner.scan_file(file_path)
            
            if results:
                rule_names = [r['rule_name'] for r in results]
                RansomwareLogger.log_security_event(
                    'YARA_MATCH', 
                    f'YARA detected matches in {file_path}: {rule_names}',
                    'CRITICAL'
                )
                
                for result in results:
                    self.db.insert_yara_event(
                        file_path, 
                        result['rule_name'], 
                        'MATCH', 
                        'CRITICAL', 
                        str(result)
                    )
            else:
                # No YARA matches but file changed - potential unknown threat
                if event_type == "Файл изменен":
                    alert_message = f'No YARA matches but file changed: {file_path}'
                    RansomwareLogger.log_security_event(
                        'UNKNOWN_THREAT', 
                        alert_message, 
                        'MEDIUM'
                    )
                    self.db.insert_netsec_alert(
                        'UNKNOWN_THREAT', 
                        alert_message, 
                        'MEDIUM', 
                        'File modified without YARA detection'
                    )
                    
        except Exception as e:
            RansomwareLogger.log_error(e, f"YARA scan error for {file_path}")


class EncryptionDetector:
    """Handles encryption detection and mass encryption monitoring."""
    
    def __init__(self, db: Database, crypto_manager: CryptoManager, 
                 mass_encryption_threshold: int, encryption_time_window: int, logger):
        self.db = db
        self.crypto_manager = crypto_manager
        self.mass_encryption_threshold = mass_encryption_threshold
        self.encryption_time_window = encryption_time_window
        self.encryption_events: List[Tuple[datetime, str]] = []
        self.logger = logger

    def check_file_encryption(self, file_path: str, event_type: str) -> None:
        """Check if file appears to be encrypted."""
        try:
            if event_type != "Файл изменен":
                return
                
            if self.crypto_manager.is_file_encrypted(file_path):
                self._handle_encryption_detection(file_path)
        except Exception as e:
            RansomwareLogger.log_error(e, f"Encryption detection error for {file_path}")

    def _handle_encryption_detection(self, file_path: str) -> None:
        """Handle detected file encryption."""
        current_time = datetime.now()
        self.encryption_events.append((current_time, file_path))

        # Log encryption event to database
        self.db.insert_fim_event(file_path, "Файл зашифрован", 'CRITICAL')
        
        RansomwareLogger.log_security_event(
            'FILE_ENCRYPTED',
            f'File encryption detected: {file_path}',
            'CRITICAL'
        )

        # Check for mass encryption
        self._check_mass_encryption()

    def _check_mass_encryption(self) -> None:
        """Check for mass encryption attack."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.encryption_time_window)

        # Clean old events
        self.encryption_events = [(t, f) for t, f in self.encryption_events if t > cutoff_time]

        # Count encryption events in time window
        encryption_count = len(self.encryption_events)

        if encryption_count >= self.mass_encryption_threshold:
            self._trigger_mass_encryption_alert(encryption_count)

    def _trigger_mass_encryption_alert(self, encryption_count: int) -> None:
        """Trigger mass encryption security alert."""
        try:
            affected_files = [f for _, f in self.encryption_events]
            file_list = ', '.join(affected_files[:5])  # Show first 5 files
            
            if encryption_count > 5:
                file_list += f" и еще {encryption_count - 5} файлов"

            alert_message = (f"Массовое шифрование файлов обнаружено: "
                           f"{encryption_count} файлов за {self.encryption_time_window} секунд")
            details = f"Затронутые файлы: {file_list}"

            RansomwareLogger.log_security_event(
                'MASS_ENCRYPTION',
                alert_message,
                'CRITICAL',
                {'affected_files': affected_files, 'count': encryption_count}
            )

            # Log to database
            self.db.insert_netsec_alert(
                'MASS_ENCRYPTION',
                alert_message,
                'CRITICAL',
                json.dumps({
                    'affected_files': affected_files,
                    'count': encryption_count,
                    'time_window': self.encryption_time_window,
                    'timestamp': datetime.now().isoformat()
                })
            )
        except Exception as e:
            RansomwareLogger.log_error(e, "Error triggering mass encryption alert")


class FileEventHandler:
    """Handles file change events and coordinates analysis."""
    
    def __init__(self, db: Database, encryption_detector: EncryptionDetector,
                 threat_analyzer: ThreatAnalyzer, logger):
        self.db = db
        self.encryption_detector = encryption_detector
        self.threat_analyzer = threat_analyzer
        self.logger = logger

    def handle_file_change(self, file_path: str, event_type: str, criticality: str) -> None:
        """Handle file change event."""
        try:
            # Log FIM event
            self.db.insert_fim_event(file_path, event_type, criticality)
            RansomwareLogger.log_security_event(
                'FIM_EVENT',
                f'{event_type}: {file_path}',
                criticality
            )

            # Check for encryption
            self.encryption_detector.check_file_encryption(file_path, event_type)
            
            # Analyze threats
            self.threat_analyzer.analyze_file_threats(file_path, event_type)
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error handling file change for {file_path}")


class FIM(LoggerMixin):
    """File Integrity Monitoring system for ransomware protection."""

    def __init__(self, config_path: str = 'config.json', db_name: str = 'firewall.db'):
        # Core components
        self.config_path = config_path
        self.db = Database(db_name)
        self.crypto_manager = CryptoManager()
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)

        # Initialize specialized components
        self.hash_calculator = FileHashCalculator(self.logger)
        self.directory_scanner = DirectoryScanner(self.hash_calculator, self.logger)
        self.encryption_detector = self._create_encryption_detector()
        self.threat_analyzer = ThreatAnalyzer(
            self.db, self.yara_scanner, self.pe_analyzer, self.logger
        )
        self.file_event_handler = FileEventHandler(
            self.db, self.encryption_detector, self.threat_analyzer, self.logger
        )

        # Configuration
        self.monitor_paths: List[str] = []
        self.check_interval = 4
        self.file_hashes: Dict[str, str] = {}
        self.running = False

        # Load configuration
        self._load_configuration()

    def _create_encryption_detector(self) -> EncryptionDetector:
        """Create encryption detector with configuration."""
        return EncryptionDetector(
            self.db, 
            self.crypto_manager,
            mass_encryption_threshold=5,  # Default values, will be overridden by config
            encryption_time_window=60,
            logger=self.logger
        )

    def _load_configuration(self) -> None:
        """Load system configuration."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # FIM configuration
            fim_config = config.get('fim', {})
            self.monitor_paths = fim_config.get('monitor_paths', ['./'])
            self.check_interval = fim_config.get('check_interval', 4)
            
            # YARA rules configuration
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)

            # Ransomware detection settings
            ransomware_config = config.get('ransomware', {})
            self.encryption_detector.mass_encryption_threshold = ransomware_config.get(
                'mass_encryption_threshold', 5
            )
            self.encryption_detector.encryption_time_window = ransomware_config.get(
                'encryption_time_window', 60
            )

            RansomwareLogger.log_operation('FIM config loaded', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error loading FIM configuration")
            self.monitor_paths = ['./']
            self.check_interval = 4

    def _initialize_file_hashes(self) -> None:
        """Initialize file hash database."""
        for path in self.monitor_paths:
            if os.path.isdir(path):
                self._hash_directory_files(path)
            elif os.path.isfile(path):
                self._hash_single_file(path)

    def _hash_directory_files(self, directory: str) -> None:
        """Hash all files in directory."""
        try:
            file_paths = self.directory_scanner.scan_directory(directory)
            for file_path in file_paths:
                file_hash = self.hash_calculator.calculate_file_hash(file_path)
                if file_hash:
                    self.file_hashes[file_path] = file_hash
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error hashing directory {directory}")

    def _hash_single_file(self, file_path: str) -> None:
        """Hash single file."""
        try:
            file_hash = self.hash_calculator.calculate_file_hash(file_path)
            if file_hash:
                self.file_hashes[file_path] = file_hash
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error hashing file {file_path}")

    def monitor(self) -> None:
        """Start FIM monitoring."""
        self.running = True
        self._initialize_file_hashes()
        
        RansomwareLogger.log_security_event(
            'FIM_START',
            f'FIM monitoring started for paths: {self.monitor_paths}',
            'INFO'
        )

        # Insert initial event to database
        try:
            self.db.insert_fim_event(','.join(self.monitor_paths), "FIM мониторинг запущен", 'INFO')
        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to write initial FIM event")

        while self.running:
            time.sleep(self.check_interval)
            self._check_all_monitored_paths()

    def _check_all_monitored_paths(self) -> None:
        """Check all monitored paths for changes."""
        for path in self.monitor_paths:
            try:
                if os.path.isdir(path):
                    self._check_directory_changes(path)
                elif os.path.isfile(path):
                    self._check_file_changes(path)
            except Exception as e:
                RansomwareLogger.log_error(e, f"Error checking path {path}")

    def _check_directory_changes(self, directory: str) -> None:
        """Check directory for file changes."""
        try:
            current_files = self.directory_scanner.scan_directory(directory)
            
            # Check for new and modified files
            for file_path in current_files:
                current_hash = self.hash_calculator.calculate_file_hash(file_path)
                if file_path not in self.file_hashes:
                    # New file
                    self.file_event_handler.handle_file_change(file_path, "Файл создан", 'INFO')
                    if current_hash:
                        self.file_hashes[file_path] = current_hash
                elif self.file_hashes[file_path] != current_hash:
                    # Modified file
                    self.file_event_handler.handle_file_change(file_path, "Файл изменен", 'CRITICAL')
                    if current_hash:
                        self.file_hashes[file_path] = current_hash

            # Check for deleted files
            self._check_deleted_files(directory, current_files)
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error checking directory {directory}")

    def _check_file_changes(self, file_path: str) -> None:
        """Check single file for changes."""
        try:
            current_hash = self.hash_calculator.calculate_file_hash(file_path)
            if file_path not in self.file_hashes:
                self.file_event_handler.handle_file_change(file_path, "Файл создан", 'INFO')
                if current_hash:
                    self.file_hashes[file_path] = current_hash
            elif self.file_hashes[file_path] != current_hash:
                self.file_event_handler.handle_file_change(file_path, "Файл изменен", 'CRITICAL')
                if current_hash:
                    self.file_hashes[file_path] = current_hash
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error checking file {file_path}")

    def _check_deleted_files(self, directory: str, current_files: Set[str]) -> None:
        """Check for deleted files in directory."""
        try:
            deleted_files = set(self.file_hashes.keys()) - current_files
            for file_path in deleted_files:
                if file_path.startswith(directory):
                    self.file_event_handler.handle_file_change(file_path, "Файл удален", 'WARNING')
                    del self.file_hashes[file_path]
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error checking deleted files in {directory}")

    def stop(self) -> None:
        """Stop FIM monitoring."""
        self.running = False
        RansomwareLogger.log_security_event('FIM_STOP', 'FIM monitoring stopped', 'INFO')
        
    def start_monitoring(self) -> None:
        """Alias for monitor() for compatibility."""
        self.monitor()
