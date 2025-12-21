#!/usr/bin/env python3
"""
Refactored Process Monitor for ransomware protection system.
Provides process monitoring, threat analysis, and ransomware detection.

This module has been refactored to:
- Eliminate code duplication and long methods
- Separate concerns into focused classes
- Use centralized logging and error handling
- Provide better structure and maintainability
"""

import psutil
import time
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from pathlib import Path

from database import Database
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer
from crypto import CryptoManager
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import ProcessError, SecurityAlert, ValidationError, DatabaseError


class ProcessWatcher(LoggerMixin):
    """Handles process monitoring and lifecycle detection."""
    
    def __init__(self, config_path: str, db: Database, check_interval: int = 5):
        self.config_path = config_path
        self.db = db
        self.check_interval = check_interval
        self.running = False
        
        # Process tracking
        self.prev_procs: Dict[int, Tuple[str, str, int]] = {}
        
        # Configuration
        self.network_threshold = 1000000
        self._load_configuration()

    def _load_configuration(self) -> None:
        """Load process monitoring configuration."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            process_config = config.get('process_monitor', {})
            self.network_threshold = process_config.get('network_threshold', 1000000)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error loading process monitoring configuration")

    def start_monitoring(self) -> None:
        """Start the process monitoring loop."""
        self.running = True
        
        RansomwareLogger.log_security_event(
            'PROCESS_MONITOR_START',
            'Process monitoring started',
            'INFO'
        )

        # Initialize process snapshot
        self._initialize_process_snapshot()
        
        # Display current processes
        self._display_current_processes()

        while self.running:
            try:
                self._monitor_processes()
                time.sleep(self.check_interval)
            except Exception as e:
                RansomwareLogger.log_error(e, "Error during process monitoring iteration")

    def stop_monitoring(self) -> None:
        """Stop the process monitoring."""
        self.running = False
        
        RansomwareLogger.log_security_event(
            'PROCESS_MONITOR_STOP',
            'Process monitoring stopped',
            'INFO'
        )

    def _initialize_process_snapshot(self) -> None:
        """Initialize the initial process snapshot."""
        try:
            current_procs = self._scan_processes()
            self.prev_procs = current_procs
            
            # Write startup event to database
            self.db.insert_process_event(0, 'ProcessWatcher', 'Process monitor started', 'INFO')
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to initialize process snapshot")

    def _display_current_processes(self) -> None:
        """Display current running processes."""
        try:
            print("Текущие процессы:")
            print(f"{'PID':<10} {'PPID':<10} {'Имя':<20} {'Путь':<50} {'Аргументы'}")
            print("-" * 100)
            
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
                    
        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to display current processes")

    def _scan_processes(self) -> Dict[int, Tuple[str, str, int]]:
        """Scan all running processes and return current snapshot."""
        current_procs = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.pid
                name = proc.info.get('name') or proc.name()
                exe_path = proc.info.get('exe') or proc.exe()
                network_bytes = self._get_process_network_usage(proc)
                
                current_procs[pid] = (name, exe_path, network_bytes)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return current_procs

    def _get_process_network_usage(self, proc) -> int:
        """Get network usage for a process (placeholder implementation)."""
        try:
            # Use io_counters() for per-process I/O, but network monitoring is system-wide
            # For simplicity, we'll use a different approach or skip detailed network tracking
            # since psutil doesn't provide per-process network counters easily
            return 0  # Placeholder - network monitoring could be implemented differently
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0

    def _monitor_processes(self) -> None:
        """Monitor processes for lifecycle changes."""
        current_procs = self._scan_processes()
        
        # Detect started and terminated processes
        started_procs = {pid: data for pid, data in current_procs.items() if pid not in self.prev_procs}
        terminated_procs = {pid: data for pid, data in self.prev_procs.items() if pid not in current_procs}

        # Process started events
        for pid, (name, exe_path, network_bytes) in started_procs.items():
            self._handle_process_started(pid, name, exe_path, network_bytes)

        # Process terminated events
        for pid, (name, exe_path, network_bytes) in terminated_procs.items():
            self._handle_process_terminated(pid, name, exe_path)

        # Update snapshot
        self.prev_procs = current_procs

    def _handle_process_started(self, pid: int, name: str, exe_path: str, network_bytes: int) -> None:
        """Handle process started event."""
        try:
            self.db.insert_process_event(pid, name, 'process_started', 'INFO')
            RansomwareLogger.log_security_event(
                'PROCESS_STARTED',
                f'Process started: {name} (PID {pid})',
                'INFO'
            )
        except DatabaseError as e:
            RansomwareLogger.log_error(e, f"Failed to log process_started for PID {pid}")

    def _handle_process_terminated(self, pid: int, name: str, exe_path: str) -> None:
        """Handle process terminated event."""
        try:
            self.db.insert_process_event(pid, name, 'process_terminated', 'WARNING')
            RansomwareLogger.log_security_event(
                'PROCESS_TERMINATED',
                f'Process terminated: {name} (PID {pid})',
                'INFO'
            )
        except DatabaseError as e:
            RansomwareLogger.log_error(e, f"Failed to log process_terminated for PID {pid}")


class ProcessAnalyzer(LoggerMixin):
    """Handles process analysis for anomalies and threats."""
    
    def __init__(self, db: Database, yara_scanner: YARAScanner, pe_analyzer: PEAnalyzer):
        self.db = db
        self.yara_scanner = yara_scanner
        self.pe_analyzer = pe_analyzer

    def analyze_process_threats(self, pid: int, name: str, exe_path: str, event_type: str) -> None:
        """Analyze process for security threats."""
        try:
            # Analyze PE files if executable
            if exe_path and self._should_analyze_pe(exe_path, event_type):
                self._perform_pe_analysis(pid, name, exe_path)
            
            # Perform YARA scanning if rules are available
            if exe_path and self._should_scan_yara(exe_path):
                self._perform_yara_scan(pid, name, exe_path)
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing threats for process {name} (PID {pid})")

    def _should_analyze_pe(self, exe_path: str, event_type: str) -> bool:
        """Determine if PE analysis should be performed."""
        return (event_type == 'process_started' and 
                os.path.exists(exe_path) and 
                self.pe_analyzer.is_pe_file(exe_path))

    def _perform_pe_analysis(self, pid: int, name: str, exe_path: str) -> None:
        """Perform PE analysis on the process executable."""
        try:
            pe_result = self.pe_analyzer.analyze_file(exe_path)
            if pe_result and self._has_pe_anomalies(pe_result):
                pe_anomalies = self._extract_pe_anomalies(pe_result)
                
                alert_message = f'PE anomalies detected in {name}: {pe_anomalies}'
                RansomwareLogger.log_security_event(
                    'PE_ANOMALY',
                    alert_message,
                    'HIGH',
                    {'pid': pid, 'exe_path': exe_path}
                )
                
                self.db.insert_netsec_alert(
                    'PROCESS_PE_ANOMALY',
                    alert_message,
                    'HIGH',
                    f"Process: {name}, Exe: {exe_path}, PE anomalies: {pe_anomalies}"
                )
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"PE analysis error for {name} (PID {pid})")

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

    def _extract_pe_anomalies(self, pe_result: Dict[str, Any]) -> List[str]:
        """Extract anomalies from PE analysis result."""
        anomalies = []
        
        # Collect section anomalies
        for section in pe_result.get('sections', []):
            if section.get('anomalies'):
                anomalies.append(f"Section {section['name']}: {section['anomalies']}")
        
        # Collect import anomalies
        for imp in pe_result.get('imports', []):
            if imp.get('suspicious'):
                anomalies.append(f"Suspicious import: {imp['function']}")
                
        return anomalies

    def _should_scan_yara(self, exe_path: str) -> bool:
        """Determine if YARA scanning should be performed."""
        return (os.path.exists(exe_path) and self.yara_scanner.rule_manager.rules)

    def _perform_yara_scan(self, pid: int, name: str, exe_path: str) -> None:
        """Perform YARA scanning on the process executable."""
        try:
            results = self.yara_scanner.scan_file(exe_path)
            
            if results:
                rule_names = [r['rule_name'] for r in results]
                RansomwareLogger.log_security_event(
                    'YARA_MATCH',
                    f'YARA detected matches in {name}: {rule_names}',
                    'CRITICAL'
                )
                
                for result in results:
                    self.db.insert_yara_event(
                        exe_path,
                        result['rule_name'],
                        'MATCH',
                        'CRITICAL',
                        str(result)
                    )
            else:
                # No YARA matches but executable - potential unknown threat
                RansomwareLogger.log_security_event(
                    'YARA_NO_MATCH',
                    f'YARA scan completed - no matches for {name} (potential unknown threat)',
                    'MEDIUM'
                )
                
                self.db.insert_yara_event(
                    exe_path,
                    'No Match',
                    'SCAN_COMPLETED',
                    'MEDIUM',
                    f"Process anomaly: {name} - executable with no YARA matches"
                )
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"YARA scan error for {name} (PID {pid})")


class RansomwareDetector(LoggerMixin):
    """Handles ransomware behavior detection and response."""
    
    def __init__(self, db: Database, crypto_manager: CryptoManager, file_operations_tracker: Dict):
        self.db = db
        self.crypto_manager = crypto_manager
        self.file_operations_tracker = file_operations_tracker
        
        # Ransomware detection settings
        self.vssadmin_suspicious = True
        self.file_extension_blacklist: List[str] = []
        self.process_whitelist: List[str] = []
        self.file_io_threshold = 100
        self.unique_extensions_threshold = 10

    def configure_detection_settings(self, config: Dict[str, Any]) -> None:
        """Configure ransomware detection settings."""
        try:
            ransomware_config = config.get('ransomware', {})
            self.vssadmin_suspicious = ransomware_config.get('vssadmin_suspicious', True)
            self.file_extension_blacklist = ransomware_config.get('file_extension_blacklist', [])
            self.process_whitelist = ransomware_config.get('process_whitelist', [])
        except Exception as e:
            RansomwareLogger.log_error(e, "Error configuring ransomware detection settings")

    def detect_ransomware_behavior(self, pid: int, name: str, exe_path: str, event_type: str) -> None:
        """Detect ransomware behavior in process."""
        try:
            if event_type == 'process_started':
                self._check_startup_ransomware_behavior(pid, name, exe_path)
            elif event_type == 'process_running':
                self._check_running_ransomware_behavior(pid, name, exe_path)
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error detecting ransomware behavior for {name} (PID {pid})")

    def _check_startup_ransomware_behavior(self, pid: int, name: str, exe_path: str) -> None:
        """Check for ransomware behavior when process starts."""
        # Check for vssadmin.exe (Volume Shadow Copy deletion)
        if self.vssadmin_suspicious and name.lower() == 'vssadmin.exe':
            self._trigger_ransomware_alert(
                pid, name, exe_path,
                "Обнаружен vssadmin.exe - потенциальное удаление теневых копий",
                'CRITICAL',
                'RANSOMWARE_BEHAVIOR'
            )

    def _check_running_ransomware_behavior(self, pid: int, name: str, exe_path: str) -> None:
        """Check for ransomware behavior in running processes."""
        current_time = datetime.now()
        
        # Monitor file operations
        if pid in self.file_operations_tracker:
            self._analyze_file_operations(pid, name, exe_path, current_time)

    def _analyze_file_operations(self, pid: int, name: str, exe_path: str, current_time: datetime) -> None:
        """Analyze file operations for ransomware patterns."""
        try:
            recent_ops = [
                (timestamp, operation, file_path) 
                for timestamp, operation, file_path in self.file_operations_tracker[pid]
                if timestamp > current_time - timedelta(minutes=1)
            ]

            # Count file write operations
            write_ops = [op for _, op, _ in recent_ops if op == 'write']
            if len(write_ops) > self.file_io_threshold:
                self._trigger_ransomware_alert(
                    pid, name, exe_path,
                    f"Массовая запись файлов: {len(write_ops)} операций за минуту",
                    'HIGH',
                    'MASS_FILE_OPERATIONS'
                )

            # Check for multiple file extensions
            extensions = self._extract_file_extensions(recent_ops)
            if len(extensions) > self.unique_extensions_threshold:
                self._trigger_ransomware_alert(
                    pid, name, exe_path,
                    f"Доступ к множеству типов файлов: {len(extensions)} расширений",
                    'MEDIUM',
                    'MULTIPLE_FILE_TYPES'
                )

            # Check for blacklisted extensions
            for ext in extensions:
                if ext in self.file_extension_blacklist:
                    self._trigger_ransomware_alert(
                        pid, name, exe_path,
                        f"Доступ к файлам с подозрительным расширением: {ext}",
                        'HIGH',
                        'BLACKLISTED_EXTENSION'
                    )
                    
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing file operations for {name} (PID {pid})")

    def _extract_file_extensions(self, file_operations: List[Tuple[datetime, str, str]]) -> Set[str]:
        """Extract file extensions from file operations."""
        extensions = set()
        for _, _, file_path in file_operations:
            if '.' in file_path:
                ext = os.path.splitext(file_path)[1].lower()
                extensions.add(ext)
        return extensions

    def _trigger_ransomware_alert(self, pid: int, name: str, exe_path: str, 
                                description: str, severity: str, alert_type: str) -> None:
        """Trigger ransomware behavior alert."""
        alert_message = f"Ransomware behavior detected: {description}"

        RansomwareLogger.log_security_event(
            'RANSOMWARE_DETECTED',
            alert_message,
            severity,
            {'pid': pid, 'process_name': name, 'exe_path': exe_path}
        )

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

        except DatabaseError as e:
            RansomwareLogger.log_error(e, f"Failed to log ransomware alert for {name} (PID {pid})")

        # If critical, try to stop the process
        if severity == 'CRITICAL':
            self._terminate_malicious_process(pid, name)

    def _terminate_malicious_process(self, pid: int, name: str) -> None:
        """Terminate malicious process."""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            RansomwareLogger.log_security_event(
                'PROCESS_TERMINATED',
                f"Malicious process {name} (PID {pid}) terminated",
                'INFO'
            )
            
            self.db.insert_process_event(pid, name, 'process_terminated_by_security', 'CRITICAL')
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            RansomwareLogger.log_error(e, f"Failed to terminate process {name} (PID {pid})")


class FileOperationsTracker:
    """Tracks file operations for ransomware detection."""
    
    def __init__(self):
        self.operations: Dict[int, List[Tuple[datetime, str, str]]] = defaultdict(list)
        self.recent_processes: Dict[int, Set[str]] = defaultdict(set)

    def track_operation(self, pid: int, operation: str, file_path: str) -> None:
        """Track file operation."""
        current_time = datetime.now()
        self.operations[pid].append((current_time, operation, file_path))

        # Track file extensions
        if '.' in file_path:
            ext = os.path.splitext(file_path)[1].lower()
            self.recent_processes[pid].add(ext)

    def cleanup_old_operations(self, max_age_minutes: int = 1) -> None:
        """Clean up old file operations."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(minutes=max_age_minutes)
        
        for pid in list(self.operations.keys()):
            self.operations[pid] = [
                (timestamp, op, path) 
                for timestamp, op, path in self.operations[pid] 
                if timestamp > cutoff_time
            ]


class ProcessMonitor(LoggerMixin):
    """Main process monitoring system for ransomware protection."""
    
    def __init__(self, config_path: str = 'config.json', db_name: str = 'firewall.db'):
        self.config_path = config_path
        
        # Core components
        self.db = Database(db_name)
        self.yara_scanner = YARAScanner(db_name)
        self.pe_analyzer = PEAnalyzer(db_name)
        self.crypto_manager = CryptoManager()
        
        # Specialized components
        self.process_watcher = None
        self.process_analyzer = None
        self.ransomware_detector = None
        self.file_operations_tracker = FileOperationsTracker()
        
        # Configuration
        self.running = False
        
        # Initialize system
        self._initialize_components()

    def _initialize_components(self) -> None:
        """Initialize all monitoring components."""
        try:
            # Load configuration
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Initialize process watcher
            process_config = config.get('process_monitor', {})
            check_interval = process_config.get('check_interval', 5)
            self.process_watcher = ProcessWatcher(self.config_path, self.db, check_interval)
            
            # Initialize process analyzer
            self.process_analyzer = ProcessAnalyzer(self.db, self.yara_scanner, self.pe_analyzer)
            
            # Initialize ransomware detector
            self.ransomware_detector = RansomwareDetector(
                self.db, self.crypto_manager, self.file_operations_tracker.operations
            )
            
            # Configure ransomware detection
            self.ransomware_detector.configure_detection_settings(config)
            
            # Compile YARA rules
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)
            
            # Process monitor initialized lazily
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to initialize ProcessMonitor components")

    def monitor(self) -> None:
        """Start the main process monitoring loop."""
        self.running = True
        
        try:
            # Start process watching
            self.process_watcher.start_monitoring()
            
            # Main monitoring loop
            while self.running:
                # Perform threat analysis on all running processes
                self._analyze_running_processes()
                
                # Cleanup old file operations
                self.file_operations_tracker.cleanup_old_operations()
                
                # Sleep for a short time to prevent CPU overload
                time.sleep(1)
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error in main process monitoring loop")
        finally:
            self.stop()

    def _analyze_running_processes(self) -> None:
        """Analyze all running processes for threats."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.pid
                    name = proc.info.get('name') or proc.name()
                    exe_path = proc.info.get('exe') or proc.exe()
                    
                    # Analyze for threats
                    self.process_analyzer.analyze_process_threats(pid, name, exe_path, 'process_running')
                    
                    # Detect ransomware behavior
                    self.ransomware_detector.detect_ransomware_behavior(pid, name, exe_path, 'process_running')
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    RansomwareLogger.log_error(e, f"Error analyzing process {name} (PID {pid})")
                    
        except Exception as e:
            RansomwareLogger.log_error(e, "Error during process analysis")

    def stop(self) -> None:
        """Stop the process monitoring system."""
        self.running = False
        
        if self.process_watcher:
            self.process_watcher.stop_monitoring()
            
        RansomwareLogger.log_security_event(
            'PROCESS_MONITOR_SHUTDOWN',
            'Process monitoring system shutdown',
            'INFO'
        )

    def track_file_operation(self, pid: int, operation: str, file_path: str) -> None:
        """Track file operation for ransomware detection."""
        self.file_operations_tracker.track_operation(pid, operation, file_path)


def main():
    """Command-line interface for process monitoring."""
    import argparse

    parser = argparse.ArgumentParser(description="Process monitoring for ransomware protection")
    parser.add_argument('--config', '-c', default='config.json', help='Configuration file path')
    parser.add_argument('--db', '-d', default='firewall.db', help='Database file path')

    args = parser.parse_args()

    try:
        monitor = ProcessMonitor(args.config, args.db)
        monitor.monitor()
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        RansomwareLogger.log_error(e, "Process monitoring error")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
