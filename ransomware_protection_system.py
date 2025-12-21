#!/usr/bin/env python3
"""
Refactored Ransomware Protection System for ransomware protection system.
Provides structured system management with centralized logging and error handling.
"""

import os
import sys
import time
import threading
import argparse
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Import all modules
from crypto import CryptoManager
from database import Database
from fim import FIM
from process_monitor import ProcessMonitor
from network_sniffer import NetworkSniffer
from pe_analyzer import PEAnalyzer
from yara_scanner import YARAScanner

# Import utilities
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import ConfigurationError, ValidationError, RansomwareProtectionError
from utils.constants import *


class ConfigurationManager(LoggerMixin):
    """Manages system configuration loading and validation."""
    
    def __init__(self, config_path: str = 'config.json'):
        self.config_path = config_path
        self.config = {}
        self.modules = {
            'crypto': True,
            'fim': False,
            'process_monitor': False,
            'network_sniffer': False,
            'pe_analyzer': True,
            'yara_scanner': True
        }

    def load_config(self) -> Dict[str, Any]:
        """Load and validate system configuration."""
        try:
            if not os.path.exists(self.config_path):
                raise ConfigurationError(f"Configuration file not found: {self.config_path}")
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            # Validate and update module settings
            self._validate_module_config()
            
            RansomwareLogger.log_operation('System configuration loaded', True)
            return self.config
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            RansomwareLogger.log_error(e, "Error loading system configuration")
            raise ConfigurationError(f"Configuration loading failed: {e}")

    def _validate_module_config(self) -> None:
        """Validate and update module configuration."""
        try:
            # FIM module configuration
            fim_config = self.config.get('fim', {})
            self.modules['fim'] = fim_config.get('enabled', True)
            
            # Process monitor configuration
            process_config = self.config.get('process_monitor', {})
            self.modules['process_monitor'] = process_config.get('enabled', True)
            
            # Network sniffer configuration (disabled by default)
            network_config = self.config.get('network_sniffer', {})
            self.modules['network_sniffer'] = network_config.get('enabled', False)
            
            # Validate required sections
            required_sections = ['fim', 'process_monitor', 'crypto']
            for section in required_sections:
                if section not in self.config:
                    RansomwareLogger.log_security_event(
                        'CONFIG_MISSING_SECTION',
                        f"Missing required configuration section: {section}",
                        'WARNING'
                    )
            
            RansomwareLogger.log_operation('Module configuration validated', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error validating module configuration")

    def get_module_config(self) -> Dict[str, bool]:
        """Get current module configuration."""
        return self.modules.copy()

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if specific module is enabled."""
        return self.modules.get(module_name, False)

    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback."""
        return self.config.get(key, default)


class EventAggregator(LoggerMixin):
    """Aggregates events from all system modules."""
    
    def __init__(self, db: Database):
        self.db = db
        self.aggregation_window = timedelta(minutes=5)

    def get_recent_events(self, event_types: List[str], limit: int = 100) -> Dict[str, List]:
        """Get recent events from specified event types."""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - self.aggregation_window
            
            events = {}
            
            for event_type in event_types:
                try:
                    all_events = self.db.query_events(event_type, limit)
                    recent_events = [
                        event for event in all_events 
                        if len(event) > 1 and event[1] > cutoff_time.isoformat()
                    ]
                    events[event_type] = recent_events
                except Exception as e:
                    RansomwareLogger.log_error(e, f"Error getting events for {event_type}")
                    events[event_type] = []
            
            return events
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error aggregating recent events")
            return {}

    def get_event_statistics(self) -> Dict[str, int]:
        """Get statistics for all event types."""
        try:
            stats = {}
            
            for table_name in [DB_TABLE_FIM_EVENTS, DB_TABLE_PROCESS_EVENTS, 
                             DB_TABLE_NETSEC_ALERTS, DB_TABLE_YARA_EVENTS]:
                try:
                    events = self.db.query_events(table_name, 1000)
                    stats[table_name] = len(events)
                except Exception as e:
                    RansomwareLogger.log_error(e, f"Error getting stats for {table_name}")
                    stats[table_name] = 0
            
            return stats
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error getting event statistics")
            return {}


class CorrelationEngine(LoggerMixin):
    """Correlates events from different modules to detect ransomware attacks."""
    
    def __init__(self, db: Database, event_aggregator: EventAggregator):
        self.db = db
        self.event_aggregator = event_aggregator
        self.correlation_interval = 30  # seconds
        self.running = False

    def start_correlation(self) -> None:
        """Start the correlation engine."""
        self.running = True
        
        while self.running:
            try:
                self._correlate_events()
                time.sleep(self.correlation_interval)
            except Exception as e:
                RansomwareLogger.log_error(e, "Error in correlation engine")
                time.sleep(60)  # Wait longer on error

    def stop_correlation(self) -> None:
        """Stop the correlation engine."""
        self.running = False

    def _correlate_events(self) -> None:
        """Correlate recent events to detect ransomware patterns."""
        try:
            # Get recent events from all sources
            event_types = [DB_TABLE_FIM_EVENTS, DB_TABLE_PROCESS_EVENTS, DB_TABLE_NETSEC_ALERTS]
            recent_events = self.event_aggregator.get_recent_events(event_types, 100)
            
            # Get correlated events from database
            fim_events = recent_events.get(DB_TABLE_FIM_EVENTS, [])
            process_events = recent_events.get(DB_TABLE_PROCESS_EVENTS, [])
            network_events = recent_events.get(DB_TABLE_NETSEC_ALERTS, [])
            
            # Perform correlation
            attack_id = self.db.correlate_ransomware_events(fim_events, process_events, network_events)
            
            if attack_id:
                RansomwareLogger.log_security_event(
                    'RANSOMWARE_ATTACK_DETECTED',
                    f"Ransomware attack detected and correlated: ID {attack_id}",
                    'CRITICAL'
                )
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error correlating events")


class StatusReporter(LoggerMixin):
    """Generates system status reports and displays information."""
    
    def __init__(self, db: Database, config_manager: ConfigurationManager):
        self.db = db
        self.config_manager = config_manager

    def display_system_status(self, running: bool) -> None:
        """Display comprehensive system status."""
        try:
            print("\n" + "=" * 60)
            print("СТАТУС СИСТЕМЫ ЗАЩИТЫ ОТ ПРОГРАММ-ВЫМОГАТЕЛЕЙ")
            print("=" * 60)
            print(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # System info
            config = self.config_manager.config
            db_name = config.get('database', {}).get('name', 'firewall.db')
            config_path = self.config_manager.config_path
            
            print(f"База данных: {db_name}")
            print(f"Конфигурация: {config_path}")
            print(f"Статус: {SYSTEM_RUNNING if running else SYSTEM_STOPPED}")
            
            # Module status
            self._display_module_status()
            
            # Event statistics
            self._display_event_statistics()
            
            print("=" * 60)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying system status")

    def _display_module_status(self) -> None:
        """Display status of all system modules."""
        print("\nМодули системы:")
        
        modules = self.config_manager.get_module_config()
        
        for module, enabled in modules.items():
            status_icon = "✓" if enabled else "✗"
            module_name = MODULE_NAMES.get(module, module)
            status_text = "Включен" if enabled else "Отключен"
            print(f"  {status_icon} {module_name}: {status_text}")

    def _display_event_statistics(self) -> None:
        """Display event statistics."""
        try:
            event_aggregator = EventAggregator(self.db)
            stats = event_aggregator.get_event_statistics()
            
            print(f"\nСтатистика событий:")
            print(f"  FIM события: {stats.get(DB_TABLE_FIM_EVENTS, 0)}")
            print(f"  События процессов: {stats.get(DB_TABLE_PROCESS_EVENTS, 0)}")
            print(f"  Оповещения безопасности: {stats.get(DB_TABLE_NETSEC_ALERTS, 0)}")
            print(f"  YARA события: {stats.get(DB_TABLE_YARA_EVENTS, 0)}")
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying event statistics")

    def display_alerts(self, limit: int = 20) -> None:
        """Display recent security alerts."""
        print(f"\nПоследние {limit} оповещений системы безопасности:")
        print("-" * 80)
        
        try:
            alerts = self.db.query_events(DB_TABLE_NETSEC_ALERTS, limit)
            
            if not alerts:
                print("Оповещения безопасности отсутствуют")
                return
            
            for alert in alerts:
                self._display_single_alert(alert)
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying alerts")

    def _display_single_alert(self, alert: tuple) -> None:
        """Display a single security alert."""
        try:
            timestamp = alert[1] if len(alert) > 1 else "Unknown"
            alert_type = alert[2] if len(alert) > 2 else "Unknown"
            description = alert[3] if len(alert) > 3 else "No description"
            severity = alert[4] if len(alert) > 4 else SEVERITY_INFO
            
            severity_icon = SEVERITY_COLORS.get(severity, SEVERITY_INFO)
            
            print(f"{severity_icon} [{severity}] {timestamp}")
            print(f"   Тип: {alert_type}")
            print(f"   Описание: {description}")
            
            if len(alert) > 5 and alert[5]:  # details
                print(f"   Детали: {alert[5]}")
            print()
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying single alert")

    def display_ransomware_attacks(self, hours: int = 24) -> None:
        """Display recent ransomware attacks."""
        print(f"\nАтаки программ-вымогателей за последние {hours} часов:")
        print("-" * 80)
        
        try:
            attacks = self.db.get_recent_ransomware_attacks(hours)
            
            if not attacks:
                print("Атаки программ-вымогателей не обнаружены")
                return

            for attack in attacks:
                self._display_single_attack(attack)
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying ransomware attacks")

    def _display_single_attack(self, attack: tuple) -> None:
        """Display a single ransomware attack."""
        try:
            timestamp = attack[1] if len(attack) > 1 else "Unknown"
            confidence = attack[2] if len(attack) > 2 else 0.0
            attack_type = attack[3] if len(attack) > 3 else "Unknown"
            description = attack[4] if len(attack) > 4 else "No description"
            status = attack[10] if len(attack) > 10 else "Unknown"
            
            confidence_icon = "🔴" if confidence >= 0.8 else "🟠" if confidence >= 0.6 else "🟡"
            
            print(f"{confidence_icon} [{confidence:.2f}] {timestamp}")
            print(f"   Тип атаки: {attack_type}")
            print(f"   Описание: {description}")
            print(f"   Статус: {status}")
            
            if len(attack) > 5 and attack[5]:  # affected files
                try:
                    files = json.loads(attack[5])
                    if files:
                        print(f"   Затронутые файлы: {len(files)}")
                except:
                    print(f"   Затронутые файлы: Data unavailable")
            print()
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error displaying single attack")


class SystemManager(LoggerMixin):
    """Manages the lifecycle and coordination of all system components."""
    
    def __init__(self, config_path: str = 'config.json', db_name: str = 'firewall.db'):
        self.config_path = config_path
        self.db_name = db_name
        self.running = False
        self.threads = []
        
        # Initialize core components
        self.db = Database(db_name)
        self.config_manager = ConfigurationManager(config_path)
        self.event_aggregator = EventAggregator(self.db)
        self.correlation_engine = CorrelationEngine(self.db, self.event_aggregator)
        self.status_reporter = StatusReporter(self.db, self.config_manager)
        
        # Initialize core components
        self.crypto_manager = CryptoManager()
        self.fim = None
        self.process_monitor = None
        self.network_sniffer = None
        self.pe_analyzer = None
        self.yara_scanner = None
        
        # Initialize flags for lazy loading
        self._yara_initialized = False
        self._pe_initialized = False
        self._fim_initialized = False
        self._process_initialized = False
        self._network_initialized = False

    @property
    def yara_scanner(self):
        """Lazy initialization of YARA scanner."""
        if not self._yara_initialized:
            self._yara_scanner = YARAScanner(self.db_name)
            self._yara_initialized = True
        return self._yara_scanner

    @yara_scanner.setter
    def yara_scanner(self, value):
        self._yara_scanner = value
        self._yara_initialized = True

    @property
    def pe_analyzer(self):
        """Lazy initialization of PE analyzer."""
        if not self._pe_initialized:
            self._pe_analyzer = PEAnalyzer(self.db_name, self.config_path)
            self._pe_initialized = True
        return self._pe_analyzer

    @pe_analyzer.setter
    def pe_analyzer(self, value):
        self._pe_analyzer = value
        self._pe_initialized = True

    @property
    def fim(self):
        """Lazy initialization of FIM module."""
        if not self._fim_initialized and self.config_manager.is_module_enabled('fim'):
            self._fim = FIM(self.config_path, self.db_name)
            self._fim_initialized = True
        return getattr(self, '_fim', None)

    @fim.setter
    def fim(self, value):
        self._fim = value
        self._fim_initialized = True

    @property
    def process_monitor(self):
        """Lazy initialization of process monitor."""
        if not self._process_initialized and self.config_manager.is_module_enabled('process_monitor'):
            self._process_monitor = ProcessMonitor(self.config_path, self.db_name)
            self._process_initialized = True
        return getattr(self, '_process_monitor', None)

    @process_monitor.setter
    def process_monitor(self, value):
        self._process_monitor = value
        self._process_initialized = True

    @property
    def network_sniffer(self):
        """Lazy initialization of network sniffer."""
        if not self._network_initialized and self.config_manager.is_module_enabled('network_sniffer'):
            self._network_sniffer = NetworkSniffer('ens33', '', self.db_name, self.config_path)
            self._network_initialized = True
        return getattr(self, '_network_sniffer', None)

    @network_sniffer.setter
    def network_sniffer(self, value):
        self._network_sniffer = value
        self._network_initialized = True

    def _initialize_system(self) -> None:
        """Initialize system components."""
        try:
            self.config_manager.load_config()
            
            # Initialize YARA scanner and PE analyzer immediately (always needed)
            if not hasattr(self, '_yara_initialized') or not self._yara_initialized:
                self.yara_scanner = YARAScanner(self.db_name)
                self._yara_initialized = True
            
            if not hasattr(self, '_pe_initialized') or not self._pe_initialized:
                self.pe_analyzer = PEAnalyzer(self.db_name, self.config_path)
                self._pe_initialized = True
            
            RansomwareLogger.log_operation('System configuration loaded', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error initializing system components")
            raise RansomwareProtectionError("System initialization failed")

    def start_protection(self) -> bool:
        """Start the ransomware protection system."""
        if self.running:
            print("Система защиты уже запущена")
            return True

        print("=" * 60)
        print("ЗАПУСК ГИБРИДНОЙ СИСТЕМЫ ЗАЩИТЫ ОТ ПРОГРАММ-ВЫМОГАТЕЛЕЙ")
        print("=" * 60)
        
        self.running = True
        
        try:
            # Start security modules
            self._start_security_modules()
            
            # Start correlation engine
            self._start_correlation_engine()
            
            print("✓ Система защиты запущена успешно")
            print("✓ Все модули работают в режиме реального времени")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error starting protection system")
            self.stop_protection()
            return False

    def _start_security_modules(self) -> None:
        """Start all enabled security modules."""
        try:
            # Start FIM monitoring
            if self.fim:
                print("Запуск FIM мониторинга...")
                fim_thread = threading.Thread(target=self._start_fim_monitoring, daemon=True)
                fim_thread.start()
                self.threads.append(fim_thread)
                time.sleep(1)

            # Start process monitoring
            if self.process_monitor:
                print("Запуск мониторинга процессов...")
                process_thread = threading.Thread(target=self._start_process_monitoring, daemon=True)
                process_thread.start()
                self.threads.append(process_thread)
                time.sleep(1)

            # Start network sniffer (optional)
            if self.network_sniffer:
                print("Запуск сетевого сниффера...")
                network_thread = threading.Thread(target=self._start_network_monitoring, daemon=True)
                network_thread.start()
                self.threads.append(network_thread)
                time.sleep(1)
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error starting security modules")

    def _start_correlation_engine(self) -> None:
        """Start the event correlation engine."""
        try:
            print("Запуск движка корреляции событий...")
            correlation_thread = threading.Thread(target=self.correlation_engine.start_correlation, daemon=True)
            correlation_thread.start()
            self.threads.append(correlation_thread)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error starting correlation engine")

    def _start_fim_monitoring(self) -> None:
        """Start FIM monitoring in a separate thread."""
        try:
            self.fim.start_monitoring()
        except Exception as e:
            RansomwareLogger.log_error(e, "FIM monitoring error")

    def _start_process_monitoring(self) -> None:
        """Start process monitoring in a separate thread."""
        try:
            self.process_monitor.monitor()
        except Exception as e:
            RansomwareLogger.log_error(e, "Process monitoring error")

    def _start_network_monitoring(self) -> None:
        """Start network monitoring in a separate thread."""
        try:
            self.network_sniffer.start_sniffing()
        except Exception as e:
            RansomwareLogger.log_error(e, "Network monitoring error")

    def stop_protection(self) -> None:
        """Stop the ransomware protection system."""
        if not self.running:
            print("Система защиты не запущена")
            return

        print("\nОстановка системы защиты...")
        self.running = False

        try:
            # Stop correlation engine
            self.correlation_engine.stop_correlation()
            
            # Stop individual modules
            if self.fim:
                self.fim.stop()
            if self.process_monitor:
                self.process_monitor.stop()
            # Network sniffer doesn't have a stop method, so we'll let it die naturally
            
            # Wait for threads to finish
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=2)

            print("✓ Система защиты остановлена")
            print("=" * 60)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error stopping protection system")

    def encrypt_file(self, file_path: str, key_file: str = None) -> bool:
        """Manually encrypt a file."""
        try:
            if not os.path.exists(file_path):
                print(f"Файл не найден: {file_path}")
                return False

            RansomwareLogger.log_operation(f'Manual encryption started: {file_path}', False)
            print(f"Шифрование файла: {file_path}")
            
            success = self.crypto_manager.encrypt_file(file_path, key_file)
            
            if success:
                print(f"✓ Файл успешно зашифрован: {file_path}")
                self.db.insert_fim_event(file_path, "Файл зашифрован вручную", SEVERITY_INFO)
                RansomwareLogger.log_operation(f'Manual encryption completed: {file_path}', True)
            else:
                print(f"✗ Ошибка шифрования файла: {file_path}")
                RansomwareLogger.log_operation(f'Manual encryption failed: {file_path}', False)
            
            return success
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error encrypting file {file_path}")
            return False

    def decrypt_file(self, file_path: str, key_file: str = None) -> bool:
        """Manually decrypt a file."""
        try:
            RansomwareLogger.log_operation(f'Manual decryption started: {file_path}', False)
            print(f"Дешифрование файла: {file_path}")
            
            success = self.crypto_manager.decrypt_file(file_path, key_file)
            
            if success:
                print(f"✓ Файл успешно расшифрован: {file_path}")
                self.db.insert_fim_event(file_path, "Файл расшифрован вручную", SEVERITY_INFO)
                RansomwareLogger.log_operation(f'Manual decryption completed: {file_path}', True)
            else:
                print(f"✗ Ошибка дешифрования файла: {file_path}")
                RansomwareLogger.log_operation(f'Manual decryption failed: {file_path}', False)
            
            return success
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error decrypting file {file_path}")
            return False

    def attempt_rollback(self, file_path: str, backup_path: str = None) -> bool:
        """Attempt to rollback a file."""
        print(f"\nПопытка отката файла: {file_path}")
        print("-" * 40)
        
        try:
            RansomwareLogger.log_operation(f'Rollback attempt: {file_path}', False)
            success = self.db.attempt_rollback(file_path, backup_path)
            
            if success:
                print(f"✓ Откат файла {file_path} выполнен успешно")
                self.db.insert_fim_event(file_path, "Файл восстановлен из резервной копии", SEVERITY_INFO)
                RansomwareLogger.log_operation(f'Rollback completed: {file_path}', True)
            else:
                print(f"✗ Ошибка отката файла {file_path}")
                RansomwareLogger.log_operation(f'Rollback failed: {file_path}', False)
            
            return success
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error during rollback of {file_path}")
            return False

    def cleanup_system(self, days: int = 30) -> None:
        """Clean up old events from database."""
        print(f"\nОчистка старых событий (старше {days} дней)...")
        
        try:
            RansomwareLogger.log_operation(f'Database cleanup started (>{days} days)', False)
            self.db.cleanup_old_events(days)
            print("✓ Очистка базы данных завершена")
            RansomwareLogger.log_operation('Database cleanup completed', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error during cleanup")

    def create_test_files(self, directory: str = "./test_files") -> None:
        """Create test files for encryption/decryption testing."""
        os.makedirs(directory, exist_ok=True)
        
        test_files = [
            "document.txt",
            "spreadsheet.xlsx", 
            "presentation.pptx",
            "image.jpg",
            "data.json"
        ]
        
        print(f"\nСоздание тестовых файлов в {directory}:")
        
        try:
            for filename in test_files:
                file_path = os.path.join(directory, filename)
                content = f"Тестовый файл {filename}\nСоздан: {datetime.now()}\nСодержимое для тестирования шифрования."
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"  ✓ Создан: {filename}")
            
            print(f"✓ Создано {len(test_files)} тестовых файлов")
            RansomwareLogger.log_operation(f'Test files created in {directory}', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error creating test files")

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information."""
        return {
            'running': self.running,
            'config_path': self.config_path,
            'db_name': self.db_name,
            'modules': self.config_manager.get_module_config(),
            'components': {
                'database': self.db is not None,
                'crypto_manager': self.crypto_manager is not None,
                'fim': self.fim is not None,
                'process_monitor': self.process_monitor is not None,
                'network_sniffer': self.network_sniffer is not None,
                'pe_analyzer': self.pe_analyzer is not None,
                'yara_scanner': self.yara_scanner is not None
            }
        }


class CLIHandler(LoggerMixin):
    """Handles command-line interface operations."""
    
    def __init__(self, system_manager: SystemManager):
        self.system_manager = system_manager
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for CLI."""
        parser = argparse.ArgumentParser(
            description='Гибридная система защиты от программ-вымогателей',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Примеры использования:
  %(prog)s start                    # Запустить систему защиты
  %(prog)s stop                     # Остановить систему защиты
  %(prog)s status                   # Показать статус системы
  %(prog)s encrypt test.txt         # Зашифровать файл
  %(prog)s decrypt test.txt.encrypted # Расшифровать файл
  %(prog)s alerts                   # Показать оповещения
  %(prog)s attacks                  # Показать атаки ransomware
  %(prog)s rollback test.txt        # Откатить файл
  %(prog)s cleanup 30               # Очистить события старше 30 дней
            """
        )
        
        parser.add_argument('--config', default='config.json', help='Путь к файлу конфигурации')
        parser.add_argument('--db', default='firewall.db', help='Имя файла базы данных')
        
        subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
        
        # Start command
        subparsers.add_parser('start', help='Запустить систему защиты')
        
        # Stop command
        subparsers.add_parser('stop', help='Остановить систему защиты')
        
        # Status command
        subparsers.add_parser('status', help='Показать статус системы')
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Зашифровать файл')
        encrypt_parser.add_argument('file', help='Путь к файлу для шифрования')
        encrypt_parser.add_argument('--key', help='Путь к файлу ключа')
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Расшифровать файл')
        decrypt_parser.add_argument('file', help='Путь к файлу для дешифрования')
        decrypt_parser.add_argument('--key', help='Путь к файлу ключа')
        
        # Alerts command
        alerts_parser = subparsers.add_parser('alerts', help='Показать оповещения системы')
        alerts_parser.add_argument('--limit', type=int, default=20, help='Количество оповещений для показа')
        
        # Attacks command
        attacks_parser = subparsers.add_parser('attacks', help='Показать атаки ransomware')
        attacks_parser.add_argument('--hours', type=int, default=24, help='Количество часов для анализа')
        
        # Rollback command
        rollback_parser = subparsers.add_parser('rollback', help='Откатить файл')
        rollback_parser.add_argument('file', help='Путь к файлу для отката')
        rollback_parser.add_argument('--backup', help='Путь к резервной копии')
        
        # Cleanup command
        cleanup_parser = subparsers.add_parser('cleanup', help='Очистить старые события')
        cleanup_parser.add_argument('days', type=int, default=30, help='Количество дней для хранения')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Создать тестовые файлы')
        test_parser.add_argument('--dir', default='./test_files', help='Директория для тестовых файлов')
        
        return parser

    def handle_command(self, args: Optional[List[str]] = None) -> None:
        """Handle command-line arguments."""
        try:
            parsed_args = self.parser.parse_args(args)
            
            if not parsed_args.command:
                self.parser.print_help()
                return
            
            self._execute_command(parsed_args)
            
        except KeyboardInterrupt:
            print("\nПрервано пользователем")
            if self.system_manager.running:
                self.system_manager.stop_protection()
        except Exception as e:
            RansomwareLogger.log_error(e, "Error handling CLI command")
            print(f"Ошибка: {e}")

    def _execute_command(self, args: argparse.Namespace) -> None:
        """Execute the parsed command."""
        try:
            if args.command == 'start':
                if self.system_manager.start_protection():
                    print("\nСистема запущена. Нажмите Ctrl+C для остановки...")
                    try:
                        while self.system_manager.running:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        self.system_manager.stop_protection()
            
            elif args.command == 'stop':
                self.system_manager.stop_protection()
            
            elif args.command == 'status':
                self.system_manager.status_reporter.display_system_status(self.system_manager.running)
            
            elif args.command == 'encrypt':
                self.system_manager.encrypt_file(args.file, args.key)
            
            elif args.command == 'decrypt':
                self.system_manager.decrypt_file(args.file, args.key)
            
            elif args.command == 'alerts':
                self.system_manager.status_reporter.display_alerts(args.limit)
            
            elif args.command == 'attacks':
                self.system_manager.status_reporter.display_ransomware_attacks(args.hours)
            
            elif args.command == 'rollback':
                self.system_manager.attempt_rollback(args.file, args.backup)
            
            elif args.command == 'cleanup':
                self.system_manager.cleanup_system(args.days)
            
            elif args.command == 'test':
                self.system_manager.create_test_files(args.dir)
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error executing command: {args.command}")
            raise


def main():
    """Main entry point for the ransomware protection system."""
    try:
        # Setup logging
        RansomwareLogger()
        
        # Initialize CLI handler
        cli_handler = CLIHandler(None)  # Temporary initialization
        
        # Parse arguments to get config and db paths
        temp_parser = argparse.ArgumentParser(add_help=False)
        temp_parser.add_argument('--config', default='config.json')
        temp_parser.add_argument('--db', default='firewall.db')
        temp_args, remaining_args = temp_parser.parse_known_args()
        
        # Initialize system manager
        system_manager = SystemManager(temp_args.config, temp_args.db)
        
        # Update CLI handler with system manager
        cli_handler.system_manager = system_manager
        
        # Handle command
        cli_handler.handle_command(remaining_args)
        
    except Exception as e:
        RansomwareLogger.log_error(e, "Fatal error in main")
        print(f"Критическая ошибка: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
