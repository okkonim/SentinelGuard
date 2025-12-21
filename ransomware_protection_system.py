#!/usr/bin/env python3
"""
Гибридная система защиты от программ-вымогателей
Комплексная система защиты от ransomware с интеграцией криптографии, FIM, поведенческого и сетевого анализа
"""

import os
import sys
import time
import threading
import argparse
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Import all modules
from crypto import CryptoManager
from database import Database
from fim import FIM
from process_monitor import ProcessMonitor
from network_sniffer import NetworkSniffer
from pe_analyzer import PEAnalyzer
from yara_scanner import YARAScanner

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ransomware_protection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class RansomwareProtectionSystem:
    """Main integrated ransomware protection system"""

    def __init__(self, config_path='config.json', db_name='firewall.db'):
        self.config_path = config_path
        self.db_name = db_name
        self.db = Database(db_name)
        
        # Initialize all components
        self.crypto_manager = CryptoManager()
        self.fim = FIM(config_path, db_name)
        self.process_monitor = ProcessMonitor(config_path, db_name)
        self.network_sniffer = NetworkSniffer('ens33', '', db_name, config_path)
        self.pe_analyzer = PEAnalyzer(db_name, config_path)
        self.yara_scanner = YARAScanner(db_name)

        # System status
        self.running = False
        self.modules = {
            'crypto': True,
            'fim': False,
            'process_monitor': False,
            'network_sniffer': False,
            'pe_analyzer': True,
            'yara_scanner': True
        }

        # Load configuration
        self.load_system_config()

    def load_system_config(self):
        """Load system configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Configure modules based on settings
            fim_config = config.get('fim', {})
            self.modules['fim'] = fim_config.get('enabled', True)
            
            process_config = config.get('process_monitor', {})
            self.modules['process_monitor'] = process_config.get('enabled', True)
            
            network_config = config.get('network_sniffer', {})
            self.modules['network_sniffer'] = network_config.get('enabled', False)  # Disabled by default
            
            logger.info("Системная конфигурация загружена")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")

    def start_protection(self):
        """Start the ransomware protection system"""
        if self.running:
            print("Система защиты уже запущена")
            return

        print("=" * 60)
        print("ЗАПУСК ГИБРИДНОЙ СИСТЕМЫ ЗАЩИТЫ ОТ ПРОГРАММ-ВЫМОГАТЕЛЕЙ")
        print("=" * 60)
        
        self.running = True
        self.threads = []

        try:
            # Start FIM monitoring
            if self.modules['fim']:
                print("Запуск FIM мониторинга...")
                fim_thread = threading.Thread(target=self.fim.monitor, daemon=True)
                fim_thread.start()
                self.threads.append(fim_thread)
                time.sleep(1)

            # Start process monitoring
            if self.modules['process_monitor']:
                print("Запуск мониторинга процессов...")
                process_thread = threading.Thread(target=self._start_process_monitoring, daemon=True)
                process_thread.start()
                self.threads.append(process_thread)
                time.sleep(1)

            # Start network sniffer (optional)
            if self.modules['network_sniffer']:
                print("Запуск сетевого сниффера...")
                network_thread = threading.Thread(target=self._start_network_monitoring, daemon=True)
                network_thread.start()
                self.threads.append(network_thread)
                time.sleep(1)

            # Start correlation engine
            print("Запуск движка корреляции событий...")
            correlation_thread = threading.Thread(target=self._start_correlation_engine, daemon=True)
            correlation_thread.start()
            self.threads.append(correlation_thread)

            print("✓ Система защиты запущена успешно")
            print("✓ Все модули работают в режиме реального времени")
            print("=" * 60)

        except Exception as e:
            logger.error(f"Ошибка запуска системы: {e}")
            self.stop_protection()

    def stop_protection(self):
        """Stop the ransomware protection system"""
        if not self.running:
            print("Система защиты не запущена")
            return

        print("\nОстановка системы защиты...")
        self.running = False

        # Stop individual modules
        try:
            self.fim.stop()
            self.process_monitor.stop()
            # Network sniffer doesn't have a stop method, so we'll let it die naturally
        except Exception as e:
            logger.error(f"Ошибка остановки модулей: {e}")

        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)

        print("✓ Система защиты остановлена")
        print("=" * 60)

    def _start_fim_monitoring(self):
        """Start FIM monitoring in a separate thread"""
        try:
            self.fim.start_monitoring()
        except Exception as e:
            logger.error(f"FIM monitoring error: {e}")

    def _start_process_monitoring(self):
        """Start process monitoring in a separate thread"""
        try:
            self.process_monitor.monitor()
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")

    def _start_network_monitoring(self):
        """Start network monitoring in a separate thread"""
        try:
            self.network_sniffer.start_sniffing()
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")

    def _start_correlation_engine(self):
        """Start event correlation engine"""
        while self.running:
            try:
                # Get recent events for correlation (last 5 minutes)
                current_time = datetime.now()
                cutoff_time = current_time.replace(second=0, microsecond=0)

                # Get recent FIM events
                fim_events = self.db.query_events('fim_events', 100)
                recent_fim = [e for e in fim_events if e[1] > cutoff_time.isoformat()]

                # Get recent process events
                process_events = self.db.query_events('process_events', 100)
                recent_process = [e for e in process_events if e[1] > cutoff_time.isoformat()]

                # Get recent network alerts
                network_events = self.db.query_events('netsec_alerts', 100)
                recent_network = [e for e in network_events if e[1] > cutoff_time.isoformat()]

                # Correlate events every 30 seconds
                attack_id = self.db.correlate_ransomware_events(recent_fim, recent_process, recent_network)

                if attack_id:
                    logger.warning(f"Ransomware attack detected and correlated: ID {attack_id}")

                time.sleep(30)
            except Exception as e:
                logger.error(f"Correlation engine error: {e}")
                time.sleep(60)  # Wait longer on error

    def encrypt_file(self, file_path: str, key_file: str = None) -> bool:
        """Manually encrypt a file"""
        try:
            if not os.path.exists(file_path):
                print(f"Файл не найден: {file_path}")
                return False

            print(f"Шифрование файла: {file_path}")
            success = self.crypto_manager.encrypt_file(file_path, key_file)
            
            if success:
                print(f"✓ Файл успешно зашифрован: {file_path}")
                # Log to database
                self.db.insert_fim_event(file_path, "Файл зашифрован вручную", 'INFO')
            else:
                print(f"✗ Ошибка шифрования файла: {file_path}")
            
            return success
        except Exception as e:
            logger.error(f"Error encrypting file {file_path}: {e}")
            return False

    def decrypt_file(self, file_path: str, key_file: str = None) -> bool:
        """Manually decrypt a file"""
        try:
            print(f"Дешифрование файла: {file_path}")
            success = self.crypto_manager.decrypt_file(file_path, key_file)
            
            if success:
                print(f"✓ Файл успешно расшифрован: {file_path}")
                # Log to database
                self.db.insert_fim_event(file_path, "Файл расшифрован вручную", 'INFO')
            else:
                print(f"✗ Ошибка дешифрования файла: {file_path}")
            
            return success
        except Exception as e:
            logger.error(f"Error decrypting file {file_path}: {e}")
            return False

    def view_alerts(self, limit: int = 20):
        """View recent security alerts"""
        print(f"\nПоследние {limit} оповещений системы безопасности:")
        print("-" * 80)
        
        try:
            alerts = self.db.query_events('netsec_alerts', limit)
            for alert in alerts:
                timestamp = alert[1]
                alert_type = alert[2]
                description = alert[3]
                severity = alert[4]
                
                severity_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                
                print(f"{severity_icon} [{severity}] {timestamp}")
                print(f"   Тип: {alert_type}")
                print(f"   Описание: {description}")
                if alert[5]:  # details
                    print(f"   Детали: {alert[5]}")
                print()
        except Exception as e:
            logger.error(f"Error viewing alerts: {e}")

    def view_ransomware_attacks(self, hours: int = 24):
        """View recent ransomware attacks"""
        print(f"\nАтаки программ-вымогателей за последние {hours} часов:")
        print("-" * 80)
        
        try:
            attacks = self.db.get_recent_ransomware_attacks(hours)
            if not attacks:
                print("Атаки программ-вымогателей не обнаружены")
                return

            for attack in attacks:
                timestamp = attack[1]
                confidence = attack[2]
                attack_type = attack[3]
                description = attack[4]
                status = attack[10]
                
                confidence_icon = "🔴" if confidence >= 0.8 else "🟠" if confidence >= 0.6 else "🟡"
                
                print(f"{confidence_icon} [{confidence:.2f}] {timestamp}")
                print(f"   Тип атаки: {attack_type}")
                print(f"   Описание: {description}")
                print(f"   Статус: {status}")
                if attack[5]:  # affected files
                    import json
                    files = json.loads(attack[5])
                    if files:
                        print(f"   Затронутые файлы: {len(files)}")
                print()
        except Exception as e:
            logger.error(f"Error viewing ransomware attacks: {e}")

    def attempt_rollback(self, file_path: str, backup_path: str = None) -> bool:
        """Attempt to rollback a file"""
        print(f"\nПопытка отката файла: {file_path}")
        print("-" * 40)
        
        try:
            success = self.db.attempt_rollback(file_path, backup_path)
            
            if success:
                print(f"✓ Откат файла {file_path} выполнен успешно")
                self.db.insert_fim_event(file_path, "Файл восстановлен из резервной копии", 'INFO')
            else:
                print(f"✗ Ошибка отката файла {file_path}")
            
            return success
        except Exception as e:
            logger.error(f"Error during rollback of {file_path}: {e}")
            return False

    def system_status(self):
        """Display system status"""
        print("\n" + "=" * 60)
        print("СТАТУС СИСТЕМЫ ЗАЩИТЫ ОТ ПРОГРАММ-ВЫМОГАТЕЛЕЙ")
        print("=" * 60)
        print(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"База данных: {self.db_name}")
        print(f"Конфигурация: {self.config_path}")
        print(f"Статус: {'РАБОТАЕТ' if self.running else 'ОСТАНОВЛЕН'}")
        
        print("\nМодули системы:")
        for module, status in self.modules.items():
            status_icon = "✓" if status else "✗"
            module_name = {
                'crypto': 'Криптография',
                'fim': 'Контроль целостности файлов (FIM)',
                'process_monitor': 'Мониторинг процессов',
                'network_sniffer': 'Сетевой анализ',
                'pe_analyzer': 'Анализ PE-файлов',
                'yara_scanner': 'YARA-сканер'
            }.get(module, module)
            print(f"  {status_icon} {module_name}: {'Включен' if status else 'Отключен'}")
        
        # Database statistics
        try:
            fim_events = len(self.db.query_events('fim_events', 1000))
            process_events = len(self.db.query_events('process_events', 1000))
            netsec_alerts = len(self.db.query_events('netsec_alerts', 1000))
            yara_events = len(self.db.query_events('yara_events', 1000))
            
            print(f"\nСтатистика событий:")
            print(f"  FIM события: {fim_events}")
            print(f"  События процессов: {process_events}")
            print(f"  Оповещения безопасности: {netsec_alerts}")
            print(f"  YARA события: {yara_events}")
        except Exception as e:
            logger.error(f"Error getting database statistics: {e}")
        
        print("=" * 60)

    def cleanup_system(self, days: int = 30):
        """Clean up old events from database"""
        print(f"\nОчистка старых событий (старше {days} дней)...")
        
        try:
            self.db.cleanup_old_events(days)
            print("✓ Очистка базы данных завершена")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def create_test_files(self, directory: str = "./test_files"):
        """Create test files for encryption/decryption testing"""
        os.makedirs(directory, exist_ok=True)
        
        test_files = [
            "document.txt",
            "spreadsheet.xlsx", 
            "presentation.pptx",
            "image.jpg",
            "data.json"
        ]
        
        print(f"\nСоздание тестовых файлов в {directory}:")
        
        for filename in test_files:
            file_path = os.path.join(directory, filename)
            content = f"Тестовый файл {filename}\nСоздан: {datetime.now()}\nСодержимое для тестирования шифрования."
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"  ✓ Создан: {filename}")
        
        print(f"✓ Создано {len(test_files)} тестовых файлов")


def main():
    """Main CLI interface"""
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
    start_parser = subparsers.add_parser('start', help='Запустить систему защиты')
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Остановить систему защиты')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Показать статус системы')
    
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize system
    system = RansomwareProtectionSystem(args.config, args.db)
    
    try:
        if args.command == 'start':
            system.start_protection()
            print("\nСистема запущена. Нажмите Ctrl+C для остановки...")
            try:
                while system.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                system.stop_protection()
        
        elif args.command == 'stop':
            system.stop_protection()
        
        elif args.command == 'status':
            system.system_status()
        
        elif args.command == 'encrypt':
            system.encrypt_file(args.file, args.key)
        
        elif args.command == 'decrypt':
            system.decrypt_file(args.file, args.key)
        
        elif args.command == 'alerts':
            system.view_alerts(args.limit)
        
        elif args.command == 'attacks':
            system.view_ransomware_attacks(args.hours)
        
        elif args.command == 'rollback':
            system.attempt_rollback(args.file, args.backup)
        
        elif args.command == 'cleanup':
            system.cleanup_system(args.days)
        
        elif args.command == 'test':
            system.create_test_files(args.dir)
    
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
        if system.running:
            system.stop_protection()
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"Ошибка: {e}")


if __name__ == '__main__':
    main()
