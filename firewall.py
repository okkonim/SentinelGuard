import argparse
import threading
import json
import logging
from network_capture import NetworkCapture
from fim import FIM
from process_monitor import ProcessMonitor
from database import Database
from network_monitor import NetworkMonitor
from yara_scanner import YARAScanner

class Firewall:
    def __init__(self, config_path='config.json'):
        self.config_path = config_path
        self.db = Database()
        self.network_capture = NetworkCapture()
        self.fim = FIM(config_path)
        self.process_monitor = ProcessMonitor(config_path)
        self.network_monitor = NetworkMonitor(external_db=self.db)
        self.yara_scanner = YARAScanner()
        self.threads = []
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            logging.basicConfig(
                level=getattr(logging, config.get('logging', {}).get('level', 'INFO')),
                filename=config.get('logging', {}).get('file'),
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)
        except Exception as e:
            print(f"Error loading config: {e}")

    def start(self):
        print("Запуск прототипа межсетевого экрана...")

        # Start network capture
        t1 = threading.Thread(target=self.network_capture.start_capture)
        t1.start()
        self.threads.append(t1)

        # Start FIM
        t2 = threading.Thread(target=self.fim.monitor)
        t2.start()
        self.threads.append(t2)

        # Start process monitor
        t3 = threading.Thread(target=self.process_monitor.monitor)
        t3.start()
        self.threads.append(t3)

        print("Межсетевой экран запущен. Нажмите Ctrl+C для остановки.")
        print("Нажмите Enter для остановки...")

    def stop(self):
        print("Остановка межсетевого экрана...")
        self.network_capture.stop_capture()
        self.fim.stop()
        self.process_monitor.stop()
        for t in self.threads:
            t.join()
        self.db.close()
        print("Межсетевой экран остановлен.")

    def view_logs(self, table, limit=10):
        events = self.db.query_events(table, limit)
        for event in events:
            print(event)

    def manual_scan(self, path):
        """Manual YARA scan of file or directory"""
        if os.path.isfile(path):
            results = self.yara_scanner.scan_file(path)
        elif os.path.isdir(path):
            results = self.yara_scanner.scan_directory(path)
        else:
            print(f"Path {path} does not exist")
            return
        if results:
            print(f"YARA scan results for {path}:")
            for result in results:
                print(f"  Rule: {result['rule_name']}, File: {result['file_path']}")
        else:
            print(f"No YARA matches found in {path}")

    def view_yara_rules(self):
        """Display loaded YARA rules"""
        if self.yara_scanner.rules:
            print("Loaded YARA rules:")
            for namespace, rules in self.yara_scanner.rules.items():
                print(f"  Namespace: {namespace}")
                for rule in rules:
                    print(f"    {rule.identifier}")
        else:
            print("No YARA rules loaded")

    def reload_config(self):
        """Reload configuration and YARA rules"""
        self.load_config()
        self.fim.load_config()
        self.process_monitor.load_config()
        print("Configuration reloaded")

    def run_netsec_scan(self):
        """Запуск сканирования NetSec Sentinel"""
        print("Запуск сканирования NetSec Sentinel...")
        results = self.network_monitor.run_comprehensive_scan()
        print("Сканирование NetSec завершено.")
        return results

    def create_baseline(self):
        """Создание базовой линии сети"""
        print("Создание базовой линии сети...")
        self.network_monitor.generate_baseline()
        print("Базовая линия создана.")

    def compare_baseline(self):
        """Сравнение с базовой линией"""
        print("Сравнение с базовой линией...")
        anomalies = self.network_monitor.compare_with_baseline()
        if anomalies:
            print("Найдены аномалии:")
            for anomaly in anomalies:
                print(f"  {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}")
        else:
            print("Аномалий не найдено.")
        return anomalies

    def reload_rules(self):
        self.network_capture.reload_rules()
        self.reload_config()

def main():
    parser = argparse.ArgumentParser(description="Гибридная система обнаружения угроз")
    parser.add_argument('command', choices=['start', 'stop', 'logs', 'reload', 'netsec-scan', 'baseline', 'compare', 'scan', 'rules'], help="Команда для выполнения")
    parser.add_argument('--table', choices=['network_events', 'fim_events', 'process_events', 'netsec_alerts', 'yara_events'], help="Таблица для просмотра логов")
    parser.add_argument('--limit', type=int, default=10, help="Количество записей логов для отображения")
    parser.add_argument('--path', help="Путь для сканирования (для команды scan)")

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
            print("Пожалуйста, укажите --table")
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
    elif args.command == 'scan':
        if not args.path:
            print("Пожалуйста, укажите --path для сканирования")
            return
        firewall.manual_scan(args.path)
    elif args.command == 'rules':
        firewall.view_yara_rules()
    elif args.command == 'stop':
        firewall.stop()
    else:
        print("Неверная команда")

if __name__ == "__main__":
    main()
