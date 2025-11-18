import argparse
import threading
import json
import logging
import os
from network_capture import NetworkCapture
from fim import FIM
from process_monitor import ProcessMonitor
from database import Database
from network_monitor import NetworkMonitor
from yara_scanner import YARAScanner
from pe_analyzer import PEAnalyzer

class Firewall:
    def __init__(self, config_path='config.json'):
        self.config_path = config_path
        self.db = Database()
        self.network_capture = NetworkCapture()
        self.fim = FIM(config_path)
        self.process_monitor = ProcessMonitor(config_path)
        self.network_monitor = NetworkMonitor(external_db=self.db)
        self.yara_scanner = YARAScanner()
        self.pe_analyzer = PEAnalyzer()
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

    def manual_pe_analysis(self, path):
        """Manual PE analysis of file with YARA integration"""
        if not os.path.isfile(path):
            print(f"File {path} does not exist")
            return

        if not self.pe_analyzer.is_pe_file(path):
            print(f"File {path} is not a PE file")
            return

        print(f"Analyzing PE file: {path}")

        # Run YARA scan first
        yara_results = self.yara_scanner.scan_file(path) if self.yara_scanner.rules else []
        yara_matches = len(yara_results) > 0

        # Run PE analysis
        result = self.pe_analyzer.analyze_file(path)
        if result:
            print("PE Analysis Results:")
            print(f"  Architecture: {result['header'].get('architecture', 'Unknown')}")
            print(f"  Entry Point: 0x{result['header'].get('entry_point', 0):08x}")
            print(f"  SHA-256: {result['sha256'][:16]}...")
            print(f"  Sections: {len(result['sections'])}")
            for section in result['sections']:
                anomalies = f" [{section['anomalies']}]" if section['anomalies'] else ""
                print(f"    {section['name']}: entropy={section['entropy']:.2f}{anomalies}")
            suspicious_imports = [imp for imp in result['imports'] if imp['suspicious']]
            print(f"  Suspicious Imports: {len(suspicious_imports)}")
            for imp in suspicious_imports:
                print(f"    {imp['function']} ({imp['dll']})")

            # Determine threat level based on PE and YARA
            pe_suspicious = any(section['anomalies'] for section in result['sections']) or suspicious_imports
            threat_reasons = []

            if pe_suspicious:
                reasons = []
                if any(section['anomalies'] for section in result['sections']):
                    high_entropy_sections = [s['name'] for s in result['sections'] if 'high_entropy' in s['anomalies']]
                    if high_entropy_sections:
                        reasons.append(f"высокая энтропия в секциях: {', '.join(high_entropy_sections)}")
                    suspicious_names = [s['name'] for s in result['sections'] if 'suspicious_name' in s['anomalies']]
                    if suspicious_names:
                        reasons.append(f"подозрительные имена секций: {', '.join(suspicious_names)}")
                if suspicious_imports:
                    reasons.append(f"подозрительные импорты: {', '.join([imp['function'] for imp in suspicious_imports])}")
                threat_reasons.append(f"Модуль PE: {', '.join(reasons)}")

            if yara_matches and not pe_suspicious:
                yara_rules = [r['rule_name'] for r in yara_results]
                threat_reasons.append(f"Модуль YARA (неизвестная угроза): правила {', '.join(yara_rules)}")
            elif yara_matches and pe_suspicious:
                yara_rules = [r['rule_name'] for r in yara_results]
                threat_reasons.append(f"Модуль YARA: правила {', '.join(yara_rules)}")

            if threat_reasons:
                print(f"  Статус: ПОДОЗРИТЕЛЬНЫЙ")
                for reason in threat_reasons:
                    print(f"    - {reason}")
            else:
                print(f"  Статус: ЧИСТ")
        else:
            print("PE analysis failed")

    def view_pe_reports(self, limit=10):
        """View PE analysis reports"""
        files = self.db.query_pe_files(limit)
        if files:
            print("Recent PE Files:")
            for file in files:
                print(f"  {file[2]}: {file[3]} ({file[4] or 'Unknown arch'})")
        else:
            print("No PE files analyzed yet.")

        sections = self.db.query_pe_sections(limit=limit)
        if sections:
            print(f"\nRecent PE Sections (last {limit}):")
            for section in sections:
                anomalies = f" [{section[7]}]" if section[7] else ""
                print(f"  File {section[1]}: {section[2]} entropy={section[6]:.2f}{anomalies}")
        else:
            print("No PE sections found.")

        imports = self.db.query_pe_imports(limit=limit)
        if imports:
            print(f"\nRecent PE Imports (last {limit}):")
            for imp in imports:
                suspicious = " [SUSPICIOUS]" if imp[4] else ""
                print(f"  File {imp[1]}: {imp[3]} ({imp[2]}){suspicious}")
        else:
            print("No PE imports found.")

    def view_yara_rules(self):
        """Display loaded YARA rules"""
        if self.yara_scanner.rules:
            print("YARA rules loaded successfully")
            # Note: YARA Rules object doesn't expose rule names directly
            # We can show that rules are compiled from config
            print("Rules compiled from config.json")
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

    def start_network_only(self):
        print("Запуск модуля захвата сети...")
        t = threading.Thread(target=self.network_capture.start_capture)
        t.start()
        print("Модуль захвата сети запущен. Нажмите Ctrl+C для остановки.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.network_capture.stop_capture()
        t.join()
        self.db.close()
        print("Модуль захвата сети остановлен.")

    def start_fim_only(self):
        print("Запуск модуля FIM...")
        t = threading.Thread(target=self.fim.monitor)
        t.start()
        print("Модуль FIM запущен. Нажмите Ctrl+C для остановки.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.fim.stop()
        t.join()
        self.db.close()
        print("Модуль FIM остановлен.")

    def start_process_only(self):
        print("Запуск модуля мониторинга процессов...")
        t = threading.Thread(target=self.process_monitor.monitor)
        t.start()
        print("Модуль мониторинга процессов запущен. Нажмите Ctrl+C для остановки.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.process_monitor.stop()
        t.join()
        self.db.close()
        print("Модуль мониторинга процессов остановлен.")

    def start_netsec_only(self):
        print("Запуск модуля NetSec Sentinel...")
        t = threading.Thread(target=self.network_monitor.start_monitoring)
        t.start()
        print("Модуль NetSec Sentinel запущен. Нажмите Ctrl+C для остановки.")
        try:
            input()
        except KeyboardInterrupt:
            pass
        self.network_monitor.stop_monitoring()
        t.join()
        self.db.close()
        print("Модуль NetSec Sentinel остановлен.")

def interactive_menu(firewall):
    while True:
        print("\n=== Прототип программного межсетевого экрана ===")
        print("1. Запустить все модули")
        print("2. Запустить модуль захвата сети")
        print("3. Запустить модуль FIM")
        print("4. Запустить модуль мониторинга процессов")
        print("5. Запустить модуль NetSec Sentinel")
        print("6. Просмотр логов")
        print("7. Перезагрузка правил")
        print("8. NetSec сканирование")
        print("9. Создание базовой линии")
        print("10. Сравнение с базовой линией")
        print("11. Ручное YARA сканирование")
        print("12. Просмотр YARA правил")
        print("13. PE анализ файла")
        print("14. Просмотр PE отчетов")
        print("0. Выход")
        choice = input("Выберите опцию (0-14): ").strip()

        if choice == '1':
            firewall.start()
        elif choice == '2':
            firewall.start_network_only()
        elif choice == '3':
            firewall.start_fim_only()
        elif choice == '4':
            firewall.start_process_only()
        elif choice == '5':
            firewall.start_netsec_only()
        elif choice == '6':
            table = input("Таблица (network_events, fim_events, process_events, netsec_alerts, yara_events): ").strip()
            if table in ['network_events', 'fim_events', 'process_events', 'netsec_alerts', 'yara_events']:
                limit = input("Количество записей (по умолчанию 10): ").strip()
                limit = int(limit) if limit.isdigit() else 10
                firewall.view_logs(table, limit)
            else:
                print("Неверная таблица.")
        elif choice == '7':
            firewall.reload_rules()
            print("Правила перезагружены.")
        elif choice == '8':
            firewall.run_netsec_scan()
        elif choice == '9':
            firewall.create_baseline()
        elif choice == '10':
            firewall.compare_baseline()
        elif choice == '11':
            path = input("Путь к файлу или директории для сканирования: ").strip()
            if path:
                firewall.manual_scan(path)
            else:
                print("Путь не указан.")
        elif choice == '12':
            firewall.view_yara_rules()
        elif choice == '13':
            path = input("Путь к PE файлу для анализа: ").strip()
            if path:
                firewall.manual_pe_analysis(path)
            else:
                print("Путь не указан.")
        elif choice == '14':
            limit = input("Количество записей (по умолчанию 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            firewall.view_pe_reports(limit)
        elif choice == '0':
            print("Выход.")
            break
        else:
            print("Неверный выбор. Попробуйте снова.")

def main():
    parser = argparse.ArgumentParser(description="Гибридная система обнаружения угроз")
    parser.add_argument('command', nargs='?', choices=['start', 'stop', 'logs', 'reload', 'netsec-scan', 'baseline', 'compare', 'start-network', 'start-fim', 'start-process', 'start-netsec', 'interactive', 'scan', 'rules', 'pe-analyze', 'pe-reports'], help="Команда для выполнения")
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
    elif args.command == 'start-network':
        firewall.start_network_only()
    elif args.command == 'start-fim':
        firewall.start_fim_only()
    elif args.command == 'start-process':
        firewall.start_process_only()
    elif args.command == 'start-netsec':
        firewall.start_netsec_only()
    elif args.command == 'interactive' or args.command is None:
        interactive_menu(firewall)
    elif args.command == 'scan':
        if not args.path:
            print("Пожалуйста, укажите --path для сканирования")
            return
        firewall.manual_scan(args.path)
    elif args.command == 'rules':
        firewall.view_yara_rules()
    elif args.command == 'pe-analyze':
        if not args.path:
            print("Пожалуйста, укажите --path для PE анализа")
            return
        firewall.manual_pe_analysis(args.path)
    elif args.command == 'pe-reports':
        firewall.view_pe_reports(args.limit)
    elif args.command == 'stop':
        firewall.stop()
    else:
        print("Неверная команда")

if __name__ == "__main__":
    main()
