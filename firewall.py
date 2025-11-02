import argparse
import threading
from network_capture import NetworkCapture
from fim import FIM
from process_monitor import ProcessMonitor
from database import Database
from network_monitor import NetworkMonitor

class Firewall:
    def __init__(self):
        self.db = Database()
        self.network_capture = NetworkCapture()
        self.fim = FIM()
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor(external_db=self.db)
        self.threads = []

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

def main():
    parser = argparse.ArgumentParser(description="Прототип программного межсетевого экрана")
    parser.add_argument('command', choices=['start', 'stop', 'logs', 'reload', 'netsec-scan', 'baseline', 'compare'], help="Команда для выполнения")
    parser.add_argument('--table', choices=['network_events', 'fim_events', 'process_events', 'netsec_alerts'], help="Таблица для просмотра логов")
    parser.add_argument('--limit', type=int, default=10, help="Количество записей логов для отображения")

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
    elif args.command == 'stop':
        firewall.stop()
    else:
        print("Неверная команда")

if __name__ == "__main__":
    main()
