import psutil
import time
from database import Database

class ProcessMonitor:
    def __init__(self, db_name='firewall.db', check_interval=5, threshold=1000000):  # threshold in bytes
        self.db = Database(db_name)
        self.check_interval = check_interval
        self.threshold = threshold  # Anomalous if network usage > threshold
        self.running = False

    def monitor(self):
        self.running = True
        print("Запуск мониторинга процессов")
        while self.running:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    net_io = proc.io_counters()
                    if net_io:
                        # Note: io_counters() doesn't have network bytes, using as placeholder
                        # In real implementation, you'd need network-specific monitoring
                        event_type = f"Мониторинг процессов активен для {proc.name()}"
                        criticality = "INFO"
                        self.db.insert_process_event(proc.pid, proc.name(), event_type, criticality)
                        print(f"Информация о процессе: {proc.name()} (PID {proc.pid}) - {event_type}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
            time.sleep(self.check_interval)

    def stop(self):
        self.running = False
        print("Остановка мониторинга процессов")
