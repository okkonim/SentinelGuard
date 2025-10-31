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
        print("Starting process monitoring")
        while self.running:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    net_io = proc.net_io_counters()
                    if net_io:
                        sent = net_io.bytes_sent
                        recv = net_io.bytes_recv
                        total = sent + recv
                        if total > self.threshold:
                            event_type = f"High network usage: {total} bytes"
                            criticality = "WARNING"
                            self.db.insert_process_event(proc.pid, proc.name(), event_type, criticality)
                            print(f"Process Alert: {proc.name()} (PID {proc.pid}) - {event_type}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(self.check_interval)

    def stop(self):
        self.running = False
        print("Stopping process monitoring")
