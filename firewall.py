import argparse
import threading
from network_capture import NetworkCapture
from fim import FIM
from process_monitor import ProcessMonitor
from database import Database

class Firewall:
    def __init__(self):
        self.db = Database()
        self.network_capture = NetworkCapture()
        self.fim = FIM()
        self.process_monitor = ProcessMonitor()
        self.threads = []

    def start(self):
        print("Starting Firewall Prototype...")

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

        print("Firewall is running. Press Ctrl+C to stop.")

    def stop(self):
        print("Stopping Firewall...")
        self.network_capture.stop_capture()
        self.fim.stop()
        self.process_monitor.stop()
        for t in self.threads:
            t.join()
        self.db.close()
        print("Firewall stopped.")

    def view_logs(self, table, limit=10):
        events = self.db.query_events(table, limit)
        for event in events:
            print(event)

    def reload_rules(self):
        self.network_capture.reload_rules()

def main():
    parser = argparse.ArgumentParser(description="Software Firewall Prototype")
    parser.add_argument('command', choices=['start', 'stop', 'logs', 'reload'], help="Command to execute")
    parser.add_argument('--table', choices=['network_events', 'fim_events', 'process_events'], help="Table to view logs from")
    parser.add_argument('--limit', type=int, default=10, help="Number of log entries to display")

    args = parser.parse_args()

    firewall = Firewall()

    if args.command == 'start':
        try:
            firewall.start()
            input("Press Enter to stop...\n")
            firewall.stop()
        except KeyboardInterrupt:
            firewall.stop()
    elif args.command == 'logs':
        if not args.table:
            print("Please specify --table")
            return
        firewall.view_logs(args.table, args.limit)
    elif args.command == 'reload':
        firewall.reload_rules()
    else:
        print("Invalid command")

if __name__ == "__main__":
    main()
