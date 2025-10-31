import hashlib
import os
import time
from database import Database

class FIM:
    def __init__(self, file_path='rules.json', db_name='firewall.db', check_interval=10):
        self.file_path = file_path
        self.db = Database(db_name)
        self.check_interval = check_interval
        self.last_hash = self.get_file_hash()
        self.running = False

    def get_file_hash(self):
        if not os.path.exists(self.file_path):
            return None
        with open(self.file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def monitor(self):
        self.running = True
        print(f"Starting FIM monitoring for {self.file_path}")
        while self.running:
            time.sleep(self.check_interval)
            current_hash = self.get_file_hash()
            if current_hash != self.last_hash:
                event_type = "File modified" if self.last_hash else "File created"
                criticality = "CRITICAL" if self.last_hash else "INFO"
                self.db.insert_fim_event(self.file_path, event_type, criticality)
                print(f"FIM Alert: {event_type} for {self.file_path}")
                self.last_hash = current_hash

    def stop(self):
        self.running = False
        print("Stopping FIM monitoring")
