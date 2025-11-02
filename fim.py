import hashlib
import os
import time
from database import Database
import logging

logger = logging.getLogger(__name__)

class FIM:
    def __init__(self, file_path='rules.json', db_name='firewall.db', check_interval=4):
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
        print(f"Запуск FIM мониторинга для {self.file_path}")
        # Insert initial event so operator sees FIM is running
        try:
            status = 'exists' if os.path.exists(self.file_path) else 'missing'
            self.db.insert_fim_event(self.file_path, f"FIM мониторинг запущен ({status})", 'INFO')
        except Exception as e:
            logger.exception(f"Failed to write initial FIM event: {e}")
        while self.running:
            time.sleep(self.check_interval)
            current_hash = self.get_file_hash()
            if current_hash != self.last_hash:
                event_type = "Файл изменен" if self.last_hash else "Файл создан"
                criticality = "CRITICAL" if self.last_hash else "INFO"
                self.db.insert_fim_event(self.file_path, event_type, criticality)
                print(f"FIM Оповещение: {event_type} для {self.file_path}")
                self.last_hash = current_hash

    def stop(self):
        self.running = False
        print("Остановка FIM мониторинга")
