import sqlite3
import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_name='firewall.db'):
        self.db_name = db_name
        self.conn = None
        self.create_tables()

    def create_tables(self):
        self.conn = sqlite3.connect(self.db_name)
        cursor = self.conn.cursor()

        # Network events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                action TEXT,
                criticality TEXT
            )
        ''')

        # FIM events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fim_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                event_type TEXT,
                criticality TEXT
            )
        ''')

        # Process events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pid INTEGER,
                process_name TEXT,
                event_type TEXT,
                criticality TEXT
            )
        ''')

        self.conn.commit()

    def insert_network_event(self, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO network_events (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality))
        self.conn.commit()
        logger.info(f"Network event logged: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol}) - {action}")

    def insert_fim_event(self, file_path, event_type, criticality='WARNING'):
        timestamp = datetime.datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO fim_events (timestamp, file_path, event_type, criticality)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, file_path, event_type, criticality))
        self.conn.commit()
        logger.warning(f"FIM event: {event_type} for {file_path}")

    def insert_process_event(self, pid, process_name, event_type, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO process_events (timestamp, pid, process_name, event_type, criticality)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, pid, process_name, event_type, criticality))
        self.conn.commit()
        logger.info(f"Process event: {process_name} (PID {pid}) - {event_type}")

    def query_events(self, table, limit=10):
        cursor = self.conn.cursor()
        cursor.execute(f'SELECT * FROM {table} ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def close(self):
        if self.conn:
            self.conn.close()
