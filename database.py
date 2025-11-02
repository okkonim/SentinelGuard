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

    def get_connection(self):
        """Get a thread-safe connection"""
        if not hasattr(self, '_conn') or self._conn is None:
            self._conn = sqlite3.connect(self.db_name, check_same_thread=False)
        return self._conn

    def create_tables(self):
        self.conn = self.get_connection()
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

        # NetSec Sentinel alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS netsec_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                description TEXT,
                severity TEXT,
                details TEXT
            )
        ''')

        self.conn.commit()

    def insert_network_event(self, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_events (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, criticality))
        conn.commit()
        logger.info(f"Network event: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol}) - {action}")

    def insert_fim_event(self, file_path, event_type, criticality='WARNING'):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO fim_events (timestamp, file_path, event_type, criticality)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, file_path, event_type, criticality))
        conn.commit()
        logger.warning(f"FIM событие: {event_type} для {file_path}")

    def insert_process_event(self, pid, process_name, event_type, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
    def insert_process_event(self, pid, process_name, event_type, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO process_events (timestamp, pid, process_name, event_type, criticality)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, pid, process_name, event_type, criticality))
        self.conn.commit()
        logger.info(f"Событие процесса: {process_name} (PID {pid}) - {event_type}")

    def insert_netsec_alert(self, alert_type, description, severity='medium', details=None):
        timestamp = datetime.datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO netsec_alerts (timestamp, alert_type, description, severity, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, alert_type, description, severity, details))
        self.conn.commit()
        logger.warning(f"NetSec Оповещение [{severity.upper()}]: {description}")

    def query_events(self, table, limit=10):
        cursor = self.conn.cursor()
        cursor.execute(f'SELECT * FROM {table} ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def close(self):
        if self.conn:
            self.conn.close()
