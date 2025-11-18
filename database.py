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
                rule_id INTEGER,
                module TEXT,
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

        # YARA events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS yara_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                rule_name TEXT,
                event_type TEXT,
                criticality TEXT,
                details TEXT
            )
        ''')

        # PE files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pe_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                sha256 TEXT UNIQUE,
                architecture TEXT,
                entry_point INTEGER,
                characteristics INTEGER
            )
        ''')

        # PE sections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pe_sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                name TEXT,
                virtual_size INTEGER,
                raw_size INTEGER,
                virtual_address INTEGER,
                entropy REAL,
                anomalies TEXT,
                FOREIGN KEY (file_id) REFERENCES pe_files (id)
            )
        ''')

        # PE imports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pe_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                dll TEXT,
                function TEXT,
                suspicious INTEGER,
                FOREIGN KEY (file_id) REFERENCES pe_files (id)
            )
        ''')

        self.conn.commit()

    def insert_network_event(self, source_ip, dest_ip, source_port, dest_port, protocol, action, rule_id, module, criticality='INFO'):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_events (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, rule_id, module, criticality)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, rule_id, module, criticality))
        conn.commit()
        logger.info(f"Network event [{module}]: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol}) - {action} (rule {rule_id})")

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
        cursor.execute('''
            INSERT INTO process_events (timestamp, pid, process_name, event_type, criticality)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, pid, process_name, event_type, criticality))
        conn.commit()
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

    def insert_yara_event(self, file_path, rule_name, event_type, criticality='WARNING', details=None):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO yara_events (timestamp, file_path, rule_name, event_type, criticality, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, file_path, rule_name, event_type, criticality, details))
        conn.commit()
        logger.warning(f"YARA событие: {rule_name} в {file_path} - {event_type}")

    def insert_pe_file(self, file_path, sha256, architecture=None, entry_point=None, characteristics=None):
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO pe_files (timestamp, file_path, sha256, architecture, entry_point, characteristics)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, file_path, sha256, architecture, entry_point, characteristics))
        file_id = cursor.lastrowid
        conn.commit()
        logger.info(f"PE file inserted: {file_path}")
        return file_id

    def insert_pe_section(self, file_id, name, virtual_size, raw_size, virtual_address, entropy, anomalies):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO pe_sections (file_id, name, virtual_size, raw_size, virtual_address, entropy, anomalies)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_id, name, virtual_size, raw_size, virtual_address, entropy, anomalies))
        conn.commit()

    def insert_pe_import(self, file_id, dll, function, suspicious):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO pe_imports (file_id, dll, function, suspicious)
            VALUES (?, ?, ?, ?)
        ''', (file_id, dll, function, 1 if suspicious else 0))
        conn.commit()

    def query_pe_files(self, limit=10):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM pe_files ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def query_pe_sections(self, file_id=None, limit=10):
        cursor = self.conn.cursor()
        if file_id:
            cursor.execute('SELECT * FROM pe_sections WHERE file_id = ? ORDER BY id LIMIT ?', (file_id, limit))
        else:
            cursor.execute('SELECT * FROM pe_sections ORDER BY id DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def query_pe_imports(self, file_id=None, limit=10):
        cursor = self.conn.cursor()
        if file_id:
            cursor.execute('SELECT * FROM pe_imports WHERE file_id = ? ORDER BY id LIMIT ?', (file_id, limit))
        else:
            cursor.execute('SELECT * FROM pe_imports ORDER BY id DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def query_events(self, table, limit=10):
        cursor = self.conn.cursor()
        cursor.execute(f'SELECT * FROM {table} ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def close(self):
        if self.conn:
            self.conn.close()
            # Also clear the cached connection if any
            if hasattr(self, '_conn'):
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
