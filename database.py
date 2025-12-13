
import sqlite3
import datetime
import logging
import json
import os

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

        # File hashes table for rollback functionality
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT UNIQUE,
                sha256 TEXT,
                file_size INTEGER,
                backup_path TEXT,
                is_encrypted INTEGER DEFAULT 0
            )
        ''')

        # Ransomware attack correlation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ransomware_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                confidence_score REAL,
                attack_type TEXT,
                description TEXT,
                affected_files TEXT,
                process_pid INTEGER,
                process_name TEXT,
                network_connections TEXT,
                status TEXT DEFAULT 'ACTIVE',
                rollback_attempted INTEGER DEFAULT 0,
                rollback_success INTEGER DEFAULT 0
            )
        ''')

        # Event correlation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                correlation_type TEXT,
                related_events TEXT,
                confidence_score REAL,
                description TEXT
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

    def query_pe_files(self, limit=10, sha256=None):
        cursor = self.conn.cursor()
        if sha256:
            cursor.execute('SELECT * FROM pe_files WHERE sha256 = ? ORDER BY timestamp DESC LIMIT ?', (sha256, limit))
        else:
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

    # New methods for ransomware protection

    def insert_file_hash(self, file_path, sha256, file_size, backup_path=None, is_encrypted=0):
        """Insert or update file hash for rollback functionality"""
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if file exists
        cursor.execute('SELECT id FROM file_hashes WHERE file_path = ?', (file_path,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing hash
            cursor.execute('''
                UPDATE file_hashes 
                SET timestamp = ?, sha256 = ?, file_size = ?, backup_path = ?, is_encrypted = ?
                WHERE file_path = ?
            ''', (timestamp, sha256, file_size, backup_path, is_encrypted, file_path))
        else:
            # Insert new hash
            cursor.execute('''
                INSERT INTO file_hashes (timestamp, file_path, sha256, file_size, backup_path, is_encrypted)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, file_path, sha256, file_size, backup_path, is_encrypted))
        
        conn.commit()

    def get_file_hash(self, file_path):
        """Get file hash for rollback"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM file_hashes WHERE file_path = ?', (file_path,))
        return cursor.fetchone()

    def insert_ransomware_attack(self, confidence_score, attack_type, description, 
                                affected_files=None, process_pid=None, process_name=None, 
                                network_connections=None):
        """Insert ransomware attack correlation data"""
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ransomware_attacks 
            (timestamp, confidence_score, attack_type, description, affected_files, 
             process_pid, process_name, network_connections)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, confidence_score, attack_type, description, 
              json.dumps(affected_files) if affected_files else None,
              process_pid, process_name, 
              json.dumps(network_connections) if network_connections else None))
        
        attack_id = cursor.lastrowid
        conn.commit()
        return attack_id

    def update_ransomware_attack_status(self, attack_id, status, rollback_attempted=None, rollback_success=None):
        """Update ransomware attack status and rollback information"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        update_query = 'UPDATE ransomware_attacks SET status = ?'
        params = [status]
        
        if rollback_attempted is not None:
            update_query += ', rollback_attempted = ?'
            params.append(rollback_attempted)
        
        if rollback_success is not None:
            update_query += ', rollback_success = ?'
            params.append(rollback_success)
        
        update_query += ' WHERE id = ?'
        params.append(attack_id)
        
        cursor.execute(update_query, params)
        conn.commit()

    def correlate_ransomware_events(self, fim_events, process_events, network_events, time_window_minutes=5):
        """Correlate FIM, process, and network events to detect ransomware attacks"""
        current_time = datetime.datetime.now()
        cutoff_time = current_time - datetime.timedelta(minutes=time_window_minutes)
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get recent events within time window
        cursor.execute('''
            SELECT * FROM fim_events WHERE timestamp > ? AND criticality IN ('HIGH', 'CRITICAL')
        ''', (cutoff_time.isoformat(),))
        recent_fim_events = cursor.fetchall()
        
        cursor.execute('''
            SELECT * FROM process_events WHERE timestamp > ? AND criticality IN ('HIGH', 'CRITICAL')
        ''', (cutoff_time.isoformat(),))
        recent_process_events = cursor.fetchall()
        
        cursor.execute('''
            SELECT * FROM netsec_alerts WHERE timestamp > ? AND severity IN ('HIGH', 'CRITICAL')
        ''', (cutoff_time.isoformat(),))
        recent_network_events = cursor.fetchall()
        
        # Analyze patterns
        mass_encryption_events = [e for e in recent_fim_events if 'массовое шифрование' in e[3].lower()]
        suspicious_processes = [e for e in recent_process_events if 'ransomware' in e[4].lower()]
        cc_connections = [e for e in recent_network_events if 'c_and_c' in e[2].lower()]
        
        # Calculate confidence score
        confidence_score = 0.0
        if mass_encryption_events:
            confidence_score += 0.4  # Mass encryption is strong indicator
        if suspicious_processes:
            confidence_score += 0.3  # Suspicious process behavior
        if cc_connections:
            confidence_score += 0.3  # C&C communication
        
        # If confidence is high enough, log correlation
        if confidence_score >= 0.7:
            description = f"Ransomware attack detected with confidence {confidence_score:.2f}"
            affected_files = [e[2] for e in mass_encryption_events] if mass_encryption_events else []
            process_pid = suspicious_processes[0][1] if suspicious_processes else None
            process_name = suspicious_processes[0][2] if suspicious_processes else None
            
            attack_id = self.insert_ransomware_attack(
                confidence_score, 'MALWARE', description, affected_files, process_pid, process_name
            )
            
            # Log correlation event
            self.insert_event_correlation(
                'RANSOMWARE_DETECTION',
                json.dumps({
                    'fim_events': mass_encryption_events,
                    'process_events': suspicious_processes,
                    'network_events': cc_connections
                }),
                confidence_score,
                description
            )
            
            return attack_id
        
        return None

    def insert_event_correlation(self, correlation_type, related_events, confidence_score, description):
        """Insert event correlation data"""
        timestamp = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO event_correlations 
            (timestamp, correlation_type, related_events, confidence_score, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, correlation_type, related_events, confidence_score, description))
        
        conn.commit()

    def attempt_rollback(self, file_path, backup_path=None):
        """Attempt to rollback a file to its previous state"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get file hash info
            cursor.execute('SELECT * FROM file_hashes WHERE file_path = ?', (file_path,))
            file_info = cursor.fetchone()
            
            if not file_info:
                logger.error(f"No backup information found for {file_path}")
                return False
            
            original_sha256 = file_info[3]  # sha256 column
            original_size = file_info[4]   # file_size column
            backup_file_path = file_info[5] if file_info[5] else backup_path
            
            if not backup_file_path or not os.path.exists(backup_file_path):
                logger.error(f"Backup file not found for {file_path}")
                return False
            
            # Restore from backup
            import shutil
            shutil.copy2(backup_file_path, file_path)
            
            # Verify restore
            import hashlib
            with open(file_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash == original_sha256:
                logger.info(f"Successfully rolled back {file_path}")
                # Update database to mark as restored
                cursor.execute('UPDATE file_hashes SET timestamp = ? WHERE file_path = ?', 
                             (datetime.datetime.now().isoformat(), file_path))
                conn.commit()
                return True
            else:
                logger.error(f"Rollback verification failed for {file_path}")
                return False
                
        except Exception as e:
            logger.error(f"Rollback failed for {file_path}: {e}")
            return False

    def get_recent_ransomware_attacks(self, hours=24):
        """Get recent ransomware attacks from database"""
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM ransomware_attacks 
            WHERE timestamp > ? 
            ORDER BY timestamp DESC
        ''', (cutoff_time.isoformat(),))
        
        return cursor.fetchall()

    def cleanup_old_events(self, days=30):
        """Clean up old events to prevent database bloat"""
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables_to_clean = ['network_events', 'fim_events', 'process_events', 'netsec_alerts', 'yara_events']
        
        for table in tables_to_clean:
            try:
                cursor.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff_time.isoformat(),))
                logger.info(f"Cleaned up old events from {table}")
            except Exception as e:
                logger.error(f"Failed to clean up {table}: {e}")
        
        conn.commit()
