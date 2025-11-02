import psutil
import time
import logging
from database import Database

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor processes but reduce noise: record only start/terminate events."""
    def __init__(self, db_name='firewall.db', check_interval=5, threshold=1000000): 
        self.db = Database(db_name)
        self.check_interval = check_interval
        self.threshold = threshold
        self.running = False
        # previous snapshot of processes: {pid: name}
        self.prev_procs = {}

    def monitor(self):
        self.running = True
        logger.info("Запуск мониторинга процессов")

        # Initial snapshot
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    self.prev_procs[proc.pid] = proc.info.get('name') or proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            # Write a single startup event
            try:
                self.db.insert_process_event(0, 'ProcessMonitor', 'Process monitor started', 'INFO')
            except Exception:
                logger.exception('Failed to write initial process monitor event')
        except Exception:
            logger.exception('Failed to take initial process snapshot')

        while self.running:
            current = {}
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        current[proc.pid] = proc.info.get('name') or proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Detect started processes
                started = {pid: name for pid, name in current.items() if pid not in self.prev_procs}
                # Detect terminated processes
                terminated = {pid: name for pid, name in self.prev_procs.items() if pid not in current}

                for pid, name in started.items():
                    try:
                        self.db.insert_process_event(pid, name, 'process_started', 'INFO')
                        logger.info(f'Process started: {name} (PID {pid})')
                    except Exception:
                        logger.exception(f'Failed to insert process_started for PID {pid}')

                for pid, name in terminated.items():
                    try:
                        self.db.insert_process_event(pid, name, 'process_terminated', 'WARNING')
                        logger.info(f'Process terminated: {name} (PID {pid})')
                    except Exception:
                        logger.exception(f'Failed to insert process_terminated for PID {pid}')

                # update snapshot
                self.prev_procs = current

            except Exception:
                logger.exception('Error during process monitoring iteration')

            time.sleep(self.check_interval)

    def stop(self):
        self.running = False
        logger.info('Остановка мониторинга процессов')
