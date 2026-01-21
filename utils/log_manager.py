"""
Centralized Log Manager for on-demand log viewing.
Provides thread-safe in-memory log buffer with query capabilities.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from collections import deque
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


@dataclass
class LogEntry:
    """Represents a single log entry."""
    timestamp: str
    level: str
    level_value: int
    module: str
    message: str
    details: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_log_record(cls, record: logging.LogRecord, module: str = "Unknown") -> 'LogEntry':
        return cls(
            timestamp=datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            level=record.levelname,
            level_value=record.levelno,
            module=module or record.name,
            message=record.getMessage(),
            details=cls._get_details(record)
        )
    
    @staticmethod
    def _get_details(record: logging.LogRecord) -> Optional[str]:
        """Extract details from log record."""
        details = []
        if record.exc_info:
            details.append(f"Exception: {record.exc_info[1]}")
        if record.funcName:
            details.append(f"Function: {record.funcName}")
        if record.lineno:
            details.append(f"Line: {record.lineno}")
        return "; ".join(details) if details else None


class LogManager:
    """
    Centralized log manager with in-memory buffering and query capabilities.
    
    Features:
    - Thread-safe circular buffer for recent logs
    - Query by level, time range, module, keyword
    - Real-time log streaming support
    - Export capabilities
    """
    
    _instance: Optional['LogManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls, max_buffer_size: int = 5000) -> 'LogManager':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, max_buffer_size: int = 5000):
        if self._initialized:
            return
        
        self.max_buffer_size = max_buffer_size
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._lock = threading.Lock()
        self._subscribers: List[callable] = []
        self._filter_level = LogLevel.INFO
        
        # Statistics
        self._stats = {
            'total_logs': 0,
            'logs_by_level': {level.value: 0 for level in LogLevel},
            'logs_by_module': {},
            'start_time': datetime.now()
        }
        
        self._initialized = True
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging to capture records."""
        self.logger = logging.getLogger('log_manager')
        self.logger.setLevel(logging.DEBUG)

        # Add handler to capture logs
        self._capture_handler = _LogCaptureHandler(self)
        self._capture_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._capture_handler.setFormatter(formatter)

        # Get ransomware logger and add our handler
        ransomware_logger = logging.getLogger('ransomware_protection')
        ransomware_logger.addHandler(self._capture_handler)
    
    def set_level_filter(self, level: LogLevel) -> None:
        """Set minimum log level to capture."""
        self._filter_level = level
    
    def add_log(self, entry: LogEntry) -> None:
        """Add a log entry to the buffer."""
        with self._lock:
            self._buffer.append(entry)
            self._update_stats(entry)
        
        # Notify subscribers
        self._notify_subscribers(entry)
    
    def _update_stats(self, entry: LogEntry) -> None:
        """Update log statistics."""
        self._stats['total_logs'] += 1
        self._stats['logs_by_level'][entry.level_value] += 1
        
        module = entry.module
        if module not in self._stats['logs_by_module']:
            self._stats['logs_by_module'][module] = 0
        self._stats['logs_by_module'][module] += 1
    
    def get_recent_logs(self, count: int = 100, 
                       level: Optional[LogLevel] = None,
                       module: Optional[str] = None,
                       keyword: Optional[str] = None,
                       since: Optional[datetime] = None) -> List[LogEntry]:
        """
        Query logs with various filters.
        
        Args:
            count: Maximum number of entries to return
            level: Filter by minimum log level
            module: Filter by module name
            keyword: Filter by keyword in message
            since: Filter by timestamp (only entries after this time)
            
        Returns:
            List of filtered log entries (most recent first)
        """
        with self._lock:
            # Start with all entries in reverse order (most recent first)
            entries = list(self._buffer)[::-1]
        
        # Apply filters
        filtered = []
        min_level = level.value if level else 0
        
        for entry in entries:
            # Level filter
            if entry.level_value < min_level:
                continue
            
            # Module filter
            if module and module.lower() not in entry.module.lower():
                continue
            
            # Keyword filter
            if keyword and keyword.lower() not in entry.message.lower():
                continue
            
            # Time filter
            if since:
                try:
                    entry_time = datetime.strptime(entry.timestamp, '%Y-%m-%d %H:%M:%S.%f')
                    if entry_time < since:
                        continue
                except ValueError:
                    pass
            
            filtered.append(entry)
            
            if len(filtered) >= count:
                break
        
        return filtered
    
    def get_logs_by_time_range(self, start: datetime, end: Optional[datetime] = None,
                               count: int = 1000) -> List[LogEntry]:
        """Get logs within a time range."""
        with self._lock:
            entries = list(self._buffer)[::-1]
        
        filtered = []
        end_time = end or datetime.now()
        
        for entry in entries:
            try:
                entry_time = datetime.strptime(entry.timestamp, '%Y-%m-%d %H:%M:%S.%f')
                if start <= entry_time <= end_time:
                    filtered.append(entry)
            except ValueError:
                continue
            
            if len(filtered) >= count:
                break
        
        return filtered
    
    def get_logs_by_level(self, level: LogLevel, count: int = 100) -> List[LogEntry]:
        """Get logs of a specific level."""
        return self.get_recent_logs(count=count, level=level)
    
    def search_logs(self, query: str, count: int = 100) -> List[LogEntry]:
        """Search logs by query string (case-insensitive)."""
        return self.get_recent_logs(count=count, keyword=query)
    
    def tail_logs(self, count: int = 20) -> List[LogEntry]:
        """Get the most recent logs."""
        return self.get_recent_logs(count=count)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get log statistics."""
        with self._lock:
            stats = self._stats.copy()
            stats['buffer_size'] = len(self._buffer)
            stats['uptime_seconds'] = (datetime.now() - stats['start_time']).total_seconds()
            stats['logs_per_second'] = stats['total_logs'] / max(stats['uptime_seconds'], 1)
            return stats
    
    def get_level_counts(self) -> Dict[str, int]:
        """Get counts by log level."""
        return {
            'DEBUG': self._stats['logs_by_level'][10],
            'INFO': self._stats['logs_by_level'][20],
            'WARNING': self._stats['logs_by_level'][30],
            'ERROR': self._stats['logs_by_level'][40],
            'CRITICAL': self._stats['logs_by_level'][50]
        }
    
    def get_modules(self) -> List[str]:
        """Get list of all modules with logs."""
        with self._lock:
            return list(self._stats['logs_by_module'].keys())
    
    def subscribe(self, callback: callable) -> None:
        """Subscribe to real-time log updates."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)
    
    def unsubscribe(self, callback: callable) -> None:
        """Unsubscribe from real-time log updates."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)
    
    def _notify_subscribers(self, entry: LogEntry) -> None:
        """Notify all subscribers of new log entry."""
        for callback in self._subscribers:
            try:
                callback(entry)
            except Exception:
                pass  # Don't let subscriber errors break logging
    
    def clear_buffer(self) -> None:
        """Clear the log buffer."""
        with self._lock:
            self._buffer.clear()
            self._stats['total_logs'] = 0
            self._stats['logs_by_level'] = {level.value: 0 for level in LogLevel}
            self._stats['logs_by_module'] = {}
    
    def export_logs(self, format: str = 'json', count: int = 1000) -> str:
        """Export logs to string format."""
        logs = self.get_recent_logs(count=count)
        
        if format == 'json':
            return json.dumps([log.to_dict() for log in logs], indent=2, ensure_ascii=False)
        elif format == 'text':
            lines = []
            for log in logs:
                lines.append(f"[{log.timestamp}] [{log.level}] {log.module}: {log.message}")
            return '\n'.join(lines)
        else:
            return str(logs)
    
    def format_logs_for_display(self, logs: List[LogEntry], 
                                show_details: bool = False,
                                colored: bool = True) -> str:
        """Format logs for console display."""
        lines = []
        
        # Define colors
        colors = {
            'DEBUG': '\033[94m',  # Blue
            'INFO': '\033[92m',   # Green
            'WARNING': '\033[93m', # Yellow
            'ERROR': '\033[91m',  # Red
            'CRITICAL': '\033[95m' # Magenta
        }
        reset = '\033[0m'
        
        for log in logs:
            level = log.level
            color = colors.get(level, '')
            
            if colored and color:
                line = f"{color}[{log.timestamp}] [{level:<8}] {log.module}: {log.message}{reset}"
            else:
                line = f"[{log.timestamp}] [{level:<8}] {log.module}: {log.message}"
            
            if show_details and log.details:
                line += f"\n    └─ {log.details}"
            
            lines.append(line)
        
        return '\n'.join(lines)
    
    def stream_logs(self, callback: callable, 
                   level: Optional[LogLevel] = None,
                   module: Optional[str] = None) -> None:
        """
        Stream logs to callback function in real-time.
        
        Args:
            callback: Function to call for each new log
            level: Optional level filter
            module: Optional module filter
        """
        min_level = level.value if level else 0
        module_filter = module.lower() if module else None
        
        def log_callback(entry: LogEntry):
            if entry.level_value < min_level:
                return
            if module_filter and module_filter not in entry.module.lower():
                return
            callback(entry)
        
        self.subscribe(log_callback)


class _LogCaptureHandler(logging.Handler):
    """Logging handler that captures logs to LogManager and outputs to console."""
    
    def __init__(self, log_manager: LogManager):
        super().__init__()
        self.log_manager = log_manager
        # Create console formatter
        self.console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record."""
        try:
            # Extract module name from logger name
            module = record.name
            if module.startswith('ransomware_protection.'):
                module = module.replace('ransomware_protection.', '')
            
            entry = LogEntry.from_log_record(record, module)
            self.log_manager.add_log(entry)
            
            # Also output to console in real-time
            if record.levelno >= logging.INFO:  # Only show INFO and above in console
                console_msg = self.console_formatter.format(record)
                print(console_msg, flush=True)
                
        except Exception:
            self.handleError(record)


# Global log manager instance
log_manager = LogManager()

# Flag to check if log manager is available
LOG_MANAGER_AVAILABLE = True


def get_log_manager() -> LogManager:
    """Get the global log manager instance."""
    return log_manager


def init_logging(config: Optional[Dict[str, Any]] = None) -> LogManager:
    """Initialize logging system."""
    if config:
        max_size = config.get('max_buffer_size', 5000)
        level = config.get('level', 'INFO')
        log_manager.max_buffer_size = max_size
        log_manager.set_level_filter(LogLevel[level])
    return log_manager