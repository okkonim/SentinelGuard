"""
Centralized logging utilities for the ransomware protection system.
Provides consistent logging patterns and reduces code duplication.
"""

import logging
import logging.handlers
import sys
from typing import Optional, Dict, Any
from pathlib import Path


class LoggerMixin:
    """Mixin class to provide logging capabilities to other classes."""

    @property
    def logger(self) -> logging.Logger:
        """Get logger instance for the class."""
        if not hasattr(self, '_logger'):
            self._logger = logging.getLogger(self.__class__.__name__)
        return self._logger


class RansomwareLogger:
    """Centralized logger configuration for the ransomware protection system."""

    _instance: Optional['RansomwareLogger'] = None
    _configured = False
    _config = None

    def __new__(cls) -> 'RansomwareLogger':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Only configure once per instance, but do it only once globally
        if not self._configured:
            self._configure_logging()
            self._configured = True

    def _configure_logging(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Configure logging with default or custom settings."""
        if config is None:
            config = {
                'level': 'INFO',
                'file': 'ransomware_protection.log',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'max_bytes': 10 * 1024 * 1024,  # 10MB
                'backup_count': 5
            }
        
        # Check if logging is already configured with same config
        if self._config == config:
            return
        
        # Store current config
        self._config = config.copy()
        
        # Ensure required fields have defaults
        config.setdefault('level', 'INFO')
        config.setdefault('file', 'ransomware_protection.log')
        config.setdefault('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        config.setdefault('max_bytes', 10 * 1024 * 1024)  # 10MB
        config.setdefault('backup_count', 5)

        # Create logger
        main_logger = logging.getLogger('ransomware_protection')
        main_logger.setLevel(getattr(logging, config['level'].upper()))

        # Only configure handlers if not already configured
        if not main_logger.handlers:
            # Create formatters
            formatter = logging.Formatter(config['format'])

            # File handler with rotation
            file_handler = logging.handlers.RotatingFileHandler(
                config['file'],
                maxBytes=config['max_bytes'],
                backupCount=config['backup_count']
            )
            file_handler.setFormatter(formatter)
            main_logger.addHandler(file_handler)

            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            main_logger.addHandler(console_handler)

            # Configure root logger only once
            root_logger = logging.getLogger()
            if not root_logger.handlers:
                root_logger.setLevel(main_logger.level)
                root_logger.addHandler(console_handler)
                root_logger.addHandler(file_handler)

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Get a logger instance for the given name."""
        return logging.getLogger(f'ransomware_protection.{name}')

    @staticmethod
    def log_operation(operation: str, success: bool, details: Optional[str] = None,
                     logger: Optional[logging.Logger] = None) -> None:
        """Log an operation result with consistent formatting."""
        if logger is None:
            logger = logging.getLogger('ransomware_protection')

        level = logging.INFO if success else logging.ERROR
        status = "успешно" if success else "ошибка"

        message = f"Операция '{operation}' {status}"
        if details:
            message += f": {details}"

        logger.log(level, message)

    @staticmethod
    def log_security_event(event_type: str, description: str, severity: str = 'INFO',
                          details: Optional[Dict[str, Any]] = None,
                          logger: Optional[logging.Logger] = None) -> None:
        """Log security-related events with consistent formatting."""
        if logger is None:
            logger = logging.getLogger('ransomware_protection')

        severity_levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }

        level = severity_levels.get(severity.upper(), logging.INFO)

        message = f"Безопасность [{event_type}]: {description}"
        if details:
            message += f" | Детали: {details}"

        logger.log(level, message)

    @staticmethod
    def log_error(error: Exception, context: Optional[str] = None,
                  logger: Optional[logging.Logger] = None) -> None:
        """Log exceptions with context."""
        if logger is None:
            logger = logging.getLogger('ransomware_protection')

        message = f"Ошибка: {str(error)}"
        if context:
            message = f"{context} - {message}"

        logger.error(message)
        logger.debug(f"Traceback: {error}", exc_info=True)


# Global logger instance
ransomware_logger = RansomwareLogger()


def get_logger(name: str) -> logging.Logger:
    """Convenience function to get a logger."""
    return RansomwareLogger.get_logger(name)


def setup_logging_from_config(config: Dict[str, Any]) -> None:
    """Setup logging from configuration dictionary."""
    RansomwareLogger()._configure_logging(config)
