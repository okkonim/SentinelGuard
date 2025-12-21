"""
Custom exception classes for the ransomware protection system.
Provides structured error handling and better error reporting.
"""

from typing import Optional, Dict, Any


class RansomwareProtectionError(Exception):
    """Base exception class for ransomware protection system errors."""

    def __init__(self, message: str, error_code: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.error_code}: {self.message} | Details: {self.details}"
        return f"{self.error_code}: {self.message}"


class ConfigurationError(RansomwareProtectionError):
    """Raised when configuration loading or validation fails."""
    pass


class DatabaseError(RansomwareProtectionError):
    """Raised when database operations fail."""
    pass


class CryptoError(RansomwareProtectionError):
    """Raised when cryptographic operations fail."""
    pass


class FileOperationError(RansomwareProtectionError):
    """Raised when file operations fail."""
    pass


class NetworkError(RansomwareProtectionError):
    """Raised when network operations fail."""
    pass


class ProcessError(RansomwareProtectionError):
    """Raised when process operations fail."""
    pass


class AnalysisError(RansomwareProtectionError):
    """Raised when analysis operations fail."""
    pass


class SecurityAlert(Exception):
    """Special exception for security alerts that should be logged but not necessarily stop execution."""

    def __init__(self, alert_type: str, description: str, severity: str,
                 details: Optional[Dict[str, Any]] = None):
        self.alert_type = alert_type
        self.description = description
        self.severity = severity
        self.details = details or {}

    def __str__(self) -> str:
        return f"Security Alert [{self.severity}]: {self.alert_type} - {self.description}"


class ValidationError(RansomwareProtectionError):
    """Raised when input validation fails."""
    pass
