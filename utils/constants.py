"""
Centralized constants for the ransomware protection system.
Provides a single source of truth for configuration values.
"""

# File extensions
PE_EXTENSIONS = {'.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.com'}
SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1'}

# Architecture constants
ARCH_X86 = 'x86'
ARCH_X64 = 'x64'
ARCH_UNKNOWN = 'Unknown'

# Severity levels
SEVERITY_CRITICAL = 'CRITICAL'
SEVERITY_HIGH = 'HIGH'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_LOW = 'LOW'
SEVERITY_INFO = 'INFO'

# Event types
EVENT_FILE_CREATED = 'FILE_CREATED'
EVENT_FILE_MODIFIED = 'FILE_MODIFIED'
EVENT_FILE_DELETED = 'FILE_DELETED'
EVENT_PROCESS_STARTED = 'PROCESS_STARTED'
EVENT_PROCESS_TERMINATED = 'PROCESS_TERMINATED'
EVENT_NETWORK_CONNECTION = 'NETWORK_CONNECTION'
EVENT_YARA_MATCH = 'YARA_MATCH'

# Timeout constants
DEFAULT_TIMEOUT = 30
NETWORK_TIMEOUT = 30
FILE_TIMEOUT = 60
PROCESS_TIMEOUT = 10

# Entropy thresholds
NORMAL_ENTROPY_THRESHOLD = 6.5
HIGH_ENTROPY_THRESHOLD = 7.0
SUSPICIOUS_ENTROPY_THRESHOLD = 8.0

# Process monitoring
PROCESS_MONITOR_INTERVAL = 1.0  # seconds
PROCESS_SCAN_INTERVAL = 5.0     # seconds

# FIM monitoring
FIM_SCAN_INTERVAL = 2.0         # seconds
FIM_HASH_CHUNK_SIZE = 8192      # bytes

# Network analysis
SYN_FLOOD_THRESHOLD = 100       # packets per minute
ICMP_FLOOD_THRESHOLD = 50       # packets per minute
BEACON_THRESHOLD = 10           # connections
BEACON_TOLERANCE = 300          # seconds
KEY_TRANSMISSION_THRESHOLD = 1024  # bytes

# Suspicious imports
SUSPICIOUS_IMPORTS = {
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'LoadLibrary', 'GetProcAddress', 'VirtualProtect', 'HeapCreate',
    'CreateProcess', 'ShellExecute', 'WinExec', 'system', 'execve',
    'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile',
    'MoveFile', 'SetFilePointer', 'SetEndOfFile', 'LockFile', 'UnlockFile',
    'RegOpenKey', 'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
    'GetCurrentProcess', 'OpenProcessToken', 'LookupPrivilegeValue',
    'AdjustTokenPrivileges', 'CreateToken', 'DuplicateToken', 'ImpersonateLoggedOnUser',
    'GetTempPath', 'GetWindowsDirectory', 'GetSystemDirectory', 'GetCurrentDirectory',
    'SearchPath', 'GetModuleHandle', 'GetProcAddress', 'FreeLibrary',
    'lstrcpy', 'lstrcat', 'lstrlen', 'wsprintf', 'sprintf', 'strcpy', 'strcat'
}

# Standard PE sections
STANDARD_SECTIONS = {
    '.text', '.data', '.rdata', '.bss', '.idata', '.edata', 
    '.pdata', '.rsrc', '.reloc', '.tls', '.upx'
}

# Suspicious process names
SUSPICIOUS_PROCESSES = {
    'notepad.exe', 'calc.exe', 'mspaint.exe', 'cmd.exe', 
    'powershell.exe', 'wscript.exe', 'cscript.exe'
}

# Suspicious ports
SUSPICIOUS_PORTS = {
    6667, 6668, 6669, 31337, 12345, 54321, 1337, 2222, 3333, 4444
}

# Known C&C servers (example list)
KNOWN_CC_SERVERS = set()  # Can be populated from config

# Network protocols
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# Protocol names
PROTOCOL_MAP = {
    1: 'icmp',
    6: 'tcp', 
    17: 'udp'
}

# TCP flags
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_URG = 0x20

DB_DEFAULT_NAME = 'firewall.db'
NETWORK_INTERFACE='ens33'
# Database table names
DB_TABLE_FIM_EVENTS = 'fim_events'
DB_TABLE_PROCESS_EVENTS = 'process_events'
DB_TABLE_NETWORK_EVENTS = 'network_events'
DB_TABLE_NETSEC_ALERTS = 'netsec_alerts'
DB_TABLE_YARA_EVENTS = 'yara_events'
DB_TABLE_PE_FILES = 'pe_files'
DB_TABLE_PE_SECTIONS = 'pe_sections'
DB_TABLE_PE_IMPORTS = 'pe_imports'
DB_TABLE_RANSOMWARE_ATTACKS = 'ransomware_attacks'

# Event severity colors for CLI
SEVERITY_COLORS = {
    SEVERITY_CRITICAL: '🔴',
    SEVERITY_HIGH: '🟠',
    SEVERITY_MEDIUM: '🟡',
    SEVERITY_LOW: '🟢',
    SEVERITY_INFO: '⚪'
}

# System status
SYSTEM_RUNNING = 'RUNNING'
SYSTEM_STOPPED = 'STOPPED'
SYSTEM_ERROR = 'ERROR'

# Module names (for display)
MODULE_NAMES = {
    'crypto': 'Cryptography',
    'fim': 'File Integrity Monitoring (FIM)',
    'process_monitor': 'Process monitoring',
    'network_sniffer': 'Network analysis',
    'pe_analyzer': 'PE file analysis',
    'yara_scanner': 'YARA scanner'
}

# Logging levels
LOG_LEVEL_DEFAULT = 'INFO'
LOG_LEVEL_DEBUG = 'DEBUG'
LOG_LEVEL_WARNING = 'WARNING'
LOG_LEVEL_ERROR = 'ERROR'
LOG_LEVEL_CRITICAL = 'CRITICAL'

# Logging files
LOG_FILE_DEFAULT = 'ransomware_protection.log'
LOG_FILE_ERROR = 'ransomware_protection_error.log'

# Configuration defaults
DEFAULT_CONFIG = {
    'entropy_threshold': 6.5,
    'syn_flood_threshold': 100,
    'icmp_flood_threshold': 50,
    'beacon_threshold': 10,
    'beacon_tolerance': 300,
    'key_transmission_threshold': 1024,
    'process_monitor_interval': 1.0,
    'fim_scan_interval': 2.0,
    'network_timeout': 30,
    'file_timeout': 60,
    'cleanup_days': 30
}
