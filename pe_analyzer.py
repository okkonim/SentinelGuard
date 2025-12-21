#!/usr/bin/env python3
"""
Refactored PE Analyzer for ransomware protection system.
Provides structured PE file analysis with centralized logging and error handling.
"""

import pefile
import hashlib
import math
import os
import json
from typing import Dict, List, Optional, Any
from database import Database
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import FileOperationError, AnalysisError, ValidationError
from utils.constants import *


class EntropyCalculator(LoggerMixin):
    """Calculates Shannon entropy for PE file sections and data."""
    
    def __init__(self):
        pass

    def calculate_entropy(self, data: Optional[bytes]) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data or len(data) == 0:
            return 0.0
            
        try:
            entropy = 0.0
            data_len = len(data)
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)
                    
            return entropy
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error calculating entropy")
            return 0.0

    def classify_entropy(self, entropy: float) -> str:
        """Classify entropy level based on thresholds."""
        if entropy >= SUSPICIOUS_ENTROPY_THRESHOLD:
            return "SUSPICIOUS"
        elif entropy >= HIGH_ENTROPY_THRESHOLD:
            return "HIGH"
        elif entropy >= NORMAL_ENTROPY_THRESHOLD:
            return "MEDIUM"
        else:
            return "NORMAL"


class PEProcessor(LoggerMixin):
    """Handles PE file loading, validation, and basic processing."""
    
    def __init__(self, db: Database):
        self.db = db
        self.entropy_calculator = EntropyCalculator()

    def load_pe_file(self, file_path: str) -> Optional[pefile.PE]:
        """Load PE file with comprehensive error handling."""
        if not self._validate_file_path(file_path):
            return None
            
        try:
            pe = pefile.PE(file_path)
            self.logger.debug(f"Successfully loaded PE file: {file_path}")
            return pe
            
        except pefile.PEFormatError as e:
            RansomwareLogger.log_security_event(
                'PE_FORMAT_ERROR',
                f"Invalid PE format for file: {file_path}",
                'HIGH',
                str(e)
            )
            return None
        except PermissionError as e:
            RansomwareLogger.log_security_event(
                'PE_ACCESS_ERROR',
                f"Permission denied accessing PE file: {file_path}",
                'MEDIUM',
                str(e)
            )
            return None
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error loading PE file: {file_path}")
            return None

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path and existence."""
        if not file_path:
            raise ValidationError("File path cannot be empty")
            
        if not os.path.exists(file_path):
            raise FileOperationError(f"File does not exist: {file_path}")
            
        if not os.path.isfile(file_path):
            raise FileOperationError(f"Path is not a file: {file_path}")
            
        if not self._check_file_size(file_path):
            return False
            
        return True

    def _check_file_size(self, file_path: str) -> bool:
        """Check if file size is reasonable for PE analysis."""
        try:
            file_size = os.path.getsize(file_path)
            max_size = 100 * 1024 * 1024  # 100MB limit
            
            if file_size > max_size:
                RansomwareLogger.log_security_event(
                    'PE_FILE_TOO_LARGE',
                    f"PE file too large for analysis: {file_path} ({file_size} bytes)",
                    'MEDIUM'
                )
                return False
                
            if file_size < 1024:  # Less than 1KB
                RansomwareLogger.log_security_event(
                    'PE_FILE_TOO_SMALL',
                    f"PE file too small: {file_path} ({file_size} bytes)",
                    'LOW'
                )
                return False
                
            return True
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error checking file size: {file_path}")
            return False

    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA-256 hash of file."""
        try:
            with open(file_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            self.logger.debug(f"Calculated hash for {file_path}: {sha256[:16]}...")
            return sha256
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error calculating hash for {file_path}")
            return None

    def extract_header_info(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract key header information from PE file."""
        header_info = {}
        
        try:
            # Architecture detection
            machine = pe.FILE_HEADER.Machine
            if machine == 0x014c:
                header_info['architecture'] = ARCH_X86
            elif machine == 0x8664:
                header_info['architecture'] = ARCH_X64
            else:
                header_info['architecture'] = f"{ARCH_UNKNOWN} ({hex(machine)})"

            # Timestamp
            header_info['timestamp'] = pe.FILE_HEADER.TimeDateStamp

            # Entry point
            header_info['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            # Characteristics
            header_info['characteristics'] = pe.FILE_HEADER.Characteristics

            # Additional header info
            header_info['sections_count'] = len(pe.sections)
            header_info['optional_header_size'] = pe.OPTIONAL_HEADER.SizeOfOptionalHeader
            
            self.logger.debug("Successfully extracted PE header information")
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error extracting PE header information")
            
        return header_info


class SectionAnalyzer(LoggerMixin):
    """Analyzes PE sections for anomalies and suspicious characteristics."""
    
    def __init__(self):
        self.entropy_calculator = EntropyCalculator()

    def analyze_sections(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Analyze all sections for anomalies."""
        sections = []
        
        try:
            for section in pe.sections:
                section_info = self._analyze_single_section(section, pe)
                if section_info:
                    sections.append(section_info)
                    
            self.logger.debug(f"Analyzed {len(sections)} PE sections")
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing PE sections")
            
        return sections

    def _analyze_single_section(self, section, pe: pefile.PE) -> Optional[Dict[str, Any]]:
        """Analyze a single PE section."""
        try:
            section_name = self._extract_section_name(section)
            
            # Basic section information
            section_info = {
                'name': section_name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'virtual_address': section.VirtualAddress,
                'raw_address': section.PointerToRawData,
                'characteristics': section.Characteristics
            }

            # Calculate entropy
            section_data = self._extract_section_data(section, pe)
            entropy = self.entropy_calculator.calculate_entropy(section_data)
            entropy_class = self.entropy_calculator.classify_entropy(entropy)
            
            section_info['entropy'] = entropy
            section_info['entropy_class'] = entropy_class

            # Detect anomalies
            anomalies = self._detect_section_anomalies(section, section_name, entropy, section_data)
            section_info['anomalies'] = anomalies
            section_info['suspicious'] = len(anomalies) > 0

            # Additional analysis
            section_info['packed'] = self._detect_packed_section(section_name, entropy)
            section_info['executable'] = self._is_executable_section(section.Characteristics)

            return section_info
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing section {section.Name}")
            return None

    def _extract_section_name(self, section) -> str:
        """Extract clean section name."""
        try:
            return section.Name.decode('utf-8').rstrip('\x00')
        except:
            return str(section.Name).strip('\x00')

    def _extract_section_data(self, section, pe: pefile.PE) -> Optional[bytes]:
        """Extract section data with fallback mechanisms."""
        # Try primary method
        try:
            if section.PointerToRawData and section.SizeOfRawData:
                return section.get_data()
        except:
            pass
            
        # Try manual file reading
        try:
            if pe.filename and section.PointerToRawData and section.SizeOfRawData:
                with open(pe.filename, 'rb') as f:
                    f.seek(section.PointerToRawData)
                    return f.read(section.SizeOfRawData)
        except:
            pass
            
        return None

    def _detect_section_anomalies(self, section, section_name: str, 
                                entropy: float, section_data: Optional[bytes]) -> List[str]:
        """Detect anomalies in PE section."""
        anomalies = []
        
        # High entropy
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            anomalies.append('high_entropy')
            
        # Suspicious section names
        if self._is_suspicious_section_name(section_name):
            anomalies.append('suspicious_name')
            
        # Unusual section sizes
        if section.Misc_VirtualSize == 0 or section.SizeOfRawData == 0:
            anomalies.append('zero_size')
            
        # Mismatched sizes
        if abs(section.Misc_VirtualSize - section.SizeOfRawData) > 4096:
            anomalies.append('size_mismatch')
            
        # Empty or suspicious content
        if section_data and len(section_data) == 0:
            anomalies.append('empty_content')
            
        return anomalies

    def _is_suspicious_section_name(self, section_name: str) -> bool:
        """Check if section name is suspicious."""
        # Non-standard sections
        if section_name not in STANDARD_SECTIONS and not section_name.startswith('.'):
            return True
            
        # Suspicious names
        suspicious_names = ['.upx', '.aspack', '.fsg', '.pecompact', '.themida']
        return any(name in section_name.lower() for name in suspicious_names)

    def _detect_packed_section(self, section_name: str, entropy: float) -> bool:
        """Detect if section might be packed."""
        # High entropy sections often indicate packing
        if entropy >= SUSPICIOUS_ENTROPY_THRESHOLD:
            return True
            
        # Known packer section names
        packer_sections = ['.upx', '.aspack', '.fsg', '.pecompact']
        return any(packer in section_name.lower() for packer in packer_sections)

    def _is_executable_section(self, characteristics: int) -> bool:
        """Check if section has executable characteristics."""
        # Check for executable flag (0x20000000 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
        return bool(characteristics & 0x20000000)


class ImportAnalyzer(LoggerMixin):
    """Analyzes imported functions for suspicious APIs and behaviors."""
    
    def __init__(self):
        self.suspicious_imports = SUSPICIOUS_IMPORTS.copy()

    def analyze_imports(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Analyze imported functions for suspicious APIs."""
        imports = []
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = self._clean_dll_name(entry.dll)
                    for imp in entry.imports:
                        import_info = self._analyze_import(dll_name, imp)
                        if import_info:
                            imports.append(import_info)
                            
            self.logger.debug(f"Analyzed {len(imports)} imports from PE")
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing PE imports")
            
        return imports

    def _clean_dll_name(self, dll_name: bytes) -> str:
        """Clean DLL name from bytes."""
        try:
            return dll_name.decode('utf-8').lower()
        except:
            return str(dll_name).lower()

    def _analyze_import(self, dll_name: str, imp) -> Optional[Dict[str, Any]]:
        """Analyze a single import."""
        try:
            func_name = self._extract_function_name(imp)
            
            import_info = {
                'dll': dll_name,
                'function': func_name,
                'ordinal': imp.ordinal if hasattr(imp, 'ordinal') else None,
                'address': imp.address if hasattr(imp, 'address') else None
            }

            # Check for suspicious functions
            is_suspicious = func_name in self.suspicious_imports
            import_info['suspicious'] = is_suspicious
            
            # Categorize function
            category = self._categorize_function(func_name, dll_name)
            import_info['category'] = category
            
            # Risk level
            risk_level = self._assess_function_risk(func_name, dll_name)
            import_info['risk_level'] = risk_level

            return import_info
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing import: {imp}")
            return None

    def _extract_function_name(self, imp) -> str:
        """Extract function name from import."""
        try:
            if imp.name:
                return imp.name.decode('utf-8')
            elif hasattr(imp, 'ordinal'):
                return f"Ordinal_{imp.ordinal}"
            else:
                return "Unknown"
        except:
            return "Unknown"

    def _categorize_function(self, func_name: str, dll_name: str) -> str:
        """Categorize function by purpose."""
        categories = {
            'file_operations': ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile'],
            'process_operations': ['CreateProcess', 'OpenProcess', 'TerminateProcess'],
            'memory_operations': ['VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory'],
            'registry_operations': ['RegOpenKey', 'RegCreateKey', 'RegSetValue'],
            'network_operations': ['WSAStartup', 'connect', 'send', 'recv'],
            'cryptography': ['CryptAcquireContext', 'CryptGenKey', 'CryptEncrypt'],
            'system_operations': ['GetCurrentProcess', 'GetSystemDirectory', 'GetWindowsDirectory']
        }
        
        for category, functions in categories.items():
            if any(func in func_name for func in functions):
                return category
                
        return 'other'

    def _assess_function_risk(self, func_name: str, dll_name: str) -> str:
        """Assess risk level of imported function."""
        high_risk_functions = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'AddScheduledTask', 'NetServerEnum', 'NetWkstaGetInfo'
        ]
        
        medium_risk_functions = [
            'CreateFile', 'WriteFile', 'RegSetValue', 'ShellExecute',
            'system', 'execve', 'popen'
        ]
        
        if any(func in func_name for func in high_risk_functions):
            return 'HIGH'
        elif any(func in func_name for func in medium_risk_functions):
            return 'MEDIUM'
        else:
            return 'LOW'


class PEAnalyzer(LoggerMixin):
    """Main PE analyzer coordinator."""
    
    def __init__(self, db_name: str = 'firewall.db', config_path: str = 'config.json'):
        self.db = Database(db_name)
        self.config_path = config_path
        
        # Initialize components
        self.pe_processor = PEProcessor(self.db)
        self.section_analyzer = SectionAnalyzer()
        self.import_analyzer = ImportAnalyzer()
        
        # Configuration
        self.config = self._load_config()
        
        # PE analyzer initialized

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config file."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                
            pe_config = config.get('pe_analysis', {})
            RansomwareLogger.log_operation('PEAnalyzer config loaded', True)
            return config
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error loading PEAnalyzer configuration")
            return {}

    def analyze_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Perform complete PE analysis."""
        try:
            RansomwareLogger.log_operation(f'PE analysis started for {file_path}', False)
            
            # Validate input
            if not self._validate_analysis_request(file_path):
                return None
            
            # Calculate file hash
            sha256 = self.pe_processor.calculate_file_hash(file_path)
            if not sha256:
                return None
            
            # Check if already analyzed
            if self._is_already_analyzed(sha256):
                RansomwareLogger.log_operation(f'PE file already analyzed: {file_path}', True)
                return self._get_existing_analysis(sha256)
            
            # Load PE file
            pe = self.pe_processor.load_pe_file(file_path)
            if not pe:
                return None
            
            # Perform analysis
            header_info = self.pe_processor.extract_header_info(pe)
            sections = self.section_analyzer.analyze_sections(pe)
            imports = self.import_analyzer.analyze_imports(pe)
            
            # Compile results
            analysis_result = {
                'file_path': file_path,
                'sha256': sha256,
                'header': header_info,
                'sections': sections,
                'imports': imports,
                'analysis_timestamp': pefile.PE.timestamp
            }
            
            # Calculate overall risk
            analysis_result['risk_assessment'] = self._assess_overall_risk(sections, imports)
            
            # Store in database
            self._store_analysis(analysis_result)
            
            RansomwareLogger.log_operation(f'PE analysis completed for {file_path}', True)
            return analysis_result
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error analyzing PE file: {file_path}")
            return None

    def _validate_analysis_request(self, file_path: str) -> bool:
        """Validate PE analysis request."""
        if not file_path:
            raise ValidationError("File path cannot be empty")
            
        if not os.path.exists(file_path):
            raise FileOperationError(f"File does not exist: {file_path}")
            
        if not self.is_pe_file(file_path):
            raise ValidationError(f"File is not a valid PE file: {file_path}")
            
        return True

    def _is_already_analyzed(self, sha256: str) -> bool:
        """Check if file has already been analyzed."""
        try:
            existing = self.db.query_pe_files(sha256=sha256)
            return len(existing) > 0
        except Exception as e:
            RansomwareLogger.log_error(e, "Error checking existing analysis")
            return False

    def _get_existing_analysis(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Get existing analysis results."""
        try:
            # This would need implementation in Database class
            # For now, return None to trigger re-analysis
            return None
        except Exception as e:
            RansomwareLogger.log_error(e, "Error getting existing analysis")
            return None

    def _assess_overall_risk(self, sections: List[Dict], imports: List[Dict]) -> Dict[str, Any]:
        """Assess overall risk based on sections and imports."""
        risk_factors = {
            'high_entropy_sections': 0,
            'suspicious_sections': 0,
            'suspicious_imports': 0,
            'high_risk_imports': 0,
            'packed_sections': 0
        }
        
        # Analyze sections
        for section in sections:
            if section.get('entropy_class') == 'SUSPICIOUS':
                risk_factors['high_entropy_sections'] += 1
            if section.get('suspicious'):
                risk_factors['suspicious_sections'] += 1
            if section.get('packed'):
                risk_factors['packed_sections'] += 1
        
        # Analyze imports
        for imp in imports:
            if imp.get('suspicious'):
                risk_factors['suspicious_imports'] += 1
            if imp.get('risk_level') == 'HIGH':
                risk_factors['high_risk_imports'] += 1
        
        # Calculate overall risk score
        risk_score = (
            risk_factors['high_entropy_sections'] * 2 +
            risk_factors['suspicious_sections'] * 1.5 +
            risk_factors['suspicious_imports'] * 1 +
            risk_factors['high_risk_imports'] * 2 +
            risk_factors['packed_sections'] * 1.5
        )
        
        # Determine risk level
        if risk_score >= 10:
            risk_level = 'CRITICAL'
        elif risk_score >= 5:
            risk_level = 'HIGH'
        elif risk_score >= 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }

    def _store_analysis(self, analysis_result: Dict[str, Any]) -> None:
        """Store analysis results in database."""
        try:
            # Insert file record
            file_id = self.db.insert_pe_file(
                analysis_result['file_path'],
                analysis_result['sha256'],
                analysis_result['header'].get('architecture'),
                analysis_result['header'].get('entry_point'),
                analysis_result['header'].get('characteristics')
            )
            
            # Insert sections
            for section in analysis_result['sections']:
                self.db.insert_pe_section(
                    file_id,
                    section['name'],
                    section['virtual_size'],
                    section['raw_size'],
                    section['virtual_address'],
                    section['entropy'],
                    ','.join(section.get('anomalies', []))
                )
            
            # Insert imports
            for imp in analysis_result['imports']:
                self.db.insert_pe_import(
                    file_id,
                    imp['dll'],
                    imp['function'],
                    imp.get('suspicious', False)
                )
            
            RansomwareLogger.log_operation('PE analysis stored in database', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error storing PE analysis")

    def is_pe_file(self, file_path: str) -> bool:
        """Check if file is a valid PE file."""
        if not file_path or not os.path.isfile(file_path):
            return False
        
        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in PE_EXTENSIONS:
            return True
        
        # Try to load as PE
        try:
            pefile.PE(file_path, fast_load=True)
            return True
        except:
            return False

    def get_analysis_summary(self, analysis_result: Dict[str, Any]) -> str:
        """Get human-readable summary of PE analysis."""
        if not analysis_result:
            return "No analysis available"
        
        summary = []
        summary.append(f"PE File Analysis: {analysis_result.get('file_path', 'Unknown')}")
        summary.append(f"SHA256: {analysis_result.get('sha256', 'Unknown')[:16]}...")
        
        # Header info
        header = analysis_result.get('header', {})
        if header:
            summary.append(f"Architecture: {header.get('architecture', 'Unknown')}")
            summary.append(f"Sections: {header.get('sections_count', 0)}")
        
        # Risk assessment
        risk = analysis_result.get('risk_assessment', {})
        if risk:
            summary.append(f"Risk Level: {risk.get('risk_level', 'Unknown')} (Score: {risk.get('risk_score', 0)})")
        
        # Import summary
        imports = analysis_result.get('imports', [])
        suspicious_imports = sum(1 for imp in imports if imp.get('suspicious'))
        if suspicious_imports > 0:
            summary.append(f"Suspicious Imports: {suspicious_imports}/{len(imports)}")
        
        # Section summary
        sections = analysis_result.get('sections', [])
        high_entropy = sum(1 for sec in sections if sec.get('entropy_class') == 'SUSPICIOUS')
        if high_entropy > 0:
            summary.append(f"High Entropy Sections: {high_entropy}/{len(sections)}")
        
        return "\n".join(summary)
