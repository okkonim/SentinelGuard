import pefile
import hashlib
import math
import os
import json
import logging
from database import Database

logger = logging.getLogger(__name__)

class PEAnalyzer:
    def __init__(self, db_name='firewall.db', config_path='config.json'):
        self.db = Database(db_name)
        self.config_path = config_path
        self.suspicious_imports = {
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'LoadLibrary', 'GetProcAddress', 'VirtualProtect', 'HeapCreate',
            'CreateProcess', 'ShellExecute', 'WinExec', 'system', 'execve'
        }
        self.entropy_threshold = 6.5
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            pe_config = config.get('pe_analysis', {})
            self.entropy_threshold = pe_config.get('entropy_threshold', 6.5)
        except Exception as e:
            logger.error(f"Error loading PE config: {e}")

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        entropy = 0.0
        data_len = len(data)
        for i in range(256):
            p = data.count(i) / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def load_pe_file(self, file_path):
        """Load PE file with exception handling."""
        try:
            pe = pefile.PE(file_path)
            return pe
        except pefile.PEFormatError as e:
            logger.error(f"PEFormatError for {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading PE file {file_path}: {e}")
            return None

    def extract_header_info(self, pe):
        """Extract key header information."""
        header_info = {}
        try:
            # Architecture
            machine = pe.FILE_HEADER.Machine
            if machine == 0x014c:
                header_info['architecture'] = 'x86'
            elif machine == 0x8664:
                header_info['architecture'] = 'x64'
            else:
                header_info['architecture'] = f'Unknown ({machine})'

            # Timestamp
            header_info['timestamp'] = pe.FILE_HEADER.TimeDateStamp

            # Entry point
            header_info['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            # Characteristics
            header_info['characteristics'] = pe.FILE_HEADER.Characteristics

        except Exception as e:
            logger.error(f"Error extracting header info: {e}")
        return header_info

    def analyze_sections(self, pe):
        """Analyze all sections for anomalies."""
        sections = []
        for section in pe.sections:
            try:
                section_name = section.Name.decode('utf-8').rstrip('\x00')
                virtual_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                virtual_address = section.VirtualAddress

                # Read section data
                section_data = None
                if section.PointerToRawData and section.SizeOfRawData:
                    pe.set_file_offset(section.PointerToRawData)
                    section_data = pe.__data__[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]

                # Calculate entropy
                entropy = self.calculate_entropy(section_data) if section_data else 0.0

                # Check for anomalies
                anomalies = []
                if entropy > self.entropy_threshold:
                    anomalies.append('high_entropy')

                # Check section name anomalies
                standard_sections = ['.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.pdata', '.rsrc', '.reloc']
                if section_name not in standard_sections and not section_name.startswith('.'):
                    anomalies.append('suspicious_name')

                section_info = {
                    'name': section_name,
                    'virtual_size': virtual_size,
                    'raw_size': raw_size,
                    'virtual_address': virtual_address,
                    'entropy': entropy,
                    'anomalies': ','.join(anomalies)
                }
                sections.append(section_info)

            except Exception as e:
                logger.error(f"Error analyzing section {section.Name}: {e}")
        return sections

    def analyze_imports(self, pe):
        """Analyze imported functions for suspicious APIs."""
        imports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8') if imp.name else f'Ordinal_{imp.ordinal}'
                        suspicious = func_name in self.suspicious_imports
                        import_info = {
                            'dll': dll_name,
                            'function': func_name,
                            'suspicious': suspicious
                        }
                        imports.append(import_info)
        except Exception as e:
            logger.error(f"Error analyzing imports: {e}")
        return imports

    def analyze_file(self, file_path):
        """Perform complete PE analysis."""
        if not os.path.exists(file_path):
            logger.warning(f"File does not exist: {file_path}")
            return None

        # Calculate SHA-256
        try:
            with open(file_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None

        pe = self.load_pe_file(file_path)
        if not pe:
            return None

        header_info = self.extract_header_info(pe)
        sections = self.analyze_sections(pe)
        imports = self.analyze_imports(pe)

        analysis_result = {
            'file_path': file_path,
            'sha256': sha256,
            'header': header_info,
            'sections': sections,
            'imports': imports
        }

        # Store in database
        self.store_analysis(analysis_result)

        return analysis_result

    def store_analysis(self, analysis_result):
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
                    section['anomalies']
                )

            # Insert imports
            for imp in analysis_result['imports']:
                self.db.insert_pe_import(
                    file_id,
                    imp['dll'],
                    imp['function'],
                    imp['suspicious']
                )

            logger.info(f"PE analysis stored for {analysis_result['file_path']}")

        except Exception as e:
            logger.error(f"Error storing PE analysis: {e}")

    def is_pe_file(self, file_path):
        """Check if file is a PE file by extension or content."""
        if not os.path.isfile(file_path):
            return False

        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.exe', '.dll', '.sys', '.ocx']:
            return True

        # Try to load as PE
        try:
            pefile.PE(file_path, fast_load=True)
            return True
        except:
            return False
