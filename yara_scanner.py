#!/usr/bin/env python3
"""
Refactored YARA Scanner for ransomware protection system.
Provides structured YARA rule management and file scanning with centralized logging.
"""

import yara
import os
import json
from typing import Dict, List, Optional, Any, Union
from database import Database
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import FileOperationError, AnalysisError, ValidationError, ConfigurationError
from utils.constants import *


class YaraRuleManager(LoggerMixin):
    """Manages YARA rule compilation, validation, and lifecycle."""
    
    def __init__(self):
        self.rules = None
        self.rule_files = {}
        self.last_compilation = None

    def compile_rules(self, rule_files: Dict[str, str]) -> bool:
        """Compile YARA rules from one or more .yar files."""
        if not rule_files:
            RansomwareLogger.log_security_event(
                'YARA_NO_RULES',
                'No YARA rule files provided for compilation',
                'WARNING'
            )
            return False

        try:
            # Validate rule files
            if not self._validate_rule_files(rule_files):
                return False

            # Compile rules
            self.rules = yara.compile(filepaths=rule_files)
            self.rule_files = rule_files.copy()
            self.last_compilation = os.path.getmtime(max(rule_files.values(), key=os.path.getmtime))
            
            RansomwareLogger.log_operation(
                f'YARA rules compiled successfully from {len(rule_files)} files', 
                True,
                f"Files: {list(rule_files.keys())}"
            )
            return True
            
        except yara.Error as e:
            RansomwareLogger.log_security_event(
                'YARA_COMPILATION_ERROR',
                f'YARA compilation failed: {str(e)}',
                'CRITICAL',
                f'Rule files: {list(rule_files.keys())}'
            )
            return False
        except Exception as e:
            RansomwareLogger.log_error(e, 'Unexpected error during YARA compilation')
            return False

    def _validate_rule_files(self, rule_files: Dict[str, str]) -> bool:
        """Validate YARA rule files before compilation."""
        try:
            for rule_name, file_path in rule_files.items():
                if not os.path.exists(file_path):
                    raise ConfigurationError(f"YARA rule file not found: {file_path}")
                
                if not file_path.lower().endswith(('.yar', '.yara')):
                    raise ConfigurationError(f"Invalid YARA rule file extension: {file_path}")
                
                if os.path.getsize(file_path) == 0:
                    raise ConfigurationError(f"Empty YARA rule file: {file_path}")
                
                # Try to parse file content
                if not self._validate_rule_content(file_path):
                    raise ConfigurationError(f"Invalid YARA rule content: {file_path}")
            
            RansomwareLogger.log_operation('YARA rule files validation', True)
            return True
            
        except ConfigurationError:
            raise
        except Exception as e:
            RansomwareLogger.log_error(e, "Error validating YARA rule files")
            return False

    def _validate_rule_content(self, file_path: str) -> bool:
        """Validate YARA rule file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Basic content validation
            if not content.strip():
                return False
            
            # Check for basic YARA syntax elements
            has_rules = 'rule ' in content or 'import ' in content
            if not has_rules:
                return False
            
            # Try to compile single rule for validation
            try:
                temp_rules = yara.compile(filepath=file_path)
                return True
            except yara.SyntaxError:
                return False
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error validating rule content: {file_path}")
            return False

    def reload_rules(self, rule_files: Optional[Dict[str, str]] = None) -> bool:
        """Reload YARA rules without restarting."""
        try:
            if rule_files is None:
                rule_files = self.rule_files
            
            if not rule_files:
                RansomwareLogger.log_security_event(
                    'YARA_RELOAD_NO_FILES',
                    'No rule files provided for reload',
                    'WARNING'
                )
                return False
            
            # Check if files have changed
            if self._check_rules_changed(rule_files):
                return self.compile_rules(rule_files)
            else:
                RansomwareLogger.log_operation('YARA rules reload skipped - no changes', True)
                return True
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error reloading YARA rules")
            return False

    def _check_rules_changed(self, rule_files: Dict[str, str]) -> bool:
        """Check if rule files have been modified since last compilation."""
        try:
            if not self.last_compilation:
                return True
            
            latest_modification = max(
                os.path.getmtime(file_path) 
                for file_path in rule_files.values()
            )
            
            return latest_modification > self.last_compilation
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error checking rule file modifications")
            return True  # Assume changed on error

    def get_rules_info(self) -> Dict[str, Any]:
        """Get information about loaded YARA rules."""
        info = {
            'loaded': self.rules is not None,
            'rule_count': 0,
            'rule_files': list(self.rule_files.keys()),
            'last_compilation': self.last_compilation
        }
        
        if self.rules:
            try:
                # Get rule count by trying to match a dummy file
                temp_dir = '/tmp'
                temp_file = os.path.join(temp_dir, 'yara_test_temp.tmp')
                
                # Create temporary file
                with open(temp_file, 'w') as f:
                    f.write('test content for yara rule counting')
                
                try:
                    matches = self.rules.match(temp_file)
                    info['rule_count'] = len(matches) if matches else 0
                except:
                    info['rule_count'] = 0
                finally:
                    try:
                        os.remove(temp_file)
                    except:
                        pass
                        
            except Exception as e:
                RansomwareLogger.log_error(e, "Error getting YARA rules info")
                info['rule_count'] = 0
        
        return info

    def unload_rules(self) -> None:
        """Unload current YARA rules."""
        try:
            self.rules = None
            self.rule_files = {}
            self.last_compilation = None
            
            RansomwareLogger.log_operation('YARA rules unloaded', True)
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error unloading YARA rules")


class YaraScanner(LoggerMixin):
    """Performs YARA scanning operations on files and directories."""
    
    def __init__(self, rule_manager: YaraRuleManager, db: Database):
        self.rule_manager = rule_manager
        self.db = db
        self.scan_stats = {
            'files_scanned': 0,
            'matches_found': 0,
            'scan_errors': 0,
            'start_time': None
        }

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file with compiled YARA rules."""
        if not self._validate_scan_request(file_path):
            return []

        try:
            self.scan_stats['files_scanned'] += 1
            
            # Get compiled rules
            rules = self.rule_manager.rules
            if not rules:
                RansomwareLogger.log_security_event(
                    'YARA_NO_COMPILED_RULES',
                    f'No compiled YARA rules available for file scan: {file_path}',
                    'WARNING'
                )
                return []

            # Perform scan
            matches = rules.match(file_path)
            results = []
            
            for match in matches:
                try:
                    yara_result = self._process_match(match, file_path)
                    if yara_result:
                        results.append(yara_result)
                        self.scan_stats['matches_found'] += 1
                        
                        # Log to database
                        self._log_match_to_db(yara_result)
                        
                except Exception as e:
                    RansomwareLogger.log_error(e, f"Error processing YARA match for {file_path}")
            
            if results:
                RansomwareLogger.log_security_event(
                    'YARA_MATCHES_FOUND',
                    f"YARA matches found in {file_path}: {len(results)}",
                    'CRITICAL',
                    f"Rules: {[r['rule_name'] for r in results]}"
                )
            
            return results
            
        except Exception as e:
            self.scan_stats['scan_errors'] += 1
            RansomwareLogger.log_error(e, f"Error scanning file {file_path}")
            return []

    def _validate_scan_request(self, file_path: str) -> bool:
        """Validate file scanning request."""
        if not file_path:
            RansomwareLogger.log_security_event(
                'YARA_SCAN_EMPTY_PATH',
                'Empty file path provided for YARA scan',
                'WARNING'
            )
            return False
        
        if not os.path.exists(file_path):
            RansomwareLogger.log_security_event(
                'YARA_SCAN_FILE_NOT_FOUND',
                f'File not found for YARA scan: {file_path}',
                'WARNING'
            )
            return False
        
        if not os.path.isfile(file_path):
            RansomwareLogger.log_security_event(
                'YARA_SCAN_NOT_FILE',
                f'Path is not a file for YARA scan: {file_path}',
                'WARNING'
            )
            return False
        
        # Check file size (skip very large files)
        try:
            file_size = os.path.getsize(file_path)
            max_size = 500 * 1024 * 1024  # 500MB limit
            
            if file_size > max_size:
                RansomwareLogger.log_security_event(
                    'YARA_SCAN_FILE_TOO_LARGE',
                    f'File too large for YARA scan: {file_path} ({file_size} bytes)',
                    'INFO'
                )
                return False
                
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error checking file size: {file_path}")
            return False
        
        return True

    def _process_match(self, match, file_path: str) -> Optional[Dict[str, Any]]:
        """Process a single YARA match result."""
        try:
            # Extract strings information with fallback
            strings_info = self._extract_strings_info(match)
            
            # Extract metadata
            meta_info = self._extract_meta_info(match)
            
            # Extract tags
            tags_info = self._extract_tags_info(match)
            
            # Create result
            result = {
                'rule_name': match.rule,
                'file_path': file_path,
                'tags': tags_info,
                'meta': meta_info,
                'strings': strings_info,
                'match_timestamp': match.timestamp if hasattr(match, 'timestamp') else None
            }
            
            # Add additional analysis
            result['severity'] = self._assess_match_severity(result)
            result['description'] = self._generate_match_description(result)
            
            return result
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error processing YARA match: {match}")
            return None

    def _extract_strings_info(self, match) -> List[Dict[str, Any]]:
        """Extract strings information from YARA match."""
        try:
            if hasattr(match, 'strings') and match.strings:
                strings = []
                for s in match.strings:
                    try:
                        string_info = {
                            'identifier': s.identifier,
                            'instances': []
                        }
                        
                        # Extract instances
                        if hasattr(s, 'instances') and s.instances:
                            for instance in s.instances:
                                instance_info = {
                                    'offset': getattr(instance, 'offset', None),
                                    'matched_data': getattr(instance, 'matched_data', b'').hex() if hasattr(instance, 'matched_data') else None,
                                    'length': len(getattr(instance, 'matched_data', b''))
                                }
                                string_info['instances'].append(instance_info)
                        
                        strings.append(string_info)
                        
                    except Exception as e:
                        RansomwareLogger.log_error(e, f"Error processing string instance: {s}")
                        continue
                
                return strings
            else:
                # Fallback for older YARA versions
                return [{'identifier': str(s), 'instances': []} for s in match.strings]
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error extracting strings info from YARA match")
            return []

    def _extract_meta_info(self, match) -> Dict[str, Any]:
        """Extract metadata from YARA match."""
        try:
            if hasattr(match, 'meta') and match.meta:
                return dict(match.meta)
            else:
                return {}
        except Exception as e:
            RansomwareLogger.log_error(e, "Error extracting metadata from YARA match")
            return {}

    def _extract_tags_info(self, match) -> List[str]:
        """Extract tags from YARA match."""
        try:
            if hasattr(match, 'tags') and match.tags:
                return list(match.tags)
            else:
                return []
        except Exception as e:
            RansomwareLogger.log_error(e, "Error extracting tags from YARA match")
            return []

    def _assess_match_severity(self, match_result: Dict[str, Any]) -> str:
        """Assess severity of YARA match."""
        try:
            # Check metadata for severity
            meta = match_result.get('meta', {})
            if 'severity' in meta:
                severity = str(meta['severity']).upper()
                if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
                    return severity
            
            # Check rule name for indicators
            rule_name = match_result.get('rule_name', '').lower()
            if any(keyword in rule_name for keyword in ['ransomware', 'crypto', 'malware']):
                return SEVERITY_CRITICAL
            elif any(keyword in rule_name for keyword in ['suspicious', 'threat']):
                return SEVERITY_HIGH
            
            # Default severity based on match characteristics
            strings_count = len(match_result.get('strings', []))
            if strings_count >= 5:
                return SEVERITY_HIGH
            elif strings_count >= 2:
                return SEVERITY_MEDIUM
            else:
                return SEVERITY_LOW
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error assessing match severity")
            return SEVERITY_MEDIUM

    def _generate_match_description(self, match_result: Dict[str, Any]) -> str:
        """Generate human-readable description of match."""
        try:
            rule_name = match_result.get('rule_name', 'Unknown Rule')
            file_path = match_result.get('file_path', 'Unknown File')
            strings_count = len(match_result.get('strings', []))
            
            description = f"YARA rule '{rule_name}' matched in {os.path.basename(file_path)}"
            
            if strings_count > 0:
                description += f" with {strings_count} string matches"
            
            # Add metadata information
            meta = match_result.get('meta', {})
            if 'description' in meta:
                description = meta['description']
            elif 'author' in meta:
                description += f" (Author: {meta['author']})"
            
            return description
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error generating match description")
            return f"YARA match in {match_result.get('file_path', 'unknown file')}"

    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """Recursively scan all files in a directory."""
        if not self._validate_directory_scan(directory_path):
            return []

        try:
            self.scan_stats['start_time'] = os.times()
            all_results = []
            
            RansomwareLogger.log_operation(
                f'Starting directory scan: {directory_path}', 
                False,
                f"Recursive: {recursive}"
            )
            
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip system and temporary files
                    if self._should_skip_file(file_path):
                        continue
                    
                    file_results = self.scan_file(file_path)
                    all_results.extend(file_results)
                
                # Skip certain directories if not recursive
                if not recursive:
                    break
            
            RansomwareLogger.log_operation(
                f'Directory scan completed: {directory_path}', 
                True,
                f"Files scanned: {self.scan_stats['files_scanned']}, Matches: {self.scan_stats['matches_found']}"
            )
            
            return all_results
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error scanning directory {directory_path}")
            return []

    def _validate_directory_scan(self, directory_path: str) -> bool:
        """Validate directory scanning request."""
        if not directory_path:
            RansomwareLogger.log_security_event(
                'YARA_SCAN_EMPTY_DIR',
                'Empty directory path provided for YARA scan',
                'WARNING'
            )
            return False
        
        if not os.path.exists(directory_path):
            RansomwareLogger.log_security_event(
                'YARA_SCAN_DIR_NOT_FOUND',
                f'Directory not found for YARA scan: {directory_path}',
                'WARNING'
            )
            return False
        
        if not os.path.isdir(directory_path):
            RansomwareLogger.log_security_event(
                'YARA_SCAN_NOT_DIR',
                f'Path is not a directory for YARA scan: {directory_path}',
                'WARNING'
            )
            return False
        
        return True

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped during directory scan."""
        try:
            file_name = os.path.basename(file_path).lower()
            
            # Skip system and temporary files
            skip_patterns = [
                '.tmp', '.temp', '.log', '.sys', '.dll', '.exe',
                'thumbs.db', 'desktop.ini', '.ds_store'
            ]
            
            return any(file_name.endswith(pattern) for pattern in skip_patterns)
            
        except Exception:
            return False

    def _log_match_to_db(self, match_result: Dict[str, Any]) -> None:
        """Log YARA match to database."""
        try:
            severity = match_result.get('severity', SEVERITY_LOW)
            
            self.db.insert_yara_event(
                match_result['file_path'],
                match_result['rule_name'],
                EVENT_YARA_MATCH,
                severity,
                json.dumps(match_result)
            )
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error logging YARA match to database")

    def get_scan_stats(self) -> Dict[str, Any]:
        """Get current scanning statistics."""
        return self.scan_stats.copy()

    def reset_scan_stats(self) -> None:
        """Reset scanning statistics."""
        self.scan_stats = {
            'files_scanned': 0,
            'matches_found': 0,
            'scan_errors': 0,
            'start_time': None
        }


class YaraProcessor(LoggerMixin):
    """Processes and analyzes YARA scan results."""
    
    def __init__(self):
        pass

    def analyze_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze YARA scan results and generate summary."""
        if not scan_results:
            return self._empty_analysis()
        
        try:
            analysis = {
                'total_matches': len(scan_results),
                'files_affected': len(set(result['file_path'] for result in scan_results)),
                'rules_matched': len(set(result['rule_name'] for result in scan_results)),
                'severity_distribution': self._count_by_severity(scan_results),
                'top_rules': self._get_top_rules(scan_results),
                'risk_assessment': self._assess_overall_risk(scan_results),
                'recommendations': self._generate_recommendations(scan_results)
            }
            
            RansomwareLogger.log_operation('YARA results analysis completed', True)
            return analysis
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing YARA results")
            return self._empty_analysis()

    def _empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis structure."""
        return {
            'total_matches': 0,
            'files_affected': 0,
            'rules_matched': 0,
            'severity_distribution': {},
            'top_rules': [],
            'risk_assessment': {'level': 'LOW', 'score': 0},
            'recommendations': []
        }

    def _count_by_severity(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count results by severity level."""
        severity_counts = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
        
        for result in results:
            severity = result.get('severity', SEVERITY_LOW)
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts

    def _get_top_rules(self, results: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
        """Get top N most frequent rules."""
        rule_counts = {}
        
        for result in results:
            rule_name = result['rule_name']
            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
        
        # Sort by frequency
        sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'rule_name': rule, 'matches': count}
            for rule, count in sorted_rules[:top_n]
        ]

    def _assess_overall_risk(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk based on scan results."""
        try:
            severity_scores = {
                SEVERITY_CRITICAL: 4,
                SEVERITY_HIGH: 3,
                SEVERITY_MEDIUM: 2,
                SEVERITY_LOW: 1
            }
            
            total_score = sum(
                severity_scores.get(result.get('severity', SEVERITY_LOW), 1)
                for result in results
            )
            
            # Determine risk level
            if total_score >= 20:
                risk_level = SEVERITY_CRITICAL
            elif total_score >= 10:
                risk_level = SEVERITY_HIGH
            elif total_score >= 5:
                risk_level = SEVERITY_MEDIUM
            else:
                risk_level = SEVERITY_LOW
            
            return {
                'level': risk_level,
                'score': total_score,
                'affected_files': len(set(result['file_path'] for result in results))
            }
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error assessing overall risk")
            return {'level': SEVERITY_LOW, 'score': 0, 'affected_files': 0}

    def _generate_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on scan results."""
        recommendations = []
        
        try:
            # Check for critical matches
            critical_matches = [r for r in results if r.get('severity') == SEVERITY_CRITICAL]
            if critical_matches:
                recommendations.append("IMMEDIATE ACTION REQUIRED: Critical threats detected. Quarantine affected files.")
            
            # Check for high risk patterns
            high_matches = [r for r in results if r.get('severity') == SEVERITY_HIGH]
            if len(high_matches) > 5:
                recommendations.append("Multiple high-risk threats detected. Review and update security policies.")
            
            # Check for file encryption patterns
            ransomware_patterns = ['crypto', 'ransom', 'encrypt', 'decrypt']
            ransomware_matches = [
                r for r in results 
                if any(pattern in r.get('rule_name', '').lower() for pattern in ransomware_patterns)
            ]
            if ransomware_matches:
                recommendations.append("Ransomware patterns detected. Activate backup systems and network isolation.")
            
            # General recommendations
            if len(results) > 10:
                recommendations.append("High volume of matches detected. Consider updating YARA rules.")
            
            recommendations.append("Review all matches and implement appropriate remediation measures.")
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error generating recommendations")
            recommendations.append("Review scan results manually for security assessment.")
        
        return recommendations


class YARAScanner(LoggerMixin):
    """Main YARA scanner coordinator."""
    
    def __init__(self, db_name: str = 'firewall.db'):
        self.db = Database(db_name)
        
        # Initialize components
        self.rule_manager = YaraRuleManager()
        self.scanner = YaraScanner(self.rule_manager, self.db)
        self.processor = YaraProcessor()
        
        # YARA scanner initialized lazily

    def compile_rules(self, rule_files: Dict[str, str]) -> bool:
        """Compile YARA rules from one or more .yar files."""
        return self.rule_manager.compile_rules(rule_files)

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file with compiled YARA rules."""
        return self.scanner.scan_file(file_path)

    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """Recursively scan all files in a directory."""
        return self.scanner.scan_directory(directory_path, recursive)

    def reload_rules(self, rule_files: Optional[Dict[str, str]] = None) -> bool:
        """Reload YARA rules without restarting."""
        return self.rule_manager.reload_rules(rule_files)

    def analyze_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze scan results and generate summary."""
        return self.processor.analyze_results(scan_results)

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive YARA scanner system information."""
        info = {
            'rule_manager': self.rule_manager.get_rules_info(),
            'scan_stats': self.scanner.get_scan_stats(),
            'database': {
                'connected': self.db is not None,
                'type': type(self.db).__name__
            }
        }
        
        return info

    def reset_stats(self) -> None:
        """Reset scanning statistics."""
        self.scanner.reset_scan_stats()

    def unload_rules(self) -> None:
        """Unload current YARA rules."""
        self.rule_manager.unload_rules()
