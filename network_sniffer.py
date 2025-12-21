#!/usr/bin/env python3
"""
Hybrid Network Sniffer with Threat Detection Integration
Combines Scapy packet capture with YARA, process monitoring, FIM, and PE analysis

This module has been refactored to:
- Eliminate code duplication and long methods
- Separate concerns into focused classes
- Use centralized logging and error handling
- Provide better structure and maintainability
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw
import threading
import queue
import time
import os
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
import psutil

from database import Database
from yara_scanner import YARAScanner
from process_monitor import ProcessMonitor
from fim import FIM
from pe_analyzer import PEAnalyzer
from crypto import CryptoManager
from utils.logging_utils import LoggerMixin, RansomwareLogger
from utils.exceptions import NetworkError, ValidationError, SecurityAlert


class PacketProcessor(LoggerMixin):
    """Handles individual packet processing and information extraction."""
    
    def __init__(self):
        self.packet_count = 0

    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process a single packet and extract information."""
        try:
            self.packet_count += 1
            packet_info = self._extract_packet_info(packet)
            
            if not packet_info:
                return None
                
            # Log packet processing
            self.logger.debug(f"Processed packet {self.packet_count}: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
            return packet_info
            
        except Exception as e:
            RansomwareLogger.log_error(e, f"Error processing packet {self.packet_count}")
            return None

    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract key information from packet."""
        info = {
            'timestamp': datetime.now().isoformat(),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload': None,
            'packet_size': len(packet)
        }

        try:
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                info['protocol'] = packet[IP].proto

            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['protocol'] = 6  # TCP
                info['flags'] = self._extract_tcp_flags(packet[TCP])

            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['protocol'] = 17  # UDP

            elif ICMP in packet:
                info['protocol'] = 1  # ICMP

            # Extract payload
            if Raw in packet:
                payload = bytes(packet[Raw])
                info['payload'] = payload
                info['http_traffic'] = self._detect_http_traffic(packet)

            return info if info['src_ip'] and info['dst_ip'] else None
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error extracting packet information")
            return None

    def _extract_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string."""
        flags = []
        if tcp_layer.flags & 0x02: flags.append('SYN')
        if tcp_layer.flags & 0x10: flags.append('ACK')
        if tcp_layer.flags & 0x01: flags.append('FIN')
        if tcp_layer.flags & 0x04: flags.append('RST')
        if tcp_layer.flags & 0x08: flags.append('PSH')
        if tcp_layer.flags & 0x20: flags.append('URG')
        return ','.join(flags)

    def _detect_http_traffic(self, packet) -> bool:
        """Detect if packet contains HTTP traffic."""
        try:
            if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80 or
                                  packet[TCP].dport == 443 or packet[TCP].sport == 443):
                return HTTPRequest in packet or HTTPResponse in packet
        except:
            pass
        return False


class TrafficAnalyzer(LoggerMixin):
    """Analyzes network traffic for anomalies and patterns."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.syn_packets = defaultdict(list)
        self.icmp_packets = defaultdict(list)
        self.beacon_connections = defaultdict(list)
        self.connection_patterns = defaultdict(list)
        
        # Anomaly thresholds
        self.syn_flood_threshold = config.get('syn_flood_threshold', 100)
        self.icmp_flood_threshold = config.get('icmp_flood_threshold', 50)
        self.beacon_threshold = config.get('beacon_threshold', 10)
        self.beacon_tolerance = config.get('beacon_tolerance', 300)

    def analyze_traffic(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze traffic for anomalies."""
        anomalies = []
        current_time = datetime.now()
        
        try:
            # SYN flood detection
            if packet_info.get('flags') and 'SYN' in packet_info['flags']:
                anomalies.extend(self._detect_syn_flood(packet_info, current_time))
            
            # ICMP flood detection
            if packet_info.get('protocol') == 1:  # ICMP
                anomalies.extend(self._detect_icmp_flood(packet_info, current_time))
            
            # Beaconing detection
            if packet_info.get('src_port') and packet_info.get('dst_port'):
                anomalies.extend(self._detect_beaconing(packet_info, current_time))
                
            return anomalies
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing traffic for anomalies")
            return []

    def _detect_syn_flood(self, packet_info: Dict[str, Any], current_time: datetime) -> List[Dict[str, Any]]:
        """Detect SYN flood attacks."""
        anomalies = []
        src_ip = packet_info['src_ip']
        self.syn_packets[src_ip].append(current_time)
        
        # Clean old entries
        cutoff = current_time - timedelta(minutes=1)
        self.syn_packets[src_ip] = [t for t in self.syn_packets[src_ip] if t > cutoff]
        
        if len(self.syn_packets[src_ip]) > self.syn_flood_threshold:
            anomalies.append({
                'type': 'SYN_FLOOD',
                'description': f"SYN flood detected from {src_ip}",
                'details': f"SYN packets: {len(self.syn_packets[src_ip])} in last minute",
                'severity': 'CRITICAL',
                'packet_info': packet_info
            })
        
        return anomalies

    def _detect_icmp_flood(self, packet_info: Dict[str, Any], current_time: datetime) -> List[Dict[str, Any]]:
        """Detect ICMP flood attacks."""
        anomalies = []
        src_ip = packet_info['src_ip']
        self.icmp_packets[src_ip].append(current_time)
        
        # Clean old entries
        cutoff = current_time - timedelta(minutes=1)
        self.icmp_packets[src_ip] = [t for t in self.icmp_packets[src_ip] if t > cutoff]
        
        if len(self.icmp_packets[src_ip]) > self.icmp_flood_threshold:
            anomalies.append({
                'type': 'ICMP_FLOOD',
                'description': f"ICMP flood detected from {src_ip}",
                'details': f"ICMP packets: {len(self.icmp_packets[src_ip])} in last minute",
                'severity': 'CRITICAL',
                'packet_info': packet_info
            })
        
        return anomalies

    def _detect_beaconing(self, packet_info: Dict[str, Any], current_time: datetime) -> List[Dict[str, Any]]:
        """Detect beaconing patterns (botnet communication)."""
        anomalies = []
        connection_key = (packet_info['src_ip'], packet_info['dst_ip'], packet_info['dst_port'])
        self.beacon_connections[connection_key].append(current_time)
        
        # Clean old entries
        cutoff = current_time - timedelta(hours=1)
        self.beacon_connections[connection_key] = [t for t in self.beacon_connections[connection_key] if t > cutoff]
        
        # Check for beaconing pattern
        if len(self.beacon_connections[connection_key]) >= self.beacon_threshold:
            timestamps = sorted(self.beacon_connections[connection_key])
            intervals = []
            
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                regular_connections = sum(1 for interval in intervals
                                        if abs(interval - avg_interval) <= self.beacon_tolerance)
                
                if regular_connections >= len(intervals) * 0.8:  # 80% regularity
                    anomalies.append({
                        'type': 'BEACONING',
                        'description': f"Botnet beaconing detected from {packet_info['src_ip']} to {packet_info['dst_ip']}:{packet_info['dst_port']}",
                        'details': f"Average interval: {avg_interval:.1f}s, connections: {len(timestamps)}",
                        'severity': 'HIGH',
                        'packet_info': packet_info
                    })
        
        return anomalies


class NetworkDetector(LoggerMixin):
    """Detects ransomware-specific network activity."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.known_cc_servers = config.get('known_cc_servers', [])
        self.suspicious_ports = config.get('suspicious_ports', [])
        self.dns_timeout = config.get('dns_timeout', 30)
        self.key_transmission_threshold = config.get('key_transmission_threshold', 1024)
        self.large_transfers = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.connection_patterns = defaultdict(list)

    def detect_ransomware_activity(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect ransomware-specific network activity."""
        detections = []
        current_time = datetime.now()
        
        try:
            # Check for C&C server connections
            if packet_info.get('dst_ip') in self.known_cc_servers:
                detections.append(self._create_detection(
                    'C_AND_C_CONNECTION',
                    f"Connection to known C&C server: {packet_info['dst_ip']}",
                    f"Source: {packet_info.get('src_ip')}:{packet_info.get('src_port')} -> {packet_info['dst_ip']}:{packet_info.get('dst_port')}",
                    'CRITICAL',
                    packet_info
                ))
            
            # Check for suspicious ports
            if packet_info.get('dst_port') in self.suspicious_ports:
                detections.append(self._create_detection(
                    'SUSPICIOUS_PORT_CONNECTION',
                    f"Connection to suspicious port: {packet_info['dst_port']}",
                    f"Source: {packet_info.get('src_ip')}:{packet_info.get('src_port')} -> {packet_info['dst_ip']}:{packet_info.get('dst_port')}",
                    'HIGH',
                    packet_info
                ))
            
            # Check for large data transfers
            if packet_info.get('packet_size', 0) > self.key_transmission_threshold:
                detections.extend(self._detect_large_transfers(packet_info, current_time))
            
            # Check for regular communication patterns
            if packet_info.get('src_ip') and packet_info.get('dst_ip'):
                detections.extend(self._detect_regular_patterns(packet_info, current_time))
            
            return detections
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error detecting ransomware network activity")
            return []

    def _detect_large_transfers(self, packet_info: Dict[str, Any], current_time: datetime) -> List[Dict[str, Any]]:
        """Detect large data transfers (potential key transmission)."""
        detections = []
        connection_key = (packet_info['src_ip'], packet_info['dst_ip'])
        self.large_transfers[connection_key].append((current_time, packet_info['packet_size']))
        
        # Clean old entries
        cutoff = current_time - timedelta(minutes=5)
        self.large_transfers[connection_key] = [(t, size) for t, size in self.large_transfers[connection_key] if t > cutoff]
        
        # Check for multiple large transfers
        if len(self.large_transfers[connection_key]) >= 3:
            detections.append(self._create_detection(
                'SUSPICIOUS_LARGE_TRANSFER',
                f"Multiple large data transfers detected: {packet_info['src_ip']} -> {packet_info['dst_ip']}",
                f"Large transfers: {len(self.large_transfers[connection_key])} in last 5 minutes",
                'MEDIUM',
                packet_info
            ))
        
        return detections

    def _detect_regular_patterns(self, packet_info: Dict[str, Any], current_time: datetime) -> List[Dict[str, Any]]:
        """Detect regular communication patterns."""
        detections = []
        connection_key = (packet_info['src_ip'], packet_info['dst_ip'])
        connection_patterns_key = f"{connection_key[0]}_{connection_key[1]}"
        self.connection_patterns[connection_patterns_key].append(current_time)
        
        # Clean old entries
        cutoff = current_time - timedelta(minutes=30)
        self.connection_patterns[connection_patterns_key] = [t for t in self.connection_patterns[connection_patterns_key] if t > cutoff]
        
        # Check for regular intervals
        if len(self.connection_patterns[connection_patterns_key]) >= 5:
            timestamps = sorted(self.connection_patterns[connection_patterns_key])
            intervals = []
            
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                regular_connections = sum(1 for interval in intervals
                                        if abs(interval - avg_interval) <= 60)  # 1 minute tolerance
                
                if regular_connections >= len(intervals) * 0.7:  # 70% regularity
                    detections.append(self._create_detection(
                        'REGULAR_C_AND_C_PATTERN',
                        f"Regular communication pattern detected: {packet_info['src_ip']} -> {packet_info['dst_ip']}",
                        f"Average interval: {avg_interval:.1f}s, connections: {len(timestamps)}",
                        'HIGH',
                        packet_info
                    ))
        
        return detections

    def _create_detection(self, anomaly_type: str, description: str, details: str, 
                         severity: str, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Create a detection dictionary."""
        return {
            'type': anomaly_type,
            'description': description,
            'details': details,
            'severity': severity,
            'packet_info': packet_info
        }


class PayloadAnalyzer(LoggerMixin):
    """Analyzes packet payloads for threats and suspicious content."""
    
    def __init__(self, yara_scanner: YARAScanner, pe_analyzer: PEAnalyzer):
        self.yara_scanner = yara_scanner
        self.pe_analyzer = pe_analyzer

    def analyze_payload(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet payload for threats."""
        threats = []
        payload = packet_info.get('payload')
        
        if not payload or len(payload) < 10:
            return threats
            
        try:
            # YARA scanning
            if self.yara_scanner.rule_manager.rules:
                threats.extend(self._scan_with_yara(packet_info, payload))
            
            # Check for executable downloads
            if packet_info.get('http_traffic') and payload:
                threats.extend(self._check_executable_downloads(packet_info, payload))
                
            return threats
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing packet payload")
            return []

    def _scan_with_yara(self, packet_info: Dict[str, Any], payload: bytes) -> List[Dict[str, Any]]:
        """Scan payload with YARA rules."""
        threats = []
        
        try:
            # Create temporary file for scanning
            temp_file = f"/tmp/payload_{int(time.time() * 1000000)}.bin"
            
            with open(temp_file, 'wb') as f:
                f.write(payload)
            
            results = self.yara_scanner.scan_file(temp_file)
            
            if results:
                for result in results:
                    threats.append({
                        'type': 'YARA_MATCH',
                        'description': f"YARA match in network payload: {result['rule_name']}",
                        'details': f"Source: {packet_info['src_ip']}:{packet_info.get('src_port')} -> {packet_info['dst_ip']}:{packet_info.get('dst_port')}",
                        'severity': 'CRITICAL',
                        'packet_info': packet_info,
                        'yara_result': result
                    })
            
            return threats
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error scanning payload with YARA")
            return threats
        finally:
            try:
                os.remove(temp_file)
            except:
                pass

    def _check_executable_downloads(self, packet_info: Dict[str, Any], payload: bytes) -> List[Dict[str, Any]]:
        """Check for executable file downloads."""
        threats = []
        
        try:
            if self._is_executable_download(payload):
                temp_file = f"/tmp/download_{packet_info['src_ip']}_{int(time.time())}.exe"
                
                with open(temp_file, 'wb') as f:
                    f.write(payload)
                
                # PE analysis
                if self.pe_analyzer.is_pe_file(temp_file):
                    pe_result = self.pe_analyzer.analyze_file(temp_file)
                    
                    if pe_result and self._has_pe_anomalies(pe_result):
                        anomalies = self._extract_pe_anomalies(pe_result)
                        threats.append({
                            'type': 'MALICIOUS_DOWNLOAD',
                            'description': f"Malicious executable downloaded from {packet_info['src_ip']}",
                            'details': f"PE anomalies: {', '.join(anomalies[:3])}",
                            'severity': 'CRITICAL',
                            'packet_info': packet_info,
                            'pe_result': pe_result
                        })
                
                try:
                    os.remove(temp_file)
                except:
                    pass
        
        except Exception as e:
            RansomwareLogger.log_error(e, "Error checking executable downloads")
        
        return threats

    def _is_executable_download(self, payload: bytes) -> bool:
        """Check if payload contains executable download."""
        # Check for executable signatures
        exe_signatures = [b'MZ', b'\x7fELF', b'#!/bin/']
        
        for sig in exe_signatures:
            if sig in payload[:100]:
                return True
        
        # Check HTTP headers
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            if 'content-type:' in payload_str:
                if any(ext in payload_str for ext in ['application/octet-stream', 
                                                     'application/x-executable',
                                                     'application/x-msdownload']):
                    return True
        except:
            pass
        
        return False

    def _has_pe_anomalies(self, pe_result: Dict[str, Any]) -> bool:
        """Check if PE analysis found anomalies."""
        for section in pe_result.get('sections', []):
            if section.get('anomalies'):
                return True
        
        for imp in pe_result.get('imports', []):
            if imp.get('suspicious'):
                return True
        
        return False

    def _extract_pe_anomalies(self, pe_result: Dict[str, Any]) -> List[str]:
        """Extract anomalies from PE analysis result."""
        anomalies = []
        
        for section in pe_result.get('sections', []):
            if section.get('anomalies'):
                anomalies.append(f"Section {section['name']}: {section['anomalies']}")
        
        for imp in pe_result.get('imports', []):
            if imp.get('suspicious'):
                anomalies.append(f"Suspicious import: {imp['function']}")
        
        return anomalies


class ConnectionTracker(LoggerMixin):
    """Tracks network connections and links to processes."""
    
    def __init__(self):
        self.connection_cache = {}

    def link_to_process(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Link network activity to running processes."""
        try:
            for conn in psutil.net_connections():
                if conn.laddr and conn.raddr:
                    if ((conn.laddr[0] == packet_info['src_ip'] and 
                         conn.laddr[1] == packet_info.get('src_port')) or
                        (conn.raddr[0] == packet_info['dst_ip'] and 
                         conn.raddr[1] == packet_info.get('dst_port'))):
                        
                        if conn.pid:
                            return self._get_process_info(conn.pid, packet_info)
            return None
        except Exception as e:
            RansomwareLogger.log_error(e, "Error linking network activity to process")
            return None

    def _get_process_info(self, pid: int, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get process information for a given PID."""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            exe_path = process.exe()
            
            return {
                'pid': pid,
                'name': process_name,
                'exe_path': exe_path,
                'packet_info': packet_info,
                'suspicious': self._is_suspicious_process(process_name, exe_path, packet_info)
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {
                'pid': pid,
                'name': 'Unknown',
                'exe_path': 'Unknown',
                'packet_info': packet_info,
                'suspicious': True  # Default to suspicious if we can't get info
            }

    def _is_suspicious_process(self, process_name: str, exe_path: str, packet_info: Dict[str, Any]) -> bool:
        """Check if process network activity is suspicious."""
        suspicious_processes = ['notepad.exe', 'calc.exe', 'mspaint.exe']
        suspicious_ports = [6667, 6668, 6669, 31337, 12345, 54321, 1337]
        
        if process_name.lower() in suspicious_processes:
            return True
        
        if packet_info.get('dst_port') in suspicious_ports:
            return True
        
        return False


class NetworkSniffer(LoggerMixin):
    """Main network sniffer coordinator."""

    def __init__(self, interface='ens33', bpf_filter='', db_name='firewall.db', config_path='config.json'):
        self.interface = interface
        self.bpf_filter = bpf_filter or 'tcp or udp or icmp'
        self.db = Database(db_name)
        self.config_path = config_path

        # Initialize integrated modules
        self.yara_scanner = YARAScanner(db_name)
        self.process_monitor = ProcessMonitor(config_path, db_name)
        self.fim = FIM(config_path, db_name)
        self.pe_analyzer = PEAnalyzer(db_name, config_path)
        self.crypto_manager = CryptoManager()

        # Configuration
        self.config = self._load_config()

        # Initialize specialized components
        self.packet_processor = PacketProcessor()
        self.traffic_analyzer = TrafficAnalyzer(self.config.get('network_sniffer', {}))
        self.network_detector = NetworkDetector(self.config.get('network_analysis', {}))
        self.payload_analyzer = PayloadAnalyzer(self.yara_scanner, self.pe_analyzer)
        self.connection_tracker = ConnectionTracker()

        # Packet processing queue
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = False

        # Processing threads
        self.capture_thread = None
        self.processing_thread = None

        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'anomalies_detected': 0,
            'yara_matches': 0,
            'start_time': None
        }


    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config.json"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)

            # YARA rules
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)

            RansomwareLogger.log_operation('NetworkSniffer config loaded', True)
            return config

        except Exception as e:
            RansomwareLogger.log_error(e, "Error loading NetworkSniffer configuration")
            return {}

    def start_sniffing(self) -> bool:
        """Start the network sniffer"""
        try:
            self.running = True
            self.stats['start_time'] = datetime.now()

            RansomwareLogger.log_security_event(
                'NETWORK_SNIFFER_START',
                f'Starting network sniffer on interface {self.interface} with filter: {self.bpf_filter}',
                'INFO'
            )

            # Check privileges
            if os.name == 'posix' and os.geteuid() != 0:
                raise NetworkError("Packet sniffing requires root privileges. Please run as root (sudo).")

            # Start processing thread
            self.processing_thread = threading.Thread(target=self._process_packets)
            self.processing_thread.daemon = True
            self.processing_thread.start()

            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()

            RansomwareLogger.log_operation('NetworkSniffer start', True)
            return True

        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to start network sniffer")
            self.running = False
            return False

    def stop_sniffing(self) -> None:
        """Stop the network sniffer"""
        try:
            self.running = False

            RansomwareLogger.log_security_event(
                'NETWORK_SNIFFER_STOP',
                'Stopping network sniffer',
                'INFO'
            )

            if self.capture_thread:
                self.capture_thread.join(timeout=5)
            if self.processing_thread:
                self.processing_thread.join(timeout=5)

            self._print_final_stats()
            RansomwareLogger.log_operation('NetworkSniffer stop', True)

        except Exception as e:
            RansomwareLogger.log_error(e, "Error stopping network sniffer")

    def _capture_packets(self) -> None:
        """Packet capture thread using Scapy"""
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            RansomwareLogger.log_error(e, "Error in packet capture")

    def _packet_callback(self, packet) -> None:
        """Callback for each captured packet"""
        if not self.running:
            return

        try:
            self.stats['packets_captured'] += 1

            # Put packet in processing queue
            if not self.packet_queue.full():
                self.packet_queue.put(packet)
            else:
                RansomwareLogger.log_security_event(
                    'PACKET_QUEUE_FULL',
                    'Packet queue full, dropping packet',
                    'WARNING'
                )

        except Exception as e:
            RansomwareLogger.log_error(e, "Error in packet callback")

    def _process_packets(self) -> None:
        """Packet processing thread"""
        while self.running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self._analyze_packet(packet)
                self.stats['packets_processed'] += 1
                self.packet_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                RansomwareLogger.log_error(e, "Error processing packet")

    def _analyze_packet(self, packet) -> None:
        """Analyze a single packet for threats and anomalies using specialized components."""
        try:
            # Process packet using PacketProcessor
            packet_info = self.packet_processor.process_packet(packet)
            
            if not packet_info:
                return

            # Log packet to database
            self._log_packet_to_db(packet_info)

            # Analyze traffic using TrafficAnalyzer
            traffic_anomalies = self.traffic_analyzer.analyze_traffic(packet_info)
            self._handle_anomalies(traffic_anomalies, 'TRAFFIC_ANOMALY')

            # Detect ransomware activity using NetworkDetector
            ransomware_detections = self.network_detector.detect_ransomware_activity(packet_info)
            self._handle_anomalies(ransomware_detections, 'RANSOMWARE_DETECTION')

            # Analyze payload using PayloadAnalyzer
            payload_threats = self.payload_analyzer.analyze_payload(packet_info)
            self._handle_anomalies(payload_threats, 'PAYLOAD_THREAT')

        except Exception as e:
            RansomwareLogger.log_error(e, "Error analyzing packet")

    def _log_packet_to_db(self, packet_info: Dict[str, Any]) -> None:
        """Log packet information to database"""
        try:
            protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
            protocol = protocol_map.get(packet_info['protocol'], str(packet_info['protocol']))

            self.db.insert_network_event(
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['src_port'],
                packet_info['dst_port'],
                protocol,
                'CAPTURED',
                None,
                'network_sniffer',
                'INFO'
            )
        except Exception as e:
            RansomwareLogger.log_error(e, "Failed to log packet to DB")

    def _handle_anomalies(self, anomalies: List[Dict[str, Any]], category: str) -> None:
        """Handle detected anomalies and threats."""
        for anomaly in anomalies:
            try:
                self._alert_anomaly(anomaly)
                
                # Link to process if available
                process_info = self.connection_tracker.link_to_process(anomaly['packet_info'])
                if process_info and process_info['suspicious']:
                    self._alert_suspicious_process(process_info, anomaly)
                
                # Update statistics
                self.stats['anomalies_detected'] += 1
                if anomaly['type'] == 'YARA_MATCH':
                    self.stats['yara_matches'] += 1
                    
            except Exception as e:
                RansomwareLogger.log_error(e, f"Error handling anomaly in category {category}")

    def _alert_anomaly(self, anomaly: Dict[str, Any]) -> None:
        """Create and log anomaly alert."""
        try:
            # Sanitize packet_info for JSON serialization
            packet_info = anomaly['packet_info']
            sanitized_packet_info = {}
            for key, value in packet_info.items():
                if isinstance(value, bytes):
                    sanitized_packet_info[key] = value.hex()
                else:
                    sanitized_packet_info[key] = value

            alert_data = {
                'anomaly_type': anomaly['type'],
                'description': anomaly['description'],
                'details': anomaly['details'],
                'packet_info': sanitized_packet_info,
                'severity': anomaly['severity'],
                'timestamp': datetime.now().isoformat()
            }

            # Log to database
            self.db.insert_netsec_alert(
                anomaly['type'], 
                anomaly['description'], 
                anomaly['severity'], 
                json.dumps(alert_data)
            )

            # Log security event
            RansomwareLogger.log_security_event(
                anomaly['type'],
                anomaly['description'],
                anomaly['severity'],
                anomaly.get('details', '')
            )

            # Print alert
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(anomaly['severity'], '⚪')
            
            print(f"[{severity_icon}] {anomaly['type']}: {anomaly['description']}")
            if anomaly.get('details'):
                print(f"  Details: {anomaly['details']}")
                
        except Exception as e:
            RansomwareLogger.log_error(e, "Error creating anomaly alert")

    def _alert_suspicious_process(self, process_info: Dict[str, Any], anomaly: Dict[str, Any]) -> None:
        """Alert about suspicious process activity."""
        try:
            description = f"Suspicious network activity by {process_info['name']} (PID {process_info['pid']})"
            
            RansomwareLogger.log_security_event(
                'SUSPICIOUS_PROCESS_NETWORK',
                description,
                'HIGH',
                f"Process: {process_info['name']}, Path: {process_info['exe_path']}"
            )

            self.db.insert_netsec_alert(
                'SUSPICIOUS_PROCESS_NETWORK',
                description,
                'HIGH',
                json.dumps({
                    'pid': process_info['pid'],
                    'name': process_info['name'],
                    'exe_path': process_info['exe_path'],
                    'network_anomaly': anomaly
                })
            )
            
        except Exception as e:
            RansomwareLogger.log_error(e, "Error alerting suspicious process")



    def _print_final_stats(self):
        """Print final statistics"""
        runtime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)

        print("\n" + "="*60)
        print("NETWORK SNIFFER STATISTICS")
        print("="*60)
        print(f"Runtime: {runtime}")
        print(f"Packets captured: {self.stats['packets_captured']}")
        print(f"Packets processed: {self.stats['packets_processed']}")
        print(f"Anomalies detected: {self.stats['anomalies_detected']}")
        print(f"YARA matches: {self.stats['yara_matches']}")
        print("="*60)

    def get_stats(self):
        """Get current statistics"""
        return self.stats.copy()

    def reload_config(self):
        """Reload configuration"""
        self.load_config()
        print("Network sniffer configuration reloaded")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Hybrid Network Sniffer with Threat Detection")
    parser.add_argument('-i', '--interface', default='ens33', help='Network interface to sniff')
    parser.add_argument('-f', '--filter', default='', help='BPF filter for packet capture')
    parser.add_argument('-c', '--config', default='config.json', help='Configuration file')
    parser.add_argument('-d', '--database', default='firewall.db', help='Database file')
    parser.add_argument('--daemon', action='store_true', help='Run in daemon mode')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('network_sniffer.log'),
            logging.StreamHandler()
        ]
    )

    # Create sniffer
    sniffer = NetworkSniffer(
        interface=args.interface,
        bpf_filter=args.filter,
        db_name=args.database,
        config_path=args.config
    )

    print("Hybrid Network Sniffer with Threat Detection")
    print("=" * 50)
    print(f"Interface: {args.interface}")
    print(f"Filter: {args.filter or 'tcp or udp or icmp'}")
    print("Starting sniffer... (Ctrl+C to stop)")

    try:
        if sniffer.start_sniffing():
            if args.daemon:
                # Daemon mode - keep running
                while True:
                    time.sleep(1)
            else:
                # Interactive mode
                input("Press Enter to stop...")
        else:
            print("Failed to start sniffer")
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        sniffer.stop_sniffing()


if __name__ == "__main__":
    main()
