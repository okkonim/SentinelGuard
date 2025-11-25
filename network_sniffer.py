#!/usr/bin/env python3
"""
Hybrid Network Sniffer with Threat Detection Integration
Combines Scapy packet capture with YARA, process monitoring, FIM, and PE analysis
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw
import threading
import queue
import time
import logging
import os
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import psutil

from database import Database
from yara_scanner import YARAScanner
from process_monitor import ProcessMonitor
from fim import FIM
from pe_analyzer import PEAnalyzer

logger = logging.getLogger(__name__)

class NetworkSniffer:
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

        # Load configuration
        self.load_config()

        # Packet processing queue
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = False

        # Anomaly detection data structures
        self.syn_packets = defaultdict(list)  # IP -> timestamps
        self.icmp_packets = defaultdict(list)  # IP -> timestamps
        self.beacon_connections = defaultdict(list)  # (src_ip, dst_ip, dst_port) -> timestamps

        # Anomaly thresholds
        self.syn_flood_threshold = 100  # SYN packets per minute
        self.icmp_flood_threshold = 50  # ICMP packets per minute
        self.beacon_threshold = 10  # Regular connections per hour
        self.beacon_tolerance = 300  # 5 minutes tolerance for beaconing

        # Packet processing threads
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

    def load_config(self):
        """Load configuration from config.json"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)

            # Network sniffer config
            sniffer_config = config.get('network_sniffer', {})
            self.syn_flood_threshold = sniffer_config.get('syn_flood_threshold', 100)
            self.icmp_flood_threshold = sniffer_config.get('icmp_flood_threshold', 50)
            self.beacon_threshold = sniffer_config.get('beacon_threshold', 10)
            self.beacon_tolerance = sniffer_config.get('beacon_tolerance', 300)

            # YARA rules
            yara_rules = config.get('yara', {}).get('rules_files', {})
            if yara_rules:
                self.yara_scanner.compile_rules(yara_rules)

        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def start_sniffing(self):
        """Start the network sniffer"""
        self.running = True
        self.stats['start_time'] = datetime.now()

        logger.info(f"Starting network sniffer on interface {self.interface} with filter: {self.bpf_filter}")

        # Check privileges
        if os.name == 'posix' and os.geteuid() != 0:
            logger.error("Packet sniffing requires root privileges. Please run as root (sudo).")
            print("Error: Packet sniffing requires root privileges (sudo).")
            return False

        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_packets)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        return True

    def stop_sniffing(self):
        """Stop the network sniffer"""
        self.running = False
        logger.info("Stopping network sniffer")

        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.processing_thread:
            self.processing_thread.join(timeout=5)

        self._print_final_stats()

    def _capture_packets(self):
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
            logger.exception(f"Error in packet capture: {e}")

    def _packet_callback(self, packet):
        """Callback for each captured packet"""
        if not self.running:
            return

        try:
            self.stats['packets_captured'] += 1

            # Put packet in processing queue
            if not self.packet_queue.full():
                self.packet_queue.put(packet)
            else:
                logger.warning("Packet queue full, dropping packet")

        except Exception as e:
            logger.exception(f"Error in packet callback: {e}")

    def _process_packets(self):
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
                logger.exception(f"Error processing packet: {e}")

    def _analyze_packet(self, packet):
        """Analyze a single packet for threats and anomalies"""
        try:
            # Extract basic packet info
            packet_info = self._extract_packet_info(packet)

            if not packet_info:
                return

            # Log packet to database
            self._log_packet_to_db(packet_info)

            # Anomaly detection
            self._detect_anomalies(packet_info, packet)

            # Payload analysis for suspicious packets
            if packet_info.get('payload'):
                self._analyze_payload(packet_info, packet)

        except Exception as e:
            logger.exception(f"Error analyzing packet: {e}")

    def _extract_packet_info(self, packet):
        """Extract key information from packet"""
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

        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto

        if TCP in packet:
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['protocol'] = 6  # TCP
            flags = []
            if packet[TCP].flags & 0x02: flags.append('SYN')
            if packet[TCP].flags & 0x10: flags.append('ACK')
            if packet[TCP].flags & 0x01: flags.append('FIN')
            if packet[TCP].flags & 0x04: flags.append('RST')
            if packet[TCP].flags & 0x08: flags.append('PSH')
            if packet[TCP].flags & 0x20: flags.append('URG')
            info['flags'] = ','.join(flags)

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

            # Check for HTTP traffic
            if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80 or
                                  packet[TCP].dport == 443 or packet[TCP].sport == 443):
                try:
                    if HTTPRequest in packet or HTTPResponse in packet:
                        info['http_traffic'] = True
                except:
                    pass

        return info if info['src_ip'] and info['dst_ip'] else None

    def _log_packet_to_db(self, packet_info):
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
            logger.error(f"Failed to log packet to DB: {e}")

    def _detect_anomalies(self, packet_info, packet):
        """Detect network anomalies"""
        current_time = datetime.now()

        # SYN Flood detection
        if packet_info.get('flags') and 'SYN' in packet_info['flags']:
            src_ip = packet_info['src_ip']
            self.syn_packets[src_ip].append(current_time)

            # Clean old entries (older than 1 minute)
            cutoff = current_time - timedelta(minutes=1)
            self.syn_packets[src_ip] = [t for t in self.syn_packets[src_ip] if t > cutoff]

            if len(self.syn_packets[src_ip]) > self.syn_flood_threshold:
                self._alert_anomaly('SYN_FLOOD', f"SYN flood detected from {src_ip}",
                                  f"SYN packets: {len(self.syn_packets[src_ip])} in last minute",
                                  packet_info, 'CRITICAL')

        # ICMP Flood detection
        if packet_info['protocol'] == 1:  # ICMP
            src_ip = packet_info['src_ip']
            self.icmp_packets[src_ip].append(current_time)

            # Clean old entries
            cutoff = current_time - timedelta(minutes=1)
            self.icmp_packets[src_ip] = [t for t in self.icmp_packets[src_ip] if t > cutoff]

            if len(self.icmp_packets[src_ip]) > self.icmp_flood_threshold:
                self._alert_anomaly('ICMP_FLOOD', f"ICMP flood detected from {src_ip}",
                                  f"ICMP packets: {len(self.icmp_packets[src_ip])} in last minute",
                                  packet_info, 'CRITICAL')

        # Beaconing detection
        if packet_info['src_port'] and packet_info['dst_port']:
            connection_key = (packet_info['src_ip'], packet_info['dst_ip'], packet_info['dst_port'])
            self.beacon_connections[connection_key].append(current_time)

            # Clean old entries (older than 1 hour)
            cutoff = current_time - timedelta(hours=1)
            self.beacon_connections[connection_key] = [t for t in self.beacon_connections[connection_key] if t > cutoff]

            # Check for beaconing pattern (only if we have enough data points)
            if len(self.beacon_connections[connection_key]) >= self.beacon_threshold:
                timestamps = sorted(self.beacon_connections[connection_key])
                intervals = []

                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)

                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    # Check if intervals are regular (within tolerance)
                    regular_connections = sum(1 for interval in intervals
                                            if abs(interval - avg_interval) <= self.beacon_tolerance)

                    if regular_connections >= len(intervals) * 0.8:  # 80% regularity
                        # Only alert once per connection key to avoid spam
                        if not hasattr(self, '_beacon_alerted'):
                            self._beacon_alerted = set()
                        if connection_key not in self._beacon_alerted:
                            self._alert_anomaly('BEACONING', f"Botnet beaconing detected from {packet_info['src_ip']} to {packet_info['dst_ip']}:{packet_info['dst_port']}",
                                              f"Average interval: {avg_interval:.1f}s, connections: {len(timestamps)}",
                                              packet_info, 'HIGH')
                            self._beacon_alerted.add(connection_key)

    def _analyze_payload(self, packet_info, packet):
        """Analyze packet payload for threats"""
        payload = packet_info.get('payload')
        if not payload or len(payload) < 10:
            return

        # YARA scanning for suspicious payloads
        if self.yara_scanner.rules:
            # Create temporary file for scanning
            temp_file = f"/tmp/payload_{int(time.time() * 1000000)}.bin"
            try:
                with open(temp_file, 'wb') as f:
                    f.write(payload)

                results = self.yara_scanner.scan_file(temp_file)
                if results:
                    self.stats['yara_matches'] += 1
                    for result in results:
                        self._alert_anomaly('YARA_MATCH', f"YARA match in network payload: {result['rule_name']}",
                                          f"Source: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}",
                                          packet_info, 'CRITICAL')

                        # Link to process if possible
                        self._link_to_process(packet_info)

            except Exception as e:
                logger.error(f"Error scanning payload: {e}")
            finally:
                try:
                    os.remove(temp_file)
                except:
                    pass

        # Check for executable downloads
        if packet_info.get('http_traffic') and payload:
            # Look for executable file signatures or HTTP downloads
            if self._is_executable_download(payload):
                self._handle_executable_download(packet_info, payload)

    def _is_executable_download(self, payload):
        """Check if payload contains executable file download"""
        # Check for common executable signatures
        exe_signatures = [
            b'MZ',  # Windows EXE
            b'\x7fELF',  # Linux ELF
            b'#!/bin/',  # Scripts
        ]

        for sig in exe_signatures:
            if sig in payload[:100]:  # Check first 100 bytes
                return True

        # Check HTTP headers for executable content
        payload_str = payload.decode('utf-8', errors='ignore').lower()
        if 'content-type:' in payload_str:
            if any(ext in payload_str for ext in ['application/octet-stream', 'application/x-executable',
                                                 'application/x-msdownload']):
                return True

        return False

    def _handle_executable_download(self, packet_info, payload):
        """Handle detected executable download"""
        # Save payload to temporary file for analysis
        temp_file = f"/tmp/download_{packet_info['src_ip']}_{int(time.time())}.exe"

        try:
            with open(temp_file, 'wb') as f:
                f.write(payload)

            # Trigger PE analysis if it's a PE file
            if self.pe_analyzer.is_pe_file(temp_file):
                logger.info(f"Analyzing downloaded PE file from {packet_info['src_ip']}")
                pe_result = self.pe_analyzer.analyze_file(temp_file)

                if pe_result:
                    # Check for anomalies
                    anomalies = []
                    for section in pe_result['sections']:
                        if section['anomalies']:
                            anomalies.append(f"Section {section['name']}: {section['anomalies']}")
                    for imp in pe_result['imports']:
                        if imp['suspicious']:
                            anomalies.append(f"Suspicious import: {imp['function']}")

                    if anomalies:
                        self._alert_anomaly('MALICIOUS_DOWNLOAD', f"Malicious executable downloaded from {packet_info['src_ip']}",
                                          f"PE anomalies: {', '.join(anomalies[:3])}",  # Limit to first 3
                                          packet_info, 'CRITICAL')

                        # Link to process and FIM
                        self._link_to_process(packet_info)
                        self._trigger_fim_check(temp_file)

        except Exception as e:
            logger.error(f"Error handling executable download: {e}")
        finally:
            try:
                os.remove(temp_file)
            except:
                pass

    def _link_to_process(self, packet_info):
        """Link network activity to running processes"""
        try:
            # Find processes with network connections
            for conn in psutil.net_connections():
                if conn.laddr and conn.raddr:
                    if (conn.laddr[0] == packet_info['src_ip'] and conn.laddr[1] == packet_info.get('src_port')) or \
                       (conn.raddr[0] == packet_info['dst_ip'] and conn.raddr[1] == packet_info.get('dst_port')):
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                process_name = process.name()
                                exe_path = process.exe()

                                # Check if this process should have network access
                                suspicious = self._is_suspicious_process_network(process_name, exe_path, packet_info)

                                if suspicious:
                                    self._alert_anomaly('SUSPICIOUS_PROCESS_NETWORK',
                                                      f"Suspicious network activity by {process_name} (PID {conn.pid})",
                                                      f"Connection: {packet_info['src_ip']}:{packet_info.get('src_port')} -> {packet_info['dst_ip']}:{packet_info.get('dst_port')}",
                                                      packet_info, 'HIGH')

                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue

        except Exception as e:
            logger.error(f"Error linking to process: {e}")

    def _is_suspicious_process_network(self, process_name, exe_path, packet_info):
        """Check if process network activity is suspicious"""
        suspicious_processes = ['notepad.exe', 'calc.exe', 'mspaint.exe']  # Processes that shouldn't have network
        suspicious_ports = [6667, 6668, 6669, 31337, 12345, 54321, 1337]

        if process_name.lower() in suspicious_processes:
            return True

        if packet_info.get('dst_port') in suspicious_ports:
            return True

        return False

    def _trigger_fim_check(self, file_path):
        """Trigger FIM check for downloaded file"""
        try:
            # Simulate FIM monitoring for this file
            self.fim.handle_file_change(file_path, "Downloaded executable", 'CRITICAL')
        except Exception as e:
            logger.error(f"Error triggering FIM check: {e}")

    def _alert_anomaly(self, anomaly_type, description, details, packet_info, severity):
        """Create anomaly alert"""
        self.stats['anomalies_detected'] += 1

        # Sanitize packet_info for JSON serialization
        sanitized_packet_info = {}
        for key, value in packet_info.items():
            if isinstance(value, bytes):
                sanitized_packet_info[key] = value.hex()  # Convert bytes to hex string
            else:
                sanitized_packet_info[key] = value

        alert_data = {
            'anomaly_type': anomaly_type,
            'description': description,
            'details': details,
            'packet_info': sanitized_packet_info,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }

        # Log to database
        try:
            self.db.insert_netsec_alert(anomaly_type, description, severity, json.dumps(alert_data))
        except Exception as e:
            logger.error(f"Failed to log anomaly alert: {e}")

        # Print alert
        print(f"[{severity}] {anomaly_type}: {description}")
        if details:
            print(f"  Details: {details}")

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
