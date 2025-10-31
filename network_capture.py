from scapy.all import sniff, IP, TCP, UDP, ICMP
from rules_manager import RulesManager
from database import Database
import threading
import time

class NetworkCapture:
    def __init__(self, interface='eth0', rules_file='rules.json', db_name='firewall.db'):
        self.interface = interface
        self.rules_manager = RulesManager(rules_file)
        self.db = Database(db_name)
        self.running = False

    def packet_callback(self, packet):
        if not self.running:
            return

        action = self.rules_manager.check_packet(packet)

        # Extract details for logging
        source_ip = dest_ip = source_port = dest_port = protocol = None
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet[IP].proto
        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            protocol = 'tcp'
        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            protocol = 'udp'
        elif packet.haslayer(ICMP):
            protocol = 'icmp'

        # Log to database
        criticality = 'INFO' if action == 'ACCEPT' else 'WARNING'
        self.db.insert_network_event(source_ip, dest_ip, source_port, dest_port, protocol, action, criticality)

        # For demonstration, print the action
        print(f"Packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol}) - {action}")

    def start_capture(self):
        self.running = True
        print(f"Starting packet capture on interface {self.interface}")
        sniff(iface=self.interface, prn=self.packet_callback, store=0, stop_filter=lambda x: not self.running)

    def stop_capture(self):
        self.running = False
        print("Stopping packet capture")

    def reload_rules(self):
        self.rules_manager.rules = self.rules_manager.load_rules()
        print("Rules reloaded")
