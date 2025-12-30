try:
    import scapy.all as scapy
    sniff = scapy.sniff
    IP = scapy.IP
    TCP = scapy.TCP
    UDP = scapy.UDP
    ICMP = scapy.ICMP
    SCAPY_AVAILABLE = True
except Exception:
    scapy = None
    sniff = None
    IP = TCP = UDP = ICMP = None
    SCAPY_AVAILABLE = False

from rules_manager import RulesManager
from database import Database
import threading
import time
import logging
import os

logger = logging.getLogger(__name__)


class NetworkCapture:
    def __init__(self, interface='ens33', rules_file='rules.json', db_name='firewall.db'):
        self.interface = interface
        self.rules_manager = RulesManager(rules_file)
        self.db = Database(db_name)
        self.running = False

    def packet_callback(self, packet):
        if not self.running:
            return

        try:
            result = self.rules_manager.check_packet(packet)
            if isinstance(result, tuple):
                action, rule_id = result
            else:
                action = result
                rule_id = None

            # Extract details for logging
            source_ip = dest_ip = source_port = dest_port = protocol = None
            if IP and packet.haslayer(IP):
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                protocol = packet[IP].proto
            if TCP and packet.haslayer(TCP):
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                protocol = 'tcp'
            elif UDP and packet.haslayer(UDP):
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
                protocol = 'udp'
            elif ICMP and packet.haslayer(ICMP):
                protocol = 'icmp'

            # Log to database
            criticality = 'INFO' if action == 'ACCEPT' else 'WARNING'
            try:
                self.db.insert_network_event(source_ip, dest_ip, source_port, dest_port, protocol, action, rule_id, 'network_capture', criticality)
            except Exception as e:
                logger.error(f"Failed to insert network event: {e}")

            # For demo purposes, log the action
            rule_info = f" (rule {rule_id})" if rule_id else " (implicit deny)"
            logger.info(f"Packet [network_capture]: {source_ip}:{source_port} -> {dest_ip}:{dest_port} ({protocol}) - {action}{rule_info}")
        except Exception as e:
            logger.exception(f"Exception in packet_callback: {e}")

    def start_capture(self):
        self.running = True
        logger.info(f"Starting packet capture on interface {self.interface}")
        # Check permissions: packet capture requires root privileges on Linux
        try:
            if os.name == 'posix' and os.geteuid() != 0:
                logger.error("Sniffing requires root privileges. Please run as root (sudo).")
                self.running = False
                return
        except AttributeError:
            # os.geteuid may not exist on some platforms (Windows), ignore
            pass
        if sniff is None:
            logger.error("Error: scapy module is not installed. Install scapy and try again.")
            self.running = False
            return

        try:
            available_ifaces = []
            try:
                available_ifaces = scapy.get_if_list()
            except Exception:
                available_ifaces = []

            iface_to_use = self.interface
            if available_ifaces and self.interface not in available_ifaces:
                logger.warning(f"Interface {self.interface} not found, using default interface {scapy.conf.iface}")
                iface_to_use = scapy.conf.iface

            try:
                sniff(iface=iface_to_use, prn=self.packet_callback, store=0, stop_filter=lambda x: not self.running)
            except Exception as e:
                logger.exception(f"Error while sniffing on interface {iface_to_use}: {e}")
                self.running = False
                return
        except Exception as e:
            logger.exception(f"Unexpected error in start_capture: {e}")
            self.running = False
            return

    def stop_capture(self):
        self.running = False
        logger.info("Stopping packet capture")

    def reload_rules(self):
        self.rules_manager.rules = self.rules_manager.load_rules()
        logger.info("Rules reloaded")
