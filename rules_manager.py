import json
import ipaddress

class RulesManager:
    def __init__(self, rules_file='rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        try:
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Файл правил {self.rules_file} не найден.")
            return []
        except json.JSONDecodeError:
            print(f"Ошибка декодирования JSON из {self.rules_file}.")
            return []

    def match_ip(self, packet_ip, rule_ip):
        if rule_ip == "any":
            return True
        try:
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip)
        except ValueError:
            return False

    def match_port(self, packet_port, rule_port):
        if rule_port == "any":
            return True
        return packet_port == rule_port

    def check_packet(self, packet):
        # Extract packet details
        if packet.haslayer('IP'):
            source_ip = packet['IP'].src
            dest_ip = packet['IP'].dst
            protocol = packet['IP'].proto
        else:
            return "DROP"  # Drop non-IP packets

        source_port = dest_port = None
        if packet.haslayer('TCP'):
            source_port = packet['TCP'].sport
            dest_port = packet['TCP'].dport
            protocol = 6  # TCP
        elif packet.haslayer('UDP'):
            source_port = packet['UDP'].sport
            dest_port = packet['UDP'].dport
            protocol = 17  # UDP
        elif packet.haslayer('ICMP'):
            protocol = 1  # ICMP

        # Check against rules
        for rule in self.rules:
            if (self.match_ip(source_ip, rule.get('source_ip', 'any')) and
                self.match_ip(dest_ip, rule.get('dest_ip', 'any')) and
                self.match_port(source_port, rule.get('source_port', 'any')) and
                self.match_port(dest_port, rule.get('dest_port', 'any')) and
                (rule.get('protocol', 'any') == 'any' or str(protocol) == str(rule['protocol']) or
                 (rule['protocol'] == 'tcp' and protocol == 6) or
                 (rule['protocol'] == 'udp' and protocol == 17) or
                 (rule['protocol'] == 'icmp' and protocol == 1))):
                return rule['action']

        # Implicit deny
        return "DROP"
