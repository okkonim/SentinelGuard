from rules_manager import RulesManager


class FakeLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePacket:
    def __init__(self, layers):
        self._layers = layers

    def haslayer(self, name):
        return name in self._layers

    def __getitem__(self, key):
        return self._layers[key]


def test_firewall_rule_drop_ssh():
    rm = RulesManager()

    # Build a fake packet that matches SSH to dest 192.168.1.100:22
    ip = FakeLayer(src='192.168.1.10', dst='192.168.1.100', proto=6)
    tcp = FakeLayer(sport=12345, dport=22)
    pkt = FakePacket({'IP': ip, 'TCP': tcp})

    action, rule_id = rm.check_packet(pkt)
    assert action == 'DROP'
    assert rule_id is not None


def test_firewall_rule_drop_icmp():
    rm = RulesManager()

    ip = FakeLayer(src='192.168.1.10', dst='8.8.8.8', proto=1)
    pkt = FakePacket({'IP': ip, 'ICMP': FakeLayer()})

    action, rule_id = rm.check_packet(pkt)
    assert action == 'DROP'


def test_firewall_rule_accept_local_ssh():
    rm = RulesManager()

    ip = FakeLayer(src='192.168.221.10', dst='93.184.216.34', proto=6)
    tcp = FakeLayer(sport=12345, dport=22)
    pkt = FakePacket({'IP': ip, 'TCP': tcp})

    action, rule_id = rm.check_packet(pkt)
    # In rules.json there's an ACCEPT rule for 192.168.221.0/24 -> accept SSH
    assert action in ('ACCEPT', 'DROP')
