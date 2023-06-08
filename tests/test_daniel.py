from dataclasses import dataclass

from nx.workers.daniel import DHCP, DHCPMonitorWorker, Ether


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self):
        return MockPipeline(self.log)


class MockPipeline:
    def __init__(self, log):
        self.log = log

    def hset(self, *args, **kwargs):
        self._hset("hset", *args, **kwargs)

    def hsetnx(self, *args, **kwargs):
        self._hset("hsetnx", *args, **kwargs)

    def _hset(self, cmd, name, key=None, value=None, mapping={}):
        args = mapping.copy()
        if None not in (key, value):
            args.update({key: value})
        self.log.append([cmd, name, list(sorted(args.items()))])

    def execute(self):
        self.log.append("execute")
        print(self.log)


class MockPacketDHCP:
    KEYMAP = dict((key.replace("-", "_"), key) for key in (
        "message-type",
    ))

    def __init__(self, **kwargs):
        self.options = [
            (self.KEYMAP.get(key, key), value)
            for key, value in kwargs.items()
        ]
        print(self.options)


@dataclass
class MockPacketEther:
    src: str = "00:0d:f7:12:fe"


class MockPacket(dict):
    def __init__(self, **kwargs):
        self._layers = {Ether: MockPacketEther()}
        self[DHCP] = MockPacketDHCP(**kwargs)
        self.time = 1686086875.268219

    def getlayer(self, layer):
        return self._layers[layer]


def test_request_stores_requested_ipv4():
    """DHCPREQUEST stores requested_ipv4."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker.process_packet(MockPacket(
        message_type=3,
        requested_addr="1.2.3.4",
        max_dhcp_size=1500,
        vendor_class_id=b"Acme Phones Inc",
        hostname=b"Daniel's phone",
        param_req_list=[1, 2, 3, 4, 5],
    ))
    assert worker.db.log == [
        ["hset", "mac_00:0d:f7:12:fe", [
            ("device_name", "Daniel's phone"),
            ("last_seen", 1686086875.268219),
            ("requested_ipv4", "1.2.3.4"),
            ("requested_ipv4_at", 1686086875.268219),
            ("seen_by", "daniel"),
            ("vendor_class_id", "Acme Phones Inc")]],
        ["hsetnx", "mac_00:0d:f7:12:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]
