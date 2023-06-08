from dataclasses import dataclass

from nx.workers.daniel import DHCP, DHCPMonitorWorker, Ether


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self):
        return MockPipeline(self.log)

    def hmget(self, *args):
        self.log.append(["hmget", args])
        return "5.6.7.8", 1686086874.682192


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
    src: str = "00:0d:f7:12:ca:fe"
    dst: str = "c8:e1:30:ba:be:23"


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
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("device_name", "Daniel's phone"),
            ("last_seen", 1686086875.268219),
            ("requested_ipv4", "1.2.3.4"),
            ("requested_ipv4_at", 1686086875.268219),
            ("seen_by", "daniel"),
            ("vendor_class_id", "Acme Phones Inc")]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]


def test_ack_retrieves_requested_ipv4():
    """DHCPACK retrieves requested_ipv4."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker.process_packet(MockPacket(
        message_type=5,
        server_id="4.3.2.1",
    ))
    assert worker.db.log == [
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("ipv4", "4.3.2.1"),
            ("last_seen", 1686086875.268219),
            ("seen_by", "daniel")]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "ipv4_4.3.2.1", [
            ("last_seen", 1686086875.268219),
            ("mac", "00:0d:f7:12:ca:fe"),
            ("seen_by", "daniel")]],
        ["hmget", (
            "mac_c8:e1:30:ba:be:23",
            "requested_ipv4",
            "requested_ipv4_at")],
        ["hset", "mac_c8:e1:30:ba:be:23", [
            ("ipv4", "5.6.7.8"),
            ("last_seen", 1686086875.268219),
            ("seen_by", "daniel")]],
        ["hset", "ipv4_5.6.7.8", [
            ("last_seen", 1686086875.268219),
            ("mac", "c8:e1:30:ba:be:23"),
            ("seen_by", "daniel")]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]
