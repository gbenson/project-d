import pytest

from dataclasses import dataclass

from nx.workers.daniel import DHCP, DHCPMonitorWorker, Ether


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self):
        return MockPipeline(self.log)

    def hmget(self, *args):
        self.log.append(["hmget", args])
        return b"5.6.7.8", b"1686086874.682192"

    def incr(self, *args):
        self.log.append(["incr", args])
        return 23


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


@pytest.mark.parametrize("extras", ((), ["end"] + ["pad"] * 4))
def test_unhandled_message_handling(extras):
    """Messages we don't understand are retained for analysis."""
    worker = DHCPMonitorWorker(MockDatabase())
    packet = MockPacket(
        message_type=42,
        max_dhcp_size=1500,
        vendor_class_id=b"what ev er",
        hostname=b"not-ascii-not-utf8\xff",
        param_req_list=[1, 4, 15, 43, 25],
    )
    packet[DHCP].options.extend(extras)
    worker.process_packet(packet)
    assert worker.db.log == [
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("seen_by", "daniel")]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219)]],
        ["incr", ("next_raw_dhcp_id",)],
        ["hset", "raw_dhcp:23", [
            ("mac", "00:0d:f7:12:ca:fe"),
            ("options",
             '[["message-type", 42],'
             ' ["max_dhcp_size", 1500],'
             ' ["vendor_class_id", "what ev er"],'
             ' ["hostname",'
             ' [110, 111, 116, 45, 97, 115, 99, 105, 105, 45,'
             ' 110, 111, 116, 45, 117, 116, 102, 56, 255]],'
             ' ["param_req_list", [1, 4, 15, 43, 25]]]'),
            ("time", 1686086875.268219)]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]


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
            ("last_DHCPREQUEST_options",
             '[["message-type", 3],'
             ' ["requested_addr", "1.2.3.4"],'
             ' ["max_dhcp_size", 1500],'
             ' ["vendor_class_id", "Acme Phones Inc"],'
             ' ["hostname", "Daniel\'s phone"],'
             ' ["param_req_list", [1, 2, 3, 4, 5]]]'),
            ("last_DHCPREQUEST_seen", 1686086875.268219),
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
            ("last_DHCPACK_options",
             '[["message-type", 5],'
             ' ["server_id", "4.3.2.1"]]'),
            ("last_DHCPACK_seen", 1686086875.268219),
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


def test_nak():
    """DHCPNAK is logged as expected."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker.process_packet(MockPacket(
        message_type=6,
        error_message=b"go 'way fool",
    ))
    assert worker.db.log == [
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_DHCPNAK_options",
             '[["message-type", 6],'
             ' ["error_message", "go \'way fool"]]'),
            ("last_DHCPNAK_seen", 1686086875.268219),
            ("last_seen", 1686086875.268219),
            ("seen_by", "daniel")]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]
