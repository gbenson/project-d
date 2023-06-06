import pytest

from nx.workers.carla import ARP, ARPMonitorCallback


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


class MockARPPacketARP:
    def __init__(self, op=1, hwsrc="00:0D:F7:12:FE", psrc="1.2.3.4"):
        self.op = op
        self.hwsrc = hwsrc
        self.psrc = psrc


class MockARPPacket(dict):
    def __init__(self, **kwargs):
        self[ARP] = MockARPPacketARP(**kwargs)
        self.time = 1686086875.268219


def test_non_arp_packet():
    """It doesn't crash if a non-ARP packet is supplied."""
    callback = ARPMonitorCallback(MockDatabase())
    callback({})
    assert not callback.db.log


def test_unhandled_arp_packet():
    """It ignores packets with unhandled operations."""
    callback = ARPMonitorCallback(MockDatabase())
    callback(MockARPPacket(op=4))
    assert not callback.db.log


@pytest.mark.parametrize("op", (1, 2))
def test_regular_packets(op):
    """It handles ordinary who-has and is-at packets."""
    callback = ARPMonitorCallback(MockDatabase())
    callback(MockARPPacket(op=op))
    assert callback.db.log == [
        ["hset", "mac_00:0d:f7:12:fe", [
            ("ipv4", "1.2.3.4"),
            ("last_seen", 1686086875.268219),
            ("seen_by", "carla")]],
        ["hsetnx", "mac_00:0d:f7:12:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "ipv4_1.2.3.4", [
            ("last_seen", 1686086875.268219),
            ("mac", "00:0d:f7:12:fe"),
            ("seen_by", "carla")]],
        "execute"]


def test_unspecified_ipv4_not_stored():
    """It doesn't store the unspecified IPv4 address."""
    callback = ARPMonitorCallback(MockDatabase())
    callback(MockARPPacket(psrc="0.0.0.0"))
    assert callback.db.log == [
        ["hset", "mac_00:0d:f7:12:fe", [
            ("last_seen", 1686086875.268219),
            ("seen_by", "carla")]],
        ["hsetnx", "mac_00:0d:f7:12:fe", [
            ("first_seen", 1686086875.268219)]],
        "execute"]
