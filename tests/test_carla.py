import pytest

from nx.workers.carla import ARP, ARPMonitorWorker


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
    worker = ARPMonitorWorker(MockDatabase())
    worker.process_packet({})
    assert not worker.db.log


def test_unhandled_arp_packet():
    """It ignores packets with unhandled operations."""
    worker = ARPMonitorWorker(MockDatabase())
    worker.process_packet(MockARPPacket(op=4))
    assert not worker.db.log


@pytest.mark.parametrize("op", (1, 2))
def test_regular_packets(op):
    """It handles ordinary who-has and is-at packets."""
    worker = ARPMonitorWorker(MockDatabase())
    worker.process_packet(MockARPPacket(op=op))
    assert worker.db.log == [
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
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219)]],
        "execute"]


def test_unspecified_ipv4_not_stored():
    """It doesn't store the unspecified IPv4 address."""
    worker = ARPMonitorWorker(MockDatabase())
    worker.process_packet(MockARPPacket(psrc="0.0.0.0"))
    assert worker.db.log == [
        ["hset", "mac_00:0d:f7:12:fe", [
            ("last_seen", 1686086875.268219),
            ("seen_by", "carla")]],
        ["hsetnx", "mac_00:0d:f7:12:fe", [
            ("first_seen", 1686086875.268219)]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219)]],
        "execute"]
