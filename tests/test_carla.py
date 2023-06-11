from dataclasses import dataclass

import pytest

from scapy.all import Ether
from nx.workers.carla import ARP, ARPMonitorWorker


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self):
        return MockPipeline(self.log)


class MockPipeline:
    def __init__(self, log):
        self.log = log

    def hincrby(self, *args):
        self.log.append(["hincrby", args])
        return 23

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


@dataclass
class MockARPPacketEther:
    src: str = "00:0D:F7:12:CA:FE"
    dst: str = "c8:e1:30:ba:be:23"


class MockARPPacketARP:
    def __init__(self, op=1, hwsrc="00:0D:F7:12:CA:FE", psrc="1.2.3.4"):
        self.op = op
        self.hwsrc = hwsrc
        self.psrc = psrc


class MockARPPacket(dict):
    def __init__(self, **kwargs):
        self[Ether] = MockARPPacketEther()
        self[ARP] = MockARPPacketARP(**kwargs)
        self.time = 1686086875.268219
        self.original = b">>raw bytes<<"


PKTHASH = "a94633760744dc5894cf1d00e74ec2353be937698580bb2141efda3131915ee5"
PKTKEY = f"pkt_{PKTHASH}"


def test_unhandled_arp_packet():
    """It ignores packets with unhandled operations."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(MockARPPacket(op=4))
    assert worker.db.log == [
        ["hset", PKTKEY, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", PKTKEY, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (PKTKEY, "num_sightings", 1)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe_packets", [
            (PKTHASH, 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]


@pytest.mark.parametrize("op", (1, 2))
def test_regular_packets(op):
    """It handles ordinary who-has and is-at packets."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(MockARPPacket(op=op))
    assert worker.db.log == [
        ["hset", PKTKEY, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", PKTKEY, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (PKTKEY, "num_sightings", 1)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe_packets", [
            (PKTHASH, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("ipv4", "1.2.3.4"),
        ]],
        ["hset", "ipv4_1.2.3.4", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("mac", "00:0d:f7:12:ca:fe"),
            ("seen_by", "carla"),
        ]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]


def test_unspecified_ipv4_not_stored():
    """It doesn't store the unspecified IPv4 address."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(MockARPPacket(psrc="0.0.0.0"))
    assert worker.db.log == [
        ["hset", PKTKEY, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", PKTKEY, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (PKTKEY, "num_sightings", 1)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by_carla", 1686086875.268219),
            ("seen_by", "carla"),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe_packets", [
            (PKTHASH, 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]
