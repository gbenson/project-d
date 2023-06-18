import pytest

from scapy.all import Ether

from nx.workers.carla import ARP, ARPMonitorWorker


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self, transaction=None):
        return MockPipeline(self.log)


class MockPipeline:
    def __init__(self, log):
        self.log = log

    def hdel(self, *args):
        self.log.append(["hdel", *args])

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
        if "raw_bytes" in args:
            args["raw_bytes"] = b">>raw bytes<<"
        self.log.append([cmd, name, list(sorted(args.items()))])

    def sadd(self, key, *args):
        self.log.append(["sadd", key, args])

    def execute(self):
        self.log.append("execute")
        print(self.log)


def make_test_packet(**kwargs):
    _kwargs, kwargs = kwargs, dict(
        op=1,
        hwsrc="00:0D:F7:12:CA:FE",
        psrc="1.2.3.4",
        pdst="8.7.6.5",
    )
    kwargs.update(**_kwargs)

    packet = Ether(
        src=kwargs["hwsrc"],
        dst="c8:e1:30:ba:be:23",
    ) / ARP(**kwargs)

    packet = packet.__class__(_pkt=bytes(packet))
    packet.time = 1686086875.268219
    return packet


def test_unhandled_arp_packet():
    """It ignores packets with unhandled operations."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(op=4))

    expect_packet_hash = ("3bd74d3e6bd2a35db46e76180db0b8a9"
                          "8ff18703bb24b88245b90653ba9411de")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["sadd", "macs", ("00:0d:f7:12:ca:fe",)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]


@pytest.mark.parametrize(
    "op,expect_packet_hash",
    ((1,
      "79199f8b42a9715f985a2f3ff6304401"
      "b3d5d1cb29137fdfc13029076f7574a0"),
     (2,
      "4cdf643ce0a21afb311885fc28172569"
      "b74a90dbfe07bbbe25fd2302cd4c9dc1"),
     ))
def test_regular_packets(op, expect_packet_hash):
    """It handles ordinary who-has and is-at packets."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(op=op))

    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["sadd", "macs", ("00:0d:f7:12:ca:fe",)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("ipv4", "1.2.3.4"),
        ]],
        ["hset", "ipv4_1.2.3.4", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
            ("mac", "00:0d:f7:12:ca:fe"),
        ]],
        ["sadd", "ipv4s", ("1.2.3.4",)],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]


def test_unspecified_ipv4_not_stored():
    """It doesn't store the unspecified IPv4 address."""
    worker = ARPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(psrc="0.0.0.0"))

    expect_packet_hash = ("d9f57a055d070c56833bc0483e56b998"
                          "ea04c75ba65a41c5c72eb5a3ca3dff31")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["sadd", "macs", ("00:0d:f7:12:ca:fe",)],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("carla", 1686086875.268219),
        ]],
        "execute"]
