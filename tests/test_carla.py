import pytest

from scapy.all import Ether

from nx.workers.carla import ARP, ARPMonitorWorker


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
    packet.sniffed_on = "wlx0023cafebabe"
    return packet


def test_unhandled_arp_packet(mockdb):
    """It ignores packets with unhandled operations."""
    worker = ARPMonitorWorker(mockdb)
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
            ("last_sniffed_on", "wlx0023cafebabe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["hset", "interfaces", [
            ("wlx0023cafebabe", 1686086875.268219),
        ]],
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
def test_regular_packets(mockdb, op, expect_packet_hash):
    """It handles ordinary who-has and is-at packets."""
    worker = ARPMonitorWorker(mockdb)
    worker._process_packet(make_test_packet(op=op))

    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "carla"),
            ("last_seen_by_carla", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("last_sniffed_on", "wlx0023cafebabe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["hset", "interfaces", [
            ("wlx0023cafebabe", 1686086875.268219),
        ]],
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


def test_unspecified_ipv4_not_stored(mockdb):
    """It doesn't store the unspecified IPv4 address."""
    worker = ARPMonitorWorker(mockdb)
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
            ("last_sniffed_on", "wlx0023cafebabe"),
            ("raw_bytes", b">>raw bytes<<"),
        ]],
        ["hsetnx", expect_packet_key, [
            ("first_seen", 1686086875.268219),
        ]],
        ["hincrby", (expect_packet_key, "num_sightings", 1)],
        ["hset", "interfaces", [
            ("wlx0023cafebabe", 1686086875.268219),
        ]],
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
