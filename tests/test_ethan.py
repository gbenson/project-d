import pytest

from scapy.all import Ether, IP, TCP

from nx.workers.ethan import HTTPMonitorWorker


def make_test_packet(**kwargs):
    _kwargs, kwargs = kwargs, dict(
        hwsrc="00:0D:F7:12:CA:FE",
        src="1.2.3.4",
        dst="8.7.6.5",
        sport=12345,
        dport=23456,
    )
    kwargs.update(**_kwargs)

    packet = Ether(
        src=kwargs["hwsrc"],
        dst="c8:e1:30:ba:be:23",
    ) / IP(
        src=kwargs["src"],
        dst=kwargs["dst"],
    ) / TCP(
        sport=kwargs["sport"],
        dport=kwargs["dport"],
    )

    packet = packet.__class__(_pkt=bytes(packet))
    packet.time = 1686086875.268219
    packet.sniffed_on = "wlx0023cafebabe"
    return packet


@pytest.mark.parametrize(
    "kwargs,expect_packet_hash",
    ((dict(
        sport=80,
      ),
      "02490a0077f712cf9a7f32b99b1f799f"
      "e70ef653c7d889cb26391c1fce1151:3",
      ),
     (dict(
         dst="1.2.3.4",
         dport=80,
         src="8.7.6.5",
         sport=23456,
      ),
      "8a45c4ce30b2ddaf63d414ea4503f3e5"
      "68b38ef488865c1e9194e55932114d:3",
      ),
     ))
def test_regular_packets(mockdb, kwargs, expect_packet_hash):
    """It handles ordinary packets."""
    worker = HTTPMonitorWorker(mockdb)
    worker._process_packet(make_test_packet(**kwargs))

    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "ethan"),
            ("last_seen_by_ethan", 1686086875.268219),
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
            ("last_seen_by", "ethan"),
            ("last_seen_by_ethan", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["sadd", "httpconns", (
            "1.2.3.4:80_8.7.6.5:23456",
        )],
        ["sadd", "httpconn:pkts_1.2.3.4:80_8.7.6.5:23456", (
            expect_packet_hash,
        )],
        ["hset", "httpconn:last_seen", [
            ("1.2.3.4:80_8.7.6.5:23456", 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("ethan", 1686086875.268219),
        ]],
        "execute"]
