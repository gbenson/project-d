import pytest

from scapy.all import Ether, IP, TCP

from nx.workers.kaitlin import HTTPSMonitorWorker


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
        sport=443,
      ),
      "d1ecc510582e39a470ff890dc0e7e323"
      "cf649d549f48a3444436d7d0d95230:3",
      ),
     (dict(
         dst="1.2.3.4",
         dport=443,
         src="8.7.6.5",
         sport=23456,
      ),
      "f0dda87bd67ee3af295d30ed785d0b5b"
      "9516110659ccbc7c445d10c4524764:3",
      ),
     ))
def test_regular_packets(mockdb, kwargs, expect_packet_hash):
    """It handles ordinary packets."""
    worker = HTTPSMonitorWorker(mockdb)
    worker._process_packet(make_test_packet(**kwargs))

    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "kaitlin"),
            ("last_seen_by_kaitlin", 1686086875.268219),
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
            ("last_seen_by", "kaitlin"),
            ("last_seen_by_kaitlin", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["sadd", "httpsconns", (
            "1.2.3.4:443_8.7.6.5:23456",
        )],
        ["sadd", "httpsconn:pkts_1.2.3.4:443_8.7.6.5:23456", (
            expect_packet_hash,
        )],
        ["hset", "httpsconn:last_seen", [
            ("1.2.3.4:443_8.7.6.5:23456", 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("kaitlin", 1686086875.268219),
        ]],
        "execute"]
