import pytest

from scapy.all import Ether

from nx.workers.ethan import IP, TCP, HTTPMonitorWorker


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
      "b9212fcd0643395644ca74a33129217b"
      "c81ba96934ed0786dd6a432af4db51e0",
      ),
     (dict(
         dst="1.2.3.4",
         dport=80,
         src="8.7.6.5",
         sport=23456,
      ),
      "49fc90fcee3c6b88baa090691f3b5dd5"
      "ebad88db75cc6d5dcd9ebd17abed0c2f",
      ),
     ))
def test_regular_packets(kwargs, expect_packet_hash):
    """It handles ordinary packets."""
    worker = HTTPMonitorWorker(MockDatabase())
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
        ["sadd", "httpconn:pkts_1.2.3.4:80_8.7.6.5:23456", (
            expect_packet_hash,
        )],
        ["sadd", "http_connections", (
            "1.2.3.4:80_8.7.6.5:23456",
        )],
        ["hset", "heartbeats", [
            ("ethan", 1686086875.268219),
        ]],
        "execute"]
