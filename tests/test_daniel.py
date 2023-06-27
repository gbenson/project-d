import pytest

from scapy.all import BOOTP, IP, UDP

from nx.workers.daniel import DHCP, DHCPMonitorWorker, Ether


class MockDatabase:
    def __init__(self):
        self.log = []

    def pipeline(self, transaction=None):
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


def make_test_packet(message_type=None, **kwargs):
    if message_type is not None:
        kwargs["message-type"] = message_type

    packet = Ether(
        src="00:0D:F7:12:CA:FE",
        dst="c8:e1:30:ba:be:23",
    ) / IP() / UDP() / BOOTP() / DHCP(
        options=kwargs.items(),
    )

    packet = packet.__class__(_pkt=bytes(packet))
    packet.time = 1686086875.268219
    packet.sniffed_on = "wlx0023cafebabe"
    print(f"{packet!r} => {packet.original!r}")

    return packet


@pytest.mark.parametrize("extras", ((), ["end"] + ["pad"] * 4))
def test_unhandled_message_handling(extras):
    """Messages we don't understand are retained for analysis."""
    worker = DHCPMonitorWorker(MockDatabase())
    packet = make_test_packet(
        message_type=42,
        max_dhcp_size=1500,
        vendor_class_id=b"what ev er",
        hostname=b"not-ascii-not-utf8\xff",
        param_req_list=[1, 4, 15, 43, 25],
    )
    packet[DHCP].options.extend(extras)
    worker._process_packet(packet)

    expect_packet_hash = ("c4a161a628870b8f8e8643581e1a58f6"
                          "9e59ac12a7955422895446a05f2044:3")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
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
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_DHCP_op42", expect_packet_hash),
            ("last_DHCP_op42_seen", 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219),
        ]],
        "execute"]


def test_request_stores_requested_ipv4():
    """DHCPREQUEST stores requested_ipv4."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(
        message_type=3,
        requested_addr="1.2.3.4",
        max_dhcp_size=1500,
        vendor_class_id=b"Acme Phones Inc",
        hostname=b"Daniel's phone",
        param_req_list=[1, 2, 3, 4, 5],
    ))

    expect_packet_hash = ("9ec693b34c4be35ca96b5a5045a3d1d6"
                          "a18690cdb2c1b39af603551b9321ec:3")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
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
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_DHCPREQUEST", expect_packet_hash),
            ("last_DHCPREQUEST_seen", 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("dhcp_device_name", "Daniel's phone"),
            ("dhcp_vendor_class_id", "Acme Phones Inc"),
            ("requested_ipv4", "1.2.3.4"),
            ("requested_ipv4_at", 1686086875.268219),
        ]],
        ["hdel", "mac_00:0d:f7:12:ca:fe",
         "device_name", "vendor_class_id"],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219)]],
        "execute"]


def test_ack_retrieves_requested_ipv4():
    """DHCPACK retrieves requested_ipv4."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(
        message_type=5,
        server_id="4.3.2.1",
    ))

    expect_packet_hash = ("675517db5f75fedce0f13ffdc8e3b367"
                          "fffc801dfe07ce49163fa88be4712d:3")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
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
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_DHCPACK", expect_packet_hash),
            ("last_DHCPACK_seen", 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("ipv4", "4.3.2.1"),
        ]],
        ["hset", "ipv4_4.3.2.1", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
            ("mac", "00:0d:f7:12:ca:fe"),
        ]],
        ["sadd", "ipv4s", ("4.3.2.1",)],
        ["hmget", (
            "mac_c8:e1:30:ba:be:23",
            "requested_ipv4",
            "requested_ipv4_at")],
        ["hset", "mac_c8:e1:30:ba:be:23", [
            ("ipv4", "5.6.7.8"),
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
        ]],
        ["hset", "ipv4_5.6.7.8", [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
            ("mac", "c8:e1:30:ba:be:23"),
        ]],
        ["sadd", "ipv4s", ("5.6.7.8",)],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219),
        ]],
        "execute"]


def test_nak():
    """DHCPNAK is logged as expected."""
    worker = DHCPMonitorWorker(MockDatabase())
    worker._process_packet(make_test_packet(
        message_type=6,
        error_message=b"go 'way fool",
    ))

    expect_packet_hash = ("433001c96676681955da499ddf91f937"
                          "7156320f2430f2bd7a93ee3d46b330:3")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
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
            ("last_seen_by", "daniel"),
            ("last_seen_by_daniel", 1686086875.268219),
        ]],
        ["hsetnx", "mac_00:0d:f7:12:ca:fe", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hset", "macpkts_00:0d:f7:12:ca:fe", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_DHCPNAK", expect_packet_hash),
            ("last_DHCPNAK_seen", 1686086875.268219),
        ]],
        ["hset", "heartbeats", [
            ("daniel", 1686086875.268219),
        ]],
        "execute"]
