from scapy.all import Ether, IP, UDP, DNS, DNSQR

from nx.workers.susan import DNSMonitorWorker


def make_test_packet(**kwargs):
    _kwargs, kwargs = kwargs, dict(
        hwsrc="00:0D:F7:12:CA:FE",
        src="1.2.3.4",
        dst="5.6.7.8",
        layer3=UDP,
        sport=12345,
        dport=53,
        qr=0,  # question
        qname=b"nx.example.com.",
        qclass=1,  # IN
        qtype=1,  # A
    )
    kwargs.update(**_kwargs)

    packet = Ether(
        src=kwargs["hwsrc"],
        dst="c8:e1:30:ba:be:23",
    ) / IP(
        src=kwargs["src"],
        dst=kwargs["dst"],
    ) / kwargs["layer3"](
        sport=kwargs["sport"],
        dport=kwargs["dport"],
    ) / DNS(
        id=12345,
        qr=kwargs["qr"],
        qd=DNSQR(
            qname=kwargs["qname"],
            qclass=kwargs["qclass"],
            qtype=kwargs["qtype"],
        ),
    )

    packet = packet.__class__(_pkt=bytes(packet))
    packet.time = 1686086875.268219
    packet.sniffed_on = "wlx0023cafebabe"
    print(f"{packet!r} => {packet.original!r}")

    return packet


def test_basic_ipv4_udp_query(mockdb):
    """Basic IPv4 UDP DNS queries are logged as expected."""
    worker = DNSMonitorWorker(mockdb)
    packet = make_test_packet()
    worker._process_packet(packet)

    expect_packet_hash = ("518f310855e1cee99362844f2d351ede"
                          "32fc4512e98ee6279578ebead0b42e:3")
    expect_packet_key = f"pkt_{expect_packet_hash}"

    assert worker.db.log == [
        ["hset", expect_packet_key, [
            ("last_seen", 1686086875.268219),
            ("last_seen_by", "susan"),
            ("last_seen_by_susan", 1686086875.268219),
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
            ("last_seen_by", "susan"),
            ("last_seen_by_susan", 1686086875.268219),
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
            ("last_seen_by", "susan"),
            ("last_seen_by_susan", 1686086875.268219),
            ("mac", "00:0d:f7:12:ca:fe"),
        ]],
        ["sadd", "ipv4s", ("1.2.3.4",)],
        ["hset", "dnsq:nx.example.com.:IN:A", [
            ("last_seen", 1686086875.268219),
            ("last_seen_from", "00:0d:f7:12:ca:fe"),
            ("last_seen_from_00:0d:f7:12:ca:fe", 1686086875.268219),
            ("last_seen_in", expect_packet_hash),
        ]],
        ["hsetnx", "dnsq:nx.example.com.:IN:A", [
            ("first_seen", 1686086875.268219),
        ]],
        ["hsetnx", "dnsq:nx.example.com.:IN:A", [
            ("first_seen_from_00:0d:f7:12:ca:fe", 1686086875.268219),
        ]],
        ["hincrby", ("dnsq:nx.example.com.:IN:A", "num_sightings", 1)],
        ["sadd", "dns_queries", ("nx.example.com.:IN:A",)],
        ["hset", "dnsq_pkts:nx.example.com.:IN:A", [
            (expect_packet_hash, 1686086875.268219),
        ]],
        ["hset", "mac_00:0d:f7:12:ca:fe", [
            ("last_dns_query", "nx.example.com.:IN:A"),
            ("last_dns_query_seen", 1686086875.268219),
        ]],
        ["expire", expect_packet_key, 2419200],
        ["hset", "heartbeats", [
            ("susan", 1686086875.268219),
        ]],
        "execute"]
