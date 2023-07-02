from scapy.all import DNS, IP, TCP, dnsclasses, dnsqtypes

from ..common.constants import MINUTES, WEEKS
from ..roles.packet_sniffer import PacketSnifferWorker, UnhandledPacket


class DNSMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Susan"
    WANTED_PACKETS = "port 53"

    def process_packet(self, packet, **kwargs):
        dns = packet.getlayer(DNS)
        if dns is None:
            self.process_non_dns_packet(packet)
            return

        if dns.opcode != 0:  # QUERY
            raise UnhandledPacket("dns_opcode")

        is_query = dns.qr == 0  # query/response
        is_response = dns.qr == 1
        if is_query is not (not is_response):
            raise UnhandledPacket("dns_qr")

        if is_query:
            self.process_query(packet, dns)
            return

        # Don't retain packets we don't (yet) process.
        self.expire_packet_after(30 * MINUTES)

    def process_query(self, packet, dns):
        if dns.rcode != 0:  # NOERROR
            raise UnhandledPacket("dns_query_rcode")
        if dns.tc:  # truncated
            raise UnhandledPacket("dns_query_tc")

        # For queries the IPv4 src is on our network.
        ipv4 = packet.getlayer(IP)
        if ipv4 is not None:
            self.record_ipv4_sighting(ipv4.src)

        if dns.qdcount != 1:
            self.record_issue("dns_query_qdcount")
        for index in range(dns.qdcount):
            self.record_dns_lookup(packet, dns.qd[index])

        # Most of these will be UDP and will hash-collide.  TCP ones
        # won't collide, but there shouldn't be anything like as many
        # of those.
        self.expire_packet_after(4 * WEEKS)

    def record_dns_lookup(self, packet, question):
        pipeline = self.pipeline
        question = ":".join((
            question.qname.decode(),
            dnsclasses[question.qclass],
            dnsqtypes[question.qtype],
        ))

        key = f"dnsq:{question}"
        fields = {
            "last_seen": packet.time,
            "last_seen_in": self.packet_hash,
            "last_seen_from": self.src_mac,
            f"last_seen_from_{self.src_mac}": packet.time,
        }
        pipeline.hset(key, mapping=fields)
        for field in ("first_seen", f"first_seen_from_{self.src_mac}"):
            pipeline.hsetnx(key, field, packet.time)
        pipeline.hincrby(key, "num_sightings", 1)

        key = f"dnsq_pkts:{question}"
        pipeline.hset(key, self.packet_hash, packet.time)

        key = self.mac_key
        fields = {
            "last_dns_query": question,
            "last_dns_query_seen": packet.time,
        }
        pipeline.hset(key, mapping=fields)

    TCP_CONNECTION_ADMIN_FLAGS = {"S", "SA", "A", "FA"}

    def process_non_dns_packet(self, packet):
        tcp = packet.getlayer(TCP)
        if tcp is None:
            raise UnhandledPacket("port_53")

        if tcp.flags not in self.TCP_CONNECTION_ADMIN_FLAGS:
            raise UnhandledPacket("port_53_tcp")

        # Don't retain (presumably) connection admin packets.
        self.expire_packet_after(30 * MINUTES)


main = DNSMonitorWorker.main
