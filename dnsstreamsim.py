"""
Simulate the arrival of the big list of DNS packets.
"""
from collections import defaultdict

from redis import Redis, WatchError
from scapy.all import Ether, DNS, DNSQR, DNSRR, DNSRROPT, DNSRRSRV, IP, UDP, TCP, dnsclasses, dnsqtypes, dnstypes

from nx.roles.packet_sniffer import calc_packet_hash


class StreamerTestWorker:
    def __init__(self):
        self.db = Redis()
        self._cleanup()
        self.start_time = None
        self.randoms = []

    def _cleanup(self):
        """Wipe output of previous versions of this script."""
        pipeline = self.db.pipeline(transaction=False)
        for key in self.db.scan_iter("pkt_*_dns_test_1"):
            pipeline.delete(key)
        # Version 1 (stream reassembler)
        for key in self.db.scan_iter("dns_stream:*"):
            pipeline.delete(key)
        pipeline.delete("dns_stream_last_seen")
        # Version 2 (unstreamed information miner)
        pipeline.delete("dns_errors")
        pipeline.delete("dns_tcp_for_reassembly")

        pipeline.execute()

    def run_simulation(self):
        global print

        self.queries = defaultdict(int)
        self.questions = defaultdict(int)
        self.responses = defaultdict(int)
        self.oddballs = defaultdict(int)

        self.question_packets = defaultdict(set)

        self.print = print
        try:
            print = lambda *args, **kwargs: None
            self._run_simulation()
        finally:
            print = self.print

        print(f"{len(self.questions)} questions => "
              f"{len(self.queries)} queries, "
              f"{len(self.responses)} responses, "
              f"{len(self.oddballs)} oddballs, "
              f"and {len(self.randoms)} TCP packets")

        print("\nTop 30:")
        for i, c_q in enumerate(sorted((-v, k) for k, v in self.questions.items())):
            count, question = c_q
            print(f"{i+1:>3}: {-count:3}: {question!r}")
            if i == 29:
                return

        print("\nTop 30:")
        for i, c_q in enumerate(sorted((-len(v), k)
                                       for k, v in self.question_packets.items())):
            count, question = c_q
            print(f"{i+1:>3}: {-count:3}: {question!r}")
            if i == 29:
                break

    def _run_simulation(self):
        pipeline = self.db.pipeline(transaction=False)

        for pkt_index, stored_pkt in enumerate(self.db.lrange("dns_pkts", 0, -1)):
            pkt_time, pkt_data = stored_pkt.split(b":", 1)
            packet = Ether(pkt_data)
            packet.time = float(pkt_time)
            if self.start_time is None:
                self.start_time = packet.time
            if pkt_index and pkt_index % 1000 == 0:
                self.print(f"{pkt_index:05}: T+{packet.time - self.start_time:013.6f}S")

            # packet processor
            packet_hash = calc_packet_hash(packet) + "_dns_test_1"
            packet_key = f"pkt_{packet_hash}"
            pipeline.hset(packet_key, "raw_bytes", packet.original)
            #pipeline.hincrby(packet_key, "num_sightings", 1)
            self.src_mac = packet[Ether].src.lower()
            pipeline.execute()

            # packet sniffer worker
            self.process_packet(
                packet=packet,
                pipeline=pipeline,
                packet_hash=packet_hash,
                packet_key=packet_key,
            )

            pipeline.execute()

            # stream decoder worker
            self.timed_stream_decode(packet.time)

    def process_packet(self, packet, pipeline, packet_hash, **kwargs):
        """DNS packet sniffer worker."""
        dns_layer = packet.getlayer(DNS)
        dns_id = dns_layer.id

        stream_id = f"{dns_id:05d}"
        timestamp = f"{packet.time}"

        stream_key = f"dns_stream:{stream_id}"
        pipeline.rpush(stream_key, f"{timestamp}:{packet_hash}")
        pipeline.hset("dns_stream_last_seen", stream_id, timestamp)

    MAX_STREAM_IDLE_TIME = 12.5  # Windows calls it after 10s
    # [from https://learn.microsoft.com/en-us/troubleshoot/windows-serve
    # r/networking/dns-client-resolution-timeouts#what-is-the-default-be
    # havior-of-a-dns-client-when-a-single-dns-server-is-configured-on-t
    # he-nic ]

    MAX_STREAM_SIZE = 512  # Stop anything growing MASSIVE

    def timed_stream_decode(self, now):
        """DNS stream decoder worker."""
        latest_idle_time = now - self.MAX_STREAM_IDLE_TIME

        last_updated = self.db.hgetall("dns_stream_last_seen")
        for last_update, stream_id in sorted(
                (float(last_update), stream_id.decode())
                for stream_id, last_update in last_updated.items()
        ):
            if last_update > latest_idle_time:
                continue

            entries = self.pop_from_stream(stream_id, latest_idle_time)
            if not entries:
                continue

            if self.handle_query_response(stream_id, entries):
                continue

            print(stream_id, entries)
            raise SystemExit

    def pop_from_stream(self, stream_id, max_timestamp):
        stream_key = f"dns_stream:{stream_id}"
        try:
            return list(self._pop_from_stream(stream_key, max_timestamp))
        except OversizeStreamError:
            # XXX wtf else to do with this overgrown stream?
            # XXX also, log this somehow!
            self.db.delete(stream_key)
        finally:
            self._update_stream_last_seen(stream_id, stream_key)

    def _pop_from_stream(self, stream_key, max_timestamp):
        for _ in range(self.MAX_STREAM_SIZE):
            entry = self.db.lpop(stream_key)
            if entry is None:  # No more entries
                return
            timestamp, packet_hash = entry.split(b":", 1)
            timestamp = float(timestamp)
            if timestamp > max_timestamp:  # Too new!
                print("pushed back")
                self.db.lpush(stream_key, entry)
                return
            yield timestamp, packet_hash.decode()
        raise OversizeStreamError

    def _update_stream_last_seen(self, stream_id, stream_key):
        try:
            pipe = self.db.pipeline()
            pipe.watch(stream_key)
            last_entry = self.db.lindex(stream_key, -1)
            if last_entry is not None:
                return  # There's still packets
            pipe.multi()
            pipe.hdel("dns_stream_last_seen", stream_id)
            pipe.execute()
        except WatchError as e:
            pass  # New packets arrived => last seen is fine

    def _rehydrate_packet(self, timestamp, packet_hash):
        packet_key = f"pkt_{packet_hash}"
        packet_data = self.db.hget(packet_key, "raw_bytes")
        if packet_data is None:
            raise KeyError(packet_key)
        packet = Ether(packet_data)
        packet.time = timestamp
        return packet

    def handle_query_response(self, stream_id, stream_entries):
        if len(stream_entries) != 2:
            return False

        packets = [self._rehydrate_packet(*e) for e in stream_entries]

        q, r = [packet.getlayer(DNS) for packet in packets]
        assert q is not None
        assert r is not None

        assert q.opcode == 0  # QUERY
        assert r.opcode == 0
        assert q.qr == 0  # query
        assert r.qr == 1  # response
        assert not q.tc  # truncated
        assert not r.tc
        assert q.rcode == 0  # no error condition
        assert r.rcode == 0  # no error condition

        assert q.qdcount == 1  # num entries in question section
        assert q.ancount == 0
        assert q.nscount == 0
        assert q.arcount == 0

        assert r.qdcount == 1  # num entries in question section
        if r.ancount == 0:
            r.show()
        assert r.ancount > 0  # num resource records in answer section
        assert r.nscount == 0
        assert r.arcount == 0

        assert q.qd == r.qd  # the entire question section
        #print(repr(q.qd))
        assert packets[0][Ether].src == "00:04:ed:f4:00:fd"
        print(f" Q?  {q.qd[0].qname.decode():}"
              f"  {dnsclasses[q.qd[0].qclass]}"
              f"  {dnsqtypes[q.qd[0].qtype]}")
        #print(repr(r.an))

        return True

    # Version 2 (extract information without sequencing?)

    timed_stream_decode = lambda *args, **kwargs: None
    XXXDBG = __name__ == "__main__"
    SRC_MACS = {
        "00:04:ed:f4:00:fd", # billion (far side)
        "b8:27:eb:40:47:5e", # slice
    }

    def record_ipv4_sighting(self, ipv4_addr, mac_addr=None):
        if mac_addr is None:
            mac_addr = self.src_mac
        assert mac_addr in self.SRC_MACS
        print(f" Q: {mac_addr} is {ipv4_addr}")

    def record_dns_lookup(self, question, XXX, packet_hash, server):
        qname = question.qname.decode()
        qclass = dnsclasses[question.qclass]
        qtype = dnsqtypes[question.qtype]
        question = " ".join((qname, qclass, qtype))
        self.questions[question] += 1

        prefix = f"Q: {self.src_mac} asked" if XXX else "-: question was"
        print(f" {prefix} {question!r}{' ?' if XXX else ''}")

        if not XXX:  # not a query
            return

        question = f"{server}, {question!r} ?"
        self.question_packets[question].add(packet_hash)


    def process_packet(self, packet, packet_hash, **kwargs):
        ip4 = packet.getlayer(IP)
        udp = ip4.getlayer(UDP)
        if udp is None:
            self.randoms.append(packet)
            self.db.rpush("dns_tcp_for_reassembly", packet_hash)
            #self.db.ltrim( ??
            return  # XXX do something with these?
        dns = udp.getlayer(DNS)

        try:
            self._process_packet(ip4, dns, packet_hash)
        except Exception:
            packet.show()
            raise

    def _process_packet(self, ip4, dns, packet_hash):
        print(f" -: dns.id = {dns.id}")

        assert dns.opcode == 0  # QUERY
        is_query = dns.qr == 0
        is_response = dns.qr == 1
        assert is_query is (not is_response)
        assert is_response or dns.rcode == 0  # NOERROR

        if dns.tc: # truncated
            assert is_response
            assert dns.rcode == 0
            assert dns.qdcount == 1
            assert dns.ancount == 0
            assert dns.nscount == 0
            assert dns.arcount == 0
            return

        # For queries the IPv4 src is on our network
        if is_query:  # query
            self.record_ipv4_sighting(ip4.src)

        # Questions
        assert dns.qdcount == 1
        for index in range(dns.qdcount):
            question = dns.qd[index]
            assert isinstance(question, DNSQR)
            if is_query or self.XXXDBG:
                self.record_dns_lookup(question, is_query, packet_hash, ip4.dst)

        # Additional records
        assert dns.arcount in (0, 1)
        for index in range(dns.arcount):
            record = dns.ar[index]
            assert isinstance(record, DNSRROPT)

        if is_query:
            assert dns.ancount == 0
            assert dns.nscount == 0
            self.queries[packet_hash] += 1
            return

        assert is_response
        if dns.rcode != 0:
            self.db.lpush("dns_errors", packet_hash)
            self.db.ltrim("dns_errors", 0, 1000)
            self.oddballs[packet_hash] += 1
            code = {3: "NXDOMAIN", 2: "SERVFAIL"}[dns.rcode]
            print(" -: {code}({dns.rcode})")
            return
        self.responses[packet_hash] += 1

        for index in range(dns.ancount):
            record = dns.an[index]
            if isinstance(record, DNSRRSRV):
                continue
            assert isinstance(record, DNSRR)
            rrname = record.rrname
            rclass = dnsclasses[record.rclass]
            rtype = dnstypes[record.type]
            ttl = record.ttl
            rdata = record.rdata
            print(f" -: {rrname!r} ttl {ttl} {rclass} {rtype} {rdata!r}")

        if dns.nscount > 0 and not self.XXXDBG:
            raise NotImplementedError


class OversizeStreamError(Exception):
    pass


def main():
    StreamerTestWorker().run_simulation()


if __name__ == "__main__":
    main()
