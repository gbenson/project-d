"""
Simulate the arrival of the big list of DNS packets.
"""
from redis import Redis, WatchError
from scapy.all import Ether, DNS, dnsqtypes, dnsclasses

from nx.roles.packet_sniffer import calc_packet_hash


class StreamerTestWorker:
    def __init__(self):
        self.db = Redis()
        self._cleanup()
        self.start_time = None

    def _cleanup(self):
        """Wipe output of previous versions of this script."""
        pipeline = self.db.pipeline(transaction=False)
        for key in self.db.scan_iter("pkt_*_dns_test_1"):
            pipeline.delete(key)
        for key in self.db.scan_iter("dns_stream:*"):
            pipeline.delete(key)
        pipeline.delete("dns_stream_last_seen")
        pipeline.execute()

    def run_simulation(self):
        pipeline = self.db.pipeline(transaction=False)
        for pkt_index, stored_pkt in enumerate(self.db.lrange("dns_pkts", 0, -1)):
            pkt_time, pkt_data = stored_pkt.split(b":", 1)
            packet = Ether(pkt_data)
            packet.time = float(pkt_time)
            if self.start_time is None:
                self.start_time = packet.time
            print(f"{pkt_index:05}: T+{packet.time - self.start_time:012.6f}S")

            # packet processor
            packet_hash = calc_packet_hash(packet) + "_dns_test_1"
            packet_key = f"pkt_{packet_hash}"
            pipeline.hset(packet_key, "raw_bytes", packet.original)
            pipeline.hincrby(packet_key, "num_sightings", 1)

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


class OversizeStreamError(Exception):
    pass


def main():
    StreamerTestWorker().run_simulation()


if __name__ == "__main__":
    main()
