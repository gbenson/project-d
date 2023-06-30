from collections import defaultdict

from redis import Redis
from scapy.all import Ether, IP, TCP, DNS, IPSession


class StreamerTestWorker:
    def __init__(self):
        self.db = Redis()
        self.start_time = None

    def _rehydrate_packet(self, packet_hash, timestamp=None):
        packet_key = f"pkt_{packet_hash}"
        packet_data = self.db.hget(packet_key, "raw_bytes")
        if packet_data is None:
            raise KeyError(packet_key)
        packet = Ether(packet_data)
        if timestamp is not None:
            packet.time = timestamp
        return packet

    def run_simulation(self):
        for pkt_hash in self.db.lrange("dns_tcp_for_reassembly", 0, -1):
            pkt_hash = pkt_hash.decode()
            packet = self._rehydrate_packet(pkt_hash)
            if DNS not in packet:
                assert packet[TCP].flags in ("S", "SA", "A", "FA")
                continue
            if packet[TCP].flags == "PA":
                continue
            packet.show()
            break


def main():
    StreamerTestWorker().run_simulation()


if __name__ == "__main__":
    main()
