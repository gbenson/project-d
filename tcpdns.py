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
        sequences = []
        sequence_ids = {}

        for pkt_hash in self.db.lrange("dns_tcp_for_reassembly", 0, -1):
            pkt_hash = pkt_hash.decode()
            packet = self._rehydrate_packet(pkt_hash)
            tcp = packet[TCP]
            seq, ack, flags = tcp.seq, tcp.ack, tcp.flags
            print(seq, flags)
            if seq == 1722820901:
                packet.show()
                
            if "A" in flags:
                assert "S" in flags or seq - 1 in sequence_ids
                assert ack - 1 in sequence_ids
            if "S" in flags:
                assert "A" in flags or ack == 0
                assert seq not in sequence_ids
                sequence_ids[seq] = len(sequences)
                sequences.append([packet])
                continue
            if seq in sequence_ids:
                assert "P" in flags
            else:
                sequence_ids[seq] = sequence_ids[seq - 1]
            sequences[sequence_ids[seq]].append(packet)
            if flags == "A":
                continue
            if flags == "PA":
                assert seq in sequence_ids  # ??
                assert DNS in tcp
                continue
            
            print(sequence_ids)
            packet.show()
            break


def main():
    StreamerTestWorker().run_simulation()


if __name__ == "__main__":
    main()
