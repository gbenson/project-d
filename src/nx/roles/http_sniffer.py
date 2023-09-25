from abc import abstractmethod
from socket import getservbyname

from scapy.all import IP, TCP

from .packet_sniffer import PacketSnifferWorker


class HTTPSnifferWorker(PacketSnifferWorker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._protocol = "tcp"
        self._port = getservbyname(self.TARGET_SERVICE, self._protocol)

    @property
    @abstractmethod
    def TARGET_SERVICE(self):
        raise NotImplementedError

    @property
    def WANTED_PACKETS(self):
        return f"{self._protocol} and port {self._port}"

    def process_packet(self, packet, packet_hash, pipeline, **kwargs):
        # Create a connection identifier from the endpoint addresses.
        src = (packet[IP].src, packet[TCP].sport)
        dst = (packet[IP].dst, packet[TCP].dport)

        # Put the endpoints in a consistent order, so packets in both
        # directions are grouped under the same connection id.
        if dst[1] != self._port:
            src, dst = dst, src
        if src[1] == self._port and src > dst:
            src, dst = dst, src

        base_key = f"{self.TARGET_SERVICE}conn"

        conn_id = f"{dst[0]}:{dst[1]}_{src[0]}:{src[1]}"
        conn_key = f"{base_key}:pkts_{conn_id}"

        pipeline.sadd(f"{base_key}s", conn_id)
        pipeline.sadd(conn_key, packet_hash)
        pipeline.hset(f"{base_key}:last_seen", conn_id, packet.time)
