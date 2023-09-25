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

        # Figure out which direction the connection was made.
        is_inbound = src[1] == self._port
        is_outbound = dst[1] == self._port
        if is_inbound == is_outbound:
            flow = "ambiguous"
        elif is_inbound:
            flow = "inbound"
        elif is_outbound:
            flow = "outbound"

        # Put the endpoints in a consistent order, so packets in both
        # directions are grouped under the same connection id.
        if dst[1] != self._port:
            src, dst = dst, src
        if src[1] == self._port and src > dst:
            src, dst = dst, src

        base_key = f"{self.TARGET_SERVICE}conn"

        conn_id = f"{dst[0]}:{dst[1]}_{src[0]}:{src[1]}"
        conn_key = f"{base_key}:{conn_id}"
        pkts_key = f"{base_key}:pkts_{conn_id}"

        pipeline.sadd(f"{base_key}s", conn_id)
        pipeline.hset(conn_key, "last_seen", packet.time)
        pipeline.hsetnx(conn_key, "first_seen", packet.time)
        pipeline.hincrby(conn_key, f"{flow}_packets", 1)
        pipeline.hincrby(conn_key, f"{flow}_bytes", len(packet.original))
        pipeline.rpush(pkts_key, packet_hash)
