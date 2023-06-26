from scapy.all import IP, TCP

from ..common.packet_sniffer import PacketSnifferWorker


class HTTPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Ethan"
    WANTED_PACKETS = "port 80"

    def process_packet(self, packet, packet_hash, pipeline, **kwargs):

        # Create a connection identifier from the endpoint addresses.
        src = (packet[IP].src, packet[TCP].sport)
        dst = (packet[IP].dst, packet[TCP].dport)

        # Put the endpoints in a consistent order, so packets in both
        # directions are grouped under the same connection id.
        if dst[1] != 80:
            src, dst = dst, src
        if src[1] == 80 and src > dst:
            src, dst = dst, src

        conn_id = f"{dst[0]}:{dst[1]}_{src[0]}:{src[1]}"
        conn_key = f"httpconn:pkts_{conn_id}"

        pipeline.sadd(conn_key, packet_hash)
        pipeline.hset("httpconn:last_seen", conn_id, packet.time)


main = HTTPMonitorWorker.main
