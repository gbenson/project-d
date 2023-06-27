"""
Stream the big list of DNS packets by the DNS id field.
"""
from collections import defaultdict

from redis import Redis
from scapy.all import Ether, DNS

def main():
    db = Redis()
    pipeline = db.pipeline(transaction=False)

    for i, stored_pkt in enumerate(db.lrange("dns_pkts", 0, -1)):
        if len(pipeline) > 100:
            pipeline.execute()

        timestamp, pkt_data = stored_pkt.split(b":", 1)
        pkt = Ether(pkt_data)
        try:
            dns_id = pkt[DNS].id
        except IndexError:
            pipeline.rpush("dns_b0rk", stored_pkt)
            continue

        dns_id = f"{dns_id:05d}"
        pipeline.rpush(f"dns_pkts_by_id:{dns_id}", stored_pkt)
        pipeline.hsetnx("dns_id_first_seen", dns_id, timestamp)

    pipeline.execute()


if __name__ == "__main__":
    main()
