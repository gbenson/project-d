from redis import Redis as LocalRedis
from nx.admin.redis import Redis as SliceRedis

def main():
    src = LocalRedis()
    dst = SliceRedis()

    pipeline = dst.pipeline(transaction=False)
    for key in src.scan_iter("pkt_*"):
        sniffed_packet = src.hgetall(key)
        if b"last_seen_by_zack" not in sniffed_packet:
            continue
        pipeline.delete(key)
    pipeline.execute()

if __name__ == "__main__":
    main()
