from redis import Redis as LocalRedis
from nx.admin.redis import Redis as SliceRedis

def main():
    src = SliceRedis()
    dst = LocalRedis()

    total = 0
    pipeline = dst.pipeline(transaction=False)
    for key in src.scan_iter("pkt_*"):
        saved_packet = src.hgetall(key)
        if b"last_seen_by_zack" not in saved_packet:
            continue
        pipeline.hset(key, mapping=saved_packet)
        if len(pipeline) >= 100:
            total += len(pipeline)
            pipeline.execute()
            print(f"Done {total}")
    print(f"Flushing final {len(pipeline)}...")
    pipeline.execute()

if __name__ == "__main__":
    main()
