"""
Drop saved DNS packets into one big list sorted by arrival time.
"""
from redis import Redis


def load_packets(db):
    for pkt_key in db.scan_iter("pkt_*"):
        pkt_meta = db.hgetall(pkt_key)

        sniffer = pkt_meta.get(b"last_seen_by", None)
        if sniffer is None:
            sniffer = pkt_meta.get(b"seen_by", None)
        if sniffer != b"zack":
            continue

        num_sightings = int(pkt_meta[b"num_sightings"])
        assert num_sightings in (1, 2)

        pkt_data = pkt_meta[b"raw_bytes"]
        for timestamp_key in b"first_seen", b"last_seen":
            time = pkt_meta[timestamp_key]
            yield float(time), b":".join((time, pkt_data))
            if num_sightings == 1:
                break


def main():
    db = Redis()

    total = 0
    pipeline = db.pipeline(transaction=False)
    for _, pkt in sorted(load_packets(db)):
        pipeline.rpush("dns_pkts", pkt)
        if len(pipeline) < 100:
            continue
        total += len(pipeline)
        pipeline.execute()
        print(f"Done {total}")

    if len(pipeline):
        total += len(pipeline)
        print(f"Flushing final {len(pipeline)}...")
        pipeline.execute()
        print(f"Done {total}")


if __name__ == "__main__":
    main()
