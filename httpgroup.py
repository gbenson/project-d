from redis import Redis
from scapy.all import Ether, IP, TCP

def main():
    r = Redis()
    p = r.pipeline(transaction=False)

    total = 0
    for pkt_key in r.scan_iter("pkt_*"):
        pkt_hash = pkt_key[4:]
        sniffed_pkt = r.hgetall(pkt_key)
        pkt = Ether(sniffed_pkt[b"raw_bytes"])

        # Create a connection key from the endpoint addresses.
        src = (pkt[IP].src, pkt[TCP].sport)
        dst = (pkt[IP].dst, pkt[TCP].dport)

        # Put them in a consistent order, so packets in both
        # directions are grouped into the same connection.
        if dst[1] != 80:
            src, dst = dst, src
        if src[1] == 80 and src > dat:
            src, dst = dst, src

        conn_key = f"http_{dst[0]}:{dst[1]}_{src[0]}:{src[1]}_pkts"

        p.sadd(conn_key, pkt_hash)
        if len(p) >= 512:
            total += len(p)
            p.execute()
            print(f"Done {total}")

    if len(p):
        print(f"Doing final {len(p)}")
        p.execute()

if __name__ == "__main__":
    main()
