import os

from collections import defaultdict

from redis import Redis
from scapy.all import BOOTP, Ether, IP, UDP


def main():
    db = Redis()

    sniffer_num_packets = defaultdict(int)
    sniffer_size_bytes = defaultdict(int)

    dhcp_by_srcdst = defaultdict(list)

    for pkt_key in db.scan_iter("pkt_*"):
        pkt_meta = db.hgetall(pkt_key)
        pkt_meta["hash"] = pkt_key[4:]
        pkt_data = pkt_meta.pop(b"raw_bytes")

        sniffer = pkt_meta.get(b"last_seen_by", None)
        if sniffer is None:
            sniffer = pkt_meta.get(b"seen_by", None)

        sniffer_num_packets[sniffer] += 1
        sniffer_size_bytes[sniffer] += len(pkt_data)

        if sniffer != b"daniel":
            continue

        pkt = Ether(_pkt=pkt_data)
        pkt.nx_meta = pkt_meta
        dhcp_by_srcdst[pkt.src, pkt.dst].append(pkt)

    #print(sniffer_num_packets)
    #print(sniffer_size_bytes)
    #print()

    num_packets = sniffer_num_packets[b'daniel']
    num_buckets = len(dhcp_by_srcdst)
    print(f"read {num_packets} packets in {num_buckets} buckets:")

    buckets = [(len(pkts), key) for key, pkts in dhcp_by_srcdst.items()]
    for num_pkts, src_dst in reversed(sorted(buckets)):
        print(f"  {' → '.join(src_dst)}: {num_pkts}")

        payloads = defaultdict(int)
        pkt_a = pkt_b = None
        for pkt in dhcp_by_srcdst[src_dst]:
            pkt[IP].id = 0
            pkt[IP].chksum = 0
            pkt[UDP].chksum = 0
            pkt[BOOTP].xid = 0
            pkt[BOOTP].secs = 0
            payloads[bytes(pkt)] += 1

            if pkt_a is None:
                pkt_a = pkt
            elif pkt_b is None and len(payloads) == 2:
                pkt_b = pkt

        print(f"  num_payloads = {len(payloads)}")

        if pkt_b is None:
            continue

        continue
        if len(payloads) < 10:
            for payload in sorted(payloads):
                print(len(payload))
                continue
                print("=" * 78)
                pkt = Ether(_pkt=payload)
                pkt.show()

        payloads = list(sorted(payloads))
        pkt_a, pkt_b = [Ether(_pkt=payload) for payload in payloads[:2]]

        print("  Differences:")
        bytes_0, bytes_1 = [pkt.original for pkt in (pkt_a, pkt_b)]
        assert len(bytes_0) == len(bytes_1)
        assert bytes_0 != bytes_1
        last_i = None
        for i, pair in enumerate(zip(bytes_0, bytes_1)):
            a, b = pair
            if a == b:
                continue
            if last_i and last_i != i - 1:
                print()
            print(f"    0x{i:03x}: 0x{a:02x} != 0x{b:02x}")
            last_i = i
        print()

        print("  Layer offsets:")
        for lyr_a, lyr_b in zip(pkt_a.iterpayloads(), pkt_b.iterpayloads()):
            assert len(lyr_a) == len(lyr_b)
            start = len(pkt_a) - len(lyr_a)
            print(f"    0x{start:04x}: {str(lyr_a).split('/', 1)[0].strip()}")
        print()

        print("  Differences:")
        print("   ", pkt_a[IP].id, pkt_b[IP].id)
        print("   ", pkt_a[IP].chksum, pkt_b[IP].chksum)
        print("   ", pkt_a[UDP].chksum, pkt_b[UDP].chksum)
        print("   ", pkt_a[BOOTP].secs, pkt_b[BOOTP].secs)
        print()

        break


if __name__ == "__main__":
    main()

# 0x02e: 0xdf != 0x72  bootp 4  xid  (transaction id)
# 0x02f: 0x19 != 0x33  bootp 5
# 0x030: 0x87 != 0x10  bootp 6
# 0x031: 0xc8 != 0x45  bootp 7

# 0x032: 0x89 != 0x01  bootp 8  secs (seconds elapsed since client started trying to boot)
# 0x033: 0x38 != 0xbf  bootp 9
