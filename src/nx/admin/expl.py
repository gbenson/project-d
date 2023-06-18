import re

import numpy as np

from scapy.all import Ether, NoPayload, Padding, Raw, TCP
from scipy.stats import entropy

from .redis import Redis


class Reporter(Redis):
    REQUEST_START = re.compile(rb"[^\r\n]+ HTTP/\d\.\d\r\n")
    RESPONSE_START = re.compile(rb"HTTP/\d\.\d \d{3} ")  # RFC1945

    MD5_HASH = re.compile(rb"\n [\da-f]{40}  ")

    def report(self):
        for key in self.scan_iter("pkt_*"):
            meta = self.hgetall(key)
            if b"last_seen_by_ethan" not in meta:
                continue
            pkt = Ether(meta[b"raw_bytes"])
            tcp = pkt[TCP]
            payload = tcp.payload
            if isinstance(payload, NoPayload):
                continue
            assert isinstance(tcp.payload, Raw)
            if isinstance(payload, Padding):
                continue
            payload_bytes = payload.original
            if self.RESPONSE_START.match(payload_bytes) is not None:
                status_line = payload_bytes.split(b"\r\n", 1)[0]
                status_line = status_line.decode("ascii")
                print(f"\x1B[36m{pkt} / {status_line}\x1B[0m")
                continue
            m = self.REQUEST_START.match(payload_bytes)
            if m is not None:
                request_line = m.group(0)[:-2]
                request_line = request_line.decode("ascii")
                print(f"\x1B[32m{pkt} / {request_line}\x1B[0m")
                continue
            if b"commands.json" in payload_bytes:
                print(f"\x1B[31m{pkt}\x1B[0m")
                continue
            if payload_bytes == b"22":
                continue
            if b"\r\nUser-Agent: Debian APT-HTTP/" in payload_bytes:
                continue
            if self.MD5_HASH.search(payload_bytes) is not None:
                continue

            v, c = np.unique(bytearray(payload_bytes), return_counts=True)
            H = entropy(c, base=min(len(payload_bytes), 256))
            if H > 0.9:
                continue

            if b"/Packages.xz" in payload_bytes:
                continue
            if b" Contents-arm64\n " in payload_bytes:
                continue
            if b" universe/dep11/" in payload_bytes:
                continue
            if b"/source/Sources.gz\n " in payload_bytes:
                continue
            if b" main/dep11/" in payload_bytes:
                continue
            if b" multiverse/dep11/" in payload_bytes:
                continue

            if str(pkt).startswith("Ether / IP / TCP 34.104.35.123:http > "):
                continue

            CUTOFF = 0.67
            print(key)
            if H < CUTOFF:
                print(meta)
            print(pkt)
            print(payload_bytes)
            print(H)

            if H < CUTOFF:
                break

    @classmethod
    def main(cls):
        with cls() as r:
            r.report()


main = Reporter.main
