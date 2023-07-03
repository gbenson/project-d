import re

from .redis import Redis


class Maintainer(Redis):
    GOOD_KEY_RE = re.compile(
        r"""^((dns_queries
              |heartbeats
              |interfaces
              |ipv4s
              |macs
             )$
             |(ipv4
              |mac
              |macpkts
              |pkt
             )_
             |(dnsq
              |dnsq_pkts
             ):
        )""", re.X)

    JUNK_KEY_RE = re.compile(
        r"""^((http_connections
              |httpconn:last_seen
              |next_raw_dhcp_id
             )$
             |(httpconn:pkts
             )_
             |(raw_dhcp
             ):
        )""", re.X)

    def delete_junk_keys(self):
        pipeline = self.pipeline(transaction=False)
        for key in self.scan_iter("*"):
            if self.GOOD_KEY_RE.match(key):
                continue
            if self.JUNK_KEY_RE.match(key):
                pipeline.delete(key)
                continue
            raise ValueError(key)
        pipeline.execute()

    def delete_junk_hash_keys(self):
        pipeline = self.pipeline(transaction=False)
        for key in [f"mac_{mac}" for mac in self.smembers("macs")]:
            pipeline.hdel(key, "last_seen_by_zack")
        pipeline.execute()

    @classmethod
    def main(cls):
        with cls(decode_responses=True) as r:
            r.delete_junk_keys()
            r.delete_junk_hash_keys()


main = Maintainer.main
