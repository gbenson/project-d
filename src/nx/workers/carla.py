import logging

from scapy.all import ARP, IFACES, sniff
from scapy.arch.linux import IFF_NOARP

from ..common import init_worker
from ..services import Redis

log = logging.getLogger(__name__)


class ARPMonitorCallback:
    def __init__(self, db=None):
        if db is None:
            db = Redis()
        self.db = db

    def __call__(self, packet):
        if ARP not in packet:
            return
        if packet[ARP].op not in (1, 2):  # who-has, is-at
            return

        # Get everything ready to store.
        macaddr = packet[ARP].hwsrc.lower()
        ipv4addr = packet[ARP].psrc
        recv_time = packet.time
        common = {
            "last_seen": recv_time,
            "seen_by": "carla",
        }

        # Pipeline everything into the database.
        pipeline = self.db.pipeline()

        mac_key = f"mac_{macaddr}"
        pipeline.hset(mac_key, "ipv4", ipv4addr, mapping=common)
        pipeline.hsetnx(mac_key, "first_seen", recv_time)

        ipv4_key = f"ipv4_{ipv4addr}"
        pipeline.hset(ipv4_key, "mac", macaddr, mapping=common)

        pipeline.execute()


def main():
    # rm .venv/bin/python3
    # cp -a /usr/bin/python3.10 .venv/bin/python3
    # sudo setcap cap_net_raw=eip .venv/bin/python3
    init_worker()
    log.info("Hi, I'm Carla")
    interfaces = [name
                  for name, iface in IFACES.items()
                  if (name != "lo"
                      and iface.is_valid()
                      and not iface.flags & IFF_NOARP)]
    # Trying this on something with IFF_NOARP gets you the following:
    # ERROR: Cannot set filter: Failed to compile filter expression arp (-1)
    # ERROR: [scapy.runtime]: Cannot set filter: Failed to compile filter \
    # expression arp (-1)
    sniff(
        prn=ARPMonitorCallback(),
        filter="arp",
        store=False,
        iface=interfaces,
    )
