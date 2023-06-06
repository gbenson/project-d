import logging

from scapy.all import DHCP, Ether, IFACES, sniff

from ..common import init_worker
from ..services import Redis

log = logging.getLogger(__name__)


class DHCPMonitorCallback:
    def __init__(self, db=None):
        if db is None:
            db = Redis()
        self.db = db

    def __call__(self, packet):
        macaddr = packet.getlayer(Ether).src  # Requester MAC
        dhcp_options = packet[DHCP].options

        id = self.db.incr("next_raw_dhcp_id")
        self.db.hset(f"raw_dhcp:{id}",
                     mapping={
                         "mac": repr(macaddr),
                         "time": packet.time,
                         "options": repr(dhcp_options)})
        return f"{macaddr!r}: {dhcp_options!r}"


def main():
    init_worker()
    log.info("Hi, I'm Daniel")
    interfaces = [name
                  for name, iface in IFACES.items()
                  if name != "lo" and iface.is_valid()]
    sniff(
        prn=DHCPMonitorCallback(),
        filter="udp and (port 67 or port 68)",
        store=False,
        iface=interfaces,
    )
