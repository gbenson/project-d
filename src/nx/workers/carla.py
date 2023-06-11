from scapy.all import ARP
from scapy.arch.linux import IFF_NOARP

from ..common import PacketSnifferWorker


class ARPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Carla"
    WANTED_PACKETS = "arp"

    def process_packet(
            self,
            packet,
            pipeline,
            macaddr,
            mac_key,
            common_fields,
            **kwargs
    ):
        if packet[ARP].op not in (1, 2):  # who-has, is-at
            return

        ipv4addr = packet[ARP].psrc
        if ipv4addr == "0.0.0.0":
            return

        pipeline.hset(mac_key, "ipv4", ipv4addr)

        ipv4_key = f"ipv4_{ipv4addr}"
        pipeline.hset(ipv4_key, "mac", macaddr, mapping=common_fields)

    # Trying this on something with IFF_NOARP gets you the following:
    # ERROR: Cannot set filter: Failed to compile filter expression arp (-1)
    # ERROR: [scapy.runtime]: Cannot set filter: Failed to compile filter \
    # expression arp (-1)
    @property
    def interfaces(self):
        return (dev
                for dev in super().interfaces
                if not dev.flags & IFF_NOARP)


main = ARPMonitorWorker.main
