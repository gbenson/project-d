from scapy.all import ARP
from scapy.arch.linux import IFF_NOARP

from ..common import PacketSnifferWorker


class ARPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Carla"
    WANTED_PACKETS = "arp"

    def process_packet(self, packet):
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
        psrc_is_valid = ipv4addr != "0.0.0.0"

        mac_key = f"mac_{macaddr}"
        mac_mapping = common.copy()
        if psrc_is_valid:
            mac_mapping["ipv4"] = ipv4addr
        pipeline.hset(mac_key, mapping=mac_mapping)

        pipeline.hsetnx(mac_key, "first_seen", recv_time)

        if psrc_is_valid:
            ipv4_key = f"ipv4_{ipv4addr}"
            pipeline.hset(ipv4_key, "mac", macaddr, mapping=common)

        pipeline.hset("heartbeats", "carla", recv_time)
        pipeline.execute()

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
