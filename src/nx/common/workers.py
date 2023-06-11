import hashlib
import logging

from abc import ABC, abstractmethod

from scapy.all import Ether, IFACES, sniff
from scapy.arch.linux import IFF_LOOPBACK

from .logging import init_logging
from ..services import Redis

log = logging.getLogger(__name__)


class Worker(ABC):
    @property
    @abstractmethod
    def WORKER_NAME(self):
        raise NotImplementedError

    @abstractmethod
    def run(self):
        log.info(f"Hi, I'm {self.WORKER_NAME}")

    @classmethod
    def main(cls):
        init_logging()
        cls().run()


class PacketSnifferWorker(Worker):
    def __init__(self, db=None):
        if db is None:
            db = Redis()
        self.db = db

        self._worker_name = self.WORKER_NAME.lower()

    @property
    def interfaces(self):
        """An iterable of network interfaces to operate on."""
        return (dev
                for dev in IFACES.values()
                if (dev.is_valid()
                    and not dev.flags & IFF_LOOPBACK))

    @property
    @abstractmethod
    def WANTED_PACKETS(self):
        """The BPF filter to apply."""
        raise NotImplementedError

    @abstractmethod
    def process_packet(self, packet):
        """Function to apply to each packet. If something is returned,
        it is displayed."""
        raise NotImplementedError

    def run(self):
        super().run()

        filter = self.WANTED_PACKETS
        log.info(f"monitoring packets matching: {filter}")

        interfaces = [dev.name for dev in self.interfaces]
        log.info(f"listening on: {', '.join(sorted(interfaces))}")

        return sniff(
            prn=self._wrapped_process_packet,
            filter=filter,
            store=False,
            iface=interfaces)

    def _wrapped_process_packet(self, packet):
        try:
            return self._process_packet(packet)
        except:  # noqa: E722
            log.error("packet processing failed:", exc_info=True)

    def _process_packet(self, packet):
        macaddr = packet[Ether].src.lower()

        common_fields = {
            "last_seen": packet.time,
            "last_seen_by": self._worker_name,
            f"last_seen_by_{self._worker_name}": packet.time,
        }

        # Log the raw packet.
        packet_hash = hashlib.blake2s(packet.original).hexdigest()
        packet_key = f"pkt_{packet_hash}"

        packet_fields = common_fields.copy()
        packet_fields.update({
            "raw_bytes": packet.original,
            "last_seen_from": macaddr,
        })

        pipeline = self.db.pipeline()

        pipeline.hset(packet_key, mapping=packet_fields)
        pipeline.hdel(packet_key, "seen_by")  # XXX temp cleanup code
        pipeline.hsetnx(packet_key, "first_seen", packet.time)
        pipeline.hincrby(packet_key, "num_sightings", 1)

        # Log the sighting.
        mac_key = f"mac_{macaddr}"

        pipeline.hset(mac_key, mapping=common_fields)
        pipeline.hdel(mac_key, "seen_by")  # XXX temp cleanup code
        pipeline.hsetnx(mac_key, "first_seen", packet.time)

        pipeline.hset(f"macpkts_{macaddr}", packet_hash, packet.time)

        # Hand over to worker-specific code.
        try:
            return self.process_packet(
                packet=packet,
                pipeline=pipeline,
                common_fields=common_fields,
                macaddr=macaddr,
                mac_key=mac_key,
                packet_hash=packet_hash,
                packet_key=packet_key,
            )

        finally:
            pipeline.hset("heartbeats", self._worker_name, packet.time)
            pipeline.execute()
