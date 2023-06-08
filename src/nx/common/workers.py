import logging

from abc import ABC, abstractmethod

from scapy.all import IFACES, sniff
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
    def process_packet(self):
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
            prn=self.process_packet,
            filter=filter,
            store=False,
            iface=interfaces)
