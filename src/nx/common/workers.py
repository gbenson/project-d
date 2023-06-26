import hashlib
import logging

from abc import abstractmethod

from scapy.all import ARP, Ether, IFACES, IP, sniff
from scapy.arch.linux import IFF_LOOPBACK

from ..services.redis import Redis
from .worker import Worker

log = logging.getLogger(__name__)

Unset = object()


class RedisClientWorker(Worker):
    def __init__(self, db=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if db is None:
            db = Redis()
        self.db = db


class PacketSnifferWorker(RedisClientWorker):
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
        finally:
            self.checkpoint_worker()

    # XXX refactor tests, then remove this method
    def _process_packet(self, packet):
        return PacketProcessor(self, packet).run()


class PacketProcessor:
    def __init__(self, worker, packet):
        self.worker = worker
        self.packet = packet

        self._issue_categories = []

        self._ether_layer = Unset
        self.packet_hash = None
        self.src_mac = None

    def run(self):
        heartbeat = self.worker.name, self.packet.time
        self.pipeline = self.worker.db.pipeline(transaction=False)
        try:
            try:
                try:
                    self._run()
                finally:
                    for set in self._issue_categories:
                        self.pipeline.sadd(set, self.packet_hash)
            finally:
                self.pipeline.hset("heartbeats", *heartbeat)
        finally:
            self.pipeline.execute()

    def _run(self):
        self.common_fields = {
            "last_seen": self.packet.time,
            "last_seen_by": self.worker.name,
            f"last_seen_by_{self.worker.name}": self.packet.time,
        }

        # Log the raw packet.
        if self.ether_layer is None:
            self.record_issue("first_layer")

        self.packet_hash = self._packet_hash()
        self.packet_key = f"pkt_{self.packet_hash}"

        if self.ether_layer is not None:
            self.src_mac = self.ether_layer.src.lower()
            self.mac_key = f"mac_{self.src_mac}"

        self._record_raw_packet()

        if self.ether_layer is None:
            return

        # Log the device sighting.
        self._record_device_sighting()

        # Hand over to worker-specific code.
        return self.worker.process_packet(
            packet=self.packet,
            pipeline=self.pipeline,
            common_fields=self.common_fields,
            macaddr=self.src_mac,
            mac_key=self.mac_key,
            packet_hash=self.packet_hash,
            packet_key=self.packet_key,
        )

    @property
    def ether_layer(self):
        if self._ether_layer is Unset:
            self._ether_layer = self.packet.getlayer(Ether)
        return self._ether_layer

    def _packet_hash(self):
        return hashlib.blake2s(self._packet_hash_bytes()).hexdigest()

    def _packet_hash_bytes(self):
        packet_bytes = self.packet.original
        if self.ether_layer is None:
            return packet_bytes

        copy_packet = self.ether_layer.__class__(packet_bytes)
        ipv4_layer = copy_packet.getlayer(IP)
        if ipv4_layer is None:
            if ARP not in copy_packet:
                self.record_issue("ether_payload")
            return packet_bytes

        ipv4_layer.id = 0xdead
        ipv4_layer.chksum = 0xbeef

        return bytes(copy_packet)

    def _record_raw_packet(self):
        fields = self.common_fields.copy()
        fields["raw_bytes"] = self.packet.original
        fields["last_sniffed_on"] = self.packet.sniffed_on
        if self.src_mac is not None:
            fields["last_seen_from"] = self.src_mac

        key, pipeline = self.packet_key, self.pipeline

        pipeline.hset(key, mapping=fields)
        pipeline.hsetnx(key, "first_seen", self.packet.time)
        pipeline.hincrby(key, "num_sightings", 1)

    def _record_device_sighting(self):
        pipeline = self.pipeline

        pipeline.sadd("macs", self.src_mac)

        key = self.mac_key
        pipeline.hset(key, mapping=self.common_fields)
        pipeline.hsetnx(key, "first_seen", self.packet.time)

        key = f"macpkts_{self.src_mac}"
        pipeline.hset(key, self.packet_hash, self.packet.time)

    def record_issue(self, category):
        """Note that there was an issue processing this packet."""
        self._issue_categories.append(f"unhandled:pkts:{category}")
