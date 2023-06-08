import logging

from scapy.all import DHCP, Ether, IFACES, sniff

from ..common import init_worker
from ..services import Redis

log = logging.getLogger(__name__)

Unknown = object()  # Sentinel


class DHCPOptions:
    def __init__(self, options):
        self.auto_config = None
        self.broadcast_address = None
        self.client_id = None
        self.domain = None
        self.error_message = None
        self.forcerenew_nonce_capable = None
        self.hostname = None
        self.lease_time = None
        self.max_dhcp_size = None
        self.message_type = None
        self.name_server = None
        self.option_145 = None
        self.param_req_list = None
        self.rapid_commit = None
        self.rebinding_time = None
        self.renewal_time = None
        self.requested_addr = None
        self.router = None
        self.server_id = None
        self.subnet_mask = None
        self.vendor_class_id = None

        self._unknown_options = []
        self._repeated_options = []

        self._load(options)
        assert not self._unknown_options  # XXX
        assert not self._repeated_options  # XXX

    def _load(self, options):
        for item in options:
            if not isinstance(item, str):
                self._load_item(*item)
            elif item not in ("pad", "end"):
                self._unknown_options.append(item)

    DECODE = {
        "domain",
        "error_message",
        "hostname",
        "vendor_class_id",
    }
    EXTRAS = {
        80: "rapid_commit",  # RFC4039
        145: "forcerenew_nonce_capable",  # RFC6704
    }

    def _load_item(self, name, *args):
        name = self.EXTRAS.get(name, name)
        if isinstance(name, int):
            name = f"option_{name}"
        attr = str(name).replace("-", "_")
        curr = getattr(self, attr, Unknown)
        if curr is None:
            value = args[0] if len(args) == 1 else args
            if attr in self.DECODE and isinstance(value, bytes):
                try:
                    value = value.decode("ascii")
                except UnicodeDecodeError:
                    pass
            setattr(self, attr, value)
            return
        if curr is Unknown:
            self._unknown_options.append((name, args))
            return
        self._repeated_options.append((name, curr, args))


class DHCPMonitorCallback:
    def __init__(self, db=None):
        if db is None:
            db = Redis()
        self.db = db

    def __call__(self, packet):
        macaddr = packet.getlayer(Ether).src
        options = DHCPOptions(packet[DHCP].options)
        recv_time = packet.time

        mac_key = f"mac_{macaddr}"
        common = {
            "last_seen": recv_time,
            "seen_by": "daniel",
        }

        pipeline = self.db.pipeline()

        if options.message_type in (1, 3):  # DISCOVER, REQUEST
            mac_mapping = common.copy()

            if options.hostname is not None:
                mac_mapping["device_name"] = options.hostname
            if options.vendor_class_id is not None:
                mac_mapping["vendor_class_id"] = options.vendor_class_id
            if options.requested_addr is not None:
                mac_mapping["requested_ipv4"] = options.requested_addr
                mac_mapping["requested_ipv4_at"] = recv_time

            pipeline.hset(mac_key, mapping=mac_mapping)
            pipeline.hsetnx(mac_key, "first_seen", recv_time)

        elif options.message_type == 5:  # ACK (server->client)
            ipv4addr = options.server_id
            ipv4_key = f"ipv4_{ipv4addr}"

            pipeline.hset(mac_key, "ipv4", ipv4addr, mapping=common)
            pipeline.hsetnx(mac_key, "first_seen", recv_time)

            pipeline.hset(ipv4_key, "mac", macaddr, mapping=common)

        elif options.message_type == 6:  # NAK (server->client)
            # nothing to see here (other than, macXXX is online)
            pipeline.hset(mac_key, mapping=common)
            pipeline.hsetnx(mac_key, "first_seen", recv_time)

        else:
            id = self.db.incr("next_raw_dhcp_id")
            pipeline.hset(f"raw_dhcp:{id}",
                          mapping={
                              "mac": repr(macaddr),
                              "time": recv_time,
                              "options": repr(options)})

        pipeline.hset("heartbeats", "daniel", recv_time)
        pipeline.execute()


def main():
    init_worker()
    log.info("Hi, I'm Daniel")
    interfaces = [name
                  for name, iface in IFACES.items()
                  if name != "lo" and iface.is_valid()]
    log.info(f"Listening on {', '.join(interfaces)}")
    sniff(
        prn=DHCPMonitorCallback(),
        filter="udp and (port 67 or port 68)",
        store=False,
        iface=interfaces,
    )
