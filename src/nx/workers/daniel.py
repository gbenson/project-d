import json

from scapy.all import DHCP, DHCPTypes, Ether

from ..common import PacketSnifferWorker

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

    @property
    def message_type_name(self):
        name = DHCPTypes.get(self.message_type, None)
        if name is None:
            name = f"_op{self.message_type}"
        else:
            name = "".join(name.split("_")).upper()
        return f"DHCP{name}"

    def _load(self, options):
        for item in options:
            if not isinstance(item, str):
                self._load_item(*item)
            elif item not in ("pad", "end"):
                self._unknown_options.append(item)
        self._raw_options = options

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

    def as_json(self):
        return json.dumps(self.as_list(), sort_keys=True)

    def as_list(self):
        result = list(map(self._sanitize_item, self._raw_options))
        while result[-1] == "pad":
            result.pop()
        if result[-1] == "end":
            result.pop()
        return result

    @classmethod
    def _sanitize_item(cls, item):
        """Try and make item JSON serializable."""
        if isinstance(item, (list, tuple)):
            return tuple(map(cls._sanitize_item, item))

        if isinstance(item, bytes):
            try:
                return item.decode("utf-8")
            except UnicodeDecodeError:
                return tuple(map(int, item))

        return item


class DHCPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Daniel"
    WANTED_PACKETS = "udp and (port 67 or port 68)"

    def process_packet(self, packet):
        ether_packet = packet.getlayer(Ether)
        macaddr = ether_packet.src
        options = DHCPOptions(packet[DHCP].options)
        typename = options.message_type_name
        recv_time = packet.time

        mac_key = f"mac_{macaddr}"
        common_fields = {
            "last_seen": recv_time,
            "seen_by": "daniel",
        }

        mac_fields = common_fields.copy()
        mac_fields.update({
            f"last_{typename}_seen": recv_time,
            f"last_{typename}_options": options.as_json(),
        })

        pipeline = self.db.pipeline()

        if options.message_type in (1, 3):  # DISCOVER, REQUEST
            if options.hostname is not None:
                mac_fields["device_name"] = options.hostname
            if options.vendor_class_id is not None:
                mac_fields["vendor_class_id"] = options.vendor_class_id
            if options.requested_addr is not None:
                mac_fields["requested_ipv4"] = options.requested_addr
                mac_fields["requested_ipv4_at"] = recv_time

            pipeline.hset(mac_key, mapping=mac_fields)
            pipeline.hsetnx(mac_key, "first_seen", recv_time)

        elif options.message_type == 5:  # ACK (server->client)
            ipv4addr = options.server_id
            ipv4_key = f"ipv4_{ipv4addr}"

            # server
            pipeline.hset(mac_key, "ipv4", ipv4addr, mapping=mac_fields)
            pipeline.hsetnx(mac_key, "first_seen", recv_time)

            pipeline.hset(ipv4_key, "mac", macaddr, mapping=common_fields)

            # client -- need to look up the ipv4 it just requested!
            client_macaddr = ether_packet.dst
            client_mac_key = f"mac_{client_macaddr}"
            client_request = self.db.hmget(
                client_mac_key,
                "requested_ipv4",
                "requested_ipv4_at"
            )
            if None not in client_request:
                client_ipv4addr, request_time = client_request
                if abs(recv_time - request_time) < 2:
                    pipeline.hset(
                        client_mac_key,
                        "ipv4",
                        client_ipv4addr,
                        mapping=common_fields,
                    )
                    # don't need first seen, we seen it for request

                    client_ipv4_key = f"ipv4_{client_ipv4addr}"
                    pipeline.hset(
                        client_ipv4_key,
                        "mac",
                        client_macaddr,
                        mapping=common_fields,
                    )

        elif options.message_type == 6:  # NAK (server->client)
            # nothing to see here (other than, macXXX is online)
            pipeline.hset(mac_key, mapping=mac_fields)
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


main = DHCPMonitorWorker.main
