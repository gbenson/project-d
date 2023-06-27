from scapy.all import DHCP, DHCPTypes, Ether

from ..common.packet_sniffer import PacketSnifferWorker

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


class DHCPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Daniel"
    WANTED_PACKETS = "udp and (port 67 or port 68)"

    def process_packet(
            self,
            packet,
            pipeline,
            macaddr,
            mac_key,
            packet_hash,
            common_fields,
            **kwargs
    ):
        options = DHCPOptions(packet[DHCP].options)
        typename = options.message_type_name

        pipeline.hset(mac_key, mapping={
            f"last_{typename}": packet_hash,
            f"last_{typename}_seen": packet.time,
        })

        if options.message_type in (1, 3):  # DISCOVER, REQUEST
            mac_fields = {}
            delete_fields = None  # XXX remove once cycled

            if options.hostname is not None:
                mac_fields["dhcp_device_name"] = options.hostname
            if options.vendor_class_id is not None:
                mac_fields["dhcp_vendor_class_id"] = options.vendor_class_id
            if options.requested_addr is not None:
                mac_fields["requested_ipv4"] = options.requested_addr
                mac_fields["requested_ipv4_at"] = packet.time

            if mac_fields:
                pipeline.hset(mac_key, mapping=mac_fields)

                delete_fields = [
                    field[5:]
                    for field in mac_fields
                    if field.startswith("dhcp_")
                ]
            if delete_fields:
                pipeline.hdel(mac_key, *delete_fields)

        elif options.message_type == 5:  # ACK (server->client)
            ipv4addr = options.server_id
            ipv4_key = f"ipv4_{ipv4addr}"

            # server
            pipeline.hset(mac_key, "ipv4", ipv4addr)
            pipeline.hset(ipv4_key, "mac", macaddr, mapping=common_fields)
            pipeline.sadd("ipv4s", ipv4addr)

            # client -- need to look up the ipv4 it just requested!
            client_macaddr = packet[Ether].dst
            client_mac_key = f"mac_{client_macaddr}"
            client_request = self.db.hmget(
                client_mac_key,
                "requested_ipv4",
                "requested_ipv4_at"
            )
            if None not in client_request:
                client_ipv4addr, request_time = (
                    (field.decode("ascii")
                     if isinstance(field, bytes)
                     else field)
                    for field in client_request)
                request_time = float(request_time)
                if abs(packet.time - request_time) < 2:
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
                    pipeline.sadd("ipv4s", client_ipv4addr)


main = DHCPMonitorWorker.main
