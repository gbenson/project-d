from ..common import PacketSnifferWorker


class DHCPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Ethan"
    WANTED_PACKETS = "port 80"

    def process_packet(
            self,
            packet,
            pipeline,
            macaddr,
            mac_key,
            common_fields,
            **kwargs
    ):
        pass


main = DHCPMonitorWorker.main
