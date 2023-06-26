from ..common.packet_sniffer import PacketSnifferWorker


class DHCPMonitorWorker(PacketSnifferWorker):
    WORKER_NAME = "Zack"
    WANTED_PACKETS = "port 53"

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
