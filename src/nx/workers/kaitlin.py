from ipaddress import ip_address

from ..roles.http_sniffer import HTTPSnifferWorker


class HTTPSMonitorWorker(HTTPSnifferWorker):
    WORKER_NAME = "Kaitlin"
    TARGET_SERVICE = "https"

    # Only monitor our own outbound traffic.
    @property
    def interfaces(self):
        return (dev
                for dev in super().interfaces
                if (dev.ip is not None
                    and not ip_address(dev.ip).is_link_local))


main = HTTPSMonitorWorker.main
