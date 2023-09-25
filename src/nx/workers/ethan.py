from ..roles.http_sniffer import HTTPSnifferWorker


class HTTPMonitorWorker(HTTPSnifferWorker):
    WORKER_NAME = "Ethan"
    TARGET_SERVICE = "http"


main = HTTPMonitorWorker.main
