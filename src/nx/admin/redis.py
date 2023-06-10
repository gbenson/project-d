import os
import warnings

from contextlib import closing
from dataclasses import dataclass
from select import select
from socketserver import ThreadingTCPServer, BaseRequestHandler
from threading import Thread

from paramiko import SSHConfig, SSHClient
from redis import (
    ConnectionPool as _ConnectionPool,
    Redis as _Redis,
)


class Redis(_Redis):
    def __init__(self, single_connection_client=False, **kwargs):
        if single_connection_client:
            warnings.warn("ignoring single_connection_client")
        super().__init__(**kwargs)

        if self.connection_pool.__class__ is not _ConnectionPool:
            raise TypeError

        self.connection_pool._ssh_client = None
        self.connection_pool._ssh_tunnel = None
        self.connection_pool.__class__ = ConnectionPool

    def close(self):
        super().close()
        if not hasattr(self, "connection_pool"):
            return
        if not hasattr(self.connection_pool, "close"):
            return
        self.connection_pool.close()


class ConnectionPool(_ConnectionPool):
    def __del__(self):
        self.close()

    def reset(self):
        self._ssh_client = None
        self._ssh_tunnel = None
        return super().reset()

    def make_connection(self):
        if self._ssh_tunnel is None:
            self.open_ssh_tunnel()
        return super().make_connection()

    def close(self):
        ssh_tunnel = getattr(self, "_ssh_tunnel", None)
        if ssh_tunnel is not None:
            self.close_ssh_tunnel()

        ssh_client = getattr(self, "_ssh_client", None)
        if ssh_client is not None:
            self.close_ssh_connection()

    def open_ssh_connection(self):
        ssh_config_filename = os.path.expanduser("~/.ssh/config")
        ssh_config = SSHConfig.from_path(ssh_config_filename)
        host_config = ssh_config.lookup("slice")
        remote_hostname = host_config["hostname"]

        ssh = self._ssh_client = SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(hostname=remote_hostname)

    def close_ssh_connection(self):
        self._ssh_client.close()
        self._ssh_client = None

    def open_ssh_tunnel(self):
        host = self.connection_kwargs["host"]
        port = self.connection_kwargs["port"]
        remote_addr = host, port

        if self._ssh_client is None:
            self.open_ssh_connection()

        self._ssh_tunnel = TunnelThread(self._ssh_client, remote_addr)
        self._ssh_tunnel.start()

        host, port = self._ssh_tunnel.local_addr
        self.connection_kwargs["host"] = host
        self.connection_kwargs["port"] = port

    def close_ssh_tunnel(self):
        self._ssh_tunnel.stop()
        self._ssh_tunnel = None


class TunnelThread(Thread):
    def __init__(self, ssh, remote_addr, *args, **kwargs):
        remote_addr, local_addr = self.__futz_addr(remote_addr)
        self.server = ThreadingTCPServer(
            local_addr,
            RequestHandlerFactory(ssh, remote_addr),
        )
        super().__init__(target=self.__main, *args, **kwargs)

    @property
    def local_addr(self):
        return self.server.server_address

    def __futz_addr(self, remote_addr):
        host, port = remote_addr
        localhost = "127.0.0.1"
        if host == "localhost":  # avoid resolver
            host = localhost
        return (host, port), (localhost, 0)

    def __main(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server = None
        self.join()


@dataclass
class RequestHandlerFactory:
    ssh: SSHClient
    remote_addr: tuple[str, int]

    def __call__(self, *args, **kwargs):
        return RequestHandler(
            self.open_channel,
            *args,
            **kwargs,
        )

    def open_channel(self, local_addr):
        return self.ssh.get_transport().open_channel(
            "direct-tcpip",
            self.remote_addr,
            local_addr,
        )


class RequestHandler(BaseRequestHandler):
    def __init__(self, channel_opener, *args, **kwargs):
        self.__open_channel = channel_opener
        super().__init__(*args, **kwargs)

    def handle(self):
        with closing(self.request):
            local_addr = self.request.getpeername()
            with closing(self.__open_channel(local_addr)) as channel:
                while True:
                    r, w, x = select([self.request, channel], [], [])
                    if self.request in r:
                        data = self.request.recv(1024)
                        if len(data) == 0:
                            break
                        channel.send(data)
                    if channel in r:
                        data = channel.recv(1024)
                        if len(data) == 0:
                            break
                        self.request.send(data)
