from redis import (
    Connection as _Connection,
    ConnectionPool,
    Redis as _Redis,
)

from ..common.exceptions import (
    ChecksNotImplementedError,
    SecurityError,
)


class Connection(_Connection):
    def __init__(self, **kwargs):
        self._preflight_host(kwargs)
        super().__init__(**kwargs)

    @classmethod
    def _preflight_host(cls, kwargs):
        """Ensure we're connecting to localhost on IPv4.
        """
        host = kwargs.pop("host", "localhost")
        if host == "localhost":
            host = "127.0.0.1"  # avoid resolver
        kwargs["host"] = str(host)

    def _connect(self):
        """Create a TCP socket connection.
        """
        if self.host != "127.0.0.1":
            raise ChecksNotImplementedError
        server_pid = pidof_localhost_server(self.port)
        raise ChecksNotImplementedError
        return super()._connect()


class Redis(_Redis):
    def __init__(self, **kwargs):
        super().__init__(
            connection_pool=ConnectionPool(
                connection_class=Connection,
                **kwargs,
            ),
            **kwargs,
        )
        if self.connection_pool.connection_class is not Connection:
            raise SecurityError
