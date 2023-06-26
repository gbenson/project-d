import logging
import struct

from abc import ABC, abstractmethod
from base64 import b16decode
from ipaddress import ip_address

from ..common.exceptions import (
    ChecksNotImplementedError,
    SecurityError,
)

log = logging.getLogger(__name__)


class ServiceAuditor(ABC):
    @abstractmethod
    def audit(self):
        raise ChecksNotImplementedError

    @classmethod
    def audit_service(cls, server_address):
        """Audit a socket-based service running on localhost before
        interacting with it.
        """
        cls(server_address)._audit()

    def __init__(self, server_address):
        self.host, self.port = server_address
        self.uids = set()
        self.inodes = []

    @property
    def uid(self):
        uids = list(self.uids)
        if len(uids) != 1:
            raise ChecksNotImplementedError
        return uids[0]

    def _audit(self):
        log.info(f"auditing service listening on port {self.port}")

        if self.host != "127.0.0.1":
            raise ChecksNotImplementedError

        if self.port not in range(1, 65535):
            raise SecurityError

        self._audit_sockets()

        self.audit()

    def _audit_sockets(self):
        """Check that the nothing is listening on this server's port
        that isn't bound to localhost.  We check TCP and UDP, IPv4
        and IPv6.  We don't have permission to search /proc/NNN/fd/
        to map socket inode numbers to PIDs, but we can get the UID
        of the socket's owner and possibly locate the server process
        that way.
        """
        port_suffix = f":{self.port:04X}"
        for pnf in _PROC_NET_FILES:
            expect_local_addr = f"{pnf.localhost}{port_suffix}"
            for line in open(pnf.filename).readlines():
                (_entry_number,
                 local_addr,
                 remote_addr,
                 _connection_state,
                 _queue,
                 _timer,
                 _retransmit,
                 uid,
                 _timeout,
                 inode,
                 _rest) = line.lstrip().split(maxsplit=10)

                if not local_addr.endswith(port_suffix):
                    continue

                uid, inode = map(int, (uid, inode))
                host, port = pnf.unpack_addr(local_addr)
                log.info(f"socket inode {inode} (owner uid "
                         f"{uid}) is bound to {host}:{port}")

                if not local_addr == expect_local_addr:
                    raise SecurityError(f"{pnf.filename}: {line!r}")

                if remote_addr.strip("0") != ":":
                    continue

                self.uids.add(uid)
                self.inodes.append(inode)


class _ProcNetFile:
    file_suffix = ""

    def __init__(self, protocol):
        self.protocol = protocol

    def __str__(self):
        return self.filename

    @property
    def filename(self):
        return f"/proc/net/{self.protocol}{self.file_suffix}"

    def unpack_addr(self, addr):
        host, port = addr.split(":")
        port = int(port, 16)

        host = b16decode(host)  # "0100007F" => b"\x01\x00\x00\x7f"
        format = f"{len(host) // 4}L"
        host = struct.unpack(f"={format}", host)  # (2130706433,)
        host = struct.pack(f"!{format}", *host)  # b"\x7f\x00\x00\x01"
        host = ip_address(host)  # IPv4Address('127.0.0.1')

        return host, port


class _PNF_IPv4(_ProcNetFile):
    localhost = "0100007F"


class _PNF_IPv6(_ProcNetFile):
    localhost = "00000000000000000000000001000000"
    file_suffix = "6"


_PROC_NET_FILES = sum(
    (tuple(family(protocol) for protocol in ("tcp", "udp"))
     for family in (_PNF_IPv4, _PNF_IPv6)), ())
