import copy
import os
import socket

from errno import EAGAIN
from socket import (
    AF_INET,
    AF_INET6,
    IPPROTO_TCP,
    SHUT_RDWR,
    SOCK_STREAM,
    TCP_NODELAY,
)

import pytest

from redis import Connection, ConnectionPool, Redis
from redis.connection import SocketBuffer


class MockSocket:
    _socket_socket = socket.socket
    _debug = False  # Set to True to see what a real server does

    def __init__(self, family, type, proto):
        assert family in (AF_INET, AF_INET6)
        assert type == SOCK_STREAM
        assert proto == IPPROTO_TCP
        self._timeout = None  # Blocking
        self._data_to_recv = []
        if self._debug:
            self._socket = self._socket_socket(family, type, proto)

    def _raise(self, errno):
        raise socket.error(errno, os.strerror(errno))

    def _wrap(self, attr, *args, **kwargs):
        call = f"socket.{attr}(*{args}, **{kwargs})"
        try:
            result = getattr(self._socket, attr)(*args, **kwargs)
            print(f"{call} returned: {result}")
            return result
        except Exception as e:
            print(f"{call} raised: {type(e).__name__}: {e}")
            raise

    def setsockopt(self, level, optname, value):
        assert level == IPPROTO_TCP
        assert optname == TCP_NODELAY
        assert value == 1
        if self._debug:
            return self._wrap("setsockopt", level, optname, value)

    def settimeout(self, timeout):
        self._timeout = timeout
        if self._debug:
            return self._wrap("settimeout", timeout)

    def connect(self, address):
        assert address in (("127.0.0.1", 6379), ("::1", 6379, 0, 0))
        if self._debug:
            return self._wrap("connect", address)
        self._data_to_recv = []

    def recv(self, bufsiz):
        if self._debug:
            return self._wrap("recv", bufsiz)
        if not self._data_to_recv:
            self._raise(EAGAIN)
        return self._data_to_recv.pop(0)

    def shutdown(self, method):
        assert method == SHUT_RDWR
        if self._debug:
            return self._wrap("shutdown", method)

    def close(self):
        if self._debug:
            return self._wrap("close")

    def sendall(self, data):
        if self._debug:
            return self._wrap("sendall", data)


class MockSocketBuffer(SocketBuffer):
    def __init__(self, data):
        super().__init__(None, None, None)
        assert self._buffer.tell() == 0
        self._buffer.write(data)
        self._buffer.seek(0)


class MockConnection(Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._command_log = []

    def __unpack_commands(self, packed_command):
        """Use a clone the response parser to parse the request.
        """
        if isinstance(packed_command, list):
            packed_command = b"".join(packed_command)

        assert self._parser._sock is self._sock
        assert self._parser._buffer._sock is self._sock

        try:
            del self._parser._sock
            del self._parser._buffer._sock

            parser = copy.deepcopy(self._parser)
            parser._buffer = MockSocketBuffer(packed_command)
            while parser._buffer.unread_bytes():
                yield parser.read_response()

        finally:
            self._parser._sock = self._sock
            self._parser._buffer._sock = self._sock

    def send_packed_command(self, packed_command, check_health=True):
        """Log the unpacked the commands, then prime our mock
        socket with an appropriate response to them.
        """
        responses = []
        for command in self.__unpack_commands(packed_command):
            self._command_log.append(command)
            response = self._mock_responses.pop(tuple(command), 0)
            responses.extend(self.__encode_response(response))
        packed_response = b"".join(responses)

        self._sock._data_to_recv.append(packed_response)
        return super().send_packed_command(packed_command, False)

    def __encode_response(self, response):
        if isinstance(response, int):
            yield b":%d\r\n" % response
            return
        yield b"*%d\r\n" % len(response)
        for element in response:
            assert isinstance(element, bytes)
            yield b"$%d\r\n%s\r\n" % (len(element), element)


class MockConnectionPool(ConnectionPool):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mock_responses = {}

    @property
    def mock_connection(self):
        assert self._created_connections == 1
        return self._available_connections[0]

    def push_mock_response(self, command, response):
        if isinstance(command, (str, bytes)):
            command = command.split()

        command[0] = command[0].upper()

        encoder = self.get_encoder()
        self._mock_responses.update({
            tuple(map(encoder.encode, command)):
            tuple(map(encoder.encode, response)),
        })

    def get_connection(self, *args, **kwargs):
        conn = super().get_connection(*args, **kwargs)
        conn._mock_responses = self._mock_responses
        return conn


class MockDatabase(Redis):
    def push_mock_response(self, *args, **kwargs):
        self.connection_pool.push_mock_response(*args, **kwargs)

    @property
    def _raw_command_log(self):
        """Raw command log."""
        return self.connection_pool.mock_connection._command_log

    @property
    def log(self):
        """Cooked command log, for existing testcases.
        """
        result = list(map(self.__cook_cmd, self._raw_command_log))
        result.append("execute")
        return result

    def __cook_cmd(self, command):
        command = list(map(self.__cook_cmd_part, command))
        command[0] = command[0].lower()
        if command[0] in ("hset", "hsetnx"):
            args = dict(self.__pair_items(command[2:]))
            if "raw_bytes" in args:
                args["raw_bytes"] = b">>raw bytes<<"
            command[2:] = [list(sorted(args.items()))]
        elif command[0] == "hincrby":
            command[1:] = [tuple(command[1:])]
        elif command[0] in ("hmget", "sadd"):
            command[2:] = [tuple(command[2:])]
        return command

    def __cook_cmd_part(self, item):
        try:
            item = item.decode(self.get_encoder().encoding)
        except UnicodeDecodeError:
            return item
        for cast in (int, float):
            try:
                return cast(item)
            except ValueError:
                pass
        return item

    def __pair_items(self, pairs):
        while pairs:
            yield tuple(pairs[:2])
            pairs = pairs[2:]


@pytest.fixture
def mockdb(monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(socket, "socket", MockSocket)
        yield MockDatabase(
            connection_pool=MockConnectionPool(
                connection_class=MockConnection,
            ),
        )
