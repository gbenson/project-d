import io
import sys

import pytest

from nx.admin.ineedyou import RedisC2Client


def test_sandbox_starts_empty(worker_client):
    """worker.globals starts empty."""
    worker, client = worker_client
    assert not worker.globals


def test_import(worker_client):
    """The `import` local command works."""
    worker, client = worker_client
    client.execute("import sys")
    assert worker.globals == {"sys": sys}


# Fixtures

class MockWorker:
    def __init__(self):
        self.globals = {}
        self.responses = []

    def recv_command(self, channel, request):
        print(f"client:{channel}: {request!r}")
        assert channel == "send-to:steve"
        self.responses.append(self.handle_request(request))

    def send_response(self):
        response = self.responses[-1]
        print(f"steve:send-to:client: {response!r}")
        return [{
            "type": "message",
            "data": response.encode("utf-8"),
        }]

    def handle_request(self, request, challenge="challenge"):
        if request == "hello steve":
            return challenge
        request = request.split(b":", 1)[-1].decode("utf-8")
        return f"{challenge}:{eval(request, self.globals)}"


@pytest.fixture
def worker_client(monkeypatch):
    worker = MockWorker()
    client = RedisC2Client()

    client.db = type("DB", (), {})
    client.db.publish = worker.recv_command
    client.ps = type("PS", (), {})
    client.ps.listen = worker.send_response

    def client_execute(*commands):
        CRLF = "\r\n"
        with monkeypatch.context() as m:
            m.setattr(sys, "stdin", io.StringIO(
                CRLF.join(commands) + CRLF,
            ))
            client.main_loop()
            worker.globals.pop("__builtins__", None)

    client.execute = client_execute

    return worker, client
