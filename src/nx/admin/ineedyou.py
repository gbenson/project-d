import base64
import hashlib
import hmac
import os
import readline
import traceback

from .redis import Redis
from .term import (
    RED,
    YELLOW,
    print,
)


class RedisC2Client:
    def __init__(self, worker_name="Steve"):
        WORKER_NAME = worker_name.upper()
        self.worker_name = worker_name.lower()

        secret = os.environ[f"{WORKER_NAME}_HMAC_SECRET"]
        if not isinstance(secret, bytes):
            secret = secret.encode("utf-8")
        self.hmac = hmac.new(secret, digestmod=hashlib.blake2s)

        self.pub_chan = f"send-to:{self.worker_name}"
        self.sub_chan = f"recv-from:{self.worker_name}"

        self.histfile = os.path.expanduser("~/.ineedyou_history")
        self.prompt = f"{self.worker_name}> "

        self._awaiting_response = False

    def run(self):
        self.db = Redis()

        self.ps = self.db.pubsub()
        self.ps.subscribe(self.sub_chan)

        try:
            readline.read_history_file(self.histfile)
        except FileNotFoundError:
            pass
        readline.set_history_length(2000)

        try:
            self.main_loop()
        finally:
            readline.write_history_file(self.histfile)

    def main_loop(self):
        self._send(f"hello {self.worker_name}")

        while True:
            text = self._read_response()
            if text is not None:
                kwargs = {}
                if text.endswith("\n"):
                    kwargs["end"] = ""
                if text.startswith("Traceback ("):
                    kwargs["color"] = YELLOW
                print(text, **kwargs)

            try:
                command = input(self.prompt)
            except EOFError:  # Ctrl-D
                print("exit")
                break

            try:
                command = self._handle_user_command(command)
            except Exception:
                print("".join(traceback.format_exc()), color=RED, end="")
                continue

            if not command:
                continue

            self._send(self._sign(command.encode("utf-8")))

    def handle_exit(self, args):
        raise SystemExit

    def handle_import(self, args):
        if len(args) != 1:
            return print("usage: import MODULE")
        [mod] = args
        return f"globals().update({{{mod!r}:__import__({mod!r})}})"

    def _handle_user_command(self, command):
        result = command.strip()
        if not result:
            return
        args = result.split()
        func = getattr(self, f"handle_{args[0]}", None)
        if func is not None:
            result = func(args[1:])
        return result

    def _sign(self, request):
        hash = self.hmac.copy()
        hash.update(self.challenge)
        hash.update(request)
        # Line below mimics secrets.token_urlsafe()
        sig = base64.urlsafe_b64encode(hash.digest()).rstrip(b"=")
        return b":".join((sig, request))

    def _read_response(self):
        if not self._awaiting_response:
            return None
        for msg in self.ps.listen():
            if msg is None:
                continue
            if msg["type"] == "message":
                break

        response = msg["data"].split(b":", 1)
        self._awaiting_response = False
        self.challenge = response[0]
        if len(response) != 2:
            return None
        result = response[1]
        if result == b"None":
            return None
        return result.decode("utf-8")

    def _send(self, data):
        self.db.publish(self.pub_chan, data)
        self._awaiting_response = True


def main():
    RedisC2Client().run()
