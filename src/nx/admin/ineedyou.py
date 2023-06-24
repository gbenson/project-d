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
                print(text)

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

            self._send_signed(command)

    def handle_exit(self, args):
        raise SystemExit

    def handle_import(self, args):
        if len(args) != 1:
            return print("usage: import MODULE")
        [mod] = args
        return f"globals().update({{{mod!r}:__import__({mod!r})}})"

    def handle_cd(self, args):
        if len(args) != 1:
            return print("usage: cd DIR")
        self._requires("os")
        return f"os.chdir({args[0]!r})"

    def handle_ls(self, args):
        return self.handle_sh(["ls", "-x"] + args)

    def handle_ll(self, args):
        return self.handle_sh(["ls", "-l"] + args)

    def handle_sh(self, args):
        if len(args) < 1:
            return print("usage: sh COMMAND [ARG...]")
        command = " ".join(args)
        self._requires("subprocess")
        return (f"subprocess.run({command!r},"
                "stdout=subprocess.PIPE,"
                "stderr=subprocess.STDOUT,"
                "shell=True).stdout.decode('utf-8') or None")

    def _handle_user_command(self, command):
        result = command.strip()
        if not result:
            return
        args = result.split()
        func = getattr(self, f"handle_{args[0]}", None)
        if func is not None:
            result = func(args[1:])
        return result

    def _requires(self, *modules):
        for module in modules:
            if self._exec(f"{module!r} in globals()") != "False":
                continue
            self._import(module)

    def _import(self, module):
        result = self._exec(self.handle_import([module]))
        if result is not None:
            print(result)

    def _exec(self, command):
        self._send_signed(command)
        return self._read_response()

    def _send_signed(self, request):
        self._send(self._sign(request.encode("utf-8")))

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
        result = result.decode("utf-8").rstrip()
        if result.startswith("Traceback ("):
            print(result, color=YELLOW)
            return None
        return result

    def _send(self, data):
        assert not self._awaiting_response
        self.db.publish(self.pub_chan, data)
        self._awaiting_response = True


def main():
    RedisC2Client().run()
