import base64
import hashlib
import hmac
import logging
import secrets
import traceback

from ..common.workers import RedisClientWorker

log = logging.getLogger(__name__)


class RedisC2Worker(RedisClientWorker):
    WORKER_NAME = "Steve"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        secret = self.load_secret("hmac.key")
        if not isinstance(secret, bytes):
            secret = secret.encode("utf-8")
        self.hmac = hmac.new(secret, digestmod=hashlib.blake2s)

        self._reset_challenge()

        self.pub_chan = f"recv-from:{self.name}"
        self.sub_chan = f"send-to:{self.name}"

        self.greet_me = f"hello {self.name}".encode("utf-8")

    def _reset_challenge(self):
        self.challenge = secrets.token_urlsafe()

    def run(self):
        super().run()
        with self.db.pubsub() as p:
            p.subscribe(self.sub_chan)
            log.info(f"listening on: {self.sub_chan!r}")
            log.info(f"publishing to: {self.pub_chan!r}")
            self.main_loop(p)

    def main_loop(self, p):
        for msg in p.listen():
            self.checkpoint_worker()
            if msg is None:
                continue
            if msg["type"] != "message":
                continue

            request = msg["data"]
            log.info(f"cmd: {request!r}")

            if request == self.greet_me:
                response = self.challenge
            else:
                response = self._handle_request(request)
                response = f"{self.challenge}:{response}"
            response = response.encode("utf-8")

            log.info(f"out: {response!r}")
            self.db.publish(self.pub_chan, response)

    def _handle_request(self, request):
        try:
            return self.handle_request(request)
        except Exception:
            return "".join(traceback.format_exc())

    def handle_request(self, request):
        recv_sig, request = request.split(b":", 1)
        hash = self.hmac.copy()
        try:
            hash.update(self.challenge.encode("ascii"))
        finally:
            self._reset_challenge()
        hash.update(request)
        # Line below mimics secrets.token_urlsafe()
        good_sig = base64.urlsafe_b64encode(hash.digest()).rstrip(b"=")
        if not hmac.compare_digest(recv_sig, good_sig):
            raise ValueError("bad signature")
        del recv_sig, good_sig, hash
        return str(eval(request.decode("utf-8")))


main = RedisC2Worker.main
