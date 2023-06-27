import logging
import os
import sys

from abc import ABC, abstractmethod
from signal import signal, SIGHUP

from ..audit.secrets import audited_open, is_valid_secret
from ..common.logging import init_logging

log = logging.getLogger(__name__)


class Worker(ABC):
    @property
    @abstractmethod
    def WORKER_NAME(self):
        raise NotImplementedError

    def __init__(self):
        self.name = self.WORKER_NAME.lower()

    def load_secret(self, key: str):
        value = self._systemd_secret(key)
        if is_valid_secret(value):
            return value
        value = self._getenv_secret(key)
        if is_valid_secret(value):
            return value
        raise KeyError(key)

    def _getenv_secret(self, key: str):
        key = f"{self.WORKER_NAME}_{key.replace('.', '_')}".upper()
        return os.getenv(key)

    def _systemd_secret(self, key: str):
        credsdir = os.getenv("CREDENTIALS_DIRECTORY")
        if not credsdir:
            return None
        return audited_open(os.path.join(credsdir, key)).read().rstrip()

    @abstractmethod
    def run(self):
        log.info(f"Hi, I'm {self.WORKER_NAME}")
        self._cmd = [sys.executable] + sys.argv
        self._waiting_to_restart = False
        signal(SIGHUP, self._handle_SIGHUP)

    def _handle_SIGHUP(self, signum, _):
        if self._waiting_to_restart:
            log.info("received second SIGHUP, forcing restart now")
            self.checkpoint_worker()
        log.info("received SIGHUP, will restart at next checkpoint")
        self._waiting_to_restart = True

    def checkpoint_worker(self):
        if not self._waiting_to_restart:
            return
        log.info("going down for restart")
        raise RestartWorker

    @classmethod
    def main(cls):
        init_logging()
        worker = cls()
        try:
            worker.run()
        except RestartWorker:
            command = worker._cmd
            log.info("restarting NOW...")
            sys.stdout.flush()
            sys.stderr.flush()
            os.execv(command[0], command)


class RestartWorker(Exception):
    pass
