import logging
import os


def init_worker():
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL") or os.getenv("LL", "INFO"),
        style="{",
        format="{levelname}: [{name}]: {message}",
    )
