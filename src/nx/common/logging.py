import logging
import os


def init_logging():
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL") or os.getenv("LL", "INFO"),
        style="{",
        format="{levelname}: [{name}]: {message}",
    )
