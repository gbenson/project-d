import math
import os

from collections import Counter
from stat import S_IMODE

from ..exceptions import (
    ChecksNotImplementedError,
    SecurityError,
)


def audited_open(filename, *args, **kwargs):
    """Audit a secrets-containing file before reading from it."""
    if filename != os.path.realpath(filename):
        raise SecurityError
    result = open(filename, *args, **kwargs)
    result_fd = result.fileno()
    if filename != os.readlink(f"/proc/{os.getpid()}/fd/{result_fd}"):
        raise SecurityError
    if others_can_access(os.fstat(result_fd)):
        raise SecurityError
    if others_can_access(os.stat(os.path.dirname(filename))):
        raise SecurityError
    return result


def others_can_access(stat_result):
    mode = S_IMODE(stat_result.st_mode)
    if mode & 0o007:
        return True
    if mode & 0o070:
        raise ChecksNotImplementedError
    return False


def is_valid_secret(secret):
    if not secret:
        return False
    if shannon_entropy_estimate(secret) < 80:
        raise SecurityError
    return True


def shannon_entropy_estimate(secret, encoding="utf-8"):
    """Estimate the Shannon entropy of a secret, in bits."""
    if not isinstance(secret, bytes):
        secret = secret.encode(encoding)
    histogram = Counter(secret).values()
    return -sum(
        p_i * math.log(p_i, 2)
        for p_i in (
                n_i / len(secret)
                for n_i in histogram
        )
    ) * len(secret)
