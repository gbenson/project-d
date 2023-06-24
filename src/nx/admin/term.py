import sys

_print = print

RED, GREEN = (f"\x1B[{cc}m" for cc in range(31, 33))


def print(*args, **kwargs):
    sys.stdout.write(kwargs.pop("color", GREEN))
    _print(*args, **kwargs)
    sys.stdout.write("\x1B[0m")
