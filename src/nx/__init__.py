import sys
import time

if "setuptools" in sys.modules:
    __version__ = f"0.0.{int(time.mktime(time.gmtime()))}"
