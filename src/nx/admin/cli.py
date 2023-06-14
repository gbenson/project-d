import os
import sys

from datetime import datetime
from numbers import Real

from .redis import Redis


class Reporter(Redis):
    def report(self):
        self._report_machines()
        self._report_heartbeats()

    def _report_heartbeats(self):
        heartbeats = self.hgetall("heartbeats")
        if not heartbeats:
            return
        print("Heartbeats:")
        for worker, seen in sorted(heartbeats.items()):
            ts = self.format_timestamp(seen, justify=True)
            print(f"  {worker:7}: {ts}")
        print()

    def _report_machines(self):
        keys = list(self.scan_iter("mac_*"))
        if not keys:
            return
        pipeline = self.pipeline()
        for key in keys:
            pipeline.hgetall(key)
        machines = zip(keys, pipeline.execute())
        max_linelen = os.get_terminal_size().columns
        for _, key, machine in sorted(
                (float(machine["last_seen"]), key, machine)
                for key, machine in machines
        ):
            print(f"{key}:")
            for field, value in sorted(machine.items()):
                if "\n" in value:
                    value = f"repr: {value!r}"
                line = f"  {field:26}: {value}"
                if len(line) > max_linelen:
                    line = line[:max_linelen - 3] + "..."
                print(line)
            print()

    @classmethod
    def format_timestamp(cls, ts, justify=False):
        if isinstance(ts, bytes):
            ts = ts.decode()
        if isinstance(ts, str):
            ts = float(ts)
        if isinstance(ts, Real):
            ts = datetime.fromtimestamp(ts)
        delta = cls.format_timedelta(datetime.now() - ts)
        if justify:
            delta = f"{delta:>10}"
        return f"{ts:%Y-%m-%d %H:%M:%S} : {delta} ago"

    TIMEDELTA_UNITS = (
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 7),
        ("weeks", 52),  # ish ;)
        ("years", sys.maxsize),
    )

    @classmethod
    def format_timedelta(cls, delta):
        q = int(delta.total_seconds())
        for unit, r in cls.TIMEDELTA_UNITS:
            q, result = divmod(q, r)
            if q:
                continue
            if result == 1:
                unit = unit.rstrip("s")
            return f"{result} {unit}"

    @classmethod
    def main(cls):
        with cls(decode_responses=True) as r:
            r.report()


main = Reporter.main
