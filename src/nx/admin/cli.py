import time

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
        now = time.mktime(time.localtime())
        for worker, seen in sorted(heartbeats.items()):
            delta = int(now - float(seen))
            seen = self._strftime(seen)
            print(f"  {worker:7}: {delta:2} seconds ago : {seen}")
        print()

    def _report_machines(self):
        keys = list(self.scan_iter("mac_*"))
        if not keys:
            return
        pipeline = self.pipeline()
        for key in keys:
            pipeline.hgetall(key)
        machines = zip(keys, pipeline.execute())
        for _, key, machine in sorted(
                (float(machine["last_seen"]), key, machine)
                for key, machine in machines
        ):
            print(f"{key}:")
            for field, value in sorted(machine.items()):
                # Clean up old-style last_DHCP* logs
                # XXX remove once DB clears of them
                if (field.startswith("last_DHCP")
                        and not field.endswith("_seen")):
                    if "\n" in value:
                        value = repr(value)
                    if len(value) > 80:
                        value = value[:77] + "..."
                print(f"  {field:26}: {value}")
            print()

    @classmethod
    def _strftime(cls, timestamp, fmt="%Y-%m-%d %H:%M:%S"):
        secs, frac = timestamp, None
        if isinstance(secs, str):
            secs, frac = timestamp.split(".", 1)
        secs = float(secs)
        result = time.strftime(fmt, time.localtime(secs))
        if frac is not None:
            result = f"{result}.{frac:7}"
        return result

    @classmethod
    def main(cls):
        with cls(decode_responses=True) as r:
            r.report()


main = Reporter.main
