import os
import sys

from collections import defaultdict
from datetime import datetime
from numbers import Real

from manuf import MacParser

from .redis import Redis


class Reporter(Redis):
    def report(self):
        self._report_machines()
        self._report_dns()
        self._report_heartbeats()

    def _report_heartbeats(self):
        w_heartbeats = self.hgetall("heartbeats")
        i_heartbeats = self.hgetall("interfaces")
        if not (w_heartbeats or i_heartbeats):
            return
        print("Heartbeats:")
        for worker, seen in sorted(w_heartbeats.items()):
            ts = self.format_timestamp(seen, justify=True)
            print(f"  {worker:7}: {ts}")
        if w_heartbeats and i_heartbeats:
            print("   :")
        for interface, seen in sorted(i_heartbeats.items()):
            ts = self.format_timestamp(seen, justify=True)
            print(f"  {interface:16}: {ts}")
        print()

    def _report_machines(self):
        keys = [f"mac_{mac}" for mac in self.smembers("macs")]
        if not keys:
            return
        mac_vendor_lookup = MacParser("/usr/share/wireshark/manuf")
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
            vendor = mac_vendor_lookup.get_all(key.split("_", 1)[-1])
            vendor = vendor.manuf_long or vendor.manuf
            if vendor is not None:
                vendor = {
                    "Ce Link Limited": "Amazon Technologies Inc",
                }.get(vendor, vendor)
                print(f"  {'mac_hardware_vendor':26}: {vendor}")
            for field, value in sorted(machine.items()):
                if (field.endswith("_seen")
                        or field.startswith("last_seen_by_")):
                    value = self.format_timestamp(value)
                if field == "first_seen":
                    value = value.rsplit(":", 1)[0].rstrip()
                if "\n" in value:
                    value = f"repr: {value!r}"
                line = f"  {field:26}: {value}"
                if len(line) > max_linelen:
                    line = line[:max_linelen - 3] + "..."
                print(line)
            print()

    def _report_dns(self, limit=20):
        keys = [f"dnsq:{q}" for q in self.smembers("dns_queries")]
        if not keys:
            return
        pipeline = self.pipeline()
        for key in keys:
            pipeline.hget(key, "num_sightings")
        queries = defaultdict(int)
        for question, count in zip(keys, pipeline.execute()):
            question = question.split(":")[1:]
            if question[-2] == "IN":
                if question[-1] == "PTR":
                    continue
                if question[-1] == "SRV":
                    continue  # ...for now...
                # if question[-1] == "HTTPS":
                #    continue  # ...for now (will be in A/AAAA also)
                if question[-1] in {"A", "AAAA", "HTTPS"}:
                    question = question[:-2]
            question = ":".join(question).rstrip(".")
            # for suffix in self.SUFFIXES:
            #    if question.endswith(suffix):
            #        question = f"*{suffix}"
            #        break
            queries[question] += int(count)
        print(f"DNS top {limit}:")
        position, last_count = 0, None
        for count, question in sorted((-c, q) for q, c in queries.items()):
            count = -count
            if count == last_count:
                prefix = "   "
            else:
                position += 1
                if position > limit:
                    break
                prefix = f"{position:>2}:"
                last_count = count
            line = f"{prefix} {count:>4}:  {question}"
            # if "*" in question:
            #    line = f"\x1B[33m{line}\x1B[0m"
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
