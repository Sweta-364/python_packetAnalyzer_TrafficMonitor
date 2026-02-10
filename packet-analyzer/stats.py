import time
import threading
from collections import defaultdict
from typing import Optional


class TrafficStats:

    def __init__(self):
        self._lock = threading.Lock()
        self._total_packets = 0
        self._total_bytes = 0
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._protocol_bytes: dict[str, int] = defaultdict(int)
        self._interval_packets = 0
        self._interval_bytes = 0
        self._start_time = time.monotonic()
        self._last_reset = time.monotonic()

    def record(self, protocol: str, size: int) -> None:
        with self._lock:
            self._total_packets += 1
            self._total_bytes += size
            self._protocol_counts[protocol] += 1
            self._protocol_bytes[protocol] += size
            self._interval_packets += 1
            self._interval_bytes += size

    def snapshot(self) -> dict:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_reset
            if elapsed <= 0:
                elapsed = 1.0
            pps = self._interval_packets / elapsed
            bps = self._interval_bytes / elapsed
            result = {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "packets_per_sec": pps,
                "bytes_per_sec": bps,
                "protocol_counts": dict(self._protocol_counts),
                "protocol_bytes": dict(self._protocol_bytes),
                "uptime": now - self._start_time,
            }
            self._interval_packets = 0
            self._interval_bytes = 0
            self._last_reset = now
            return result


def format_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def format_stats_banner(snap: dict) -> str:
    lines = [
        "",
        "=" * 72,
        f"  TRAFFIC STATS  |  Uptime: {snap['uptime']:.0f}s  |  "
        f"Total Packets: {snap['total_packets']}  |  "
        f"Total: {format_bytes(snap['total_bytes'])}",
        f"  Rate: {snap['packets_per_sec']:.1f} pkt/s  |  "
        f"Bandwidth: {format_bytes(snap['bytes_per_sec'])}/s",
        "-" * 72,
    ]
    proto_counts = snap["protocol_counts"]
    proto_bytes = snap["protocol_bytes"]
    total = snap["total_packets"] if snap["total_packets"] > 0 else 1
    for proto in sorted(proto_counts.keys()):
        count = proto_counts[proto]
        nbytes = proto_bytes.get(proto, 0)
        pct = (count / total) * 100
        lines.append(
            f"  {proto:<8}  {count:>8} pkts  ({pct:5.1f}%)  "
            f"{format_bytes(nbytes):>12}"
        )
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)
