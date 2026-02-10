#!/usr/bin/env python3

import os
import sys
import time
import signal
import argparse
import threading
from datetime import datetime
from typing import Optional

from parser import (
    parse_packet,
    ParsedPacket,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
)
from sniffer import PacketSniffer
from stats import TrafficStats, format_stats_banner
from logger import PacketLogger


class PacketAnalyzer:

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._stats = TrafficStats()
        self._logger: Optional[PacketLogger] = None
        self._sniffer: Optional[PacketSniffer] = None
        self._shutdown = threading.Event()
        self._allowed_protocols = self._build_protocol_filter()

    def _build_protocol_filter(self) -> Optional[set[int]]:
        filters = set()
        if self._args.tcp:
            filters.add(PROTO_TCP)
        if self._args.udp:
            filters.add(PROTO_UDP)
        if self._args.icmp:
            filters.add(PROTO_ICMP)
        return filters if filters else None

    def _format_packet_line(self, pkt: ParsedPacket) -> str:
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        ipv4 = pkt.ipv4
        src = f"{ipv4.src_ip}:{pkt.src_port}" if pkt.src_port else ipv4.src_ip
        dst = f"{ipv4.dst_ip}:{pkt.dst_port}" if pkt.dst_port else ipv4.dst_ip
        flags = ""
        if pkt.tcp:
            flag_bits = []
            f = pkt.tcp.flags
            if f & 0x02:
                flag_bits.append("SYN")
            if f & 0x10:
                flag_bits.append("ACK")
            if f & 0x01:
                flag_bits.append("FIN")
            if f & 0x04:
                flag_bits.append("RST")
            if f & 0x08:
                flag_bits.append("PSH")
            if flag_bits:
                flags = f" [{','.join(flag_bits)}]"
        if pkt.icmp:
            flags = f" type={pkt.icmp.icmp_type} code={pkt.icmp.code}"
        return (
            f"{ts}  {pkt.protocol_name:<5}  {src:<22} -> "
            f"{dst:<22}  {pkt.raw_size:>5}B{flags}"
        )

    def _on_packet(self, raw_data: bytes, timestamp: float) -> None:
        pkt = parse_packet(raw_data, timestamp)
        if pkt is None or pkt.ipv4 is None:
            return

        if self._allowed_protocols and pkt.ipv4.protocol not in self._allowed_protocols:
            return

        self._stats.record(pkt.protocol_name, pkt.raw_size)
        line = self._format_packet_line(pkt)

        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except OSError:
            pass

        if self._logger:
            self._logger.write(line)

    def _stats_loop(self) -> None:
        interval = self._args.interval
        while not self._shutdown.wait(timeout=interval):
            snap = self._stats.snapshot()
            banner = format_stats_banner(snap)
            try:
                sys.stdout.write(banner)
                sys.stdout.flush()
            except OSError:
                pass

    def run(self) -> int:
        if os.geteuid() != 0:
            sys.stderr.write("Error: root privileges required. Run with sudo.\n")
            return 1

        if self._args.log:
            self._logger = PacketLogger(self._args.log)
            self._logger.open()

        self._sniffer = PacketSniffer(
            interface=self._args.interface,
            callback=self._on_packet,
        )

        def signal_handler(signum, frame):
            self._shutdown.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        header = (
            f"{'Time':<14}  {'Proto':<5}  {'Source':<22}    "
            f"{'Destination':<22}  {'Size':>5}"
        )
        sys.stdout.write("\n" + header + "\n")
        sys.stdout.write("-" * 80 + "\n")
        sys.stdout.flush()

        self._sniffer.start()

        stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="stats"
        )
        stats_thread.start()

        self._shutdown.wait()

        self._sniffer.stop()
        self._shutdown.set()
        stats_thread.join(timeout=3.0)

        if self._logger:
            self._logger.close()

        snap = self._stats.snapshot()
        banner = format_stats_banner(snap)
        sys.stdout.write("\nFinal Statistics:\n" + banner)
        sys.stdout.flush()

        return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Linux Network Packet Analyzer & Traffic Monitor",
    )
    ap.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to capture on (e.g., eth0). Default: all interfaces.",
    )
    ap.add_argument(
        "--tcp",
        action="store_true",
        default=False,
        help="Capture TCP packets only.",
    )
    ap.add_argument(
        "--udp",
        action="store_true",
        default=False,
        help="Capture UDP packets only.",
    )
    ap.add_argument(
        "--icmp",
        action="store_true",
        default=False,
        help="Capture ICMP packets only.",
    )
    ap.add_argument(
        "--log",
        type=str,
        default=None,
        help="Log output to file (append mode).",
    )
    ap.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Statistics display interval in seconds. Default: 5.",
    )
    return ap


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    analyzer = PacketAnalyzer(args)
    return analyzer.run()


if __name__ == "__main__":
    sys.exit(main())
