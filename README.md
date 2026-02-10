# Linux Network Packet Analyzer & Traffic Monitor

A high-performance, production-grade CLI tool for real-time network packet capture and traffic analysis on Linux. Built entirely with the Python standard library using `AF_PACKET` raw sockets.

---

## Features

- **Real-time packet capture** at the Ethernet layer via raw sockets
- **Protocol parsing**: Ethernet, IPv4, TCP, UDP, ICMP
- **Protocol filtering**: `--tcp`, `--udp`, `--icmp` (combinable)
- **Live traffic statistics**: packets/sec, bandwidth/sec, protocol distribution
- **Multithreaded architecture**: dedicated capture thread + stats/display thread
- **Optional file logging** in append mode (`--log <file>`)
- **Malformed packet handling**: validates all headers before access

---

## Requirements

- Python 3.10+
- Ubuntu Linux (or any Linux with `AF_PACKET` support)
- Root / sudo privileges (required for raw sockets)

---

## Installation

```bash
git clone <repo-url>
cd packet-analyzer
```

---

## Usage

```bash
sudo python3 main.py [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `-i`, `--interface` | Network interface (e.g., `eth0`, `wlan0`). Default: all. |
| `--tcp` | Show only TCP packets |
| `--udp` | Show only UDP packets |
| `--icmp` | Show only ICMP packets |
| `--log FILE` | Append captured packets to a log file |
| `--interval N` | Stats display interval in seconds (default: 5) |

### Example Commands

**Capture all traffic on all interfaces:**

```bash
sudo python3 main.py
```

**Capture only TCP traffic on eth0:**

```bash
sudo python3 main.py -i eth0 --tcp
```

**Capture UDP and ICMP, log to file:**

```bash
sudo python3 main.py --udp --icmp --log traffic.log
```

**Capture on wlan0 with 10-second stats interval:**

```bash
sudo python3 main.py -i wlan0 --interval 10
```

**Filter TCP and UDP simultaneously:**

```bash
sudo python3 main.py --tcp --udp
```

---

## Output Format

```
Time            Proto  Source                  Destination              Size
--------------------------------------------------------------------------------
14:23:01.482  TCP    192.168.1.5:443        10.0.0.1:52184            1500B [ACK]
14:23:01.483  UDP    10.0.0.1:53            192.168.1.5:41822           78B
14:23:01.501  ICMP   8.8.8.8                10.0.0.1                    84B type=0 code=0

========================================================================
  TRAFFIC STATS  |  Uptime: 30s  |  Total Packets: 1542  |  Total: 1.2 MB
  Rate: 51.4 pkt/s  |  Bandwidth: 41.2 KB/s
------------------------------------------------------------------------
  ICMP        42 pkts  (  2.7%)        3.4 KB
  TCP       1280 pkts  ( 83.0%)        1.1 MB
  UDP        220 pkts  ( 14.3%)      102.5 KB
========================================================================
```

---

## Permissions

Raw sockets (`AF_PACKET`) require root privileges on Linux. Always run with `sudo`:

```bash
sudo python3 main.py
```

If you run without `sudo`, the program will exit with an error message.

---

## Architecture

```
main.py      → CLI entry point, argument parsing, orchestration
sniffer.py   → Raw socket creation & threaded packet capture
parser.py    → Ethernet/IPv4/TCP/UDP/ICMP header parsing (struct-based)
stats.py     → Thread-safe traffic statistics & formatting
logger.py    → Thread-safe file logging in append mode
```

---

## License

MIT
