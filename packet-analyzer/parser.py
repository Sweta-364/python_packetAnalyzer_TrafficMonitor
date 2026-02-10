import struct
import socket
from dataclasses import dataclass, field
from typing import Optional


PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

PROTO_NAMES = {
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
    PROTO_ICMP: "ICMP",
}

ETH_HEADER_LEN = 14
IPV4_MIN_HEADER_LEN = 20
TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
ETH_P_IP = 0x0800


@dataclass(slots=True)
class EthernetFrame:
    dest_mac: str
    src_mac: str
    eth_type: int


@dataclass(slots=True)
class IPv4Packet:
    version: int
    ihl: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str
    header_length: int
    total_length: int


@dataclass(slots=True)
class TCPSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int


@dataclass(slots=True)
class UDPDatagram:
    src_port: int
    dst_port: int
    length: int


@dataclass(slots=True)
class ICMPMessage:
    icmp_type: int
    code: int
    checksum: int


@dataclass(slots=True)
class ParsedPacket:
    timestamp: float = 0.0
    raw_size: int = 0
    ethernet: Optional[EthernetFrame] = None
    ipv4: Optional[IPv4Packet] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPDatagram] = None
    icmp: Optional[ICMPMessage] = None
    protocol_name: str = ""
    src_port: int = 0
    dst_port: int = 0


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(data: bytes) -> Optional[EthernetFrame]:
    if len(data) < ETH_HEADER_LEN:
        return None
    dest_mac = _format_mac(data[0:6])
    src_mac = _format_mac(data[6:12])
    eth_type = struct.unpack("!H", data[12:14])[0]
    return EthernetFrame(dest_mac=dest_mac, src_mac=src_mac, eth_type=eth_type)


def parse_ipv4(data: bytes) -> Optional[IPv4Packet]:
    if len(data) < IPV4_MIN_HEADER_LEN:
        return None
    version_ihl = data[0]
    version = version_ihl >> 4
    if version != 4:
        return None
    ihl = version_ihl & 0x0F
    header_length = ihl * 4
    if header_length < IPV4_MIN_HEADER_LEN or len(data) < header_length:
        return None
    fields = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ttl = fields[5]
    protocol = fields[6]
    total_length = fields[2]
    src_ip = socket.inet_ntoa(fields[8])
    dst_ip = socket.inet_ntoa(fields[9])
    return IPv4Packet(
        version=version,
        ihl=ihl,
        ttl=ttl,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        header_length=header_length,
        total_length=total_length,
    )


def parse_tcp(data: bytes) -> Optional[TCPSegment]:
    if len(data) < TCP_MIN_HEADER_LEN:
        return None
    fields = struct.unpack("!HHIIBBHHH", data[:20])
    src_port = fields[0]
    dst_port = fields[1]
    seq = fields[2]
    ack = fields[3]
    offset_reserved = fields[4]
    flags = fields[5]
    window = fields[6]
    data_offset = (offset_reserved >> 4) * 4
    if data_offset < TCP_MIN_HEADER_LEN:
        return None
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
    )


def parse_udp(data: bytes) -> Optional[UDPDatagram]:
    if len(data) < UDP_HEADER_LEN:
        return None
    fields = struct.unpack("!HHHH", data[:8])
    return UDPDatagram(
        src_port=fields[0],
        dst_port=fields[1],
        length=fields[2],
    )


def parse_icmp(data: bytes) -> Optional[ICMPMessage]:
    if len(data) < ICMP_HEADER_LEN:
        return None
    fields = struct.unpack("!BBH", data[:4])
    return ICMPMessage(
        icmp_type=fields[0],
        code=fields[1],
        checksum=fields[2],
    )


def parse_packet(raw_data: bytes, timestamp: float) -> Optional[ParsedPacket]:
    packet = ParsedPacket(timestamp=timestamp, raw_size=len(raw_data))

    eth = parse_ethernet(raw_data)
    if eth is None:
        return None
    packet.ethernet = eth

    if eth.eth_type != ETH_P_IP:
        return None

    ip_data = raw_data[ETH_HEADER_LEN:]
    ipv4 = parse_ipv4(ip_data)
    if ipv4 is None:
        return None
    packet.ipv4 = ipv4

    transport_data = ip_data[ipv4.header_length:]
    proto = ipv4.protocol
    packet.protocol_name = PROTO_NAMES.get(proto, f"OTHER({proto})")

    if proto == PROTO_TCP:
        tcp = parse_tcp(transport_data)
        if tcp is not None:
            packet.tcp = tcp
            packet.src_port = tcp.src_port
            packet.dst_port = tcp.dst_port
    elif proto == PROTO_UDP:
        udp = parse_udp(transport_data)
        if udp is not None:
            packet.udp = udp
            packet.src_port = udp.src_port
            packet.dst_port = udp.dst_port
    elif proto == PROTO_ICMP:
        icmp = parse_icmp(transport_data)
        if icmp is not None:
            packet.icmp = icmp

    return packet
