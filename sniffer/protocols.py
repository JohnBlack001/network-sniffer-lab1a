"""Bounded, dependency-free decoders for the protocols used by experiment 1A.

Each packet is independent: TCP application messages and IP fragments are not
reassembled here. Unavailable bytes remain unavailable and errors are visible
to the caller. TLS decoding exposes record metadata only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
import struct


@dataclass
class Packet:
    number: int = 0
    timestamp: float = 0.0
    raw: bytes = b""
    wire_length: int = 0
    linktype: int = 1
    src: str = ""
    dst: str = ""
    protocol: str = "Unknown"
    transport: str = ""
    network: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    summary: str = ""
    layers: list[tuple[str, dict[str, str | int]]] = field(default_factory=list)
    payload: bytes = b""
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_flags: int = 0
    errors: list[str] = field(default_factory=list)


def decode_packet(data: bytes, timestamp: float = 0.0, linktype: int = 1,
                  number: int = 0, wire_length: int | None = None) -> Packet:
    """Decode a captured frame, retaining errors instead of reading past bounds."""
    packet = Packet(number=number, timestamp=timestamp, raw=bytes(data),
                    wire_length=len(data) if wire_length is None else wire_length,
                    linktype=linktype)
    packet.layers.append(("Frame", {"Number": number, "Captured length": len(data),
                                   "Wire length": packet.wire_length, "Link type": linktype,
                                   "Timestamp": f"{timestamp:.6f}"}))
    try:
        ethertype, body = _link(packet, packet.raw)
        if ethertype == 0x0800:
            _ipv4(packet, body)
        elif ethertype == 0x86DD:
            _ipv6(packet, body)
        elif ethertype == 0x0806:
            _arp(packet, body)
        elif ethertype is not None:
            packet.summary = f"EtherType 0x{ethertype:04x}, {len(body)} bytes"
    except _DecodeError as exc:
        packet.errors.append(str(exc))
    if not packet.summary:
        packet.summary = packet.protocol
    return packet


class _DecodeError(ValueError):
    pass


def _require(data: bytes, offset: int, size: int, name: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise _DecodeError(f"Truncated {name}: need {size} bytes at {offset}, have {max(0, len(data) - offset)}")


def _mac(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _link(packet: Packet, data: bytes) -> tuple[int | None, bytes]:
    if packet.linktype == 1:
        _require(data, 0, 14, "Ethernet header")
        packet.dst, packet.src = _mac(data[:6]), _mac(data[6:12])
        ethertype = struct.unpack_from("!H", data, 12)[0]
        packet.protocol = "Ethernet"
        packet.layers.append(("Ethernet", {"Source": packet.src, "Destination": packet.dst,
                                           "Type": f"0x{ethertype:04x}"}))
        offset = 14
    elif packet.linktype in (0, 108):
        _require(data, 0, 4, "loopback header")
        family = struct.unpack_from("!I" if packet.linktype == 108 else "<I", data)[0]
        # DLT_NULL uses the capturing host's byte order, which may differ from ours.
        if packet.linktype == 0 and family not in (2, 10, 23, 24, 28, 30):
            family = struct.unpack_from("!I", data)[0]
        packet.layers.append(("Loopback", {"Address family": family}))
        if family not in (2, 10, 23, 24, 28, 30):
            raise _DecodeError(f"Unsupported loopback address family {family}")
        return (0x0800 if family == 2 else 0x86DD), data[4:]
    elif packet.linktype == 101:
        _require(data, 0, 1, "raw IP header")
        version = data[0] >> 4
        if version not in (4, 6):
            raise _DecodeError(f"Invalid raw IP version {version}")
        return (0x0800 if version == 4 else 0x86DD), data
    elif packet.linktype == 113:
        _require(data, 0, 16, "Linux cooked header")
        kind, hardware, address_length = struct.unpack_from("!HHH", data)
        ethertype = struct.unpack_from("!H", data, 14)[0]
        packet.layers.append(("Linux cooked", {"Packet type": kind, "Hardware type": hardware,
                                               "Address": _mac(data[6:6 + min(address_length, 8)]),
                                               "Type": f"0x{ethertype:04x}"}))
        offset = 16
    elif packet.linktype == 276:
        _require(data, 0, 20, "Linux cooked v2 header")
        ethertype, _, index, hardware, kind, address_length = struct.unpack_from("!HHIHBB", data)
        packet.layers.append(("Linux cooked v2", {"Interface index": index, "Packet type": kind,
                                                  "Hardware type": hardware,
                                                  "Address": _mac(data[12:12 + min(address_length, 8)]),
                                                  "Type": f"0x{ethertype:04x}"}))
        offset = 20
    else:
        raise _DecodeError(f"Unsupported link type {packet.linktype}")
    for _ in range(16):
        if ethertype not in (0x8100, 0x88A8, 0x9100):
            return ethertype, data[offset:]
        _require(data, offset, 4, "VLAN tag")
        tci, ethertype = struct.unpack_from("!HH", data, offset)
        packet.layers.append(("VLAN", {"ID": tci & 0xFFF, "Priority": tci >> 13,
                                       "DEI": (tci >> 12) & 1, "Type": f"0x{ethertype:04x}"}))
        offset += 4
    raise _DecodeError("Too many nested VLAN tags")


def _arp(packet: Packet, data: bytes) -> None:
    _require(data, 0, 8, "ARP header")
    hardware, protocol, hlen, plen, operation = struct.unpack_from("!HHBBH", data)
    _require(data, 8, 2 * (hlen + plen), "ARP addresses")
    packet.protocol = packet.network = "ARP"
    sha = data[8:8 + hlen]
    spa = data[8 + hlen:8 + hlen + plen]
    tha = data[8 + hlen + plen:8 + 2 * hlen + plen]
    tpa = data[8 + 2 * hlen + plen:8 + 2 * (hlen + plen)]
    source = str(ipaddress.IPv4Address(spa)) if protocol == 0x0800 and plen == 4 else spa.hex()
    destination = str(ipaddress.IPv4Address(tpa)) if protocol == 0x0800 and plen == 4 else tpa.hex()
    packet.src, packet.dst = source, destination
    packet.layers.append(("ARP", {"Hardware type": hardware, "Protocol type": f"0x{protocol:04x}",
                                  "Hardware length": hlen, "Protocol length": plen,
                                  "Operation": operation, "Sender MAC": _mac(sha), "Sender IP": source,
                                  "Target MAC": _mac(tha), "Target IP": destination}))
    packet.summary = (f"Who has {destination}? Tell {source}" if operation == 1
                      else f"{source} is at {_mac(sha)}" if operation == 2
                      else f"ARP operation {operation}: {source} → {destination}")


def _ipv4(packet: Packet, data: bytes) -> None:
    _require(data, 0, 20, "IPv4 header")
    version, ihl = data[0] >> 4, (data[0] & 0xF) * 4
    length, identification, fragment = struct.unpack_from("!HHH", data, 2)
    if version != 4 or ihl < 20 or length < ihl:
        raise _DecodeError(f"Invalid IPv4 version/header/total length: {version}/{ihl}/{length}")
    _require(data, 0, ihl, "IPv4 options")
    packet.protocol = packet.network = "IPv4"
    packet.src = str(ipaddress.IPv4Address(data[12:16]))
    packet.dst = str(ipaddress.IPv4Address(data[16:20]))
    offset, more = (fragment & 0x1FFF) * 8, bool(fragment & 0x2000)
    packet.layers.append(("IPv4", {"Version": version, "Header length": ihl, "Total length": length,
                                   "Identification": identification, "TTL": data[8], "Protocol": data[9],
                                   "Flags": fragment >> 13, "Fragment offset": offset,
                                   "Source": packet.src, "Destination": packet.dst}))
    if length > len(data):
        packet.errors.append(f"Truncated IPv4 packet: declared {length}, captured {len(data)}")
    if offset:
        packet.summary = f"IPv4 fragment, offset {offset}, more={int(more)}"
        return
    packet.summary = f"IPv4 protocol {data[9]}"
    _transport(packet, data[ihl:min(length, len(data))], data[9], fragmented=more)


def _ipv6(packet: Packet, data: bytes) -> None:
    _require(data, 0, 40, "IPv6 header")
    if data[0] >> 4 != 6:
        raise _DecodeError("Invalid IPv6 version")
    length, next_header, hop_limit = struct.unpack_from("!HBB", data, 4)
    packet.protocol = packet.network = "IPv6"
    packet.src = str(ipaddress.IPv6Address(data[8:24]))
    packet.dst = str(ipaddress.IPv6Address(data[24:40]))
    packet.layers.append(("IPv6", {"Version": 6, "Payload length": length, "Next header": next_header,
                                   "Hop limit": hop_limit, "Flow label": int.from_bytes(data[:4], "big") & 0xFFFFF,
                                   "Source": packet.src, "Destination": packet.dst}))
    if length + 40 > len(data):
        packet.errors.append(f"Truncated IPv6 packet: declared {length + 40}, captured {len(data)}")
    if length == 0 and len(data) > 40 and next_header != 59:
        raise _DecodeError("IPv6 jumbograms are not supported")
    body, offset, fragmented = data[40:min(40 + length, len(data))], 0, False
    names = {0: "Hop-by-Hop", 43: "Routing", 60: "Destination Options", 51: "Authentication", 44: "Fragment"}
    for _ in range(32):
        if next_header not in names:
            break
        _require(body, offset, 2, "IPv6 extension header")
        following = body[offset]
        if next_header == 44:
            _require(body, offset, 8, "IPv6 fragment header")
            bits, identification = struct.unpack_from("!HI", body, offset + 2)
            fragment_offset, more = (bits >> 3) * 8, bool(bits & 1)
            packet.layers.append(("IPv6 Fragment", {"Next header": following, "Offset": fragment_offset,
                                                    "More fragments": int(more), "Identification": identification}))
            if fragment_offset:
                packet.summary = f"IPv6 fragment, offset {fragment_offset}, more={int(more)}"
                return
            fragmented = fragmented or more
            extension_length = 8
        else:
            extension_length = ((body[offset + 1] + 2) * 4 if next_header == 51
                                else (body[offset + 1] + 1) * 8)
            if next_header == 51 and extension_length < 12:
                raise _DecodeError("Invalid IPv6 authentication header length")
            _require(body, offset, extension_length, "IPv6 extension body")
            packet.layers.append((f"IPv6 {names[next_header]}", {"Next header": following,
                                                               "Length": extension_length}))
        next_header, offset = following, offset + extension_length
    else:
        raise _DecodeError("Too many IPv6 extension headers")
    packet.summary = f"IPv6 next header {next_header}"
    if next_header == 50:
        packet.protocol = "ESP"
        packet.layers.append(("ESP", {"Encrypted bytes": len(body) - offset}))
        packet.summary = "ESP encrypted payload"
    elif next_header != 59:
        _transport(packet, body[offset:], next_header, fragmented)


def _transport(packet: Packet, data: bytes, protocol: int, fragmented: bool = False) -> None:
    if protocol == 6:
        _require(data, 0, 20, "TCP header")
        source, destination, seq, ack, control, window, checksum, urgent = struct.unpack_from("!HHIIHHHH", data)
        header_length = (control >> 12) * 4
        if header_length < 20:
            raise _DecodeError(f"Invalid TCP data offset {header_length}")
        _require(data, 0, header_length, "TCP options")
        packet.protocol = packet.transport = "TCP"
        packet.src_port, packet.dst_port = source, destination
        packet.tcp_seq, packet.tcp_ack, packet.tcp_flags = seq, ack, control & 0x1FF
        flags = ",".join(name for bit, name in [(0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"),
                                               (0x20, "URG"), (0x10, "ACK"), (8, "PSH"), (4, "RST"),
                                               (2, "SYN"), (1, "FIN")] if packet.tcp_flags & bit)
        packet.layers.append(("TCP", {"Source port": source, "Destination port": destination,
                                      "Sequence": seq, "Acknowledgment": ack, "Header length": header_length,
                                      "Flags": flags or "None", "Window": window,
                                      "Checksum": f"0x{checksum:04x}", "Urgent pointer": urgent}))
        packet.payload = data[header_length:]
        packet.summary = f"{source} → {destination} [{flags}] Seq={seq} Ack={ack} Len={len(packet.payload)}"
    elif protocol == 17:
        _require(data, 0, 8, "UDP header")
        source, destination, length, checksum = struct.unpack_from("!HHHH", data)
        if length < 8:
            raise _DecodeError(f"Invalid UDP length {length}")
        packet.protocol = packet.transport = "UDP"
        packet.src_port, packet.dst_port = source, destination
        packet.layers.append(("UDP", {"Source port": source, "Destination port": destination,
                                      "Length": length, "Checksum": f"0x{checksum:04x}"}))
        if length > len(data) and not fragmented:
            packet.errors.append(f"Truncated UDP datagram: declared {length}, captured {len(data)}")
        packet.payload = data[8:min(length, len(data))]
        packet.summary = f"{source} → {destination} Len={len(packet.payload)}"
    elif protocol in (1, 58):
        _require(data, 0, 4, "ICMP header")
        name = "ICMPv6" if protocol == 58 else "ICMP"
        packet.protocol = packet.transport = name
        kind, code, checksum = struct.unpack_from("!BBH", data)
        values: dict[str, str | int] = {"Type": kind, "Code": code, "Checksum": f"0x{checksum:04x}"}
        header_length = 4
        if kind in ((128, 129) if protocol == 58 else (0, 8)):
            _require(data, 0, 8, "ICMP echo header")
            values["Identifier"], values["Sequence"] = struct.unpack_from("!HH", data, 4)
            header_length = 8
        elif protocol == 1:
            _require(data, 0, 8, "ICMP message header")
            header_length = 8
        packet.layers.append((name, values))
        packet.payload = data[header_length:]
        packet.summary = f"{name} Type={kind} Code={code}"
        return
    else:
        return
    if packet.payload and not fragmented:
        _application(packet)


_HTTP_REQUEST = re.compile(rb"(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^\x00-\x20]+ HTTP/[12]\.\d$")
_HTTP_RESPONSE = re.compile(rb"HTTP/[12]\.\d [1-5]\d\d(?: [^\r\n\x00]*)?$")


def _application(packet: Packet) -> None:
    payload = packet.payload
    if packet.transport == "TCP":
        first_line = payload.split(b"\r\n", 1)[0]
        if b"\r\n" in payload and (_HTTP_REQUEST.fullmatch(first_line) or _HTTP_RESPONSE.fullmatch(first_line)):
            text = first_line.decode("latin-1")
            values: dict[str, str | int] = {"Start line": text}
            # Headers have a fixed display budget; the complete bytes remain in payload.
            for line in payload[:16384].split(b"\r\n")[1:101]:
                if not line:
                    break
                name, separator, value = line.partition(b":")
                if separator and name.lower() in (b"host", b"content-type", b"content-length", b"user-agent", b"server"):
                    values[name.decode("latin-1").title()] = value.strip().decode("latin-1")
            packet.protocol, packet.summary = "HTTP", text
            packet.layers.append(("HTTP", values))
            return
    if packet.src_port in (53, 5353) or packet.dst_port in (53, 5353):
        message = payload
        if packet.transport == "TCP":
            _require(message, 0, 2, "DNS TCP length")
            length = struct.unpack_from("!H", message)[0]
            _require(message, 2, length, "DNS TCP message")
            message = message[2:2 + length]
        _dns(packet, message)
        return
    if packet.transport == "TCP":
        _tls(packet, payload)


@dataclass
class _DNSNameBudget:
    # Shared by all owner names, questions and supported name RDATA in one message.
    remaining: int = 16384


def _dns_name(data: bytes, offset: int, budget: _DNSNameBudget) -> tuple[str, int]:
    labels: list[str] = []
    seen: set[int] = set()
    end: int | None = None
    expanded_length = 1
    pointer_hops = 0
    while True:
        if budget.remaining <= 0:
            raise _DecodeError("DNS name decoding work limit exceeded")
        budget.remaining -= 1
        _require(data, offset, 1, "DNS name")
        if offset in seen:
            raise _DecodeError("DNS compression pointer loop")
        seen.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            pointer_hops += 1
            if pointer_hops > 64:
                raise _DecodeError("DNS compression pointer hop limit exceeded (64)")
            _require(data, offset, 2, "DNS pointer")
            pointer = ((size & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if size & 0xC0:
            raise _DecodeError("Invalid DNS label prefix")
        offset += 1
        if size == 0:
            return ".".join(labels) or ".", end if end is not None else offset
        _require(data, offset, size, "DNS label")
        expanded_length += size + 1
        if expanded_length > 255:
            raise _DecodeError("DNS name exceeds 255 bytes")
        labels.append(data[offset:offset + size].decode("ascii", errors="backslashreplace"))
        offset += size


def _dns(packet: Packet, data: bytes) -> None:
    _require(data, 0, 12, "DNS header")
    transaction, flags, questions, answers, authorities, additional = struct.unpack_from("!6H", data)
    # Every question needs at least five bytes; every resource record needs eleven.
    if questions * 5 + (answers + authorities + additional) * 11 > len(data) - 12:
        raise _DecodeError("DNS counts exceed available message bytes")
    values: dict[str, str | int] = {"Transaction ID": f"0x{transaction:04x}", "Flags": f"0x{flags:04x}",
                                   "Questions": questions, "Answers": answers, "Authority records": authorities,
                                   "Additional records": additional, "Response code": flags & 0xF}
    offset, first_name = 12, ""
    budget = _DNSNameBudget()
    for index in range(questions):
        name, offset = _dns_name(data, offset, budget)
        _require(data, offset, 4, "DNS question")
        kind, dns_class = struct.unpack_from("!HH", data, offset)
        offset += 4
        if index == 0:
            first_name = name
            values.update({"Query": name, "Query type": kind, "Query class": dns_class})
    for index in range(answers + authorities + additional):
        name, offset = _dns_name(data, offset, budget)
        _require(data, offset, 10, "DNS resource record")
        kind, dns_class, ttl, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        _require(data, offset, size, "DNS resource data")
        value = data[offset:offset + size].hex()
        if kind == 1 and size == 4:
            value = str(ipaddress.IPv4Address(data[offset:offset + size]))
        elif kind == 28 and size == 16:
            value = str(ipaddress.IPv6Address(data[offset:offset + size]))
        elif kind in (2, 5, 12):
            value, name_end = _dns_name(data, offset, budget)
            if name_end > offset + size:
                raise _DecodeError("DNS name extends beyond resource data")
        if index < 32:
            values[f"Record {index + 1}"] = f"{name} type={kind} class={dns_class} ttl={ttl} {value}"
        offset += size
    packet.protocol = "DNS"
    packet.layers.append(("DNS", values))
    packet.summary = f"DNS {'response' if flags & 0x8000 else 'query'} 0x{transaction:04x} {first_name}"


def _tls(packet: Packet, data: bytes) -> None:
    if len(data) < 5 or data[0] not in (20, 21, 22, 23, 24) or data[1] != 3 or data[2] > 4:
        return
    length = struct.unpack_from("!H", data, 3)[0]
    if length == 0 or length > 18432:
        return
    types = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
    values: dict[str, str | int] = {"Content type": types[data[0]], "Record version": f"3.{data[2]}",
                                   "Record length": length}
    if len(data) < 5 + length:
        packet.errors.append(f"Truncated TLS record: declared {length}, captured {max(0, len(data) - 5)}")
    if data[0] == 22 and min(length, len(data) - 5) >= 4:
        handshakes = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
                      8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
                      13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
                      16: "ClientKeyExchange", 20: "Finished", 24: "KeyUpdate"}
        values["Handshake"] = handshakes.get(data[5], f"Type {data[5]}")
        values["Handshake length"] = int.from_bytes(data[6:9], "big")
    packet.protocol = "TLS"
    packet.layers.append(("TLS", values))
    packet.summary = f"TLS {values.get('Handshake', values['Content type'])}, record length {length} (encrypted traffic is not decrypted)"
