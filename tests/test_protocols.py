"""Hand-built wire packets exercise parser boundaries without a capture driver."""

import importlib
import ipaddress
import struct

import pytest


def decode(data, **kwargs):
    # Lazy import lets the initial missing-module run report individual failures.
    return importlib.import_module("sniffer.protocols").decode_packet(data, **kwargs)


def ethernet(body, ethertype=0x0800):
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ethertype) + body


def ipv4(body, proto=6, fragment=0, total=None, ihl=5):
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total or (ihl * 4 + len(body)),
                         7, fragment, 64, proto, 0, b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02")
    return header + b"\x00" * max(0, ihl * 4 - 20) + body


def ipv6(body, next_header=6):
    return (struct.pack("!IHBB", 6 << 28, len(body), next_header, 64)
            + ipaddress.IPv6Address("2001:db8::1").packed
            + ipaddress.IPv6Address("2001:db8::2").packed + body)


def tcp(payload=b"", src=12345, dst=80, flags=0x18, seq=100, ack=200, offset=5):
    return struct.pack("!HHIIBBHHH", src, dst, seq, ack, offset << 4, flags, 8192, 0, 0) + payload


def udp(payload=b"", src=12345, dst=53, length=None):
    return struct.pack("!HHHH", src, dst, length or (8 + len(payload)), 0) + payload


def layer(packet, name):
    return dict(packet.layers)[name]


def test_http_content_on_nonstandard_port_and_packet_metadata():
    body = b"GET /hello?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
    raw = ethernet(ipv4(tcp(body, dst=8088)))
    packet = decode(raw, timestamp=123.25, number=7, wire_length=len(raw) + 4)
    assert (packet.number, packet.timestamp, packet.raw, packet.wire_length, packet.linktype) == (
        7, 123.25, raw, len(raw) + 4, 1)
    assert (packet.src, packet.dst) == ("192.0.2.1", "198.51.100.2")
    assert (packet.protocol, packet.network, packet.transport) == ("HTTP", "IPv4", "TCP")
    assert (packet.src_port, packet.dst_port, packet.tcp_seq, packet.tcp_ack, packet.tcp_flags) == (
        12345, 8088, 100, 200, 0x18)
    assert packet.payload == body
    assert layer(packet, "HTTP")["Host"] == "example.test"
    assert "/hello?q=1" in packet.summary
    assert not packet.errors


@pytest.mark.parametrize("payload", [b"arbitrary data", b"GET /incomplete", b"\x00" * 20])
def test_http_is_not_inferred_from_port(payload):
    assert decode(ethernet(ipv4(tcp(payload)))).protocol == "TCP"


def test_http_response_status():
    packet = decode(ethernet(ipv4(tcp(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", src=80))))
    assert packet.protocol == "HTTP"
    assert "404" in packet.summary


def test_arp_addresses_and_operation():
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex(
        "66778899aabbc0000201000000000000c0000202")
    packet = decode(ethernet(arp, 0x0806))
    assert (packet.protocol, packet.network, packet.src, packet.dst) == (
        "ARP", "ARP", "192.0.2.1", "192.0.2.2")
    assert layer(packet, "ARP")["Operation"] == 1


def test_stacked_vlan_tags_preserve_network_payload():
    raw = ethernet(struct.pack("!HHHH", 100, 0x8100, 200, 0x0800) + ipv4(udp(b"x", dst=9000), 17), 0x88A8)
    packet = decode(raw)
    assert packet.protocol == "UDP"
    assert [values["ID"] for name, values in packet.layers if name == "VLAN"] == [100, 200]
    assert packet.payload == b"x"


def test_ipv4_options_and_ethernet_padding_are_not_tcp_payload():
    packet = decode(ethernet(ipv4(tcp(b"ok"), ihl=6)) + b"padding")
    assert packet.payload == b"ok"
    assert not packet.errors


def test_ipv4_noninitial_fragment_is_not_a_transport_header():
    packet = decode(ethernet(ipv4(tcp(b"fake transport"), fragment=1)))
    assert (packet.network, packet.transport, packet.src_port, packet.tcp_seq) == ("IPv4", "", None, None)
    assert "fragment" in packet.summary.lower()


def test_first_ipv4_fragment_can_expose_tcp_but_not_partial_http():
    packet = decode(ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\n"), fragment=0x2000)))
    assert packet.transport == "TCP"
    assert packet.protocol == "TCP"


@pytest.mark.parametrize("raw", [ipv4(b"", ihl=4), ipv4(b"", total=10), b"\x45" + b"\x00" * 5])
def test_invalid_or_truncated_ipv4_records_error(raw):
    packet = decode(ethernet(raw))
    assert packet.errors
    assert not packet.transport


def test_ipv4_declared_length_beyond_capture_is_reported():
    packet = decode(ethernet(ipv4(tcp(b"part"), total=100)))
    assert packet.transport == "TCP"
    assert packet.payload == b"part"
    assert packet.errors


def test_truncated_tcp_does_not_read_ports_from_incomplete_header():
    packet = decode(ethernet(ipv4(b"\x00\x50\x01\xbb")))
    assert packet.protocol == "IPv4"
    assert packet.src_port is None
    assert packet.errors


def test_tcp_invalid_data_offset_does_not_expose_payload():
    packet = decode(ethernet(ipv4(tcp(b"body", offset=4))))
    assert packet.errors
    assert packet.payload == b""


def test_udp_length_bounds_exclude_padding_and_report_invalid_length():
    good = decode(ethernet(ipv4(udp(b"abc") + b"PAD", 17)))
    bad = decode(ethernet(ipv4(udp(b"abc", length=7), 17)))
    assert good.payload == b"abc"
    assert bad.errors
    assert bad.payload == b""


def test_icmp_echo_fields():
    packet = decode(ethernet(ipv4(struct.pack("!BBHHH", 8, 0, 0, 123, 1) + b"ping", 1)))
    assert (packet.protocol, packet.transport, packet.payload) == ("ICMP", "ICMP", b"ping")
    assert layer(packet, "ICMP")["Type"] == 8


def test_ipv6_hop_routing_destination_and_authentication_extensions():
    body = (bytes([43, 0]) + b"\x00" * 6 + bytes([60, 0]) + b"\x00" * 6
            + bytes([51, 0]) + b"\x00" * 6 + bytes([17, 1]) + b"\x00" * 10
            + udp(b"v6", dst=9000))
    packet = decode(ethernet(ipv6(body, 0), 0x86DD))
    assert (packet.network, packet.transport, packet.src, packet.dst, packet.payload) == (
        "IPv6", "UDP", "2001:db8::1", "2001:db8::2", b"v6")
    assert not packet.errors


def test_ipv6_noninitial_fragment_is_not_a_transport_header():
    fragment = struct.pack("!BBHI", 6, 0, 9, 123) + tcp(b"not a header")
    packet = decode(ethernet(ipv6(fragment, 44), 0x86DD))
    assert (packet.transport, packet.src_port, packet.tcp_seq) == ("", None, None)
    assert "fragment" in packet.summary.lower()


def test_ipv6_atomic_fragment_can_parse_transport():
    fragment = struct.pack("!BBHI", 17, 0, 0, 123) + udp(b"atomic", dst=9000)
    packet = decode(ethernet(ipv6(fragment, 44), 0x86DD))
    assert (packet.transport, packet.payload) == ("UDP", b"atomic")


def test_ipv6_truncated_extension_and_esp_remain_safe():
    bad = decode(ethernet(ipv6(bytes([6, 5]) + b"\x00" * 6, 60), 0x86DD))
    encrypted = decode(ethernet(ipv6(b"\x01" * 30, 50), 0x86DD))
    assert bad.errors
    assert not bad.transport
    assert not encrypted.transport
    assert encrypted.protocol == "ESP"


def test_icmpv6_echo_and_no_next_header():
    echo = decode(ethernet(ipv6(struct.pack("!BBHHH", 128, 0, 0, 1, 2) + b"v6", 58), 0x86DD))
    empty = decode(ethernet(ipv6(b"", 59), 0x86DD))
    assert (echo.protocol, echo.transport, echo.payload) == ("ICMPv6", "ICMPv6", b"v6")
    assert empty.protocol == "IPv6"
    assert not empty.errors


DNS_QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x04test\x00\x00\x01\x00\x01"


def test_dns_query_and_compressed_answer():
    query = decode(ethernet(ipv4(udp(DNS_QUERY), 17)))
    response = DNS_QUERY[:2] + bytes.fromhex("81800001000100000000") + DNS_QUERY[12:]
    response += bytes.fromhex("c00c000100010000003c0004c000020a")
    answer = decode(ethernet(ipv4(udp(response, src=53, dst=12345), 17)))
    assert query.protocol == "DNS"
    assert layer(query, "DNS")["Query"] == "example.test"
    assert answer.protocol == "DNS"
    assert "192.0.2.10" in str(layer(answer, "DNS"))


@pytest.mark.parametrize("name", [b"\xc0\x0c", b"\xc0\xff", b"\x3fabc"])
def test_dns_compression_loop_or_out_of_bounds_is_reported(name):
    malformed = DNS_QUERY[:12] + name + b"\x00\x01\x00\x01"
    packet = decode(ethernet(ipv4(udp(malformed), 17)))
    assert packet.errors
    assert packet.transport == "UDP"


def test_dns_over_tcp_uses_message_length_prefix():
    packet = decode(ethernet(ipv4(tcp(struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY, dst=53))))
    assert packet.protocol == "DNS"
    assert layer(packet, "DNS")["Query"] == "example.test"


def test_tls_record_and_client_hello_are_metadata_only():
    hello_body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x13\x01\x01\x00"
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    packet = decode(ethernet(ipv4(tcp(record, dst=443))))
    assert packet.protocol == "TLS"
    assert "ClientHello" in str(layer(packet, "TLS"))
    assert packet.payload == record
    assert "HTTP" not in dict(packet.layers)


def test_port_443_does_not_imply_tls():
    assert decode(ethernet(ipv4(tcp(b"unrecognized", dst=443)))).protocol == "TCP"


@pytest.mark.parametrize("linktype,prefix", [(0, struct.pack("<I", 2)), (108, struct.pack("!I", 2)),
                                               (101, b""),
                                               (113, struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800)),
                                               (276, struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x00" * 8))])
def test_common_capture_linktypes(linktype, prefix):
    packet = decode(prefix + ipv4(udp(b"raw", dst=9000), 17), linktype=linktype)
    assert (packet.network, packet.transport, packet.payload) == ("IPv4", "UDP", b"raw")


def test_unknown_linktype_is_not_assumed_ethernet():
    packet = decode(ethernet(ipv4(tcp())), linktype=999)
    assert packet.protocol == "Unknown"
    assert not packet.network
    assert packet.errors


@pytest.mark.parametrize("raw,linktype", [(b"", 1), (b"\x00" * 13, 1), (b"\x00", 0), (b"\x00" * 15, 113),
                                           (b"\x00" * 19, 276), (b"\x01", 101)])
def test_short_or_invalid_link_headers_return_packet_with_error(raw, linktype):
    packet = decode(raw, linktype=linktype)
    assert packet.raw == raw
    assert packet.errors
    assert not packet.transport


def test_every_prefix_of_valid_frames_is_safe():
    frames = [ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\n\r\n"))),
              ethernet(ipv4(udp(DNS_QUERY), 17)),
              ethernet(ipv6(udp(b"hello", dst=9000), 17), 0x86DD)]
    for raw in frames:
        for length in range(len(raw)):
            packet = decode(raw[:length], wire_length=len(raw))
            assert packet.errors, (length, len(raw))
            assert packet.raw == raw[:length]
