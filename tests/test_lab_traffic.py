"""Controlled loopback traffic and independently checked synthetic packets."""

import importlib
import json
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest


def _traffic_module():
    return importlib.import_module("tools.lab_traffic")


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _read_pcap(path):
    raw = path.read_bytes()
    assert raw[:4] == b"\xd4\xc3\xb2\xa1"
    assert struct.unpack_from("<I", raw, 20)[0] == 1
    offset = 24
    frames = []
    while offset < len(raw):
        _, _, captured, original = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        assert captured == original
        frame = raw[offset : offset + captured]
        assert len(frame) == captured
        frames.append(frame)
        offset += captured
    return frames


def test_generate_round_trips_http_and_dns_on_loopback():
    with _traffic_module().TrafficLab(http_port=0, dns_port=0) as lab:
        result = lab.generate()
        assert result["source"] == "real-loopback"
        assert result["ipv4_http"]["ok"]
        assert result["ipv4_http"]["status"] == 200
        assert "TCP stream reassembly" in result["ipv4_http"]["body"]
        assert "\n\n" in result["ipv4_http"]["body"]
        assert result["udp_dns"]["ok"]
        assert result["udp_dns"]["answer"] == "192.0.2.10"
        assert result["udp_dns"]["question"] == "lab1a.local"
        assert result["ping"]["requested"] is False
        if lab.ipv6_available:
            assert result["ipv6_http"]["ok"]
            assert result["ipv6_http"]["body"] == result["ipv4_http"]["body"]
        else:
            assert result["ipv6_http"]["available"] is False
            assert result["ipv6_http"]["reason"]


def test_context_releases_listeners_and_idle_http_connections():
    lab = _traffic_module().TrafficLab(http_port=0, dns_port=0)
    with lab:
        http_port, dns_port, ipv6_port = lab.http_port, lab.dns_port, lab.ipv6_port
        idle = socket.create_connection(("127.0.0.1", http_port), timeout=2)
        idle.sendall(b"GET /lab1a.txt HTTP/1.1\r\n")
    try:
        assert idle.recv(1) == b""
    except ConnectionResetError:
        pass
    finally:
        idle.close()
    for family, address, kind in [
        (socket.AF_INET, ("127.0.0.1", http_port), socket.SOCK_STREAM),
        (socket.AF_INET, ("127.0.0.1", dns_port), socket.SOCK_DGRAM),
    ]:
        with socket.socket(family, kind) as probe:
            probe.bind(address)
    if ipv6_port is not None:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", ipv6_port))
    assert not [t for t in threading.enumerate() if t.name.startswith("lab1a-")]


def test_generate_requires_active_context():
    lab = _traffic_module().TrafficLab(http_port=0, dns_port=0)
    with pytest.raises(RuntimeError, match="context"):
        lab.generate()


def test_http_does_not_serve_local_files():
    with _traffic_module().TrafficLab(http_port=0, dns_port=0) as lab:
        with socket.create_connection(("127.0.0.1", lab.http_port), timeout=2) as client:
            client.sendall(b"GET /../requirements.txt HTTP/1.0\r\n\r\n")
            assert client.recv(4096).startswith(b"HTTP/1.1 404")


def test_dns_ignores_malformed_datagrams_and_stays_available():
    with _traffic_module().TrafficLab(http_port=0, dns_port=0) as lab:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"invalid", ("127.0.0.1", lab.dns_port))
        assert lab.generate()["udp_dns"]["ok"]


def test_sample_is_reproducible_and_explicitly_synthetic(tmp_path):
    first, second = tmp_path / "first.pcap", tmp_path / "second.pcap"
    info = _traffic_module().generate_sample(first)
    _traffic_module().generate_sample(second)
    assert info["synthetic"] is True
    assert info["source"] == "synthetic"
    assert info["packet_count"] >= 25
    assert "synthetic" in info["description"].lower()
    assert first.read_bytes() == second.read_bytes()
    assert len(_read_pcap(first)) == info["packet_count"]


def test_sample_has_valid_checksums_and_required_protocols(tmp_path):
    path = tmp_path / "sample.pcap"
    _traffic_module().generate_sample(path)
    seen = set()
    tcp_payloads = {4: [], 6: []}
    for frame in _read_pcap(path):
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype == 0x0806:
            seen.add("ARP")
            assert struct.unpack_from("!HHBB", frame, 14) == (1, 0x0800, 6, 4)
            continue
        ip = frame[14:]
        version = ip[0] >> 4
        if version == 4:
            header_length = (ip[0] & 15) * 4
            length = struct.unpack_from("!H", ip, 2)[0]
            assert length == len(ip)
            assert _checksum(ip[:header_length]) == 0
            protocol = ip[9]
            transport = ip[header_length:length]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, protocol, len(transport))
        else:
            assert version == 6
            assert struct.unpack_from("!H", ip, 4)[0] == len(ip) - 40
            protocol = ip[6]
            transport = ip[40:]
            pseudo = ip[8:40] + struct.pack("!I3xB", len(transport), protocol)
        seen.add((version, protocol))
        if protocol in (6, 17, 58):
            assert _checksum(pseudo + transport) == 0
        elif protocol == 1:
            assert _checksum(transport) == 0
        if protocol == 6:
            payload = transport[(transport[12] >> 4) * 4 :]
            if payload:
                sequence = struct.unpack_from("!I", transport, 4)[0]
                tcp_payloads[version].append((sequence, payload))
        if protocol == 17:
            assert struct.unpack_from("!H", transport, 4)[0] == len(transport)
            assert struct.unpack_from("!H", transport, 6)[0] != 0
    assert seen >= {"ARP", (4, 6), (4, 17), (4, 1), (6, 6), (6, 17), (6, 58)}
    for payloads in tcp_payloads.values():
        assert any(payload.startswith(b"GET /lab1a.txt") for _, payload in payloads)
        assert any(payload.startswith(b"HTTP/1.1 200") for _, payload in payloads)
        assert len(set(payloads)) < len(payloads), "missing TCP retransmission"
        response = [(seq, data) for seq, data in payloads if seq >= 9001]
        sequences = [seq for seq, _ in response]
        assert sequences != sorted(sequences), "missing out-of-order TCP segment"


def test_sample_preserves_ethernet_addresses_in_both_ip_directions(tmp_path):
    path = tmp_path / "sample.pcap"
    _traffic_module().generate_sample(path)
    expected_source_macs = {
        socket.inet_pton(socket.AF_INET, "192.0.2.10"): bytes.fromhex("020000000001"),
        socket.inet_pton(socket.AF_INET, "198.51.100.20"): bytes.fromhex("020000000002"),
        socket.inet_pton(socket.AF_INET6, "2001:db8::1"): bytes.fromhex("020000000001"),
        socket.inet_pton(socket.AF_INET6, "2001:db8::20"): bytes.fromhex("020000000002"),
    }
    for frame in _read_pcap(path):
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype == 0x0800:
            source, destination = frame[26:30], frame[30:34]
        elif ethertype == 0x86DD:
            source, destination = frame[22:38], frame[38:54]
        else:
            continue
        assert frame[6:12] == expected_source_macs[source]
        assert frame[:6] == expected_source_macs[destination]


def test_cli_outputs_json_for_synthetic_sample(tmp_path):
    path = tmp_path / "cli.pcap"
    result = subprocess.run(
        [sys.executable, "-m", "tools.lab_traffic", "--sample", str(path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["synthetic"] is True
    assert path.is_file()
