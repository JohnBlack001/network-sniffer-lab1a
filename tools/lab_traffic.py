"""Generate real loopback traffic or an explicitly synthetic offline PCAP.

No external network or local document is used. The sample packet addresses are
reserved for documentation, and the HTTP resource is generated in memory.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import ipaddress
import json
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path


HTTP_BODY = (
    "Network Sniffer Lab 1A: controlled loopback HTTP traffic.\n\n"
    "This response is generated in memory for TCP stream reassembly.\n"
)
_CLIENT_MAC = bytes.fromhex("020000000001")
_SERVER_MAC = bytes.fromhex("020000000002")


class _HTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(1.0)
        super().setup()

    def do_GET(self):
        body = HTTP_BODY.encode("utf-8") if self.path == "/lab1a.txt" else b"Not found\n"
        self.send_response(200 if self.path == "/lab1a.txt" else 404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        midpoint = len(body) // 2
        self.wfile.write(body[:midpoint])
        self.wfile.flush()
        time.sleep(0.02)
        self.wfile.write(body[midpoint:])
        self.close_connection = True

    def log_message(self, format, *args):
        pass


class _HTTPServer(http.server.HTTPServer):
    """A single daemon worker with explicit ownership of accepted sockets."""

    allow_reuse_address = True

    def __init__(self, address, family=socket.AF_INET):
        self.address_family = family
        self._clients = set()
        self._clients_lock = threading.Lock()
        super().__init__(address, _HTTPHandler)

    def get_request(self):
        connection, address = super().get_request()
        with self._clients_lock:
            self._clients.add(connection)
        return connection, address

    def close_request(self, request):
        with self._clients_lock:
            self._clients.discard(request)
        super().close_request(request)

    def close_clients(self):
        with self._clients_lock:
            clients = tuple(self._clients)
        for connection in clients:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def handle_error(self, request, client_address):
        # A peer may close a split request while the lab context is shutting down.
        pass


def _dns_query(name="lab1a.local", query_type=1):
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1A01, 0x0100, 1, 0, 0, 0) + question + b"\0" + struct.pack("!HH", query_type, 1)


def _dns_answer(query, address="192.0.2.10"):
    if len(query) < 17:
        return None
    identifier, flags, questions, _, _, _ = struct.unpack_from("!HHHHHH", query)
    if flags & 0xF800 or questions != 1:
        return None
    offset = 12
    while offset < len(query) and query[offset]:
        length = query[offset]
        if length > 63 or offset + length + 1 >= len(query):
            return None
        offset += length + 1
    if offset + 5 > len(query) or offset - 12 > 254:
        return None
    question_end = offset + 5
    query_type, query_class = struct.unpack_from("!HH", query, offset + 1)
    answer_address = ipaddress.ip_address(address)
    answer_type = 1 if answer_address.version == 4 else 28
    supported = query_type == answer_type and query_class == 1
    header = struct.pack("!HHHHHH", identifier, 0x8080 | (flags & 0x0100), 1, int(supported), 0, 0)
    answer = b""
    if supported:
        answer = struct.pack("!HHHIH", 0xC00C, answer_type, 1, 60, len(answer_address.packed)) + answer_address.packed
    return header + query[12:question_end] + answer


class TrafficLab:
    """Own short-lived HTTP/DNS listeners used by a real capture demonstration.

    IPv4 HTTP and DNS startup failures are reported to the caller. IPv6 is
    optional: inspect ``ipv6_available`` or the generate result for its reason.
    Pass port zero to let the OS select an unused port for automated tests.
    """

    def __init__(self, http_port=8765, dns_port=53535, enable_ipv6=True):
        self.http_port = http_port
        self.dns_port = dns_port
        self.ipv6_port = None
        self.ipv6_available = False
        self.ipv6_unavailable_reason = "IPv6 disabled"
        self._enable_ipv6 = enable_ipv6
        self._http_servers = []
        self._threads = []
        self._dns_socket = None
        self._stop = threading.Event()
        self._active = False

    def __enter__(self):
        if self._active:
            raise RuntimeError("TrafficLab context is already active")
        self._stop.clear()
        try:
            server = _HTTPServer(("127.0.0.1", self.http_port))
            self.http_port = server.server_address[1]
            self._start_http(server, "lab1a-http4")
            if self._enable_ipv6:
                try:
                    server6 = _HTTPServer(("::1", self.http_port), socket.AF_INET6)
                except OSError as error:
                    self.ipv6_unavailable_reason = str(error)
                else:
                    self.ipv6_port = server6.server_address[1]
                    self.ipv6_available = True
                    self._start_http(server6, "lab1a-http6")
            self._dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_socket.bind(("127.0.0.1", self.dns_port))
            self._dns_socket.settimeout(0.1)
            self.dns_port = self._dns_socket.getsockname()[1]
            thread = threading.Thread(target=self._serve_dns, name="lab1a-dns", daemon=True)
            self._threads.append(thread)
            thread.start()
            self._active = True
            return self
        except BaseException:
            self.close()
            raise

    def _start_http(self, server, name):
        self._http_servers.append(server)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, name=name, daemon=True)
        self._threads.append(thread)
        thread.start()

    def _serve_dns(self):
        listener = self._dns_socket
        while not self._stop.is_set():
            try:
                query, peer = listener.recvfrom(4096)
                answer = _dns_answer(query)
                if answer is not None:
                    listener.sendto(answer, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self._active = False
        self._stop.set()
        if self._dns_socket is not None:
            self._dns_socket.close()
        for server in self._http_servers:
            server.close_clients()
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self._http_servers.clear()
        self._threads.clear()
        self._dns_socket = None

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @staticmethod
    def _request_http(host, port, family):
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect((host, port))
            request = b"GET /lab1a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            client.sendall(request[:24])
            time.sleep(0.02)
            client.sendall(request[24:])
            response = http.client.HTTPResponse(client)
            try:
                response.begin()
                body = response.read().decode("utf-8")
                return {"available": True, "ok": response.status == 200 and body == HTTP_BODY,
                        "status": response.status, "body": body, "port": port}
            finally:
                response.close()

    def generate(self, include_ping=False):
        if not self._active:
            raise RuntimeError("TrafficLab.generate requires an active context")
        result = {"source": "real-loopback"}
        result["ipv4_http"] = self._request_http("127.0.0.1", self.http_port, socket.AF_INET)
        if self.ipv6_available:
            result["ipv6_http"] = self._request_http("::1", self.ipv6_port, socket.AF_INET6)
        else:
            result["ipv6_http"] = {"available": False, "ok": False, "reason": self.ipv6_unavailable_reason}
        query = _dns_query()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.connect(("127.0.0.1", self.dns_port))
            client.send(query)
            answer = client.recv(4096)
        valid = (len(answer) == len(query) + 16 and answer[:2] == query[:2]
                 and struct.unpack_from("!H", answer, 2)[0] & 0x8000
                 and struct.unpack_from("!H", answer, 6)[0] == 1)
        address = socket.inet_ntoa(answer[-4:]) if valid else None
        result["udp_dns"] = {"available": True, "ok": bool(valid and address == "192.0.2.10"),
                             "question": "lab1a.local", "answer": address, "port": self.dns_port}
        result["ping"] = {"requested": bool(include_ping)}
        if include_ping:
            for key, host in (("ipv4", "127.0.0.1"), ("ipv6", "::1")):
                command = ["ping", "-n", "1", "-w", "500", host] if os.name == "nt" else ["ping", "-c", "1", "-W", "1", host]
                try:
                    ping = subprocess.run(command, capture_output=True, timeout=2, check=False)
                    result["ping"][key] = {"ok": ping.returncode == 0, "returncode": ping.returncode}
                except (OSError, subprocess.TimeoutExpired) as error:
                    result["ping"][key] = {"ok": False, "reason": str(error)}
        return result


def _checksum(data):
    padded = data + (b"\0" if len(data) % 2 else b"")
    total = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _network_packet(source, destination, protocol, transport, identifier):
    source_ip, destination_ip = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    reverse = str(source_ip) in {"198.51.100.20", "2001:db8::20"}
    ethernet = (_CLIENT_MAC + _SERVER_MAC if reverse else _SERVER_MAC + _CLIENT_MAC)
    if source_ip.version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), identifier,
                             0x4000, 64, protocol, 0, source_ip.packed, destination_ip.packed)
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        return ethernet + b"\x08\x00" + header + transport
    header = struct.pack("!IHBB16s16s", 6 << 28, len(transport), protocol, 64, source_ip.packed, destination_ip.packed)
    return ethernet + b"\x86\xdd" + header + transport


def _checked_transport(source, destination, protocol, transport, checksum_offset):
    source_ip, destination_ip = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if source_ip.version == 4:
        pseudo = source_ip.packed + destination_ip.packed + struct.pack("!BBH", 0, protocol, len(transport))
    else:
        pseudo = source_ip.packed + destination_ip.packed + struct.pack("!I3xB", len(transport), protocol)
    checksum = _checksum(pseudo + transport)
    if protocol == 17 and checksum == 0:
        checksum = 0xFFFF
    return transport[:checksum_offset] + struct.pack("!H", checksum) + transport[checksum_offset + 2:]


def _sample_packets():
    packets = []
    client4, server4 = "192.0.2.10", "198.51.100.20"
    client6, server6 = "2001:db8::1", "2001:db8::20"
    for reply in (False, True):
        sender_mac, target_mac = (_SERVER_MAC, _CLIENT_MAC) if reply else (_CLIENT_MAC, b"\0" * 6)
        sender_ip, target_ip = (server4, client4) if reply else (client4, server4)
        ethernet = (_CLIENT_MAC if reply else b"\xff" * 6) + sender_mac + b"\x08\x06"
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2 if reply else 1,
                          sender_mac, socket.inet_aton(sender_ip), target_mac, socket.inet_aton(target_ip))
        packets.append(ethernet + arp)

    def add(source, destination, protocol, data):
        packets.append(_network_packet(source, destination, protocol, data, len(packets) + 1))

    def tcp(source, destination, source_port, destination_port, sequence, acknowledgement, flags, payload=b""):
        segment = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence,
                              acknowledgement, 5 << 4, flags, 32768, 0, 0) + payload
        add(source, destination, 6, _checked_transport(source, destination, 6, segment, 16))

    request = b"GET /lab1a.txt HTTP/1.1\r\nHost: lab1a.example\r\nConnection: close\r\n\r\n"
    body = HTTP_BODY.encode("utf-8")
    response = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body)
    for client, server, port in ((client4, server4, 41000), (client6, server6, 42000)):
        tcp(client, server, port, 80, 1000, 0, 0x02)
        tcp(server, client, 80, port, 9000, 1001, 0x12)
        tcp(client, server, port, 80, 1001, 9001, 0x10)
        tcp(client, server, port, 80, 1001, 9001, 0x18, request[:30])
        tcp(client, server, port, 80, 1031, 9001, 0x18, request[30:])
        request_end = 1001 + len(request)
        tcp(server, client, 80, port, 9001, request_end, 0x10)
        # The last portion arrives before the middle; the middle is retransmitted.
        for start, end in ((0, 80), (145, len(response)), (80, 145), (80, 145)):
            tcp(server, client, 80, port, 9001 + start, request_end, 0x18, response[start:end])
        response_end = 9001 + len(response)
        tcp(client, server, port, 80, request_end, response_end, 0x10)
        tcp(server, client, 80, port, response_end, request_end, 0x11)
        tcp(client, server, port, 80, request_end, response_end + 1, 0x11)
        tcp(server, client, 80, port, response_end + 1, request_end + 1, 0x10)

    for client, server, query_type, address in ((client4, server4, 1, client4), (client6, server6, 28, server6)):
        query = _dns_query("lab1a.example", query_type)
        answer = _dns_answer(query, address)
        for source, destination, source_port, destination_port, payload in (
            (client, server, 53000, 53, query), (server, client, 53, 53000, answer)
        ):
            datagram = struct.pack("!HHHH", source_port, destination_port, len(payload) + 8, 0) + payload
            add(source, destination, 17, _checked_transport(source, destination, 17, datagram, 6))
        for reply in (False, True):
            source, destination = (server, client) if reply else (client, server)
            version = ipaddress.ip_address(source).version
            kind = (0 if reply else 8) if version == 4 else (129 if reply else 128)
            message = struct.pack("!BBHHH", kind, 0, 0, 0x1A, 1) + b"lab1a-echo"
            if version == 4:
                message = message[:2] + struct.pack("!H", _checksum(message)) + message[4:]
            else:
                message = _checked_transport(source, destination, 58, message, 2)
            add(source, destination, 1 if version == 4 else 58, message)
    return packets


def generate_sample(path):
    """Write deterministic *synthetic*, non-live Ethernet frames as classic PCAP."""
    from sniffer.capture import CapturedFrame
    from sniffer.pcap_io import write_pcap

    packets = _sample_packets()
    frames = [CapturedFrame(data=data, timestamp=1700000000.0 + index * 0.01,
                            linktype=1, wire_length=len(data)) for index, data in enumerate(packets)]
    write_pcap(path, frames)
    return {"source": "synthetic", "synthetic": True, "path": str(Path(path)),
            "packet_count": len(frames),
            "description": "Synthetic offline protocol and TCP reassembly sample; not a live capture."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sample", metavar="PATH", help="write an explicitly synthetic PCAP")
    mode.add_argument("--generate", action="store_true", help="generate real loopback HTTP/DNS traffic")
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--dns-port", type=int, default=53535)
    parser.add_argument("--ping", action="store_true", help="also attempt one IPv4/IPv6 loopback ping")
    args = parser.parse_args(argv)
    try:
        if args.sample:
            result = generate_sample(args.sample)
        else:
            with TrafficLab(http_port=args.http_port, dns_port=args.dns_port) as lab:
                result = lab.generate(include_ping=args.ping)
    except (OSError, RuntimeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True))
        return 1
    # ASCII JSON 在 Windows 的 GBK/UTF-8 管道之间也可无损解析。
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
