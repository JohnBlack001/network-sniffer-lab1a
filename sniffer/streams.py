"""Bidirectional TCP conversations and conservative sequence reassembly."""

from dataclasses import dataclass, field

import psutil


STREAM_PREVIEW_BYTES = 256 * 1024


def _endpoint(packet, source=True):
    return (packet.src, packet.src_port) if source else (packet.dst, packet.dst_port)


def _label(endpoint):
    address, port = endpoint
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _sequence_delta(sequence, anchor):
    return ((sequence - anchor + (1 << 31)) % (1 << 32)) - (1 << 31)


def _display_bytes(data):
    text = data.decode("utf-8", errors="replace")
    return "".join(character if character.isprintable() or character in "\n\r\t"
                   else f"\\x{ord(character):02x}" for character in text)


@dataclass
class TCPStream:
    id: int
    endpoint_a: tuple
    endpoint_b: tuple
    packets: list = field(default_factory=list)
    _processes: list | None = field(default=None, repr=False)
    _initial_syn: tuple | None = field(default=None, repr=False)

    def _reassemble(self, endpoint):
        packets = [packet for packet in self.packets if _endpoint(packet) == endpoint]
        syn = next((packet for packet in packets if packet.tcp_flags & 0x02), None)
        payload_packets = [packet for packet in packets if packet.payload]
        if not payload_packets:
            return [], 0, syn is not None
        anchor = ((syn.tcp_seq + 1) & 0xFFFFFFFF) if syn else payload_packets[0].tcp_seq
        segments = []
        for order, packet in enumerate(payload_packets):
            sequence = (packet.tcp_seq + bool(packet.tcp_flags & 0x02)) & 0xFFFFFFFF
            segments.append((_sequence_delta(sequence, anchor), order, packet.payload))
        segments.sort(key=lambda value: (value[0], value[1]))
        cursor = min(0, segments[0][0]) if syn else segments[0][0]
        chunks = []
        contiguous = []
        overlap = 0
        for start, _, payload in segments:
            if start > cursor:
                if contiguous:
                    chunks.append(b"".join(contiguous))
                    contiguous.clear()
                chunks.append(start - cursor)
                cursor = start
            skip = min(len(payload), max(0, cursor - start))
            overlap += skip
            remaining = payload[skip:]
            if remaining:
                contiguous.append(remaining)
                cursor = start + len(payload)
        if contiguous:
            chunks.append(b"".join(contiguous))
        return chunks, overlap, syn is not None

    @property
    def byte_count(self):
        return sum(len(chunk) for endpoint in (self.endpoint_a, self.endpoint_b)
                   for chunk in self._reassemble(endpoint)[0] if isinstance(chunk, bytes))

    @property
    def processes(self):
        if self._processes is None:
            names = set()
            try:
                for connection in psutil.net_connections(kind="tcp"):
                    if not connection.laddr or connection.pid is None or connection.pid <= 0:
                        continue
                    local = (connection.laddr[0], connection.laddr[1])
                    remote = (connection.raddr[0], connection.raddr[1]) if connection.raddr else None
                    endpoints = (self.endpoint_a, self.endpoint_b)
                    if local not in endpoints or remote not in endpoints:
                        continue
                    try:
                        names.add(f"{psutil.Process(connection.pid).name()} (PID {connection.pid})")
                    except (psutil.Error, OSError):
                        names.add(f"未知进程名 (PID {connection.pid})")
                self._processes = sorted(names) or ["未知（连接已结束、非本机连接或权限不足）"]
            except (psutil.Error, OSError, RuntimeError):
                self._processes = ["未知（无法读取本机连接，可能权限不足）"]
        return self._processes

    def render(self):
        directions = {endpoint: self._reassemble(endpoint) for endpoint in (self.endpoint_a, self.endpoint_b)}
        size = sum(len(chunk) for chunks, _, _ in directions.values() for chunk in chunks if isinstance(chunk, bytes))
        lines = [f"TCP 流 #{self.id}  {_label(self.endpoint_a)} ↔ {_label(self.endpoint_b)}",
                 f"捕获包数：{len(self.packets)}    去重有效载荷：{size} 字节",
                 "进程：" + "；".join(self.processes),
                 "按方向与序列号重组；重传/重叠字节去重，缺口明确保留。",
                 "文本以 UTF-8 容错显示；TLS 等加密内容无法还原为明文。",
                 "边界：新 SYN 建立新流；未捕获新 SYN 时无法可靠区分四元组复用。",
                 "仅标注已观察序列号之间的缺口，尾部缺失无法判断；跨度超过 2³¹ 字节时可能有歧义。"]
        for source, destination in ((self.endpoint_a, self.endpoint_b), (self.endpoint_b, self.endpoint_a)):
            chunks, overlap, has_syn = directions[source]
            lines.extend(["", f"── {_label(source)} → {_label(destination)} ──"])
            if not has_syn:
                lines.append("[未捕获 SYN：捕获可能从连接中途开始，起始缺失量未知]")
            if overlap:
                lines.append(f"[重传/重叠已去重：{overlap} 字节；重叠时保留排序后的首段]")
            if not chunks:
                lines.append("[该方向没有捕获到应用数据]")
            else:
                remaining = STREAM_PREVIEW_BYTES
                for chunk in chunks:
                    if remaining == 0:
                        break
                    if isinstance(chunk, int):
                        lines.append(f"[缺失 {chunk} 字节]")
                    else:
                        preview = chunk[:remaining]
                        lines.append(_display_bytes(preview))
                        remaining -= len(preview)
                direction_size = sum(len(chunk) for chunk in chunks if isinstance(chunk, bytes))
                if direction_size > STREAM_PREVIEW_BYTES:
                    lines.append(f"[预览已截断：该方向显示前 {STREAM_PREVIEW_BYTES:,} / {direction_size:,} 字节；完整原始数据仍可保存为 PCAP。]")
        return "\n".join(lines)


class StreamTracker:
    def __init__(self):
        self._streams = []
        self._latest = {}
        self._packet_streams = {}

    def add(self, packet):
        if packet.transport != "TCP" or packet.tcp_seq is None:
            return
        source, destination = _endpoint(packet), _endpoint(packet, False)
        if source[1] is None or destination[1] is None:
            return
        key = tuple(sorted((source, destination)))
        stream = self._latest.get(key)
        opening_syn = bool(packet.tcp_flags & 0x02) and not bool(packet.tcp_flags & 0x10)
        signature = (source, packet.tcp_seq)
        new_connection = stream is not None and opening_syn and (
            stream._initial_syn != signature or any(previous.tcp_flags & 0x05 for previous in stream.packets))
        if stream is None or new_connection:
            stream = TCPStream(len(self._streams) + 1, source, destination)
            self._streams.append(stream)
            self._latest[key] = stream
        if opening_syn:
            stream._initial_syn = signature
        stream.packets.append(packet)
        self._packet_streams[id(packet)] = stream

    def list_streams(self):
        return list(self._streams)

    def get_stream(self, packet):
        return self._packet_streams.get(id(packet))
