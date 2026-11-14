"""经典 PCAP 读写：不执行文件中的内容，所有长度先校验再读取。"""
from __future__ import annotations

import math
import os
import struct
import tempfile
from pathlib import Path

from .capture import CapturedFrame

MAX_PACKETS = 10000
MAX_BYTES = 64 * 1024 * 1024
_MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
          b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}


def read_pcap(path) -> list[CapturedFrame]:
    with open(path, 'rb') as stream:
        header = stream.read(24)
        if len(header) < 24 or header[:4] not in _MAGIC:
            raise ValueError('不是支持的经典 PCAP 文件（PCAPNG 请先转换为 PCAP）。')
        endian, scale = _MAGIC[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_BYTES:
            raise ValueError('PCAP 版本或快照长度无效。')
        # PCAP 的高位可携带 FCS 元信息，链路类型位于低16位。
        linktype = network & 0xffff
        frames, total = [], 0
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError('PCAP 包头被截断。')
            sec, fraction, length, original = struct.unpack(endian + 'IIII', record)
            if fraction >= scale or length > snaplen or length > original:
                raise ValueError('PCAP 数据包长度或时间戳无效。')
            total += length
            if len(frames) >= MAX_PACKETS or total > MAX_BYTES:
                raise ValueError('PCAP 超过 10000 包或 64 MiB 限额，请先分割文件。')
            data = stream.read(length)
            if len(data) != length:
                raise ValueError('PCAP 数据包被截断。')
            frames.append(CapturedFrame(data, sec + fraction / scale, linktype, original))
        return frames


def write_pcap(path, frames):
    frames = list(frames)
    if len(frames) > MAX_PACKETS or sum(len(f.data) for f in frames) > MAX_BYTES:
        raise ValueError('数据超过 10000 包或 64 MiB 保存限额。')
    linktype = frames[0].linktype if frames else 1
    if any(f.linktype != linktype for f in frames):
        raise ValueError('同一个 PCAP 文件不能混合不同链路类型。')
    if not 0 <= linktype <= 65535:
        raise ValueError('无效的链路类型。')
    # 校验全部帧后再写临时文件，避免错误输入破坏已有抓包。
    for frame in frames:
        if (not math.isfinite(frame.timestamp) or not 0 <= frame.timestamp < 2 ** 32
                or round(frame.timestamp * 1000000) >= 2 ** 32 * 1000000):
            raise ValueError('时间戳超出经典 PCAP 的范围。')
        if not len(frame.data) <= frame.wire_length <= 0xffffffff:
            raise ValueError('原始包长不能小于捕获长度。')
    target = Path(path)
    fd, temp_path = tempfile.mkstemp(prefix='.' + target.name + '-', suffix='.tmp', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            snaplen = max(65535, max((len(f.data) for f in frames), default=0))
            stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
            for frame in frames:
                micros = round(frame.timestamp * 1000000)
                sec, usec = divmod(micros, 1000000)
                stream.write(struct.pack('<IIII', sec, usec, len(frame.data), frame.wire_length))
                stream.write(frame.data)
        os.replace(temp_path, target)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
