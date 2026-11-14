"""Npcap/libpcap 的小型 ctypes 封装；句柄仅由抓包线程持有。"""
from __future__ import annotations

import ctypes as C
import ctypes.util
import os
import queue
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QThread, Signal


@dataclass(frozen=True)
class CapturedFrame:
    data: bytes
    timestamp: float
    linktype: int = 1
    wire_length: int | None = None

    def __post_init__(self):
        if self.wire_length is None:
            object.__setattr__(self, 'wire_length', len(self.data))


@dataclass(frozen=True)
class Interface:
    name: str
    description: str
    addresses: tuple[str, ...] = ()
    flags: int = 0


class Timeval(C.Structure):
    # Windows 的 timeval 使用两个 LONG，即使 Python/Npcap 都是 64 位。
    _fields_ = [('tv_sec', C.c_int32 if sys.platform == 'win32' else C.c_long),
                ('tv_usec', C.c_int32 if sys.platform == 'win32' else C.c_long)]


class PcapHeader(C.Structure):
    _fields_ = [('ts', Timeval), ('caplen', C.c_uint32), ('len', C.c_uint32)]


class _PcapIf(C.Structure):
    pass


_PcapIf._fields_ = [('next', C.POINTER(_PcapIf)), ('name', C.c_char_p),
                   ('description', C.c_char_p), ('addresses', C.c_void_p), ('flags', C.c_uint32)]


class _PcapAddr(C.Structure):
    pass


_PcapAddr._fields_ = [('next', C.POINTER(_PcapAddr)), ('addr', C.c_void_p),
                     ('netmask', C.c_void_p), ('broadaddr', C.c_void_p), ('dstaddr', C.c_void_p)]


class _BpfProgram(C.Structure):
    _fields_ = [('bf_len', C.c_uint), ('bf_insns', C.c_void_p)]


_library = None
_dll_directories = []


def _text(value):
    return value.decode('utf-8', errors='replace') if value else ''


def _load_library():
    global _library
    if _library is not None:
        return _library
    if sys.platform == 'win32':
        folder = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Npcap'
        if folder.is_dir():
            _dll_directories.append(os.add_dll_directory(str(folder)))
        path = str(folder / 'wpcap.dll') if (folder / 'wpcap.dll').is_file() else 'wpcap.dll'
    else:
        path = ctypes.util.find_library('pcap')
        if not path:
            raise RuntimeError('未找到 libpcap。请安装 libpcap 后再启动实时抓包。')
    try:
        lib = C.CDLL(path)
    except OSError as exc:
        raise RuntimeError('无法加载 Npcap。请安装与 Python 位数一致的 Npcap；离线 PCAP 仍可打开。') from exc
    signatures = {
        'pcap_findalldevs': ([C.POINTER(C.POINTER(_PcapIf)), C.c_char_p], C.c_int),
        'pcap_freealldevs': ([C.POINTER(_PcapIf)], None),
        'pcap_open_live': ([C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p], C.c_void_p),
        'pcap_close': ([C.c_void_p], None),
        'pcap_datalink': ([C.c_void_p], C.c_int),
        'pcap_next_ex': ([C.c_void_p, C.POINTER(C.POINTER(PcapHeader)),
                          C.POINTER(C.POINTER(C.c_ubyte))], C.c_int),
        'pcap_setnonblock': ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
        'pcap_compile': ([C.c_void_p, C.POINTER(_BpfProgram), C.c_char_p, C.c_int, C.c_uint32], C.c_int),
        'pcap_setfilter': ([C.c_void_p, C.POINTER(_BpfProgram)], C.c_int),
        'pcap_freecode': ([C.POINTER(_BpfProgram)], None),
        'pcap_geterr': ([C.c_void_p], C.c_char_p),
        'pcap_stats': ([C.c_void_p, C.c_void_p], C.c_int),
        'pcap_lib_version': ([], C.c_char_p),
    }
    for name, (args, result) in signatures.items():
        function = getattr(lib, name)
        function.argtypes, function.restype = args, result
    _library = lib
    return lib


def capture_version():
    return _text(_load_library().pcap_lib_version())


def list_interfaces() -> list[Interface]:
    lib = _load_library()
    devices = C.POINTER(_PcapIf)()
    error = C.create_string_buffer(256)
    if lib.pcap_findalldevs(C.byref(devices), error) != 0:
        raise RuntimeError('枚举网卡失败：' + _text(error.value))
    result = []
    try:
        current = devices
        while current:
            item = current.contents
            addresses = []
            address = C.cast(item.addresses, C.POINTER(_PcapAddr))
            while address:
                ptr = address.contents.addr
                if ptr:
                    family = C.c_ushort.from_address(ptr).value
                    if family == socket.AF_INET:
                        addresses.append(socket.inet_ntop(socket.AF_INET, C.string_at(ptr + 4, 4)))
                    elif family == socket.AF_INET6:
                        addresses.append(socket.inet_ntop(socket.AF_INET6, C.string_at(ptr + 8, 16)))
                address = address.contents.next
            name = _text(item.name)
            result.append(Interface(name, _text(item.description) or name, tuple(addresses), item.flags))
            current = item.next
    finally:
        lib.pcap_freealldevs(devices)
    return result


class CaptureDevice:
    """打开/读取/关闭均在同一线程调用，可用于 GUI 和真实抓包验证。"""

    def __init__(self, interface_name: str, bpf: str = '', promiscuous: bool = True):
        self.lib = _load_library()
        self.handle = None
        error = C.create_string_buffer(256)
        self.handle = self.lib.pcap_open_live(interface_name.encode('utf-8'), 65535,
                                               int(promiscuous), 100, error)
        if not self.handle:
            raise RuntimeError('打开网卡失败：' + _text(error.value) + '。请检查网卡及抓包权限。')
        try:
            self.linktype = self.lib.pcap_datalink(self.handle)
            if self.lib.pcap_setnonblock(self.handle, 1, error) != 0:
                raise RuntimeError('设置非阻塞抓包失败：' + _text(error.value))
            if bpf.strip():
                program = _BpfProgram()
                if self.lib.pcap_compile(self.handle, C.byref(program), bpf.encode('utf-8'), 1, 0xffffffff) < 0:
                    raise ValueError('BPF 表达式错误：' + _text(self.lib.pcap_geterr(self.handle)))
                try:
                    if self.lib.pcap_setfilter(self.handle, C.byref(program)) < 0:
                        raise ValueError('设置 BPF 失败：' + _text(self.lib.pcap_geterr(self.handle)))
                finally:
                    self.lib.pcap_freecode(C.byref(program))
        except Exception:
            self.close()
            raise

    def read(self) -> CapturedFrame | None:
        header = C.POINTER(PcapHeader)()
        data = C.POINTER(C.c_ubyte)()
        result = self.lib.pcap_next_ex(self.handle, C.byref(header), C.byref(data))
        if result == 0:
            return None
        if result < 0:
            raise RuntimeError('读取抓包失败：' + _text(self.lib.pcap_geterr(self.handle)))
        h = header.contents
        if h.caplen > 65535 or h.caplen > h.len or not 0 <= h.ts.tv_usec < 1000000:
            raise RuntimeError('Npcap 返回了无效包头，请检查驱动与 Python 架构。')
        return CapturedFrame(C.string_at(data, h.caplen), h.ts.tv_sec + h.ts.tv_usec / 1000000,
                             self.linktype, h.len)

    def statistics(self):
        # Windows pcap_stat 在前三项后含扩展字段，预留空间避免 ABI 越界。
        buffer = (C.c_uint32 * 32)()
        if self.lib.pcap_stats(self.handle, buffer) != 0:
            return {}
        return dict(received=int(buffer[0]), dropped=int(buffer[1]), interface_dropped=int(buffer[2]))

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class CaptureWorker(QThread):
    error = Signal(str)
    status = Signal(str)

    def __init__(self, interface_name: str, bpf: str = '', promiscuous: bool = True):
        super().__init__()
        self.interface_name, self.bpf, self.promiscuous = interface_name, bpf, promiscuous
        self.frames: queue.Queue[CapturedFrame] = queue.Queue(maxsize=4096)
        self._stop_event = threading.Event()
        self._stats = dict(received=0, dropped=0, interface_dropped=0, queue_dropped=0)

    @property
    def stats(self):
        return dict(self._stats)

    def stop(self):
        self._stop_event.set()

    def run(self):
        try:
            with CaptureDevice(self.interface_name, self.bpf, self.promiscuous) as device:
                self.status.emit('正在实时抓包')
                last_stats = time.monotonic()
                while not self._stop_event.is_set():
                    frame = device.read()
                    if frame is None:
                        self._stop_event.wait(0.01)
                    else:
                        try:
                            self.frames.put_nowait(frame)
                        except queue.Full:
                            self._stats['queue_dropped'] += 1
                    if time.monotonic() - last_stats >= 0.5:
                        self._stats.update(device.statistics())
                        last_stats = time.monotonic()
                self._stats.update(device.statistics())
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.status.emit('抓包已停止')
