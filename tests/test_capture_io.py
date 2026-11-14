import ctypes
import math
import struct

import pytest

from sniffer.capture import CapturedFrame, PcapHeader
from sniffer.pcap_io import read_pcap, write_pcap


def test_windows_pcap_header_matches_npcap_abi():
    assert ctypes.sizeof(PcapHeader) == 16
    assert PcapHeader.caplen.offset == 8


def test_pcap_roundtrip_preserves_original_length_and_linktype(tmp_path):
    frames = [CapturedFrame(b'abcdef', 1730000000.123456, 0, 60)]
    path = tmp_path / 'capture.pcap'
    write_pcap(path, frames)
    result = read_pcap(path)
    assert result[0].data == b'abcdef'
    assert result[0].timestamp == pytest.approx(frames[0].timestamp, abs=1e-6)
    assert result[0].linktype == 0
    assert result[0].wire_length == 60


def test_reads_big_endian_nanosecond_pcap(tmp_path):
    path = tmp_path / 'nano.pcap'
    path.write_bytes(bytes.fromhex('a1b23c4d') + struct.pack('>HHIIII', 2, 4, 0, 0, 65535, 1)
                     + struct.pack('>IIII', 10, 125000000, 3, 3) + b'abc')
    assert read_pcap(path)[0].timestamp == 10.125


@pytest.mark.parametrize('data', [b'', b'1234', bytes.fromhex('0a0d0d0a'),
    struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b'partial'])
def test_rejects_truncated_or_unsupported_capture(tmp_path, data):
    path = tmp_path / 'broken.pcap'
    path.write_bytes(data)
    with pytest.raises(ValueError):
        read_pcap(path)


def test_rejects_inconsistent_record_length(tmp_path):
    path = tmp_path / 'bad.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack('<IIII', 1, 0, 100, 2) + b'ab')
    with pytest.raises(ValueError):
        read_pcap(path)


def test_cannot_save_mixed_linktypes(tmp_path):
    with pytest.raises(ValueError, match='链路'):
        write_pcap(tmp_path / 'mixed.pcap', [CapturedFrame(b'a', 1, 1), CapturedFrame(b'b', 2, 0)])


def test_rejects_timestamp_rounding_past_pcap_limit(tmp_path):
    with pytest.raises(ValueError, match='时间戳'):
        write_pcap(tmp_path / 'overflow.pcap', [CapturedFrame(b'a', math.nextafter(float(2**32), 0.0))])
