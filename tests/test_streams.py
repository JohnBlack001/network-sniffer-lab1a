from types import SimpleNamespace

from sniffer.streams import StreamTracker


def tcp(seq, payload=b"", reverse=False, flags=0x18):
    return SimpleNamespace(
        number=1, timestamp=0.0, raw=b"", wire_length=len(payload), linktype=1,
        src="127.0.0.1" if not reverse else "127.0.0.2",
        dst="127.0.0.2" if not reverse else "127.0.0.1",
        src_port=12345 if not reverse else 80,
        dst_port=80 if not reverse else 12345,
        protocol="TCP", transport="TCP", network="IPv4", summary="TCP",
        layers=[], payload=payload, tcp_seq=seq, tcp_ack=0,
        tcp_flags=flags, errors=[],
    )


def test_out_of_order_retransmissions_and_both_directions():
    tracker = StreamTracker()
    packets = [tcp(100, flags=2), tcp(106, b"world"), tcp(101, b"hello"),
               tcp(103, b"llo"), tcp(501, b"OK", reverse=True)]
    for packet in packets:
        tracker.add(packet)
    stream = tracker.get_stream(packets[0])
    assert len(tracker.list_streams()) == 1
    assert stream.byte_count == 12
    rendered = stream.render()
    assert "helloworld" in rendered
    assert "OK" in rendered
    assert "12345" in rendered and "80" in rendered
    assert "重传" in rendered


def test_gap_and_missing_connection_start_are_explicit():
    tracker = StreamTracker()
    first = tcp(100, b"abc")
    tracker.add(first)
    tracker.add(tcp(110, b"xyz"))
    rendered = tracker.get_stream(first).render()
    assert "缺失 7 字节" in rendered
    assert "未捕获 SYN" in rendered
    assert "abc" in rendered and "xyz" in rendered


def test_sequence_wrap_and_new_syn_separate_connections():
    tracker = StreamTracker()
    first = tcp(0xFFFFFFFC, flags=2)
    tracker.add(first)
    tracker.add(tcp(0xFFFFFFFD, b"abc"))
    tracker.add(tcp(0, b"def"))
    assert "abcdef" in tracker.get_stream(first).render()
    tracker.add(tcp(200, flags=2))
    assert len(tracker.list_streams()) == 2


def test_syn_with_payload_consumes_sequence_number():
    tracker = StreamTracker()
    first = tcp(10, b"ab", flags=2)
    tracker.add(first)
    tracker.add(tcp(13, b"cd"))
    assert "abcd" in tracker.get_stream(first).render()


def test_new_syn_splits_a_previously_midstream_capture():
    tracker = StreamTracker()
    first = tcp(100, b"old")
    new = tcp(900, flags=2)
    tracker.add(first)
    tracker.add(new)
    assert tracker.get_stream(first) is not tracker.get_stream(new)
    assert len(tracker.list_streams()) == 2


def test_syn_retransmission_stays_in_stream_but_syn_after_close_opens_new():
    tracker = StreamTracker()
    first = tcp(100, flags=2)
    tracker.add(first)
    retransmission = tcp(100, flags=2)
    tracker.add(retransmission)
    assert tracker.get_stream(first) is tracker.get_stream(retransmission)
    tracker.add(tcp(101, flags=0x14))
    restart = tcp(100, flags=2)
    tracker.add(restart)
    assert tracker.get_stream(first) is not tracker.get_stream(restart)


def test_non_tcp_and_process_permission_failure_are_safe(monkeypatch):
    tracker = StreamTracker()
    packet = tcp(10)
    packet.transport = "UDP"
    tracker.add(packet)
    assert tracker.list_streams() == []
    assert tracker.get_stream(packet) is None
    packet.transport = "TCP"
    tracker.add(packet)
    import sniffer.streams as streams
    def denied(*args, **kwargs):
        raise PermissionError("denied")
    monkeypatch.setattr(streams.psutil, "net_connections", denied)
    assert any("未知" in value for value in tracker.get_stream(packet).processes)
