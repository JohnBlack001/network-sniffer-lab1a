import os
import struct
from queue import Queue
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from sniffer.ui import MainWindow


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def write_fixture(path):
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip_tcp = b"\x45\x00\x00\x2b\x00\x01\x00\x00\x40\x06\x00\x00" + bytes([127, 0, 0, 1, 127, 0, 0, 2])
    tcp = struct.pack("!HHIIHHHH", 12345, 80, 100, 0, 0x5018, 65535, 0, 0) + b"abc"
    ip_udp = b"\x45\x00\x00\x1c\x00\x02\x00\x00\x40\x11\x00\x00" + bytes([127, 0, 0, 2, 127, 0, 0, 1])
    udp = struct.pack("!HHHH", 5353, 9999, 8, 0)
    packets = [ethernet + ip_tcp + tcp, ethernet + ip_udp + udp]
    content = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, data in enumerate(packets):
        content += struct.pack("<IIII", 1700000000 + index, 0, len(data), len(data)) + data
    path.write_bytes(content)


@pytest.fixture
def window(app, monkeypatch):
    import sniffer.ui as ui
    monkeypatch.setattr(ui, "list_interfaces", lambda: [SimpleNamespace(name="test0", description="测试网卡", addresses=("127.0.0.1",), flags=0)])
    result = MainWindow()
    yield result
    result.close()
    app.processEvents()


def test_load_filter_select_and_save_preserves_original_packets(window, tmp_path):
    capture = tmp_path / "input.pcap"
    output = tmp_path / "output.pcap"
    write_fixture(capture)
    assert window.load_capture(capture)
    assert len(window.packets) == 2
    assert window.packet_table.rowCount() == 2
    window.protocol_combo.setCurrentText("TCP")
    window.apply_filter()
    assert window.packet_table.rowCount() == 1
    assert len(window.packets) == 2
    window.select_packet(0)
    assert window.detail_tree.topLevelItemCount() >= 3
    assert "61 62 63" in window.hex_view.toPlainText()
    assert window.save_capture(output)
    from sniffer.pcap_io import read_pcap
    assert len(read_pcap(output)) == 2
    window.protocol_combo.setCurrentIndex(0)
    window.filter_edit.setText("udp")
    window.apply_filter()
    assert window.packet_table.rowCount() == 1
    assert window.packets[1].protocol == "UDP"


def test_filter_and_file_errors_are_readable_without_losing_packets(window, tmp_path):
    capture = tmp_path / "input.pcap"
    write_fixture(capture)
    window.load_capture(capture)
    window.filter_edit.setText("tcp and (")
    assert window.apply_filter() is False
    assert window.packet_table.rowCount() == 2
    assert "错误" in window.status_label.text()
    assert window.load_capture(tmp_path / "missing.pcap") is False
    assert len(window.packets) == 2


class FakeWorker(QObject):
    error = Signal(str)
    status = Signal(str)
    finished = Signal()

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.frames = Queue()
        self.stats = {"received": 0, "dropped": 0, "interface_dropped": 0, "queue_dropped": 0}
        self.running = False

    def start(self):
        self.running = True

    def isRunning(self):
        return self.running

    def stop(self):
        self.running = False

    def wait(self, timeout=3000):
        return not self.running


def test_async_capture_error_restores_controls(window, monkeypatch, app):
    import sniffer.ui as ui
    monkeypatch.setattr(ui, "CaptureWorker", FakeWorker)
    window.start_capture()
    worker = window._worker
    assert not window.start_button.isEnabled()
    worker.error.emit("Npcap 测试错误")
    worker.running = False
    worker.finished.emit()
    app.processEvents()
    assert window.start_button.isEnabled()
    assert not window.stop_button.isEnabled()
    assert "Npcap" in window.status_label.text()


def test_loading_after_stop_discards_old_worker_queue(window, monkeypatch, tmp_path, app):
    import sniffer.ui as ui
    monkeypatch.setattr(ui, "CaptureWorker", FakeWorker)
    window.start_capture()
    old_worker = window._worker
    old_worker.frames.put(SimpleNamespace(data=b"stale", timestamp=1.0, linktype=1, wire_length=5))
    capture = tmp_path / "input.pcap"
    write_fixture(capture)
    assert window.load_capture(capture)
    window._poll_capture()
    app.processEvents()
    assert len(window.packets) == 2
    assert all(packet.raw != b"stale" for packet in window.packets)


def test_capture_memory_limit_stops_instead_of_discarding_old_packets(window, monkeypatch):
    import sniffer.ui as ui
    monkeypatch.setattr(ui, "CaptureWorker", FakeWorker)
    monkeypatch.setattr(ui, "MAX_PACKETS", 1)
    window.start_capture()
    worker = window._worker
    worker.frames.put(SimpleNamespace(data=b"one", timestamp=1.0, linktype=1, wire_length=3))
    worker.frames.put(SimpleNamespace(data=b"two", timestamp=2.0, linktype=1, wire_length=3))
    window._poll_capture()
    assert len(window.packets) == 1
    assert not worker.isRunning()
    assert "上限" in window.status_label.text()


def test_reaching_limit_without_an_extra_packet_already_stops(window, monkeypatch):
    import sniffer.ui as ui
    monkeypatch.setattr(ui, "CaptureWorker", FakeWorker)
    monkeypatch.setattr(ui, "MAX_CAPTURE_BYTES", 3)
    window.start_capture()
    worker = window._worker
    worker.frames.put(SimpleNamespace(data=b"one", timestamp=1.0, linktype=1, wire_length=3))
    window._poll_capture()
    assert len(window.packets) == 1
    assert not worker.isRunning()
    assert "上限" in window.status_label.text()


def test_stream_dialog_contains_real_payload_and_close_stops_worker(window, monkeypatch, tmp_path, app):
    import sniffer.ui as ui
    capture = tmp_path / "input.pcap"
    write_fixture(capture)
    window.load_capture(capture)
    window.select_packet(0)
    dialog = window.follow_stream()
    from PySide6.QtWidgets import QPlainTextEdit
    assert "abc" in dialog.findChild(QPlainTextEdit).toPlainText()
    assert "未捕获 SYN" in dialog.findChild(QPlainTextEdit).toPlainText()
    dialog.close()
    monkeypatch.setattr(ui, "CaptureWorker", FakeWorker)
    window.start_capture()
    worker = window._worker
    window.close()
    app.processEvents()
    assert not worker.isRunning()


def test_saving_to_unavailable_directory_does_not_lose_packets(window, tmp_path):
    capture = tmp_path / "input.pcap"
    write_fixture(capture)
    window.load_capture(capture)
    assert not window.save_capture(tmp_path / "missing" / "output.pcap")
    assert len(window.packets) == 2
    assert "保存文件错误" in window.status_label.text()
