"""Qt desktop interface; capture threads hand raw frames to the GUI in batches."""

from collections import Counter
from datetime import datetime
from queue import Empty

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog,
    QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QPushButton, QPlainTextEdit, QSizePolicy, QSplitter,
    QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from .capture import CaptureWorker, list_interfaces
from .filters import compile_display_filter
from .pcap_io import read_pcap, write_pcap
from .protocols import decode_packet
from .streams import StreamTracker


MAX_PACKETS = 10_000
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
BATCH_SIZE = 200
HEX_PREVIEW_BYTES = 16_384


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope · 网络协议分析器 | 实验 1A")
        self.resize(1360, 920)
        self.setMinimumSize(1180, 780)
        self.packets = []
        self._frames = []
        self._visible_packets = []
        self._byte_count = 0
        self._worker = None
        self._tracker = StreamTracker()
        self._predicate = lambda packet: True
        self._quick_protocol = ""
        self._capture_error = ""
        self._limit_reached = False
        self._last_stats = {}
        self._dialogs = []
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._poll_capture)
        self._timer.start()
        self.refresh_interfaces()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(18, 16, 18, 12)
        layout.setSpacing(11)

        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 14, 18, 14)
        brand = QVBoxLayout()
        title = QLabel("NetScope  网络协议分析器")
        title.setObjectName("brand")
        subtitle = QLabel("实验 1A  /  实时捕获 · 协议解析 · TCP 流重组")
        subtitle.setObjectName("subtitle")
        brand.addWidget(title)
        brand.addWidget(subtitle)
        header_layout.addLayout(brand)
        header_layout.addStretch()
        self.open_button = QPushButton("打开 PCAP")
        self.save_button = QPushButton("保存全部原始包")
        self.clear_button = QPushButton("清空")
        self.open_button.clicked.connect(self._open_dialog)
        self.save_button.clicked.connect(self._save_dialog)
        self.clear_button.clicked.connect(self.clear_capture)
        for button in (self.open_button, self.save_button, self.clear_button):
            header_layout.addWidget(button)
        layout.addWidget(header)

        controls = QFrame()
        controls.setObjectName("panel")
        controls_layout = QVBoxLayout(controls)
        controls_layout.setContentsMargins(14, 12, 14, 12)
        first_row = QHBoxLayout()
        first_row.addWidget(QLabel("捕获网卡"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(420)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        first_row.addWidget(self.interface_combo, 1)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        first_row.addWidget(self.refresh_button)
        self.promiscuous_check = QCheckBox("混杂模式")
        self.promiscuous_check.setChecked(True)
        self.promiscuous_check.setToolTip("请求网卡接收可见的链路层流量；可见范围由网络与驱动决定")
        first_row.addWidget(self.promiscuous_check)
        self.start_button = QPushButton("▶  开始捕获")
        self.start_button.setObjectName("primary")
        self.stop_button = QPushButton("■  停止")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        first_row.addWidget(self.start_button)
        first_row.addWidget(self.stop_button)
        controls_layout.addLayout(first_row)

        second_row = QHBoxLayout()
        second_row.addWidget(QLabel("捕获过滤 BPF"))
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("例如 tcp port 80 / udp / host 127.0.0.1；开始捕获时生效")
        self.bpf_edit.setToolTip("BPF 在捕获时生效，被排除的包不会进入文件。显示过滤仅隐藏列表行。")
        second_row.addWidget(self.bpf_edit)
        controls_layout.addLayout(second_row)
        layout.addWidget(controls)

        cards = QHBoxLayout()
        self._stat_labels = {}
        for key, caption in (("captured", "保留数据包"), ("displayed", "当前显示"),
                             ("bytes", "原始数据量"), ("streams", "TCP 会话"), ("dropped", "丢包 / 队列")):
            card = QFrame()
            card.setObjectName("statCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(13, 9, 13, 9)
            value = QLabel("0")
            value.setObjectName("statValue")
            card_layout.addWidget(value)
            caption_label = QLabel(caption)
            caption_label.setObjectName("muted")
            card_layout.addWidget(caption_label)
            self._stat_labels[key] = value
            cards.addWidget(card)
        layout.addLayout(cards)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("显示过滤"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["全部协议", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "DNS", "TLS", "ARP"])
        self.protocol_combo.setMinimumWidth(115)
        self.protocol_combo.currentIndexChanged.connect(self.apply_filter)
        filters.addWidget(self.protocol_combo)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('例如 tcp and ip.addr == 127.0.0.1 / port == 80 / contains "GET"')
        self.filter_edit.setToolTip("支持 and、or、not、括号；ip.src/ip.dst/ip.addr、port/tcp.port/udp.port == 或 !=；contains 文本")
        self.filter_edit.returnPressed.connect(self.apply_filter)
        filters.addWidget(self.filter_edit, 1)
        self.apply_button = QPushButton("应用")
        self.apply_button.clicked.connect(self.apply_filter)
        filters.addWidget(self.apply_button)
        self.stream_button = QPushButton("跟踪 TCP 流")
        self.stream_button.clicked.connect(self.follow_stream)
        filters.addWidget(self.stream_button)
        layout.addLayout(filters)

        self.packet_table = QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels(["编号", "时间", "源地址", "目的地址", "协议", "长度", "概要"])
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(28)
        self.packet_table.setShowGrid(False)
        self.packet_table.setWordWrap(False)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((62, 115, 172, 172, 78, 65)):
            self.packet_table.setColumnWidth(column, width)
        self.packet_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.packet_table.itemSelectionChanged.connect(self._selection_changed)
        self.packet_table.itemDoubleClicked.connect(lambda item: self.follow_stream())

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["协议 / 字段", "值"])
        self.detail_tree.setColumnWidth(0, 240)
        self.detail_tree.setAlternatingRowColors(True)
        self.detail_tree.setWordWrap(True)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.hex_view.setFont(QFont("Consolas", 10))
        self.hex_view.setPlaceholderText("选择一个数据包，查看原始字节和 ASCII")
        details = QSplitter(Qt.Horizontal)
        details.addWidget(self._titled_panel("协议分层与字段", self.detail_tree))
        details.addWidget(self._titled_panel("原始字节  /  HEX + ASCII", self.hex_view))
        details.setSizes([520, 780])
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.packet_table)
        split.addWidget(details)
        split.setSizes([330, 260])
        split.setChildrenCollapsible(False)
        layout.addWidget(split, 1)

        self.protocol_summary_label = QLabel("协议分布：暂无数据")
        self.protocol_summary_label.setObjectName("muted")
        layout.addWidget(self.protocol_summary_label)
        self.status_label = QLabel("就绪 · 选择网卡开始捕获，或打开 PCAP 文件")
        self.status_label.setObjectName("status")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #f3f6fa; color: #20354a; font-family: 'Microsoft YaHei UI', 'Segoe UI'; font-size: 12px; }
            QFrame#header { background: #102c46; border-radius: 9px; }
            QLabel#brand { background: transparent; color: #f4fbff; font-size: 23px; font-weight: 650; }
            QLabel#subtitle { background: transparent; color: #a4c1d6; font-size: 11px; }
            QFrame#panel, QFrame#statCard { background: white; border: 1px solid #dfe7ef; border-radius: 7px; }
            QFrame#statCard QLabel { background: transparent; }
            QLabel#statValue { color: #126c81; font-size: 23px; font-weight: 650; }
            QLabel#muted { color: #718497; font-size: 11px; }
            QLabel#section { color: #526e87; font-size: 11px; font-weight: 600; padding: 5px 1px; }
            QPushButton { background: white; border: 1px solid #ccd9e5; border-radius: 5px; padding: 7px 13px; font-weight: 550; }
            QPushButton:hover { background: #e9f5f8; border-color: #57a7b6; }
            QPushButton:disabled { color: #9daebc; background: #edf1f5; border-color: #e0e6ec; }
            QPushButton#primary { background: #087e91; color: white; border-color: #087e91; }
            QPushButton#primary:hover { background: #076d7d; }
            QPushButton#primary:disabled { background: #a5c7ce; border-color: #a5c7ce; color: #f4f9fa; }
            QLineEdit, QComboBox { background: white; border: 1px solid #ccd9e5; border-radius: 5px; min-height: 29px; padding: 1px 8px; }
            QLineEdit:focus, QComboBox:focus { border-color: #087e91; }
            QComboBox::drop-down { border: none; width: 22px; }
            QTableWidget, QTreeWidget, QPlainTextEdit { background: white; alternate-background-color: #f5f8fb; border: 1px solid #dce5ed; border-radius: 5px; selection-background-color: #d4ebf2; selection-color: #123b54; }
            QHeaderView::section { background: #e8eff5; color: #526a80; border: none; padding: 8px 6px; font-weight: 600; }
            QTableWidget::item { padding: 3px 6px; border-bottom: 1px solid #f0f4f7; }
            QTreeWidget::item { padding: 3px; }
            QSplitter::handle { background: #e2e9f0; }
            QLabel#status { background: #e6f0f4; color: #2d6178; border-radius: 5px; padding: 8px 11px; }
            QCheckBox { background: transparent; }
        """)

    @staticmethod
    def _titled_panel(title, widget):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        label = QLabel(title)
        label.setObjectName("section")
        layout.addWidget(label)
        layout.addWidget(widget, 1)
        return panel

    def _set_status(self, message, error=False):
        self.status_label.setText(message)
        self.status_label.setStyleSheet("color: #a34332; background: #fff0e9;" if error else "")

    def refresh_interfaces(self):
        previous = self.interface_combo.currentData()
        self.interface_combo.clear()
        try:
            for interface in list_interfaces():
                addresses = ", ".join(interface.addresses)
                text = interface.description or interface.name
                if addresses:
                    text += f"  [{addresses}]"
                self.interface_combo.addItem(text, interface.name)
                self.interface_combo.setItemData(self.interface_combo.count() - 1, interface.name, Qt.ToolTipRole)
            index = self.interface_combo.findData(previous)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
            if not self.interface_combo.count():
                self._set_status("未发现可用网卡。请确认 Npcap 已安装，然后刷新。", True)
        except Exception as error:
            self._set_status(f"网卡枚举错误：{error}。请安装 Npcap（启用 WinPcap API 兼容模式）。", True)

    def _capture_controls(self, running):
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        for widget in (self.interface_combo, self.refresh_button, self.bpf_edit, self.promiscuous_check, self.clear_button):
            widget.setEnabled(not running)

    def _reset_packets(self):
        self.packets.clear()
        self._frames.clear()
        self._visible_packets.clear()
        self._byte_count = 0
        self._tracker = StreamTracker()
        self._limit_reached = False
        self._last_stats = {}
        self.packet_table.setRowCount(0)
        self.detail_tree.clear()
        self.hex_view.clear()
        self._update_statistics()

    def clear_capture(self):
        if not self._stop_and_wait():
            return False
        self._reset_packets()
        self._set_status("已清空捕获数据")
        return True

    def start_capture(self):
        if self._worker is not None and self._worker.isRunning():
            return False
        interface = self.interface_combo.currentData()
        if not interface:
            self._set_status("开始失败：请选择可用网卡，或安装 Npcap 后刷新。", True)
            return False
        if not self.apply_filter():
            return False
        if not self._stop_and_wait():
            return False
        self._reset_packets()
        self._capture_error = ""
        try:
            worker = CaptureWorker(interface, bpf=self.bpf_edit.text().strip(),
                                   promiscuous=self.promiscuous_check.isChecked())
            self._worker = worker
            worker.error.connect(self._capture_failed)
            worker.status.connect(self._capture_status)
            worker.finished.connect(self._capture_finished)
            self._capture_controls(True)
            self._set_status("正在启动捕获…")
            worker.start()
            return True
        except Exception as error:
            self._stop_and_wait()
            self._capture_controls(False)
            self._set_status(f"捕获启动错误：{error}", True)
            return False

    def stop_capture(self):
        if self._worker is not None:
            self._worker.stop()
            self.stop_button.setEnabled(False)
            if not self._limit_reached and not self._capture_error:
                self._set_status("正在停止捕获；保留的数据包仍可过滤和保存…")

    def _stop_and_wait(self):
        worker = self._worker
        if worker is None:
            return True
        worker.stop()
        if not worker.wait(3000):
            self._set_status("捕获线程尚未退出，请稍后重试。", True)
            return False
        self._release_worker(worker)
        return True

    def _release_worker(self, worker):
        """Release a stopped worker, including frames excluded by a memory limit."""
        self._last_stats = dict(worker.stats)
        if worker is self._worker:
            self._worker = None
        while True:
            try:
                worker.frames.get_nowait()
            except Empty:
                break
        worker.error.disconnect(self._capture_failed)
        worker.status.disconnect(self._capture_status)
        worker.finished.disconnect(self._capture_finished)
        worker.deleteLater()
        self._capture_controls(False)

    @Slot(str)
    def _capture_failed(self, message):
        worker = self.sender()
        if worker is not None and worker is self._worker:
            self._capture_error = str(message)
            self._set_status(f"捕获错误：{message}", True)
            worker.stop()

    @Slot(str)
    def _capture_status(self, message):
        worker = self.sender()
        if worker is not None and worker is self._worker and not self._capture_error and not self._limit_reached:
            self._set_status(str(message))

    @Slot()
    def _capture_finished(self):
        worker = self.sender()
        if worker is None or worker is not self._worker:
            return
        # Retain any final frames before releasing the finished worker.
        while not worker.frames.empty() and not self._limit_reached:
            self._poll_capture()
        self._release_worker(worker)
        self._update_statistics()
        if self._capture_error:
            self._set_status(f"捕获错误：{self._capture_error}", True)
        elif not self._limit_reached:
            self._set_status(f"捕获已停止 · 保留 {len(self.packets):,} 个数据包，可继续过滤或保存")

    def _append_frame(self, frame):
        if len(self.packets) >= MAX_PACKETS or self._byte_count + len(frame.data) > MAX_CAPTURE_BYTES:
            self._capture_limit()
            return False
        packet = decode_packet(frame.data, timestamp=frame.timestamp, linktype=frame.linktype,
                               number=len(self.packets) + 1, wire_length=frame.wire_length)
        self._frames.append(frame)
        self.packets.append(packet)
        self._byte_count += len(frame.data)
        self._tracker.add(packet)
        if self._matches(packet):
            self._append_row(packet)
        if self._worker is not None and (len(self.packets) >= MAX_PACKETS or self._byte_count >= MAX_CAPTURE_BYTES):
            self._capture_limit()
        return True

    def _capture_limit(self):
        self._limit_reached = True
        self.stop_capture()
        self._set_status(f"已达到内存上限（{MAX_PACKETS:,} 包 / {MAX_CAPTURE_BYTES // 1024 // 1024} MiB），自动停止。现有原始包已保留，请保存后清空。", True)

    def _poll_capture(self):
        worker = self._worker
        if worker is None:
            return
        self.packet_table.setUpdatesEnabled(False)
        try:
            for _ in range(BATCH_SIZE):
                try:
                    frame = worker.frames.get_nowait()
                except Empty:
                    break
                if self._limit_reached or not self._append_frame(frame):
                    break
        finally:
            self.packet_table.setUpdatesEnabled(True)
        self._last_stats = dict(worker.stats)
        self._update_statistics()

    def _matches(self, packet):
        return (not self._quick_protocol or self._quick_protocol in
                (packet.protocol.upper(), packet.transport.upper(), packet.network.upper())
                or (self._quick_protocol == "ICMP" and packet.protocol.upper().startswith("ICMP"))) and self._predicate(packet)

    def apply_filter(self):
        try:
            predicate = compile_display_filter(self.filter_edit.text().strip())
        except ValueError as error:
            self.filter_edit.setStyleSheet("border: 1px solid #c35c42; background: #fff7f3;")
            self._set_status(f"显示过滤错误：{error}。原列表已保留。", True)
            return False
        self.filter_edit.setStyleSheet("")
        self._predicate = predicate
        self._quick_protocol = "" if self.protocol_combo.currentIndex() == 0 else self.protocol_combo.currentText().upper()
        self.packet_table.setUpdatesEnabled(False)
        try:
            self.packet_table.setRowCount(0)
            self._visible_packets.clear()
            self.detail_tree.clear()
            self.hex_view.clear()
            for packet in self.packets:
                if self._matches(packet):
                    self._append_row(packet)
        finally:
            self.packet_table.setUpdatesEnabled(True)
        self._update_statistics()
        self._set_status(f"显示 {len(self._visible_packets):,} / {len(self.packets):,} 包 · 显示过滤不改变原始数据及保存内容")
        return True

    def _append_row(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self._visible_packets.append(packet)
        try:
            stamp = datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]
        except (OSError, ValueError, OverflowError):
            stamp = str(packet.timestamp)
        values = (packet.number, stamp, packet.src, packet.dst, packet.protocol, packet.wire_length, packet.summary)
        colors = {"HTTP": "#087c60", "TCP": "#25629b", "UDP": "#95631a", "DNS": "#8350a1", "TLS": "#087b8c", "ICMP": "#b05645", "ICMPv6": "#b05645"}
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setToolTip(str(value))
            if column in (0, 4, 5):
                item.setTextAlignment(Qt.AlignCenter)
            if column == 4:
                item.setForeground(QColor(colors.get(packet.protocol, "#536c80")))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.packet_table.setItem(row, column, item)

    def _update_statistics(self):
        self._stat_labels["captured"].setText(f"{len(self.packets):,}")
        self._stat_labels["displayed"].setText(f"{len(self._visible_packets):,}")
        size = self._byte_count
        self._stat_labels["bytes"].setText(f"{size / 1024 / 1024:.2f} MiB" if size >= 1024 * 1024 else f"{size / 1024:.1f} KiB")
        self._stat_labels["streams"].setText(str(len(self._tracker.list_streams())))
        stats = self._last_stats
        dropped, queue_dropped = stats.get("dropped", 0), stats.get("queue_dropped", 0)
        self._stat_labels["dropped"].setText(f"{dropped:,} / {queue_dropped:,}")
        self._stat_labels["dropped"].setToolTip(f"Npcap接收：{stats.get('received', 0):,}；驱动丢包：{dropped:,}；网卡丢包：{stats.get('interface_dropped', 0):,}；界面队列丢包：{queue_dropped:,}。停止后的统计可能仍为驱动最后一次报告值。")
        counts = Counter(packet.protocol for packet in self.packets)
        self.protocol_summary_label.setText("协议分布：" + ("    ·    ".join(f"{name} {count:,}" for name, count in counts.most_common()) or "暂无数据"))

    def select_packet(self, index):
        if 0 <= index < len(self._visible_packets):
            self.packet_table.selectRow(index)
            self._show_packet(self._visible_packets[index])
            return True
        return False

    def _selection_changed(self):
        rows = self.packet_table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self._visible_packets):
            self._show_packet(self._visible_packets[rows[0].row()])

    def _show_packet(self, packet):
        self.detail_tree.clear()
        frame = QTreeWidgetItem([f"Frame #{packet.number}", f"{len(packet.raw)} 字节已捕获 / {packet.wire_length} 字节线上长度"])
        self.detail_tree.addTopLevelItem(frame)
        frame.addChild(QTreeWidgetItem(["链路类型", str(packet.linktype)]))
        frame.addChild(QTreeWidgetItem(["时间戳", f"{packet.timestamp:.6f}"]))
        for name, fields in packet.layers:
            layer = QTreeWidgetItem([name, ""])
            for key, value in fields.items():
                layer.addChild(QTreeWidgetItem([str(key), str(value)]))
            self.detail_tree.addTopLevelItem(layer)
        if packet.errors:
            errors = QTreeWidgetItem(["解析提示 / 截断", "；".join(packet.errors)])
            errors.setForeground(0, QColor("#b05645"))
            self.detail_tree.addTopLevelItem(errors)
        self.detail_tree.expandToDepth(0)
        lines = []
        preview_size = min(len(packet.raw), HEX_PREVIEW_BYTES)
        for offset in range(0, preview_size, 16):
            chunk = packet.raw[offset:offset + 16]
            hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            lines.append(f"{offset:04x}  {hex_bytes:<47}  |{ascii_text}|")
        lines.extend(["", f"已显示 {preview_size:,} / 总计 {len(packet.raw):,} 字节。"])
        if preview_size < len(packet.raw):
            lines.append("[预览已截断；完整原始数据仍可保存为 PCAP。]")
        self.hex_view.setPlainText("\n".join(lines))

    def follow_stream(self):
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            self._set_status("请先选择一个 TCP 数据包，再跟踪其所在会话。")
            return None
        packet = self._visible_packets[rows[0].row()]
        stream = self._tracker.get_stream(packet)
        if stream is None:
            self._set_status("所选数据包没有可跟踪的 TCP 流（请选择 TCP、HTTP 或 TLS 数据包）。")
            return None
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        dialog.setWindowTitle(f"TCP 流 #{stream.id} · 双向重组")
        dialog.resize(980, 680)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setFont(QFont("Consolas", 10))
        text.setPlainText(stream.render())
        layout.addWidget(text)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(dialog.close)
        layout.addWidget(close_button, alignment=Qt.AlignRight)
        self._dialogs.append(dialog)
        dialog.destroyed.connect(lambda: self._dialogs.remove(dialog) if dialog in self._dialogs else None)
        dialog.show()
        return dialog

    def load_capture(self, path):
        try:
            frames = read_pcap(path)
            if len(frames) > MAX_PACKETS or sum(len(frame.data) for frame in frames) > MAX_CAPTURE_BYTES:
                raise ValueError(f"文件超过界面上限（{MAX_PACKETS:,} 包 / 64 MiB），请先拆分捕获文件")
        except (OSError, ValueError) as error:
            self._set_status(f"打开文件错误：{error}", True)
            return False
        if not self._stop_and_wait():
            return False
        self._reset_packets()
        self.packet_table.setUpdatesEnabled(False)
        try:
            for frame in frames:
                self._append_frame(frame)
        finally:
            self.packet_table.setUpdatesEnabled(True)
        self._update_statistics()
        self._set_status(f"已打开 {path} · {len(self.packets):,} 包；当前显示 {len(self._visible_packets):,} 包")
        return True

    def save_capture(self, path):
        try:
            # A GUI-thread snapshot includes every retained packet, even hidden rows.
            write_pcap(path, list(self._frames))
        except (OSError, ValueError) as error:
            self._set_status(f"保存文件错误：{error}", True)
            return False
        self._set_status(f"已保存 {len(self._frames):,} 个原始包：{path}")
        return True

    def _open_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开捕获文件", "", "PCAP 文件 (*.pcap *.cap);;所有文件 (*)")
        if path:
            self.load_capture(path)

    def _save_dialog(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存全部原始数据包", "capture.pcap", "PCAP 文件 (*.pcap)")
        if path:
            self.save_capture(path)

    def closeEvent(self, event):
        if self._stop_and_wait():
            self._timer.stop()
            event.accept()
        else:
            event.ignore()
