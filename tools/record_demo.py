"""录制真实 Qt 窗口：先实时回环抓包，再演示明确标记的合成 PCAP。"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if (ROOT / '.tools').exists():
    sys.path.insert(0, str(ROOT / '.tools'))

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont, QImage
from PySide6.QtWidgets import QApplication

from sniffer.pcap_io import read_pcap
from sniffer.ui import MainWindow
from tools.lab_traffic import TrafficLab


WIDTH, HEIGHT, CAPTION, FPS = 1280, 800, 104, 8


def pil_image(widget):
    picture = widget.grab().toImage().convertToFormat(QImage.Format_RGB888)
    return Image.frombytes('RGB', (picture.width(), picture.height()),
                           picture.bits().tobytes(), 'raw', 'RGB', picture.bytesPerLine())


def record(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    screenshots = output / 'screenshots'
    screenshots.mkdir(exist_ok=True)
    app = QApplication([])
    app.setFont(QFont('Microsoft YaHei UI', 10))
    window = MainWindow()
    window.resize(WIDTH, HEIGHT)
    window.show()
    loopback = next(index for index in range(window.interface_combo.count())
                    if 'loopback' in str(window.interface_combo.itemData(index)).lower())
    window.interface_combo.setCurrentIndex(loopback)
    window.promiscuous_check.setChecked(False)
    lab = TrafficLab(http_port=0, dns_port=0)
    lab.__enter__()
    ports = sorted(set([lab.http_port, lab.dns_port] + ([lab.ipv6_port] if lab.ipv6_port else [])))
    window.bpf_edit.setText('(' + ' or '.join(f'port {p}' for p in ports) + ') or icmp or icmp6')
    target = output / '实验1A_play.mp4'
    log = open(output / 'ffmpeg.log', 'w', encoding='utf-8')
    encoder = subprocess.Popen([imageio_ffmpeg.get_ffmpeg_exe(), '-hide_banner', '-loglevel', 'error',
        '-y', '-f', 'rawvideo', '-pixel_format', 'rgb24', '-video_size', f'{WIDTH}x{HEIGHT + CAPTION}',
        '-framerate', str(FPS), '-i', '-', '-an', '-c:v', 'libx264', '-preset', 'fast', '-crf', '20',
        '-pix_fmt', 'yuv420p', '-movflags', '+faststart', str(target)], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=log)
    font_path = str(Path(r'C:\Windows\Fonts\msyh.ttc'))
    title_font, body_font = ImageFont.truetype(font_path, 23), ImageFont.truetype(font_path, 17)
    state = dict(frame=0, title='01  网卡选择与捕获过滤',
                 subtitle='选择 Npcap 回环接口；本段仅产生并捕获本机实验流量。',
                 dialog=None, live_count=0, live_protocols={}, traffic={}, errors=[], completed=False)

    def caption(title, subtitle):
        state['title'], state['subtitle'] = title, subtitle
        print(f'{state["frame"] / FPS:04.1f}s {title}', flush=True)

    def select_http():
        index = next(i for i, p in enumerate(window._visible_packets) if p.protocol == 'HTTP')
        window.select_packet(index)
        window.packet_table.scrollToItem(window.packet_table.item(index, 0))

    def generate():
        try:
            state['traffic'] = lab.generate(include_ping=True)
        except Exception as exc:
            state['errors'].append(str(exc))

    def close_dialog():
        if state['dialog'] is not None:
            state['dialog'].close()
            state['dialog'] = None

    def frame():
        try:
            n = state['frame']
            if n == 24:
                caption('02  开始真实抓包', '后台直接调用 Npcap；使用 BPF 限定实验端口与 ICMP。')
                window.start_capture()
            elif n == 40:
                caption('03  产生双栈实验流量', '本机 HTTP 请求/响应、UDP DNS 请求/响应、IPv4 与 IPv6 ping。')
                threading.Thread(target=generate, daemon=True).start()
            elif n == 88:
                assert len(window.packets) > 0, window.status_label.text()
                caption('04  查看实时捕获结果', '列表、协议树、HEX + ASCII 与统计均来自本次真实数据包。')
                select_http()
            elif n == 96:
                pil_image(window).save(screenshots / '01-live.png')
            elif n == 112:
                state['live_count'] = len(window.packets)
                state['live_protocols'] = dict(Counter(p.protocol for p in window.packets))
                assert state['live_protocols'].get('HTTP', 0) >= 2
                assert any(p.network == 'IPv6' for p in window.packets)
                window.stop_capture()
            elif n == 128:
                caption('05  HTTP 显示过滤', '显示过滤只改变列表；所有原始数据包仍保留，可随时重新筛选。')
                window.protocol_combo.setCurrentText('HTTP')
                select_http()
            elif n == 144:
                pil_image(window).save(screenshots / '02-http.png')
            elif n == 176:
                caption('06  跟踪真实 TCP 流', '按方向与序列号重组；可看到请求、响应与实验正文，加密流量不解密。')
                state['dialog'] = window.follow_stream()
                assert state['dialog'] is not None
            elif n == 192:
                pil_image(state['dialog']).save(screenshots / '03-stream.png')
            elif n == 240:
                close_dialog()
            elif n == 256:
                caption('07  IPv6 协议过滤', '直接筛选本次捕获的 IPv6 数据包，同时查看传输层与应用层字段。')
                window.protocol_combo.setCurrentText('IPv6')
                window.select_packet(0)
            elif n == 288:
                caption('08  ICMP / ICMPv6', 'ICMP 快速过滤同时包含 IPv4 与 IPv6 的控制报文。')
                window.protocol_combo.setCurrentText('ICMP')
                window.select_packet(0)
            elif n == 320:
                caption('09  保存全部原始数据', '即使当前只显示 ICMP，保存仍包含本次捕获的所有原始包。')
                assert window.save_capture(output / 'demo-live.pcap')
                assert len(read_pcap(output / 'demo-live.pcap')) == len(window.packets)
            elif n == 344:
                caption('10  离线样例：合成 PCAP', '以下为明确标记的 38 包合成样例，用于复现 ARP、DNS 与 TCP 乱序/重传。')
                window.protocol_combo.setCurrentIndex(0)
                assert window.load_capture(ROOT / 'samples' / 'synthetic-protocols.pcap')
                select_http()
            elif n == 360:
                pil_image(window).save(screenshots / '04-offline.png')
            elif n == 392:
                caption('11  组合显示过滤', '表达式：ipv6 and (tcp or icmp)，支持逻辑运算与括号。')
                window.filter_edit.setText('ipv6 and (tcp or icmp)')
                assert window.apply_filter()
                window.select_packet(0)
            elif n == 416:
                caption('12  DNS 字段分析', '合成样例使用标准 DNS 端口，可查看事务号、问题与应答字段。')
                window.filter_edit.clear()
                window.protocol_combo.setCurrentText('DNS')
                window.apply_filter()
                window.select_packet(0)
                window.detail_tree.expandAll()
            elif n == 440:
                caption('13  输入错误保护', '不完整的显示过滤表达式会提示错误，原列表与原始数据仍保留。')
                window.filter_edit.setText('tcp and')
                assert not window.apply_filter()
            elif n == 464:
                window.filter_edit.clear()
                window.protocol_combo.setCurrentIndex(0)
                window.apply_filter()
                select_http()
            elif n == 480:
                caption('14  合成样例：乱序与重传', 'TCP 流按序列号恢复顺序、去除重叠；无法恢复的缺口会明确标注。')
                state['dialog'] = window.follow_stream()
                assert state['dialog'] is not None
            elif n == 496:
                pil_image(state['dialog']).save(screenshots / '05-reassembly.png')
            elif n == 536:
                close_dialog()
                caption('15  演示完成', '已演示真实捕获、协议过滤、字段/原始字节、流追踪、保存和离线复现。')
            elif n >= 560:
                assert not state['errors'], state['errors']
                state['completed'] = True
                timer.stop()
                window.close()
                app.quit()
                return
            image = pil_image(window).resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
            if state['dialog'] is not None and state['dialog'].isVisible():
                dialog = pil_image(state['dialog'])
                dialog.thumbnail((1040, 720), Image.Resampling.LANCZOS)
                image.paste(dialog, ((WIDTH - dialog.width) // 2, (HEIGHT - dialog.height) // 2))
            canvas = Image.new('RGB', (WIDTH, HEIGHT + CAPTION), '#102d45')
            canvas.paste(image, (0, 0))
            draw = ImageDraw.Draw(canvas)
            draw.text((24, HEIGHT + 12), state['title'], font=title_font, fill='#ffffff')
            draw.text((24, HEIGHT + 53), state['subtitle'], font=body_font, fill='#bddee6')
            draw.text((WIDTH - 110, HEIGHT + 15), f'{n // FPS:02d}s / 70s', font=body_font, fill='#8bced6')
            encoder.stdin.write(canvas.tobytes())
            state['frame'] += 1
        except Exception as exc:
            state['errors'].append(repr(exc))
            timer.stop()
            window.close()
            app.quit()

    timer = QTimer()
    timer.timeout.connect(frame)
    timer.start(round(1000 / FPS))
    try:
        app.exec()
    finally:
        window.stop_capture()
        window._stop_and_wait()
        close_dialog()
        lab.__exit__(None, None, None)
        encoder.stdin.close()
        encoder.wait(timeout=30)
        log.close()
    state.pop('dialog', None)
    state['video'] = str(target)
    state['fps'] = FPS
    state['duration_seconds'] = state['frame'] / FPS
    (output / 'demo-verification.json').write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
    if not state['completed'] or encoder.returncode:
        raise RuntimeError('录像未完成：' + repr(state['errors']) + '; see ffmpeg.log')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default=str(ROOT / 'output'))
    args = parser.parse_args()
    print(record(args.output))
