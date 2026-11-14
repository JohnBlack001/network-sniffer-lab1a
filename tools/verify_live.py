"""仅捕获本机实验流量；运行后输出可复现的真实抓包证据。"""
import argparse
from collections import Counter
import json
from pathlib import Path
import threading
import time

from PySide6.QtCore import QCoreApplication

from sniffer.capture import CaptureDevice, CaptureWorker, capture_version, list_interfaces
from sniffer.pcap_io import read_pcap, write_pcap
from sniffer.protocols import decode_packet
from tools.lab_traffic import TrafficLab


def verify(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    interface = next(i for i in list_interfaces() if 'loopback' in i.name.lower())
    frames, traffic, producer_errors = [], {}, []
    with TrafficLab(http_port=0, dns_port=0) as lab:
        ports = [lab.http_port, lab.dns_port] + ([lab.ipv6_port] if lab.ipv6_port else [])
        bpf = '(' + ' or '.join(f'port {port}' for port in ports) + ') or icmp or icmp6'
        with CaptureDevice(interface.name, bpf, False) as device:
            def produce():
                try:
                    traffic.update(lab.generate(include_ping=True))
                except Exception as exc:
                    producer_errors.append(str(exc))
            thread = threading.Thread(target=produce)
            thread.start()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                frame = device.read()
                if frame:
                    frames.append(frame)
                else:
                    time.sleep(0.005)
                if not thread.is_alive() and time.monotonic() > deadline - 5:
                    break
            thread.join(timeout=4)
            if thread.is_alive() or producer_errors:
                raise RuntimeError('本机流量生成失败：' + str(producer_errors))
            stats = device.statistics()
    if not frames:
        raise AssertionError('真实抓包未捕获任何实验流量')
    assert all(abs(time.time() - f.timestamp) < 60 for f in frames), 'Npcap时间戳ABI错误'
    packets = [decode_packet(f.data, f.timestamp, f.linktype, i + 1, f.wire_length)
               for i, f in enumerate(frames)]
    protocols = Counter(p.protocol for p in packets)
    assert protocols['HTTP'] >= 2 and protocols['UDP'] >= 2
    assert protocols['ICMP'] >= 2
    if lab.ipv6_available:
        assert any(p.network == 'IPv6' and p.protocol == 'HTTP' for p in packets)
        assert protocols['ICMPv6'] >= 2
    assert not any(p.errors for p in packets), [(p.number, p.errors) for p in packets if p.errors]
    path = output / 'live-loopback.pcap'
    write_pcap(path, frames)
    assert [f.data for f in read_pcap(path)] == [f.data for f in frames]
    try:
        CaptureDevice(interface.name, 'tcp and and invalid', False)
    except ValueError:
        invalid_bpf_rejected = True
    else:
        raise AssertionError('无效BPF未被拒绝')
    app = QCoreApplication.instance() or QCoreApplication([])
    worker = CaptureWorker(interface.name, 'tcp port 1', False)
    errors = []
    worker.error.connect(errors.append)
    worker.start()
    time.sleep(0.25)
    started = time.monotonic()
    worker.stop()
    assert worker.wait(2000), '无流量时抓包线程无法停止'
    app.processEvents()
    assert not errors, errors
    result = dict(source='real-loopback', driver=capture_version(), interface=interface.name,
                  bpf=bpf, captured=len(frames), protocols=dict(protocols),
                  networks=dict(Counter(p.network for p in packets)), stats=stats,
                  timestamp_abi='passed', pcap_roundtrip='passed', invalid_bpf_rejected=invalid_bpf_rejected,
                  idle_stop_ms=round((time.monotonic() - started) * 1000, 2), traffic=traffic)
    (output / 'live-verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='samples')
    args = parser.parse_args()
    print(json.dumps(verify(args.output), ensure_ascii=False, indent=2))
