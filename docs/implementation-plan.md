# 实验 1A 实现计划

**Goal:** 在 Windows 上实现使用 Npcap 的 GUI 网络嗅探器，并交付源码、真实运行演示、PDF 报告与 ZIP。

**Architecture:** PySide6 提供列表、协议树和十六进制视图；ctypes 直接调用 Npcap，后台抓包与界面分离。协议解析、显示过滤、TCP 流处理和 PCAP 文件读写各自独立，不依赖 Scapy 或 Wireshark。

**Tech Stack:** Python >=3.10、PySide6 >=6.6、psutil >=5.9、Npcap。报告使用 ReportLab；这些生成工具不属于程序运行依赖。

**Spec:** 用户已确认的实现方案，以及 `../实验 1 讲解 2026.pdf` 第 2、3、5、9、14、15 页。姓名和学号留空。仓库：https://github.com/JohnBlack001/network-sniffer-lab1a。

## 全局约束

- 实际抓包；HTTP、TCP、UDP、IPv4、IPv6、ICMP 过滤；完整源码、MP4 演示和 PDF 报告。
- 只处理实验 1A；不实现 1B 文件传输功能，不将加密流量声称为明文。
- 使用本机可控流量验证，不把示例 PCAP 冒充实时捕获。
- 使用已有 LICENSE 和 .gitignore，程序说明放在报告中，不创建 README。
- 工作目录为现有新仓库；功能分支 feat/lab1a，不更改全局 Git/代理配置。
- 分阶段 Git 提交；最终同步已授权的同名仓库，保留开发历史。

## 文件与接口

- `sniffer/protocols.py`: `decode_packet(data, timestamp=0.0, linktype=1, number=0, wire_length=None) -> Packet`。Packet 含 number/timestamp/raw/wire_length/linktype/src/dst/protocol/transport/network/src_port/dst_port/summary/layers/payload/tcp_seq/tcp_ack/tcp_flags/errors；layers 为 `(层名称, 字段字典)` 列表。
- `sniffer/capture.py`: `list_interfaces() -> list[Interface]`；`CaptureWorker(interface_name, bpf='', promiscuous=True)` 为 QThread，`frames` 为有上限的 queue.Queue[CapturedFrame]，frame 含 data/timestamp/linktype/wire_length；`error`/`status` 信号及 `stop()`；`stats` 返回 received/dropped/interface_dropped/queue_dropped。
- `sniffer/filters.py`: `compile_display_filter(expression) -> Callable[[Packet], bool]`，支持协议与 and/or/not/括号、地址和端口比较，不使用 eval；错误抛 ValueError。
- `sniffer/streams.py`: `StreamTracker.add(packet)`；`list_streams()`；`get_stream(packet) -> TCPStream | None`；TCPStream 包含 id/endpoint_a/endpoint_b/packets/byte_count/processes，`render() -> str` 显示方向、重传去重与缺口；进程关联尽力进行，权限不足则标注未知。
- `sniffer/pcap_io.py`: `read_pcap(path) -> list[CapturedFrame]`、`write_pcap(path, frames)`，支持常见字节序及时间精度，不支持的格式明确报错。
- `sniffer/ui.py`: `MainWindow`；列表/协议树/原始字节、快速过滤和显示表达式、BPF、统计、TCP 流、打开/保存。保留原始包并重新过滤；处理停止/关闭、错误表达式、缺少驱动与内存上限。
- `main.py`、`requirements.txt`、`start.bat`：入口、依赖及 Windows 启动。
- `tests/`：协议、过滤器、重组、文件与 GUI 集成验证。
- `tools/`：可控流量、样例捕获生成、真实抓包验证、报告/演示及提交打包工具。

## 执行任务

### 1. 协议解析（独立模块）
- [ ] 先写测试：Ethernet/ARP、IPv4/IPv6（含扩展头与分片）、TCP/UDP/ICMP、HTTP/DNS/TLS、截断与畸形输入，确认失败。
- [ ] 实现 Packet 与解析器；只在完整首部范围内解析，不从端口单独断言 HTTP。
- [ ] 运行解析器测试并提交。

### 2. 抓包与过滤、文件读写
- [ ] 写 ctypes ABI、显示过滤表达式、PCAP 往返与截断文件测试，确认失败。
- [ ] 实现 Npcap 句柄生命周期、nonblocking 停止、BPF 编译错误、丢包统计和有界队列；实现安全过滤器、PCAP 读写。
- [ ] 用回环接口捕获本机 HTTP 流，核对实际包字节、BPF 和停止行为，然后提交。

### 3. TCP 流与图形界面
- [ ] 先验证流方向、乱序、重传和缺口行为，确认失败后实现；通过 psutil 获取本机连接的进程信息。
- [ ] 实现完整桌面界面，批量读取抓包队列，固定原始数据上限，停止后可保存与过滤。
- [ ] 测试 GUI 的打开/选择/过滤/跟踪/保存，验证关闭时线程退出，并提交。

### 4. 联调、审查和交付
- [ ] 运行完整测试和独立代码审查，修复影响正确性的发现。
- [ ] 录制真实运行视频（含本机实际抓包），保留样例 PCAP 与复现工具。
- [ ] 报告覆盖需求对应、设计、协议格式、OSI 思考题、运行方法、实测结果、局限与 Git 链接。
- [ ] 渲染检查 PDF 和视频画面；打包无加密 ZIP，校验内部文件，分阶段提交并推送仓库。

## 重点验证

1. Npcap ctypes 时间戳/包头 ABI 在当前 Windows 与驱动上真实验证。
2. IPv4/IPv6 非首分片不得误解析为传输首部；截断包不能崩溃。
3. TCP 乱序、重传、捕获中途开始及缺包明确显示，不伪造完整流。
4. 无流量也可停止，关闭窗口不遗留抓包线程；文件操作失败应在界面提示。
5. PCAP 包长、大小限制、链路类型及文件边界校验，不静默错误解析。
