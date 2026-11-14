"""Build the Chinese NetScope experiment 1A report from verified local evidence.

Requires ReportLab only for report authoring; it is not a runtime dependency of
NetScope. Run from any directory with ``python -m tools.build_report --output
output/实验1A_report.pdf``. The artifact authoring marker and rendered-page QA
belong to the caller's delivery workflow, before and after this command.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import partial
from html import escape
import json
from pathlib import Path
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, PageBreak, PageTemplate,
    Paragraph, Preformatted, Spacer, Table, TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/JohnBlack001/network-sniffer-lab1a"
PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT = RIGHT = 46
TOP = 61
BOTTOM = 48
CONTENT_WIDTH = PAGE_WIDTH - LEFT - RIGHT
CONTENT_HEIGHT = PAGE_HEIGHT - TOP - BOTTOM
TOTAL_PAGES = 11
NAVY = colors.HexColor("#15344d")
TEAL = colors.HexColor("#087f8c")
TEXT = colors.HexColor("#253d50")
MUTED = colors.HexColor("#62798b")
LINE = colors.HexColor("#d9e4eb")
PALE = colors.HexColor("#f1f6f8")
REGULAR = "NetScopeSong"
BOLD = "NetScopeHei"
SCREENSHOT_NAMES = ("01-live", "02-http", "03-stream", "04-offline")


def _log(message):
    print(f"[build_report] {message}", file=sys.stderr)


@dataclass
class ReportInputs:
    root: Path
    live: dict
    tests: dict | None
    screenshots: dict[str, Path]
    report_date: str


def _read_object(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON 顶层必须是对象：{path}")
    return value


def load_inputs(root, report_date):
    root = Path(root).resolve()
    live_path = root / "samples" / "live-verification.json"
    live = _read_object(live_path)
    if live.get("source") != "real-loopback":
        raise ValueError("实测记录必须明确标为 real-loopback，不能用合成样例替代。")
    if not isinstance(live.get("captured"), int) or live["captured"] < 0:
        raise ValueError("实测记录缺少有效 captured 计数。")
    if not isinstance(live.get("protocols"), dict) or not isinstance(live.get("networks"), dict):
        raise ValueError("实测记录缺少协议与网络层计数。")
    test_path = root / "output" / "test-results.json"
    tests = _read_object(test_path) if test_path.is_file() else None
    if tests is None:
        _log(f"缺少最终测试结果 {test_path}；报告将明确标注尚未记录。")
    else:
        for key in ("passed", "failed"):
            if not isinstance(tests.get(key), int) or tests[key] < 0:
                raise ValueError(f"测试结果中的 {key} 必须是非负整数。")
        if not isinstance(tests.get("command"), str):
            raise ValueError("测试结果必须记录 command 字符串。")
    screenshots = {name: root / "output" / "screenshots" / f"{name}.png" for name in SCREENSHOT_NAMES}
    for path in screenshots.values():
        if not path.is_file():
            _log(f"缺少真实截图 {path}；保留等高截图位置，补齐后请重新生成。")
    return ReportInputs(root, live, tests, screenshots, report_date)


def register_fonts(regular_path, bold_path):
    for path in (regular_path, bold_path):
        if not Path(path).is_file():
            raise FileNotFoundError(f"缺少中文字体：{path}；可通过 --font-regular / --font-bold 指定。")
    pdfmetrics.registerFont(TTFont(REGULAR, str(regular_path), subfontIndex=0))
    pdfmetrics.registerFont(TTFont(BOLD, str(bold_path), subfontIndex=0))
    pdfmetrics.registerFontFamily(REGULAR, normal=REGULAR, bold=BOLD, italic=REGULAR, boldItalic=BOLD)


def make_styles():
    base = dict(fontName=REGULAR, textColor=TEXT, wordWrap="CJK", splitLongWords=True)
    return {
        "body": ParagraphStyle("body", fontSize=10, leading=16, spaceAfter=8, **base),
        "small": ParagraphStyle("small", fontSize=9.2, leading=14.2, spaceAfter=6, **base),
        "caption": ParagraphStyle("caption", fontSize=8.8, leading=13.5, textColor=MUTED,
                                  fontName=REGULAR, wordWrap="CJK", spaceBefore=5, spaceAfter=10),
        "title": ParagraphStyle("title", fontName=BOLD, fontSize=29, leading=39,
                                textColor=NAVY, wordWrap="CJK", spaceAfter=14),
        "subtitle": ParagraphStyle("subtitle", fontName=REGULAR, fontSize=13, leading=21,
                                   textColor=MUTED, wordWrap="CJK", spaceAfter=15),
        "h1": ParagraphStyle("h1", fontName=BOLD, fontSize=18.5, leading=27,
                             textColor=NAVY, wordWrap="CJK", spaceAfter=11),
        "h2": ParagraphStyle("h2", fontName=BOLD, fontSize=11.5, leading=18,
                             textColor=TEAL, wordWrap="CJK", spaceBefore=8, spaceAfter=6),
        "cell": ParagraphStyle("cell", fontSize=9.3, leading=14.2, **base),
        "headcell": ParagraphStyle("headcell", fontName=BOLD, fontSize=9.3, leading=14.2,
                                   textColor=colors.white, wordWrap="CJK"),
        "metric": ParagraphStyle("metric", fontName=BOLD, fontSize=20, leading=27,
                                 textColor=TEAL, alignment=TA_CENTER),
        "metriclabel": ParagraphStyle("metriclabel", fontName=REGULAR, fontSize=9,
                                      leading=14, textColor=MUTED, alignment=TA_CENTER),
        "code": ParagraphStyle("code", fontName="Courier", fontSize=8.6, leading=13.3,
                               textColor=NAVY, backColor=PALE, borderPadding=8,
                               spaceBefore=3, spaceAfter=10),
    }


class Screenshot(Flowable):
    """A fixed-height image area; missing evidence is conspicuous and logged."""

    def __init__(self, path, height):
        super().__init__()
        self.path = Path(path)
        self.width = CONTENT_WIDTH
        self.height = height

    def draw(self):
        self.canv.saveState()
        self.canv.setStrokeColor(LINE)
        self.canv.setFillColor(PALE)
        self.canv.roundRect(0, 0, self.width, self.height, 5, stroke=1, fill=1)
        if self.path.is_file():
            image = ImageReader(str(self.path))
            width, height = image.getSize()
            scale = min((self.width - 8) / width, (self.height - 8) / height)
            image_width, image_height = width * scale, height * scale
            self.canv.drawImage(image, (self.width - image_width) / 2,
                                (self.height - image_height) / 2,
                                width=image_width, height=image_height, mask="auto")
        else:
            self.canv.setFillColor(MUTED)
            self.canv.setFont(BOLD, 12)
            self.canv.drawCentredString(self.width / 2, self.height / 2 + 14, "真实截图尚未补齐")
            self.canv.setFont(REGULAR, 9)
            self.canv.drawCentredString(self.width / 2, self.height / 2 - 5, self.path.name)
            self.canv.drawCentredString(self.width / 2, self.height / 2 - 23, "本位置仅保留布局，不作为实验结果。")
        self.canv.restoreState()


class ReportPage(Flowable):
    """Lay out one intentional page and fail rather than spill into extra pages."""

    def __init__(self, number, items):
        super().__init__()
        self.number = number
        self.items = items
        self.width = CONTENT_WIDTH
        self.height = CONTENT_HEIGHT
        self._positions = []

    def wrap(self, available_width, available_height):
        cursor = self.height
        self._positions = []
        for item in self.items:
            cursor -= item.getSpaceBefore()
            _, height = item.wrapOn(self.canv, self.width, 100000)
            cursor -= height
            self._positions.append((item, cursor))
            cursor -= item.getSpaceAfter()
        if cursor < -0.5:
            raise ValueError(f"报告第 {self.number} 页超出布局 {-cursor:.1f} pt；请缩减内容或截图高度。")
        return self.width, self.height

    def draw(self):
        for item, y in self._positions:
            self.canv.saveState()
            item.drawOn(self.canv, 0, y)
            self.canv.restoreState()


class ReportBuilder:
    def __init__(self, inputs):
        self.inputs = inputs
        self.styles = make_styles()

    def p(self, text, style="body"):
        return Paragraph(text, self.styles[style])

    def h(self, text):
        return self.p(text, "h2")

    def code(self, text):
        return Preformatted(text, self.styles["code"])

    def table(self, headers, rows, widths):
        data = [[self.p(escape(str(value)), "headcell") for value in headers]]
        data.extend([[self.p(str(value), "cell") for value in row] for row in rows])
        table = Table(data, colWidths=[CONTENT_WIDTH * value for value in widths], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, NAVY),
            ("LINEBELOW", (0, 1), (-1, -1), 0.35, LINE),
        ]))
        table.spaceAfter = 8
        return table

    def metrics(self, values):
        data = [[self.p(escape(str(value)), "metric") for value, _ in values],
                [self.p(escape(label), "metriclabel") for _, label in values]]
        table = Table(data, colWidths=[CONTENT_WIDTH / len(values)] * len(values))
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALE),
            ("TOPPADDING", (0, 0), (-1, 0), 11),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
            ("LINEAFTER", (0, 0), (-2, -1), 0.5, LINE),
        ]))
        table.spaceAfter = 14
        return table

    def shot(self, name, height, caption):
        return [Screenshot(self.inputs.screenshots[name], height), self.p(caption, "caption")]

    def heading(self, number, title):
        return self.p(f"{number:02d}  {title}", "h1")

    def pages(self):
        live = self.inputs.live
        tests = self.inputs.tests
        packets = live["captured"]
        networks = live["networks"]
        stats = live.get("stats", {})
        protocols = live["protocols"]
        passed = str(tests["passed"]) if tests is not None else "待记录"
        test_summary = (f"{tests['passed']} 项通过，{tests['failed']} 项失败" if tests is not None
                        else "最终测试结果尚未记录；本报告不据此认定全通过")
        test_command = escape(tests["command"]) if tests is not None else "待写入 output/test-results.json"
        observed = "；".join(f"{escape(str(name))} {count}" for name, count in protocols.items())
        status = lambda value: "通过" if value is True or value == "passed" else "未通过或未记录"
        pages = []

        pages.append([
            Spacer(1, 20),
            self.p("NetScope", "title"),
            self.p("实验 1A  网络嗅探与协议分析", "subtitle"),
            self.p("基于 Python、PySide6 与 Npcap 的图形化网络协议分析器", "body"),
            self.table(["报告信息", "内容"], [
                ("姓名 / 学号", "姓名：________________　学号：________________"),
                ("实验范围 / 日期", f"实验 1A　/　{escape(self.inputs.report_date)}"),
                ("源码仓库", f'<link href="{REPOSITORY}" color="#087f8c">{REPOSITORY}</link>'),
            ], [.22, .78]),
            self.h("摘要"),
            self.p("NetScope 通过 Npcap 获取实际网卡或回环接口上的原始帧，将协议列表、分层字段和十六进制字节并列呈现。程序支持捕获过滤、显示过滤、双向 TCP 流重组，以及经典 PCAP 文件的打开和保存，便于从原始字节追溯分析结果。"),
            self.p("验证采用本机可控 HTTP、UDP DNS 和 ICMP 流量。真实验证记录与合成离线样例分别保存，后者用于稳定复现乱序、重传及协议混合场景，不能当作实时抓包证据。报告中的通过数量由最终测试记录读取，截图来自程序的实际界面。"),
            self.metrics([(packets, "真实回环捕获 / 包"), (networks.get("IPv6", 0), "IPv6 / 包"),
                          (stats.get("dropped", "未记录"), "本次驱动丢包"), (passed, "自动化测试通过")]),
            self.h("阅读导航"),
            self.table(["页码", "主要内容"], [
                ("2-3", "需求对应、安装运行、模块职责与抓包生命周期"),
                ("4-6", "协议分层、两类过滤、TCP 重组与进程关联"),
                ("7-9", "真实抓包、HTTP 字段与 PCAP 离线分析画面"),
                ("10-11", "测试与复现、OSI 思考、局限和参考资料"),
            ], [.15, .85]),
        ])

        pages.append([
            self.heading(1, "需求对应与运行环境"),
            self.p("实现范围按实验 1A 的网络嗅探任务组织：围绕真实捕获、协议理解和可复现分析建立验收依据。"),
            self.table(["验收点", "程序中的对应行为", "检查依据"], [
                ("真实捕获", "枚举实际网卡和回环接口；开始、停止、混杂模式与捕获统计", "实时界面；live-verification.json"),
                ("协议查看", "包列表、分层字段树、HEX/ASCII 原始字节；覆盖指定协议", "协议测试；HTTP 画面"),
                ("过滤", "HTTP/TCP/UDP/IPv4/IPv6/ICMP 快速筛选；BPF 和显示表达式", "过滤器测试；筛选前后包数"),
                ("TCP 流", "双向会话、按序重组、重传去重、缺口提示、进程尽力关联", "流重组测试；TCP 流画面"),
                ("捕获文件", "打开和保存经典 PCAP；保存全部保留原始包", "往返验证；离线画面"),
                ("交付", "源代码、测试、真实验证记录、样例、PDF 报告与 MP4 演示", "仓库及交付包清单"),
            ], [.17, .51, .32]),
            self.h("Windows 安装与启动"),
            self.p("使用 Python 3.10 或以上版本。程序依赖 PySide6（6.6 至 7.0 之前）和 psutil（5.9 至 8.0 之前）。实时抓包另需安装与 Python 架构匹配的 Npcap；程序直接加载 Npcap 目录中的 DLL，抓包权限受驱动安装选项影响，必要时以管理员身份运行。"),
            self.code("python -m pip install -r requirements.txt\npython main.py"),
            self.table(["操作", "说明"], [
                ("选择接口", "外部通信选择实际使用的以太网或 WLAN 网卡；本机实验选择 Npcap Loopback Adapter。"),
                ("开始与停止", "需要 BPF 时先填写，再开始捕获；停止后仍可筛选、跟踪 TCP 流并保存原始包。"),
                ("驱动不可用", "界面显示枚举或启动错误；离线 PCAP 分析仍可使用。"),
            ], [.20, .80]),
            self.p("ReportLab 仅用于生成本报告，不加入 NetScope 的程序运行依赖。", "small"),
        ])

        pages.append([
            self.heading(2, "模块结构与捕获生命周期"),
            self.table(["文件", "主要对象 / 函数与职责"], [
                ("main.py / start.bat", "创建 Qt 应用和 MainWindow；提供 Windows 启动入口。"),
                ("sniffer/capture.py", "list_interfaces 枚举；CaptureDevice 封装句柄；CaptureWorker 后台读取；CapturedFrame 保存原始帧。"),
                ("sniffer/protocols.py", "decode_packet 返回 Packet；_link、_ipv4、_ipv6、_transport、_application 逐层解析。"),
                ("sniffer/filters.py", "compile_display_filter 生成 Packet 谓词；递归下降解析 and/or/not，不使用 eval。"),
                ("sniffer/streams.py", "StreamTracker.add/get_stream/list_streams 管理会话；TCPStream._reassemble/render 负责重组与展示。"),
                ("sniffer/pcap_io.py", "read_pcap / write_pcap 校验并读写捕获文件，保留时间戳、链路类型与线上包长。"),
                ("sniffer/ui.py", "MainWindow 批量收包、更新列表和统计，连接过滤、分层查看、文件与流窗口。"),
                ("tools/ / tests/", "本机流量、合成样例与真实验证脚本；协议、过滤、重组、文件和界面测试。"),
            ], [.27, .73]),
            self.h("Npcap 调用顺序"),
            self.table(["阶段", "调用与资源处理"], [
                ("枚举", "pcap_findalldevs 获取链表，在 finally 中 pcap_freealldevs。"),
                ("打开", "pcap_open_live：snaplen 65535、超时参数 100 ms；pcap_datalink 获取实际链路类型。"),
                ("过滤", "pcap_setnonblock 启用非阻塞；有 BPF 时 pcap_compile 后 pcap_setfilter，最终 pcap_freecode。"),
                ("读取与停止", "pcap_next_ex 返回原始字节；无包时用停止事件等待 10 ms；句柄在所属抓包线程内 pcap_close。"),
            ], [.17, .83]),
            self.p("后台队列最多 4096 帧，满时记录 queue_dropped；驱动统计约每 0.5 s 更新。GUI 每 50 ms 消费一批，单批最多 200 帧，避免每包信号导致界面拥塞。GUI 达到 10000 包或 64 MiB 后停止捕获，并保留已有原始数据。", "small"),
        ])

        pages.append([
            self.heading(3, "协议分层与解析边界"),
            self.p("解析器依据链路类型和上层协议字段递进读取；所有首部先检查可用字节，再解释字段。错误写入 Packet.errors 并在界面显示，原始字节继续保留。"),
            self.table(["层次 / 协议", "关键字段与实现行为"], [
                ("链路层", "Ethernet 源/目的 MAC、EtherType；802.1Q 等 VLAN 标签的 ID、优先级与 DEI。支持 loopback、raw IP、Linux cooked v1/v2。"),
                ("ARP", "操作码、硬件/协议类型、发送方和目标方 MAC/IP。ARP 将本链路 IP 寻址与链路地址联系起来。"),
                ("IPv4", "首部长度、总长度、标识、TTL、协议号、分片标志/偏移、源/目的地址。非首分片不误当作 TCP/UDP 首部。"),
                ("IPv6", "载荷长度、Next Header、Hop Limit、Flow Label 和地址；遍历 Hop-by-Hop、Routing、Destination、AH、Fragment 扩展头。"),
                ("TCP / UDP", "TCP 端口、Seq/Ack、首部长度、标志、窗口、校验和字段；UDP 端口、长度和校验和字段。"),
                ("ICMP / ICMPv6", "Type、Code、校验和；Echo 报文另读 Identifier 和 Sequence，辅助观察回环连通性。"),
                ("HTTP", "依据可辨识的明文请求行或状态行识别，不仅凭 80 端口；展示 Host、Content-Type、Content-Length 等有限首部。"),
                ("DNS", "53/5353 端口的 UDP 或带长度前缀的 TCP DNS；解析压缩域名及 A/AAAA 记录，限制指针跳数、名称长度与报文解码预算。"),
                ("TLS", "只解释可识别记录的类型、版本、长度和可见握手类型；不解密应用数据。"),
            ], [.20, .80]),
            self.h("分层关系与保守处理"),
            self.p("以太网帧通过 EtherType 指示 IPv4、IPv6 或 ARP；IP 协议号 / Next Header 指示 TCP、UDP 或 ICMP；传输层载荷才可能是 HTTP、DNS 或 TLS。程序的单包协议名取最深可识别层，因此 HTTP 包仍属于 TCP 与 IPv4/IPv6，可被相应过滤器命中。"),
            self.p("IP 分片不进行跨包重组：非首分片保留为网络层数据；首分片的未完整载荷不继续判定应用协议。IPv6 ESP 作为加密载荷显示，不解析内部内容；IPv6 jumbogram 明确不支持。校验和字段会展示，抓到的报文不进行全量校验和有效性判定。", "small"),
        ])

        pages.append([
            self.heading(4, "捕获过滤与显示过滤"),
            self.table(["比较项", "捕获过滤 BPF", "显示过滤"], [
                ("生效时机", "开始捕获前，由 Npcap 编译并安装", "已保留数据解析后，可反复重新应用"),
                ("数据影响", "被排除的包不进入本次原始捕获", "只隐藏列表行，不删除原始包或流数据"),
                ("实现", "pcap_compile / pcap_setfilter", "compile_display_filter 返回布尔谓词"),
                ("错误处理", "编译失败终止该次启动并给出错误", "表达式失败保留原列表和原有效过滤"),
            ], [.16, .42, .42]),
            self.h("BPF 示例：减少进入程序的数据"),
            self.code("tcp port 80\nudp or icmp or icmp6\nhost 127.0.0.1 and not port 22\n(tcp port 8765 or udp port 53535) or icmp or icmp6"),
            self.p("BPF 语法由 libpcap 提供。抓取本机可控实验时，端口需与流量工具的实际端口一致；使用端口 0 时由操作系统分配，应依据输出填写。"),
            self.h("显示过滤示例：从保留数据中选择观察对象"),
            self.code('tcp and ip.addr == 127.0.0.1\n(http or dns) and not udp\nipv6 and tcp.port == 8765\nport == 80 or port == 53535\ncontains "GET"\nlength >= 100 and not arp'),
            self.p("支持 and、or、not 及括号，也支持 &amp;&amp;、||、!；优先级为 not、and、or。ip.src / ip.dst / ip.addr 支持 ==、!=，地址先标准化；端口支持源、目的与双向字段，length 比较线上包长。contains 在原始字节中检索 UTF-8 文本，不执行输入内容。"),
            self.p("上方协议下拉框与表达式共同生效。ICMP 选项兼顾 ICMPv6；显示过滤中的 ip 表示 IPv4 或 IPv6。过滤器限制输入长度和 token 数，并对错误、非法地址及越界端口给出提示。保存操作始终写出全部保留原始包，不局限于当前可见行。", "small"),
        ])

        pages.append([
            self.heading(5, "TCP 双向流与进程关联"),
            self.table(["步骤", "实现要点"], [
                ("会话与方向", "按端点地址和端口的无序对聚合，内部保留两个发送方向；观察到新的连接 SYN 时分流。"),
                ("序列与去重", "优先以 SYN+1 作方向锚点，排序载荷段；重传与重叠部分跳过，保留排序后的首段。"),
                ("缺口与回绕", "用有符号模 2^32 差值处理邻近序列号回绕；已观察段之间的间隙明确显示字节数。"),
            ], [.20, .80]),
            *self.shot("03-stream", 350, "图 3  TCP 双向流窗口。各方向独立按序展示，重传去重与缺口信息保留在文本中。截图来源：程序实际运行界面。"),
            self.h("本机进程关联的证据范围"),
            self.p("TCPStream.processes 通过 psutil.net_connections(kind=\"tcp\") 快照匹配两端并读取有效 PID；PID 0 等无有效归属记录被跳过，结果在流对象中缓存。权限不足、连接已结束或非本机连接时标注未知，一次快照不能确定历史归属。每方向文本预览限制 256 KiB，完整原始包仍可保存。"),
            self.p("未捕获 SYN 时会提示起点可能缺失；只能标注已观察序列号之间的缺口，无法判断未到达的尾部。未观察到新 SYN 时不能可靠区分四元组复用；序列跨度超过 2^31 字节时存在歧义。UTF-8 容错文本也不意味着加密数据已成为明文。", "small"),
        ])

        pages.append([
            self.heading(6, "真实回环抓包验证"),
            self.p("真实验证脚本先启动受控本机服务，再通过 Npcap 回环接口捕获实际套接字通信。数据来自 samples/live-verification.json；以下计数描述这一次运行，不代表吞吐量或长期稳定性基准。"),
            self.metrics([(packets, "捕获总包数"), (networks.get("IPv4", 0), "IPv4"),
                          (networks.get("IPv6", 0), "IPv6"), (stats.get("dropped", "未记录"), "驱动丢包")]),
            *self.shot("01-live", 315, "图 1  真实回环捕获界面。截图来自演示录像中的另一轮实际捕获，因此包数可与本页 JSON 记录不同。"),
            self.table(["验证项目", "记录结果"], [
                ("驱动与接口", escape(str(live.get("driver", "未记录"))) + "<br/>" + escape(str(live.get("interface", "未记录")))),
                ("包列表协议分布", observed),
                ("时间戳 / PCAP 往返", f"ABI：{status(live.get('timestamp_abi'))}；原始字节往返：{status(live.get('pcap_roundtrip'))}"),
                ("错误与停止", f"无效 BPF 被拒绝：{status(live.get('invalid_bpf_rejected'))}；无流量停止用时：{live.get('idle_stop_ms', '未记录')} ms"),
            ], [.25, .75]),
            self.p("本次合法 DNS 请求/应答使用动态非标准端口，因此单包分类记录为 UDP；DNS 结构与常见端口分类另用离线样例和单元测试验证。驱动丢包为 0 仅描述本次短时低负载实验。", "small"),
        ])

        pages.append([
            self.heading(7, "HTTP 数据包与原始字节"),
            self.p("本机 HTTP 服务只提供内存生成的 /lab1a.txt，两段正文不读取真实文件。IPv4 和 IPv6 客户端均通过标准套接字发起请求，可拆分发送以产生跨段数据。"),
            *self.shot("02-http", 360, "图 2  HTTP 筛选及协议字段。选择数据包后，分层树展示协议解释，右侧保留原始 HEX/ASCII，二者可逐项对应。"),
            self.table(["观察对象", "应核对的内容"], [
                ("请求", "GET /lab1a.txt HTTP/1.1；Host 与 Connection 等首部位于 TCP 载荷中。"),
                ("应答", "HTTP/1.1 200 OK；Content-Type 为 text/plain；Content-Length 对应生成正文的字节数。"),
                ("底层字段", "IP 源/目的地址、TCP 源/目的端口、Seq/Ack 与载荷长度；同一应用报文可以跨多个 TCP 段。"),
            ], [.20, .80]),
            self.h("单包识别与流重组的分工"),
            self.p("列表中的 HTTP 标签来自当前包内可辨识的请求行或状态行。部分后续 TCP 段只有正文，仍显示为 TCP，并不意味着它不属于 HTTP 会话。需要观察完整交互时应选择该会话中的包，打开 TCP 流窗口按两个方向重组。"),
            self.p("真实 JSON 记录两种地址族的 HTTP 状态均为 200、正文验证成功，并记录本机 UDP DNS 应答与 IPv4/IPv6 ping 的结果。报告不把该本机实验外推为对互联网服务器的测试。", "small"),
        ])

        pages.append([
            self.heading(8, "PCAP 文件与合成离线样例"),
            *self.shot("04-offline", 320, "图 4  离线样例分析界面。合成样例专门用于稳定观察协议混合、TCP 乱序与重传，不能替代真实捕获记录。"),
            self.table(["文件能力", "支持与限制"], [
                ("经典 PCAP", "读取版本 2.4、大小端、微秒或纳秒时间戳；写出小端、微秒精度经典 PCAP。"),
                ("原始信息", "保留原始字节、时间戳、链路类型及 wire_length；一个文件不混合多种链路类型。"),
                ("输入校验", "检查 magic、版本、snaplen、时间戳分数、捕获/线上长度与截断；上限 10000 包或 64 MiB。"),
                ("格式边界", "不直接读取 PCAPNG，需先转换。无法识别的链路类型明确提示；写入采用同目录临时文件后替换目标。"),
            ], [.20, .80]),
            self.h("两类样本必须分别说明"),
            self.p("samples/live-loopback.pcap 来源于真实本机回环通信；合成样例则由 tools.lab_traffic.generate_sample 手工构造 Ethernet、ARP、IPv4/IPv6、TCP、UDP、ICMP/ICMPv6，并计算相应校验和。合成数据使用文档地址，时间戳固定，含双向握手、分段、乱序与重复 TCP 载荷，便于重复比较。"),
            self.code("python -m tools.lab_traffic --sample samples/synthetic-demo.pcap"),
            self.p("打开样例后，先查看整体协议分布，再过滤 HTTP 或 TCP，并跟踪流确认重传去重与乱序恢复。切换显示过滤不会改变保存的数据；需要重新分析时可再次打开原始 PCAP。", "small"),
        ])

        pages.append([
            self.heading(9, "测试、复现与交付"),
            self.table(["测试记录", "当前读取结果"], [
                ("最终测试集", escape(test_summary)),
                ("执行命令", test_command),
                ("来源", "output/test-results.json；由最终测试执行后写入，报告不内置旧的通过数量。"),
            ], [.23, .77]),
            self.h("验证覆盖"),
            self.table(["层次", "重点场景"], [
                ("解析与过滤", "IPv4/IPv6、扩展头与分片、HTTP/DNS/TLS、畸形与截断；逻辑组合、地址/端口以及无效表达式。"),
                ("流与文件", "双向分流、乱序、重传、重叠、缺口及序列号回绕；PCAP 往返、长度与文件边界。"),
                ("界面与生命周期", "载入、筛选、选择、协议树、HEX、流窗口、全部原始包保存；达到限额及停止/关闭行为。"),
                ("本机实测", "Npcap 时间戳 ABI、双栈 HTTP、UDP DNS、ICMP；无效 BPF 拒绝、无流量停止与驱动统计。"),
            ], [.23, .77]),
            self.h("演示复现顺序"),
            self.table(["步骤", "操作与检查"], [
                ("1", "安装依赖与 Npcap，运行 python main.py；选择回环接口，开始捕获。"),
                ("2", "另开终端运行下列流量命令。观察包数增长，停止后筛选 HTTP、IPv4、IPv6 或 ICMP。"),
                ("3", "选择 HTTP/TCP 包查看协议树与 HEX，再跟踪双向流；保存全部原始包并重新打开核对。"),
                ("4", "打开明确标记的合成 PCAP，展示稳定的乱序/重传场景。MP4 演示按相同观察顺序记录。"),
            ], [.10, .90]),
            self.code("python -m tools.lab_traffic --generate --ping\npython -m tools.verify_live --output samples\npython -m pytest -q"),
            self.p("交付以完整源码、requirements.txt、启动入口、测试、真实验证 JSON/PCAP、合成样例、PDF 报告及 MP4 演示组成。仓库地址见封面与末页；运行方法写在本报告中。报告的证据范围以实际保存的记录与截图为准。", "small"),
        ])

        pages.append([
            self.heading(10, "OSI 思考、局限与参考资料"),
            self.h("为何代理抓到 HTTP 不等于观测了底层 TCP？"),
            self.p("Thor 一类代理工具主要在应用层处理 HTTP 请求和响应，可能分别建立客户端到代理、代理到服务器的连接。它显示的应用消息不等于原连接上的 TCP 段，也不能直接替代对 Seq/Ack、窗口、重传、握手与丢包的观测。"),
            self.p("NetScope 从 Npcap 获取链路层或回环原始帧，经 IP 与传输层逐层解释，并将 TCP 载荷重组为可读文本。HTTP 属于应用层；TCP 提供传输层字节流；IP 负责网络层寻址。HTTPS 中的 TLS 保护内容，本程序只观察可见元数据和密文，不提供 TLS 解密。"),
            self.h("实现局限"),
            self.table(["边界", "实际含义"], [
                ("可见流量与性能", "网卡、驱动、交换网络与权限决定可见范围；有界队列与 GUI 内存限额用于控制资源，不属于线速抓包器。"),
                ("重组与归属", "不做 IP 分片重组；TCP 未见起始/尾部或 SYN 时存在明确不确定性；进程快照不能追溯历史归属。"),
                ("应用协议", "只实现有限字段与识别规则；不实现通用 HTTP/2、HTTP/3 或 TLS 解密；加密与压缩载荷不还原业务内容。"),
            ], [.20, .80]),
            self.h("参考资料与源码"),
            self.table(["编号", "资料与官方链接"], [
                ("[1]", "《实验 1 讲解 2026.pdf》：实验 1A 对应第 2、3、5、9、14、15 页。"),
                ("[2]", '<link href="https://npcap.com/guide/npcap-devguide.html" color="#087f8c">Npcap Developer Guide</link>；<link href="https://www.tcpdump.org/manpages/pcap.3pcap.html" color="#087f8c">libpcap pcap(3PCAP)</link>；<link href="https://www.tcpdump.org/manpages/pcap-filter.7.html" color="#087f8c">pcap-filter(7)</link>。'),
                ("[3]", '<link href="https://www.rfc-editor.org/rfc/rfc791" color="#087f8c">RFC 791 IPv4</link>；<link href="https://www.rfc-editor.org/rfc/rfc8200" color="#087f8c">RFC 8200 IPv6</link>；<link href="https://www.rfc-editor.org/rfc/rfc9293" color="#087f8c">RFC 9293 TCP</link>；<link href="https://www.rfc-editor.org/rfc/rfc768" color="#087f8c">RFC 768 UDP</link>。'),
                ("[4]", '<link href="https://www.rfc-editor.org/rfc/rfc792" color="#087f8c">RFC 792 ICMP</link>；<link href="https://www.rfc-editor.org/rfc/rfc4443" color="#087f8c">RFC 4443 ICMPv6</link>；<link href="https://www.rfc-editor.org/rfc/rfc9112" color="#087f8c">RFC 9112 HTTP/1.1</link>。'),
                ("[5]", '<link href="https://www.rfc-editor.org/rfc/rfc1035" color="#087f8c">RFC 1035 DNS</link>；<link href="https://www.rfc-editor.org/rfc/rfc8446" color="#087f8c">RFC 8446 TLS 1.3</link>。'),
                ("源码", f'<link href="{REPOSITORY}" color="#087f8c">{REPOSITORY}</link>'),
            ], [.12, .88]),
            self.p("本报告根据项目实现、自动化测试记录和本机真实验证整理，不声称未记录的外部网络测试或用户个人操作。", "caption"),
        ])
        if len(pages) != TOTAL_PAGES:
            raise ValueError("报告分页清单与页脚总页数不一致。")
        return pages


def _page_decoration(canv, doc, report_date):
    canv.saveState()
    canv.setStrokeColor(TEAL)
    canv.setLineWidth(1.5)
    canv.line(LEFT, PAGE_HEIGHT - 40, PAGE_WIDTH - RIGHT, PAGE_HEIGHT - 40)
    canv.setFont(BOLD, 9)
    canv.setFillColor(NAVY)
    canv.drawString(LEFT, PAGE_HEIGHT - 29, "NetScope  |  实验 1A 网络协议分析")
    canv.setFont(REGULAR, 8)
    canv.setFillColor(MUTED)
    canv.drawRightString(PAGE_WIDTH - RIGHT, PAGE_HEIGHT - 29, "技术实验报告")
    canv.setStrokeColor(LINE)
    canv.setLineWidth(0.5)
    canv.line(LEFT, 36, PAGE_WIDTH - RIGHT, 36)
    canv.setFont(REGULAR, 7.8)
    canv.drawString(LEFT, 23, f"依据项目源码与本机验证记录  |  {report_date}")
    canv.drawRightString(PAGE_WIDTH - RIGHT, 23, f"{doc.page:02d} / {TOTAL_PAGES:02d}")
    canv.restoreState()


def build_report(output, inputs, regular_font, bold_font):
    register_fonts(regular_font, bold_font)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    document = BaseDocTemplate(str(output), pagesize=A4,
                               leftMargin=LEFT, rightMargin=RIGHT,
                               topMargin=TOP, bottomMargin=BOTTOM,
                               title="NetScope - 实验 1A 网络嗅探与协议分析", author="",
                               subject="程序设计、真实验证、复现与实现边界", allowSplitting=0)
    frame = Frame(LEFT, BOTTOM, CONTENT_WIDTH, CONTENT_HEIGHT,
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    document.addPageTemplates(PageTemplate(id="report", frames=[frame],
                                          onPage=partial(_page_decoration, report_date=inputs.report_date)))
    story = []
    for number, items in enumerate(ReportBuilder(inputs).pages(), start=1):
        if story:
            story.append(PageBreak())
        story.append(ReportPage(number, items))
    document.build(story, canvasmaker=partial(canvas.Canvas, invariant=1))
    _log(f"已生成 {TOTAL_PAGES} 页报告：{output.resolve()}")
    _log("请渲染全部页面，检查文字、截图、分页与链接后再交付。")
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("output/实验1A_report.pdf"))
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root containing samples and output")
    parser.add_argument("--date", default="2026-11-14", help="displayed experiment date, YYYY-MM-DD")
    parser.add_argument("--font-regular", type=Path, default=Path(r"C:\Windows\Fonts\simsun.ttc"))
    parser.add_argument("--font-bold", type=Path, default=Path(r"C:\Windows\Fonts\simhei.ttf"))
    args = parser.parse_args(argv)
    try:
        inputs = load_inputs(args.root, args.date)
        output = args.output if args.output.is_absolute() else inputs.root / args.output
        build_report(output, inputs, args.font_regular, args.font_bold)
    except (OSError, ValueError, TypeError) as error:
        _log(f"生成失败：{error}")
        return 1
    print(json.dumps({"output": str(output.resolve()), "pages": TOTAL_PAGES}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
