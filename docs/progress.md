# 实验 1A 工作记录

- 已核对全部讲义；1A 与 1B 需求分开。
- 已获用户确认 Python + PySide6 + Npcap、完整源码/报告/视频；姓名学号留空。
- 初始基线 e4d0b20，仅 .gitignore 与 LICENSE；无现有代码或测试。
- 2026-11-14：开始于 feat/lab1a。现有新仓库直接在功能分支实现，避免额外 worktree；所有更改限制在本实验。
- 约定接口见 implementation-plan.md，抓包后台使用有界队列，GUI 按批次读取。
- 协议解析、Npcap 抓包、BPF/显示过滤、PCAP 读写、GUI 与双向 TCP 流已实现并分阶段提交。
- 实际 Npcap 1.89 回环验证：42 包（IPv4 22、IPv6 20），HTTP/UDP/ICMP/ICMPv6；驱动丢包 0；无流量停止 3.45 ms；无效 BPF 被拒绝；PCAP 原始字节往返一致。
- 独立审查发现线程信号循环引用及 DNS 压缩指针工作量问题，已分别用失败回归复现并修复；增加 PID 0 归属过滤和大数据预览上限。
- 最终完整测试：107 passed，0 failed；命令和 JUnit 结果保存在 output/test-results.*。
- 演示为真实 Qt 窗口录制，前半段实际本机抓包，后半段明确标注合成样例；11 页 PDF 据实测、截图和最终测试生成。
