# PCAP Sherlock

## TCP 两端分析入口

新入口 `sherlock.py` 使用 SQLite 磁盘索引和流式 tshark 输出，仅需 Python 3.10+ 和 tshark。

```bash
python3 sherlock.py --a client.pcap --b server.pcap --output analysis
python3 sherlock.py --a client-1.pcap client-2.pcap --b server.pcap --offset-b -0.25 --output aligned
# 导出排名前 5 个异常窗口，保留同连接前后各 5 秒上下文
python3 sherlock.py --a client.pcap --b server.pcap --export-bursts 5 --context 5 --output evidence-analysis
python3 -m unittest discover -s tests -v
```

输出目录必须尚不存在。`--b` 可省略以执行单点分析；`--offset-b` 是加到 B 端时间上的秒数。
`--window` 默认 60 秒，`--threshold` 默认 10 个事件包，使用 epoch 对齐的固定窗口。

输出 `report.html`（离线可折叠表格）、`report.json` 和 `index.sqlite`。
报告包含方向级连接统计、重传／重复 ACK／乱序／零窗口／RST、可用 ACK RTT、
分钟趋势、最多 500 个异常窗口及最多 1000 对两端证据样例，匹配总数单独统计。
保留原始文件与包号；报告中的 TCP stream 过滤器必须用于对应文件。
载荷截断但 TCP 头部完整的报文可以分析；捕获长度和原始长度分别保存。
tshark 失败会非零退出，不生成成功报告，可能保留部分索引供检查。

### 抓包质量与证据导出

输入统计包含已解码 TCP 包数、可索引包数、头部不完整数、截断数、原始时间范围、
捕获长度范围及按文件顺序观察到的时间戳倒退次数。截断统计包含被跳过的不完整头部记录。
TCP 固定头部及声明的选项必须完整才能进入索引；最大捕获长度不是配置 snaplen 的推断值。
时间戳倒退是观测，不直接断言发生了校时或网络乱序。

`--export-bursts N` 默认关闭，最多 500；按异常窗口排名导出，每个文件只包含
该异常所属原始文件、同一 TCP stream 的双向报文及时间上下文。
不会自动补齐另一端或相邻轮转文件。每个导出都重新扫描一次原始文件，建议先导出少量重点窗口。

导出文件位于 `evidence/*.pcapng`，报告提供直接打开的链接。
原始时间戳、载荷截断保留不变；手动时间偏移只参与选择区间。
`report.json` 的 `exports` 记录源文件、原 stream、事件包号范围、原始时间范围、
过滤器和导出状态。导出文件会重新分配包号与 stream，不能把原文件过滤器直接套到导出文件。
tshark 还可能写入匹配报文依赖的分片；上下文不保证包含完整握手或完整会话。
单项导出失败会记录错误并清理该项临时文件，其他导出和分析报告仍保留，命令最终非零退出。

JSON 当前 `schema_version` 为 2。无对端匹配时计数为 0；两端签名先聚合为临时索引再关联，
重复头部仍按歧义处理。测试包含动态生成的截断 TCP 抓包及导出回读；
本机没有 tshark 时这两项集成测试会明确跳过，GitHub Actions 配置为安装 tshark 后运行全部测试。

### 当前限制

- 两端关联采用地址、端口、原始序列号、ACK、长度、标志和窗口的精确头部候选匹配；重复签名标记为歧义。
- 未观察到匹配不代表链路丢包；TCP 分析标记不是故障证明。两端时间差包含时钟误差，不是单向时延。
- 字节计数包含重传及 offload 影响，不代表应用有效吞吐。
- 只索引 tshark 已解码的 TCP；头部不完整记录跳过并计数。各文件 stream 独立，轮转会话尚未合并。
- 序列范围重组、TSO/GRO 分段差异、NAT／四元组复用消歧、自动时钟校准、握手耗时与无进展检测、图形下钻尚未实现。
- 全天真实抓包的耗时、内存及报告体积尚待验收。

## 旧版异常计数工具

这是一个用于分析PCAP文件中异常值集中出现时间点的Python工具集。该工具可以帮助网络管理员和安全分析师识别网络流量中的异常模式和潜在问题。

## 功能特性

- 🔍 **异常事件检测**: 使用tshark分析PCAP文件中的TCP异常事件
- 📊 **时间窗口分析**: 可配置的滑动窗口检测异常集中时间段
- 📈 **可视化图表**: 生成时间序列和频率分布图表
- 📋 **详细统计**: 提供异常事件的统计信息和分析报告
- 🛠️ **灵活配置**: 支持自定义过滤器、阈值和时间窗口
- 🚀 **错误处理**: robust的错误处理，支持损坏的PCAP文件

## 安装要求

### 系统依赖
- Python 3.10+
- tshark (Wireshark命令行工具)
- uv (Python包管理器)

### Python依赖
```bash
# 使用uv安装依赖
uv sync
```

依赖包:
- pandas >= 2.3.1
- numpy >= 2.2.6
- matplotlib >= 3.10.3

## 使用方法

### 基本用法

```bash
# 基本异常检测
uv run python pcap_anomaly_detector.py your_file.pcap

# 自定义参数
uv run python pcap_anomaly_detector.py your_file.pcap --window 5 --threshold 10

# 详细模式with统计信息
uv run python pcap_anomaly_detector.py your_file.pcap --verbose --stats
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--window` | 5 | 滑动窗口大小(秒) |
| `--threshold` | 10 | 异常阈值(窗口内事件数) |
| `--filter` | `tcp.analysis.flags` | tshark过滤器表达式 |
| `--output` | `anomaly_bursts.png` | 输出图表文件名 |
| `--verbose` | False | 详细输出模式 |
| `--stats` | False | 显示统计信息 |

### 常用过滤器

```bash
# TCP重传检测
uv run python pcap_anomaly_detector.py file.pcap --filter "tcp.analysis.retransmission"

# 重复ACK检测
uv run python pcap_anomaly_detector.py file.pcap --filter "tcp.analysis.duplicate_ack"

# TCP丢失段检测
uv run python pcap_anomaly_detector.py file.pcap --filter "tcp.analysis.lost_segment"

# ICMP消息检测
uv run python pcap_anomaly_detector.py file.pcap --filter "icmp"
```

## 示例

### 运行示例脚本

```bash
# 运行多个分析示例
uv run python example_usage.py

# 查看参数帮助
uv run python example_usage.py --help
```

### 输出示例

```
检测到 1 个异常集中时间段:
================================================================================
 1. 2025-07-28 12:06:15.913000107 ~ 2025-07-28 12:06:20.913000107
    持续时间: 5.0秒, 事件数: 403, 平均速率: 80.6 事件/秒
================================================================================

=== 统计信息 ===
总事件数: 478
时间跨度: 2802.01 秒
平均事件率: 0.17 事件/秒
异常集中数: 1
异常集中事件数: 403 (84.3%)
正常事件数: 75 (15.7%)
```

## 文件说明

- `main.py` - 原始的简单版本脚本
- `pcap_anomaly_detector.py` - 增强版异常检测工具
- `example_usage.py` - 使用示例和演示脚本
- `tcpdump-trace-250728-193554.pcap` - 示例PCAP文件
- `*.png` - 生成的可视化图表

## 输出文件

工具会生成以下文件:

1. **可视化图表** (PNG格式)
   - 上图: 异常事件时间线散点图
   - 下图: 事件频率分布直方图
   - 红色区域: 标识异常集中时间段

2. **终端输出**
   - 异常集中时间段列表
   - 统计信息(可选)
   - 详细调试信息(可选)

## 故障排除

### 常见问题

1. **tshark未找到**
   ```bash
   # macOS安装
   brew install wireshark
   
   # Ubuntu/Debian安装
   sudo apt-get install tshark
   ```

2. **PCAP文件损坏**
   - 工具会自动处理损坏的PCAP文件
   - 使用`--verbose`查看详细错误信息

3. **未检测到异常**
   - 尝试降低`--threshold`值
   - 调整`--window`大小
   - 检查`--filter`是否匹配预期事件

4. **中文字体显示问题**
   - 工具会自动尝试多种字体
   - 图表标题使用英文避免字体问题

## 开发

### 项目结构
```
app/
├── main.py                    # 原始脚本
├── pcap_anomaly_detector.py   # 主要工具
├── example_usage.py           # 使用示例
├── pyproject.toml            # 项目配置
├── uv.lock                   # 依赖锁定
└── README.md                 # 项目文档
```

### 扩展功能

可以通过修改`pcap_anomaly_detector.py`来添加新功能:
- 支持更多网络协议
- 添加机器学习异常检测
- 实现实时流量监控
- 集成告警系统

## 许可证

本项目使用MIT许可证。
