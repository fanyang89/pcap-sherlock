# PCAP异常检测工具

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