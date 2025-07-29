#!/usr/bin/env python3
"""
PCAP异常值检测脚本
用于分析pcap文件中异常事件的集中时间点

用法:
  python pcap_anomaly_detector.py <pcap_file> [选项]

参数:
  --window     滑动窗口秒数 (默认 5s)
  --threshold  窗口内异常事件数超过此值即算异常集中 (默认 10)
  --filter     tshark过滤器 (默认 'tcp.analysis.flags')
  --output     输出图片文件名 (默认 'anomaly_bursts.png')
  --verbose    详细输出模式
  --stats      显示统计信息

输出:
  - 终端打印异常集中时间段
  - 生成可视化图表
  - 可选的统计信息
"""

import subprocess
import argparse
import json
import sys
import os
from io import StringIO
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import warnings

# 忽略pandas的FutureWarning
warnings.filterwarnings('ignore', category=FutureWarning)

TSHARK = "tshark"
DEFAULT_FILTER = "tcp.analysis.flags"

def extract_events(pcap, filter_expr=DEFAULT_FILTER, verbose=False):
    """
    从pcap文件中提取异常事件
    返回 DataFrame: ts (秒), event (1)
    """
    cmd = [TSHARK, "-r", pcap, "-Y", filter_expr,
           "-T", "fields", "-e", "frame.time_epoch"]
    
    if verbose:
        print(f"执行命令: {' '.join(cmd)}")
    
    try:
        # 使用 stderr=subprocess.DEVNULL 来忽略警告信息
        txt = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"tshark 执行失败: {e}")
        print("尝试忽略错误继续处理...")
        # 尝试使用 run 而不是 check_output，允许非零退出码
        result = subprocess.run(cmd, capture_output=True, text=True)
        txt = result.stdout
        if not txt.strip():
            print("无法从 pcap 文件中提取任何数据")
            return pd.DataFrame(columns=["ts", "event"])
    
    if not txt.strip():
        print("未找到匹配的事件")
        return pd.DataFrame(columns=["ts", "event"])
    
    df = pd.read_csv(StringIO(txt), names=["ts"])
    df["ts"] = pd.to_numeric(df["ts"], errors='coerce')
    df = df.dropna()  # 移除无效的时间戳
    df["event"] = 1
    
    if verbose:
        print(f"提取到 {len(df)} 个事件")
    
    return df[["ts", "event"]]

def detect_bursts(df, window, threshold, verbose=False):
    """
    使用滑动窗口检测异常集中
    返回 burst 区间列表 [(start,end,count), ...]
    """
    if df.empty:
        return []
    
    bins = np.arange(df.ts.min(), df.ts.max() + window, window)
    counts = df.groupby(pd.cut(df.ts, bins), observed=False).event.sum().fillna(0)
    bursts = counts[counts >= threshold]
    
    if verbose:
        print(f"总时间窗口数: {len(counts)}")
        print(f"超过阈值的窗口数: {len(bursts)}")
    
    if bursts.empty:
        return []
    
    # 把连续 bin 合并为区间
    intervals = []
    current_start = None
    current_end = None
    current_count = 0
    
    for interval, count in bursts.items():
        if current_start is None:
            current_start = interval.left
            current_end = interval.right
            current_count = count
        elif interval.left == current_end:  # 连续区间
            current_end = interval.right
            current_count += count
        else:  # 非连续区间，保存当前区间并开始新的
            intervals.append((current_start, current_end, current_count))
            current_start = interval.left
            current_end = interval.right
            current_count = count
    
    # 添加最后一个区间
    if current_start is not None:
        intervals.append((current_start, current_end, current_count))
    
    return intervals

def calculate_statistics(df, bursts, verbose=False):
    """
    计算统计信息
    """
    if df.empty:
        return {}
    
    total_events = len(df)
    time_span = df.ts.max() - df.ts.min()
    avg_rate = total_events / time_span if time_span > 0 else 0
    
    burst_events = sum(count for _, _, count in bursts)
    normal_events = total_events - burst_events
    
    stats = {
        'total_events': total_events,
        'time_span_seconds': time_span,
        'avg_events_per_second': avg_rate,
        'burst_count': len(bursts),
        'burst_events': burst_events,
        'normal_events': normal_events,
        'burst_percentage': (burst_events / total_events * 100) if total_events > 0 else 0
    }
    
    if verbose:
        print("\n=== 统计信息 ===")
        print(f"总事件数: {stats['total_events']}")
        print(f"时间跨度: {stats['time_span_seconds']:.2f} 秒")
        print(f"平均事件率: {stats['avg_events_per_second']:.2f} 事件/秒")
        print(f"异常集中数: {stats['burst_count']}")
        print(f"异常集中事件数: {stats['burst_events']} ({stats['burst_percentage']:.1f}%)")
        print(f"正常事件数: {stats['normal_events']} ({100-stats['burst_percentage']:.1f}%)")
    
    return stats

def create_visualization(df, bursts, window, output_file, verbose=False):
    """
    创建可视化图表
    """
    if df.empty:
        print("没有数据可以可视化")
        return
    
    # 设置matplotlib支持中文字体
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False
    
    plt.figure(figsize=(15, 8))
    
    # 创建子图
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
    
    # 上图：时间序列散点图
    ax1.scatter(df.ts, [1] * len(df), alpha=0.6, s=10, c='blue', label='Anomaly Events')
    for i, (start, end, count) in enumerate(bursts):
        label = f'Anomaly Burst ({int(count)} events)' if i == 0 else ""
        ax1.axvspan(start, end, color='red', alpha=0.3, label=label)
    
    ax1.set_ylabel('Events')
    ax1.set_title('Anomaly Events Timeline')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 下图：直方图
    bins_count = max(50, int((df.ts.max() - df.ts.min()) / window))
    ax2.hist(df.ts, bins=bins_count, alpha=0.7, color='skyblue', edgecolor='black')
    
    for start, end, count in bursts:
        ax2.axvspan(start, end, color='red', alpha=0.3)
    
    ax2.set_xlabel('Time (Unix Timestamp)')
    ax2.set_ylabel('Event Count')
    ax2.set_title(f'Anomaly Event Frequency Distribution (Window: {window}s)')
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    
    if verbose:
        print(f"图表已保存到: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='PCAP异常值检测脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("pcap", help="PCAP文件路径")
    parser.add_argument("--window", type=int, default=5, help="滑动窗口秒数 (默认: 5)")
    parser.add_argument("--threshold", type=int, default=10, help="异常阈值 (默认: 10)")
    parser.add_argument("--filter", default=DEFAULT_FILTER, help=f"tshark过滤器 (默认: '{DEFAULT_FILTER}')")
    parser.add_argument("--output", default="anomaly_bursts.png", help="输出图片文件名 (默认: anomaly_bursts.png)")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出模式")
    parser.add_argument("--stats", "-s", action="store_true", help="显示统计信息")
    
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        sys.exit(f"错误: PCAP文件 '{args.pcap}' 不存在")

    print(f"分析PCAP文件: {args.pcap}")
    print(f"使用过滤器: {args.filter}")
    print(f"窗口大小: {args.window}秒, 阈值: {args.threshold}")
    print()

    print("提取异常事件...")
    df = extract_events(args.pcap, args.filter, args.verbose)
    
    if df.empty:
        print("未检测到任何异常事件")
        return

    print("检测异常集中...")
    bursts = detect_bursts(df, args.window, args.threshold, args.verbose)
    
    if not bursts:
        print(f"未检测到显著的异常集中 (阈值: {args.threshold})")
        print("建议尝试降低阈值或调整窗口大小")
    else:
        print(f"\n检测到 {len(bursts)} 个异常集中时间段:")
        print("=" * 80)
        for i, (start, end, count) in enumerate(bursts, 1):
            start_time = pd.to_datetime(start, unit='s')
            end_time = pd.to_datetime(end, unit='s')
            duration = end - start
            print(f"{i:2d}. {start_time} ~ {end_time}")
            print(f"    持续时间: {duration:.1f}秒, 事件数: {int(count)}, 平均速率: {count/duration:.1f} 事件/秒")
        print("=" * 80)

    # 统计信息
    if args.stats or args.verbose:
        calculate_statistics(df, bursts, True)

    # 生成可视化
    print(f"\n生成可视化图表: {args.output}")
    create_visualization(df, bursts, args.window, args.output, args.verbose)
    print("分析完成!")

if __name__ == "__main__":
    main()