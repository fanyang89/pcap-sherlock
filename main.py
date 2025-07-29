#!/usr/bin/env python3
"""
在已对齐的多机 pcap 中找故障集中时间段
用法:
  python find_fault_bursts.py merged.pcap --window 5 --threshold 10
参数:
  --window     滑动窗口秒数 (默认 5s)
  --threshold  窗口内异常事件数超过此值即算 burst
输出:
  终端打印 burst 起止时间，并生成 bursts.png
"""

import subprocess, argparse, json, sys, os
from io import StringIO
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

TSHARK = "tshark"
FILTER = "tcp.analysis.flags"

def extract_events(pcap):
    """返回 DataFrame: ts (秒), event (1)"""
    cmd = [TSHARK, "-r", pcap, "-Y", FILTER,
           "-T", "fields", "-e", "frame.time_epoch"]
    try:
        # 使用 stderr=subprocess.DEVNULL 来忽略警告信息
        txt = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
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
    return df[["ts", "event"]]

def detect_bursts(df, window, threshold):
    """滑动窗口计数，返回 burst 区间列表 [(start,end,count), ...]"""
    bins = np.arange(df.ts.min(), df.ts.max() + window, window)
    counts = df.groupby(pd.cut(df.ts, bins), observed=False).event.sum().fillna(0)
    bursts = counts[counts >= threshold]
    if bursts.empty:
        return []
    # 把连续 bin 合并为区间
    start = None
    intervals = []
    for left, right in zip(bursts.index, bursts.index[1:]):
        if start is None:
            start = left.left
        if right.left != left.right:
            intervals.append((start, left.right, counts.loc[left]))
            start = None
    # 最后一截
    if start is not None:
        intervals.append((start, bursts.index[-1].right, counts.iloc[-1]))
    return intervals

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--window", type=int, default=1)
    parser.add_argument("--threshold", type=int, default=10)
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        sys.exit("pcap 不存在")

    print("提取事件 …")
    df = extract_events(args.pcap)
    if df.empty:
        print("未检测到任何异常事件")
        return

    print("检测 burst …")
    bursts = detect_bursts(df, args.window, args.threshold)
    if not bursts:
        print("未检测到显著 burst")
        return

    print("\n故障集中时间段：")
    for start, end, cnt in bursts:
        print(f"{pd.to_datetime(start, unit='s')}  ~  {pd.to_datetime(end, unit='s')}  ({int(cnt)} events)")

    # 画图
    plt.figure(figsize=(12, 3))
    plt.hist(df.ts, bins=int((df.ts.max() - df.ts.min())/args.window))
    for s, e, _ in bursts:
        plt.axvspan(s, e, color='r', alpha=0.3)
    plt.title("Exceptions")
    plt.xlabel("time")
    plt.ylabel("events")
    plt.tight_layout()
    plt.savefig("bursts.png")
    print("已保存 bursts.png")

if __name__ == "__main__":
    main()
