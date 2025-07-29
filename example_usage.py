#!/usr/bin/env python3
"""
PCAP异常检测工具使用示例

这个脚本展示了如何使用pcap_anomaly_detector.py来分析网络流量中的异常模式
"""

import subprocess
import sys
import os

def run_analysis_examples():
    """
    运行不同参数的分析示例
    """
    pcap_file = "tcpdump-trace-250728-193554.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"错误: 找不到PCAP文件 {pcap_file}")
        return
    
    print("PCAP异常检测工具使用示例")
    print("=" * 50)
    
    examples = [
        {
            "name": "基本分析 - 检测高频异常",
            "cmd": ["python", "pcap_anomaly_detector.py", pcap_file, "--threshold", "50", "--window", "5"]
        },
        {
            "name": "详细分析 - 低阈值检测所有异常",
            "cmd": ["python", "pcap_anomaly_detector.py", pcap_file, "--threshold", "1", "--window", "10", "--verbose", "--stats"]
        },
        {
            "name": "自定义过滤器 - 检测TCP重传",
            "cmd": ["python", "pcap_anomaly_detector.py", pcap_file, "--filter", "tcp.analysis.retransmission", "--threshold", "5"]
        },
        {
            "name": "精细时间窗口分析",
            "cmd": ["python", "pcap_anomaly_detector.py", pcap_file, "--window", "1", "--threshold", "10", "--output", "fine_grained_analysis.png"]
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['name']}")
        print(f"命令: {' '.join(example['cmd'])}")
        
        try:
            # 使用uv运行
            cmd = ["uv", "run"] + example['cmd']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ 执行成功")
                # 只显示关键输出行
                lines = result.stdout.split('\n')
                for line in lines:
                    if ('检测到' in line and '异常集中' in line) or ('持续时间' in line) or ('统计信息' in line):
                        print(f"   {line}")
            else:
                print(f"❌ 执行失败: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("⏰ 执行超时")
        except Exception as e:
            print(f"❌ 执行错误: {e}")
        
        print("-" * 30)

def show_help():
    """
    显示工具的帮助信息
    """
    print("\nPCAP异常检测工具参数说明:")
    print("=" * 40)
    
    params = [
        ("--window", "滑动窗口大小(秒)", "控制时间粒度，越小越精细"),
        ("--threshold", "异常阈值", "窗口内事件数超过此值算异常"),
        ("--filter", "tshark过滤器", "指定要分析的网络事件类型"),
        ("--output", "输出文件名", "生成的图表文件名"),
        ("--verbose", "详细模式", "显示更多调试信息"),
        ("--stats", "统计信息", "显示详细的统计数据")
    ]
    
    for param, desc, detail in params:
        print(f"{param:12} - {desc:15} - {detail}")
    
    print("\n常用tshark过滤器:")
    filters = [
        ("tcp.analysis.flags", "TCP分析标志 (默认)"),
        ("tcp.analysis.retransmission", "TCP重传"),
        ("tcp.analysis.duplicate_ack", "重复ACK"),
        ("tcp.analysis.lost_segment", "丢失段"),
        ("icmp", "ICMP消息"),
        ("dns.flags.response eq 0", "DNS查询")
    ]
    
    for filter_expr, desc in filters:
        print(f"  {filter_expr:30} - {desc}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        show_help()
        return
    
    print("开始运行PCAP异常检测示例...")
    run_analysis_examples()
    
    print("\n" + "=" * 50)
    print("示例运行完成!")
    print("\n生成的文件:")
    
    output_files = [
        "anomaly_bursts.png",
        "fixed_anomaly_bursts.png", 
        "fine_grained_analysis.png"
    ]
    
    for file in output_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"  ✅ {file} ({size} bytes)")
        else:
            print(f"  ❌ {file} (未生成)")
    
    print("\n使用 'python example_usage.py --help' 查看更多参数说明")

if __name__ == "__main__":
    main()