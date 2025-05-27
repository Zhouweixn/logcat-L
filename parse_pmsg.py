# parse_pmsg.py
# This script is used to parse Android pmsg-ramoops log files and print them in a format similar to `logcat -L`.
# Project: https://github.com/Zhouweixn/logcat-L
# Usage: python parse_pmsg.py <pmsg-ramoops-0-1>
# Author: github-copilot-bot

#!/usr/bin/env python3
import struct
import sys
import time
from enum import IntEnum
import io
import string
import time as pytime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# 定义日志类型枚举
class LogId(IntEnum):
    LOG_ID_MIN = 0
    LOG_ID_MAIN = 0
    LOG_ID_RADIO = 1
    LOG_ID_EVENTS = 2
    LOG_ID_SYSTEM = 3
    LOG_ID_CRASH = 4
    LOG_ID_STATS = 5
    LOG_ID_SECURITY = 6
    LOG_ID_KERNEL = 7
    LOG_ID_MAX = 8
    LOG_ID_DEFAULT = 0x7FFFFFFF

# 定义日志优先级枚举
class LogPriority(IntEnum):
    ANDROID_LOG_UNKNOWN = 0
    ANDROID_LOG_DEFAULT = 1
    ANDROID_LOG_VERBOSE = 2
    ANDROID_LOG_DEBUG = 3
    ANDROID_LOG_INFO = 4
    ANDROID_LOG_WARN = 5
    ANDROID_LOG_ERROR = 6
    ANDROID_LOG_FATAL = 7
    ANDROID_LOG_SILENT = 8

# 定义pmsg头部结构
class PmsgHeader:
    def __init__(self, data):
        # 确保数据长度足够
        if len(data) < 7:
            raise ValueError(f"PmsgHeader data too short: {len(data)} bytes")
        # 解析头部字段
        self.magic = data[0]  # 1字节magic
        self.len = struct.unpack('<H', data[1:3])[0]  # 2字节长度字段
        self.uid = struct.unpack('<H', data[3:5])[0]  # 2字节uid字段
        self.pid = struct.unpack('<H', data[5:7])[0]  # 2字节pid字段
        self.data = data[7:]

# 定义log头部结构
class LogHeader:
    def __init__(self, data):
        # logcat源码结构: 1字节log_id, 2字节tid, 4字节sec, 4字节nsec
        self.id, self.tid, self.sec, self.nsec = struct.unpack('<BHIi', data[:11])
        self.data = data[11:]

def is_valid_header(data, offset):
    # 只判断结构和magic
    if offset + 7 + 11 + 1 > len(data):
        return False
    if data[offset] != ord('l'):
        return False
    return True

def is_printable_ascii(s):
    return all((chr(c) in string.printable and c != 0) for c in s)

def is_reasonable_log(data, offset, msg_len):
    # 只要不越界就输出
    if offset + 7 + 11 + 1 + msg_len > len(data):
        return False
    return True

def parse_pmsg_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    log_id_map = {
        0: 'main',
        1: 'radio',
        2: 'events',
        3: 'system',
        4: 'crash',
        5: 'stats',
        6: 'security',
        7: 'kernel'
    }
    printed_log_ids = set()
    offset = 0
    while offset < len(data):
        try:
            # 只要剩余长度够，直接尝试解包
            if offset + 7 + 11 + 1 > len(data):
                break
            pmsg_header = PmsgHeader(data[offset:offset+7])
            log_header = LogHeader(data[offset+7:offset+7+11])
            prio = data[offset+7+11]
            msg_len = pmsg_header.len - 7 - 11 - 1
            if msg_len <= 0 or offset+7+11+1+msg_len > len(data) or msg_len > 4096:
                raise Exception("invalid length")
            msg_data = data[offset+7+11+1:offset+7+11+1+msg_len]
            offset += 7 + 11 + 1 + msg_len
            # 只在每个log_id第一次出现时插入分隔符
            if log_header.id not in printed_log_ids:
                print(f"--------- beginning of {log_id_map.get(log_header.id, str(log_header.id))}")
                printed_log_ids.add(log_header.id)
            # 解析TAG和Message，最大程度还原logcat -L原始字节流
            try:
                tag_end = msg_data.find(0)
                if tag_end < 0:
                    tag = msg_data.decode('latin1', errors='replace')
                    msg = ''
                else:
                    tag = msg_data[:tag_end].decode('latin1', errors='replace')
                    msg = msg_data[tag_end+1:].decode('latin1', errors='replace')
            except Exception:
                tag = msg_data.decode('latin1', errors='replace')
                msg = ''
            timestamp = time.strftime('%m-%d %H:%M:%S', time.localtime(log_header.sec))
            msec = int((log_header.nsec // 1_000_000) % 1000)
            timestamp = f"{timestamp}.{msec:03d}"
            level_map = {2: 'V', 3: 'D', 4: 'I', 5: 'W', 6: 'E', 7: 'F'}
            level = level_map.get(prio & 0xF, '?')
            msg_lines = msg.split('\n')
            for line in msg_lines:
                line = line.rstrip('\r\n\0\uFFFD')
                print(f"{timestamp} {pmsg_header.pid:5d} {log_header.tid:5d} {level} {tag:<16}: {line}")
        except Exception:
            # 只要有异常，跳到下一个 'l'
            next_l = data.find(b'l', offset + 1)
            if next_l == -1:
                break
            offset = next_l

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python parse_pmsg.py <pmsg-ramoops-0-1>", file=sys.stderr)
        sys.exit(1)
    parse_pmsg_file(sys.argv[1])