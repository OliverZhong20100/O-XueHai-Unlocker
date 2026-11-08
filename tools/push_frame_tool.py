#!/usr/bin/env python3
"""推送通道帧构造与回读工具（离线）。

用途：
    1. 按协议规范构造一条下行业务消息帧；
    2. 用独立解码器回读校验，确认字段与长度编码正确；
    3. 输出十六进制，便于与线上真实帧逐字节比对。

协议摘要：
    帧头 = magic(0x09) + version(1) + cmd(1) + 长度指示(1+n)
    长度 = len(content) + 3，n 为 (长度 >> 6) 右移 8 位的次数
    业务消息 content = mode(1) + count(2, BE) + count × (msgId(8,BE) + len(4,BE) + json)
"""

import json
import struct
import sys

MAGIC = 0x09
CMD_MESSAGE = 0x03
MAX_PACKET_LENGTH = 0xA00000


def encode_length(value: int) -> bytes:
    """把内容长度编码为 1+n 字节的长度指示。"""
    n = 0
    v = value >> 6
    while v > 0:
        n += 1
        v >>= 8
    head = ((n & 0x3) << 6) | ((value >> (8 * n)) & 0x3F)
    out = bytearray([head])
    for i in range(n - 1, -1, -1):
        out.append((value >> (8 * i)) & 0xFF)
    return bytes(out)


def decode_length(data: bytes):
    """返回 (内容长度, 长度字段占用的字节数)。"""
    head = data[0]
    n = (head >> 6) & 0x3
    value = head & 0x3F
    for i in range(n):
        value = (value << 8) | data[1 + i]
    return value - 3, 1 + n


def build_frame(cmd: int, content: bytes, version: int = 1) -> bytes:
    return bytes([MAGIC, version, cmd]) + encode_length(len(content) + 3) + content


def build_message(entries, mode: int = 0) -> bytes:
    """entries: [(msg_id:int, content:str|dict), ...]"""
    body = bytearray([mode & 0xFF])
    body += struct.pack(">H", len(entries) & 0xFFFF)
    for msg_id, content in entries:
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)
        raw = content.encode("utf-8")
        body += struct.pack(">q", msg_id)
        body += struct.pack(">i", len(raw))
        body += raw
    return bytes(body)


def decode_message(content: bytes):
    mode = content[0]
    count = struct.unpack(">H", content[1:3])[0]
    off = 3
    entries = []
    for _ in range(count):
        msg_id = struct.unpack(">q", content[off:off + 8])[0]
        off += 8
        length = struct.unpack(">i", content[off:off + 4])[0]
        off += 4
        if length < 0 or length > MAX_PACKET_LENGTH:
            raise ValueError("数据包长度异常(%d)" % length)
        text = content[off:off + length].decode("utf-8")
        off += length
        entries.append((msg_id, text))
    return mode, entries


def build_assist_notify(msg_id, assist_id, uid, device_id, hidden=1):
    notify = {
        "assistId": assist_id,      # 注意：字段名为 assistId，不是 id
        "hidden": hidden,           # 非 0 表示不显示浮动界面
        "operate": "ENTRY",
        "deviceId": device_id,
        "userId": uid,
    }
    push = {
        "appId": "zty_stu",
        "subAppId": "zty_stu",      # 必须与 appId 相等，否则不路由
        "clientId": "",
        "msgId": str(msg_id),
        "msgType": "assist-notify",
        "subMsgType": "assist-notify",
        "payload": json.dumps(notify, ensure_ascii=False),
        "userId": str(uid),
        "style": 0,
    }
    return build_message([(msg_id, push)])


def selftest() -> int:
    msg_id = 1750000000000
    content = build_assist_notify(msg_id, "assist_probe_1", 1000001, "R0000000001")
    frame = build_frame(CMD_MESSAGE, content)

    body_len, len_len = decode_length(frame[3:])
    assert body_len == len(content), (body_len, len(content))
    assert len(frame) == 3 + len_len + len(content)

    mode, entries = decode_message(frame[3 + len_len:])
    assert len(entries) == 1
    got_id, got_text = entries[0]
    assert got_id == msg_id

    push = json.loads(got_text)
    assert push["appId"] == push["subAppId"]
    assert json.loads(push["payload"])["assistId"] == "assist_probe_1"

    print("frame  : %d bytes, head=%s" % (len(frame), frame[:3].hex()))
    print("length : content=%d, encoded=%d bytes" % (len(content), len_len))
    print("msgId  : %d  (roundtrip ok)" % got_id)
    print("debug  : mode=%d count=%d" % (mode, len(entries)))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--hex":
        msg_id = int(sys.argv[2]) if len(sys.argv) > 2 else 1750000000000
        c = build_assist_notify(msg_id, "assist_probe_1", 1000001, "R0000000001")
        print(build_frame(CMD_MESSAGE, c).hex())
    else:
        sys.exit(selftest())
