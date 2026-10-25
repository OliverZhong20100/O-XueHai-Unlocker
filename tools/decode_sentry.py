# -*- coding: utf-8 -*-
"""decode_sentry.py - 从冒充器日志里把端侧发往 sentry 的 gzip body 提取并解压,
看 App 的真实报错（能判断 7z 解压/短语下载是否失败）。
"""
import ast
import gzip
import io
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "npcap_http80.log")
OUT = os.path.join(BASE, "sentry_decoded.txt")

pat = re.compile(r"body=(\d+)B (b'.*'|b\".*\")")


def main():
    with io.open(LOG, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    hits = []
    for ln in lines[-200000:]:
        if "sentry.yunzuoye.net" not in ln:
            continue
        m = pat.search(ln)
        if not m:
            continue
        try:
            raw = ast.literal_eval(m.group(2))
        except Exception:
            continue
        if not raw:
            continue
        body = None
        for dec in (lambda b: gzip.decompress(b), lambda b: b):
            try:
                body = dec(raw)
                break
            except Exception:
                pass
        if not body:
            continue
        txt = body.decode("utf-8", "replace")
        hits.append(txt)
    with io.open(OUT, "w", encoding="utf-8") as f:
        for t in hits:
            f.write(t + "\n---\n")
    print("decoded %d sentry bodies -> %s" % (len(hits), OUT))
    # 打印含关键字的行
    keys = ("error", "exception", "unzip", "7z", "zip", "phrase", "download", "fail",
            "Exception", "Error", "extract", "ctv4", "voice")
    for t in hits[-12:]:
        for ln in t.splitlines():
            if any(k in ln for k in keys):
                print("  | " + ln[:220])


if __name__ == "__main__":
    main()
