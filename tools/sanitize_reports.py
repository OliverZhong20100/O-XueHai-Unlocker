# -*- coding: utf-8 -*-
"""sanitize_reports.py - 批量脱敏报告: 设备标识/账号/令牌/内网IP/厂商域名 -> 占位符
仅替换文本内容, 保持文档结构/格式不变。
"""
import io
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)  # sm-p200-takeover

REPL = [
    # 设备标识
    ("80:20:fd:8b:4b:fa", "<MAC>"),
    ("80-20-fd-8b-4b-fa", "<MAC>"),
    ("R52N9067SSF", "<序列号>"),
    ("2112229", "<userId>"),
    ("zhonghaoyang7", "<账号>"),
    ("zhonghaoyang", "<账号>"),
    ("UXHOVJJF", "<课堂ID>"),
    # 令牌
    (r"eyJhbGciOiJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "<JWT>"),
    (r"Bearer\s+eyJ[A-Za-z0-9_\-\.]+", "Bearer <JWT>"),
    # 内网
    (r"192\.168\.137\.\d+", "<内网IP>"),
    (r"192\.168\.137\.\*", "<内网IP>"),
    ("192.168.137.0/24", "<内网网段>"),
    # 厂商域名
    (r"[a-z0-9\-]+\.yunzuoye\.net", "<厂商域名>"),
    (r"[a-z0-9\-]+\.xht\.com", "<厂商域名>"),
    (r"zjxhedu\.com", "<厂商域名>"),
    ("yunzuoye.net", "<厂商域名>"),
    # 包名
    (r"com\.xh\.smartclassstu", "<学生包名>"),
    (r"com\.xh\.smartclasstch", "<教师包名>"),
    (r"com\.xh\.zhitongyunstu", "<启动器包名>"),
    (r"com\.zhitongyun\.sysupdate", "<agent包名>"),
    (r"com\.xh\.[a-z0-9\.]+", "<厂商包名>"),
    # 本地路径/用户
    (r"C:\\Users\\Olive\\[^\\\s\)\]]*", "<工作区路径>"),
    (r"Olive", "<用户>"),
]


def sanitize(text):
    n = 0
    for pat, rep in REPL:
        if pat.startswith("eyJ") or pat.startswith("Bearer") or pat.startswith("192\\") or \
           pat.startswith("[a-z0-9") or pat.startswith("com\\.") or pat.startswith("C:\\\\"):
            new, k = re.subn(pat, rep, text)
        else:
            k = text.count(pat)
            new = text.replace(pat, rep)
        if k:
            n += k
            text = new
    return text, n


def main():
    total_files = 0
    total_hits = 0
    for dp, dn, fs in os.walk(ROOT):
        # 跳过反编译树/日志/载荷目录
        rel = os.path.relpath(dp, ROOT)
        if rel.startswith("pentest\\cls_dec") or rel.startswith("pentest\\ztp") or \
           rel.startswith("pentest\\xhsettings") or rel.startswith("pentest\\wm") or \
           rel.startswith("pentest\\launcher_dec") or rel.startswith("pentest\\verify_dec") or \
           rel.startswith("pentest\\payload_src") or rel.startswith("pentest\\pylibs") or \
           rel.startswith("dec_") or rel.startswith("portal\\"):
            continue
        for fn in fs:
            if not fn.lower().endswith((".md", ".txt")):
                continue
            p = os.path.join(dp, fn)
            try:
                s = io.open(p, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            out, n = sanitize(s)
            if n > 0:
                io.open(p, "w", encoding="utf-8").write(out)
                total_files += 1
                total_hits += n
                print("sanitized %-46s %d处" % (fn[:44], n))
    print("\nfiles=%d  replacements=%d" % (total_files, total_hits))


if __name__ == "__main__":
    main()
