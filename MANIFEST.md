# 项目组件汇集清单（MANIFEST）

> 汇集时间：2026-10-24
> 说明：仅收录项目实际使用的工具组件、载荷样本、报告与数据资产。
> 已排除：运行日志（*.log）、临时输出（*_out.txt/*_err.txt）、编译缓存、反编译树、旧快照与中间产物。

---

## 目录结构

```
New folder (2)/
├── MANIFEST.md          ← 本清单
├── tools/               ← 63 个 Python 工具组件
├── payloads/            ← 13 个载荷/样本/证书
├── reports/             ← 12 份报告（已脱敏）
├── data/                ← 3 个数据资产
└── launchers/           ← 12 个启动器脚本
```

---

## 一、tools/（63 个 Python 组件）

### 1.1 网络层主力
| 文件 | 作用 |
|---|---|
| `npcap_http80.py` | 主冒充器：80 端口 L2 抢答、HTTP 代理/注入、页面与载荷投递（含 [GETPAGE-INJECT]/[WEBP-SERVE]/[PAYLOAD-SERVE2]/[CHECKLIST] 等）|
| `ws8889.py` | 课堂 WebSocket 嗅探/注入器（ISN 采纳 + ACK 追踪）|
| `proxy8888.py` | 应用列表/APK 下发代理 |
| `fake_classroom.py` | 假课堂：多播公告 + WS 服务 + 消息矩阵 |
| `cloud_api.py` | 厂商 API 仿真（服务表/版本变更/协助任务）|
| `cloud_3200.py` / `npcap3200.py` | 3200 端口业务仿真 |
| `npcap_pbs.py` / `push_pbs.py` | 推送 PBS 长连接服务 |
| `npcap_8089.py` | 8089 端口组件 |
| `tls_passthrough.py` / `tls_relay_v2.py` / `mitm443.py` | 443 SNI 直通 / TLS 中继 / MITM 尝试 |
| `dns_hijack.py` | DNS 劫持 |
| `windivert_dnat_v9.py` | WinDivert 目标端口重定向（最新版）|
| `arp_captive.py` / `arp_basket.py` | ARP/强制门户 |
| `ws_server_local.py` | 本地 WS 服务 |
| `ftp_share_exploit.py` | 内置文件共享服务扫描/读/写 |
| `assist_orchestrator.py` | 协助链编排（checklist → task → install）|
| `keepalive.py` / `supervisor.py` | 进程守护 |
| `verify_all.py` | 全链路自检 |
| `probe8099.py` / `scan_dyn_ports.py` / `watch_ports.py` | 端口探测/扫描 |
| `go.py` / `dryrun_unattended.py` / `plan_c_autochain.py` / `agent_connect.py` | 自动化编排 |

### 1.2 载荷构造
| 文件 | 作用 |
|---|---|
| `build_slip_proxy.py` | 生成启动器代理开关 ZIP-SLIP（7z 头补丁 + CRC 修正）|
| `build_slip_compat.py` | 最大兼容 7z 载荷 |
| `build_slip_zip.py` | 真 ZIP 版 ZIP-SLIP |
| `build_final_7z.py` | 最终 7z 载荷 |
| `patch_biz_zipslip.py` / `patch_proxy_real.py` | 业务包/代理开关补丁 |

### 1.3 注入器
| 文件 | 作用 |
|---|---|
| `inject_upclass.py` | ★制造"上课中"状态（type=400 code_syn_start_sign → UP_CLASS_STATE）+ 任务触发 |
| `inject_carrier.py` / `inject_carrier_ti.py` | 载体构造 + 完整信封注入 |
| `inject_doc_answer.py` | 文档答案图片注入 |
| `inject_task0.py` / `inject_task2_db.py` / `inject_multi_types.py` | 任务消息注入 |
| `inject_ppt_resource.py` / `inject_cwp.py` / `inject_startclass.py` | PPT/CWP/开课注入 |
| `inject_50001*.py` | 50001 文件传输链注入 |

### 1.4 分析/定位工具
| 文件 | 作用 |
|---|---|
| `map_server_types.py` / `map_all_handlers.py` | 消息类型 → action 自动映射 |
| `find_upclass_setters.py` | ★课堂状态设置器调用链定位 |
| `find_teacher_jwt.py` | APK 内令牌扫描 |
| `find_receivers2.py` | 消息接收器枚举 |
| `find_unzip_callers2.py` / `find_downloader.py` / `find_seturls.py` / `find_batch.py` | 下载/解压链定位 |
| `extract_frames.py` | WS 帧解析（真实消息库）|
| `decode_sentry.py` | 遥测解码 |
| `sanitize_reports.py` | 报告批量脱敏 |
| `ws_autoburst.py` / `ws_reconnect_autoburst.py` | WS 自动重连/突发 |

---

## 二、payloads/（13 个）

| 文件 | 大小 | 用途 |
|---|---|---|
| `agent.apk` | 1.87MB | 自研 agent（4711 shell）|
| `payload_proxy.7z` | 9,312B | ★ZIP-SLIP 主载荷（42 条 ../ 深度 1-20）|
| `payload_slip.7z` | 14,092B | 7z 版 ZIP-SLIP |
| `payload_malicious.cwp` | 1,422B | CWP 变体 |
| `nso.webp` | 350B | ★CVE-2023-4863 武器化样本 |
| `fullchain.pem` / `server.key` | 3.4KB/1.7KB | MITM 证书（仅本实验）|
| `clienthello.bin` | 517B | TLS 指纹 |
| `note.html` / `mitm_page.html` / `bridge_probe.html` / `webview_bridge_probe.js` / `payload_webview.html` | — | WebView 桥探测页 |

---

## 三、reports/（12 份，已脱敏）

| 文件 | 内容 |
|---|---|
| `README.md` | GitHub 项目页（含完整免责声明）|
| `PROJECT-OVERVIEW.md` | 项目介绍 + 组件登记表（脱敏模板）|
| `FINAL-REPORT-2026-10-24.md` | 主报告（WS 注入链 + 判死清单）|
| `REPORT-2026-10-24-WS注入链路.md` | 课堂 WS 注入链路详述 |
| `REPORT-2026-10-24-CVE-2023-4863.md` | 沙箱逃逸专项 |
| `REVIEW-FINAL-ALLCHAINS.md` | 十条链逐条裁决 |
| `LAST-MILE-BREAKTHROUGH.md` | isEndUpClass 闸门根因 |
| `ASSIST-CHAIN-FINAL.md` | 协助链（静默安装原语）|
| `Z7EXTRACTOR-ARBITRARY-WRITE.md` | Z7Extractor 无路径校验证明 |
| `FULL-CHAIN-ARBITRARY-WRITE.md` | 历史全链假设（已标注误判处）|
| `FINAL-REPORT-APK-PUSH-CHAIN.md` | APK 推送链报告 |
| `INDEX-总览.md` | 项目总览 |

---

## 四、data/（3 个数据资产）

| 文件 | 内容 |
|---|---|
| `ws_message_map.txt` | 90 个消息类型 → action 映射 |
| `ws_real_messages.txt` | ★56 类真实消息样本（端侧 + 注入）|
| `REAL_TOKEN.txt` | 会话令牌（已脱敏为 `<JWT>`）|

---

## 五、launchers/（12 个启动器）

| 文件 | 作用 |
|---|---|
| `full_rebuild.cmd` | 全量重建（杀进程 → 依次启全部组件 → 热点）|
| `start_spoofer.cmd` | 启动主冒充器 |
| `start_all14.ps1` | 8 组件批量启动 |
| `start_fake_8080.cmd` | 启动假课堂 |
| `ws8889_solo.cmd` | WS 注入器单实例 |
| `rebuild14.cmd` / `retest_prep.cmd` | 快速重建/复测准备 |
| `watchdog3.cmd` | 进程守护 |
| `run_ftp_probe.cmd` / `run_canvas_sweep.cmd` / `run_verify50001.cmd` / `run_extract.cmd` | 专项测试启动 |

> 所有 `.cmd` 必须 ASCII-only；建议通过 `Invoke-CimMethod Win32_Process Create` 启动。

---

## 六、未收录（按你的要求排除）

```
✗ 运行日志：npcap_http80.log / ws8889.log / classroom.log / proxy8888.log / ws_frames.log
✗ 临时输出：*_out.txt / *_err.txt / *_capture.log
✗ 编译缓存：__pycache__ / *.pyc
✗ 反编译树：cls_dec / ztpt_dec / xhsettings_dec / wm_dec / launcher_dec / verify_dec
✗ 旧快照：SNAPSHOT-1007-*.md / 历史计划类文档
✗ 中间载荷：payload_stage2/unlock/proxy_zip.bin 等变体
```

如需这些材料，原始工作区仍在：
`C:\Users\Olive\AppData\Roaming\Tencent\Marvis\User\...\workspace\...\sm-p200-takeover\`
