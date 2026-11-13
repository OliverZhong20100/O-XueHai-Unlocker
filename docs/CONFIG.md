# 配置参考（环境变量）

本仓库所有脚本**都没有 `--help` / `--version`**（未使用 argparse）。
配置一律通过环境变量注入；未设置时使用下表的脚本内置默认值。
优先级：**环境变量 > 脚本默认值**。

> 表中的 IP / 端口 / ID 全部是**实验室占位值**，不是任何真实环境参数。
> 使用时请替换为你自己的实验网段与测试设备参数。

## 1. 明文 HTTP 应答器 `tools/plaintext_http_responder.py`

| 变量 | 默认 | 说明 |
|---|---|---|
| `HTTP80_TARGET_DST` | 见脚本（默认拦截的目标 IP 列表） | 只对这些目的地做冒充；逗号分隔 |
| `HTTP80_ALL_DST` | `0` | `1` = 拦截所有目的 IP 的 80 端口（仅隔离实验网使用） |
| `HTTP80_EXCLUDE` | `47.110.163.128` | 排除的目的 IP，逗号分隔 |
| `HTTP80_EXCLUDE_PREFIX` | `39.173.108.` | 排除的目的网段前缀，逗号分隔 |
| `HTTP80_DNS_IP` | `192.168.1.10` | 应答 DNS 时返回的实验机地址 |
| `HTTP80_DNS_HIJACK` | 未设置 | 需要劫持的域名列表（逗号分隔） |
| `HTTP80_DNS_PATTERNS` | 未设置 | 需要劫持的域名后缀/模式 |
| `HTTP80_PORTAL_PORT` | `80` | 门户页监听端口 |
| `HTTP80_PORTAL_RELAY` | `1` | `1` = 门户页请求中继到真实服务器 |
| `HTTP80_PORTAL_UA` | `okhttp/3.12.1` | 门户页请求使用的 User-Agent |
| `HTTP80_RELAY_HOSTS` | 空 | 需要透明中继的 Host 列表 |
| `CLASS_ID` | `CLASSROOM_ID` | 课堂号占位（**必须替换**，否则注入帧无效） |
| `TABLE_FORCE_OURS` | `1` | `1` = 服务表响应一律指向实验机 |

## 2. 推送通道应答器 `tools/push_channel_responder.py`

| 变量 | 默认 | 说明 |
|---|---|---|
| `PUSH_USER_ID` | `1000001` | 目标账号 ID（实验室占位） |
| `PUSH_DEVICE_ID` | `R0000000001` | 目标设备标识（实验室占位） |
| `PUSH_CLIENT_ID` | `3f025ad5…`（40 字节十六进制） | 推送客户端 ID，可由 AUTH 帧解析得到 |
| `PUSH_ASSIST_ID` | `assist_marvis_0001` | 协助会话 ID |
| `PUSH_PROBES` | `assist-…` | 注入的消息类型列表（逗号分隔） |
| `USER_IDS` | `1000001` | 帧内 userId 候选集合 |
| `FORCE_AFTER` | `12` | 连接建立后等待多少秒开始注入 |

## 3. APK 下载服务器 `tools/download_server.py`

| 变量 | 默认 | 说明 |
|---|---|---|
| `DL_PORT` | `8080` | 监听端口（服务根目录固定为 `tools/`） |
| `UPGRADE_URL` | `http://<lab-host>:8080/agent.apk`（默认值是 Windows 热点网关，属占位） | 下发的升级地址 |
| `UPGRADE_MD5` | `2c44a3a421a1e26fcd5405e890c583ba` | 下发载荷的 MD5 |
| `UPGRADE_PKG` | `com.olive.agent` | 目标包名（示例载荷） |
| `UPGRADE_VER` | `9999` | 目标 versionCode |

## 4. 观测与自检脚本

| 变量 | 默认 | 说明 |
|---|---|---|
| `ROOT_PATH` | `/sdcard/xuehai/share` | 目标设备上用于 ZIP-SLIP 演示的根路径 |
| `WAKE_PKG` / `WAKE_ACTION` | 未设置 | `wire_probe.py` 观察唤醒行为时用的包名/动作 |

## 5. 运行时前置

- Python **3.11+**（实测 3.11.9）
- `scapy>=2.5,<3`（实测 2.8.0）
- Windows：**Npcap**（安装时勾选 WinPcap 兼容模式）
- 抓包/注入需要**管理员权限**
- 隔离实验网段：所有冒充行为都只应在你完全控制的二层网络中进行

## 6. 已知限制

- BPF 过滤器在部分无线网卡上会静默抓不到包；脚本内已改为 `filter="ip"` 后自行按端口过滤。
- Windows ICS 会占用 UDP 53，`bind(53)` 会失败（`WinError 10048`）；本仓库的 DNS 逻辑走包级伪造，不依赖系统端口。
- 脚本没有统一的 CLI 入口，也不做参数校验；错误通常表现为"没有日志输出"。
