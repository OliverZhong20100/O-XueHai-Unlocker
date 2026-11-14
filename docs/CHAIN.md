# 端到端链路

本文按执行顺序给出当前**实际可用**的接管链路——课堂实时通道（WebSocket `:8889`）——逐环标注机制、代码位置与验证状态。

> 早期基于推送通道（`:3200`）的 assist 链路已归档，见文末「附录：已弃用链路」。原因：设备侧消息接收器未注册，帧虽被解析并回执，但业务分支从不执行；课堂通道则是**现场实测可用**的。

状态定义：

- **已闭合**：逻辑链两端均已在反编译代码中定位，且现场行为与预期一致；
- **已观测**：可观测层面已确认（线上字节、回执、连接建立）；
- **未闭合**：逻辑上必要，但被外部信任边界阻断。

## 链路总览

```
① 设备接入研究者控制的接入点（研究者成为其网关与 DNS）
        ↓
② 设备与课堂服务器建立 WebSocket 长连接（明文、自定义 JSON 帧、无证书校验）
        ↓
③ 研究者以服务端身份抢占连接（伪造 SYNACK + 双向 RST 风暴打掉真服务器）
        ↓
④ 构造并注入业务消息（cmd:3 + canvas_tag + smsg.data）
        ↓
⑤ 设备端逐帧回执，序号完全对齐（注入被确认）
        ↓
⑥ HandleSocketMsgService 过白名单门 → 按 createTag 分发
        ↓
⑦ MessageHandleForCanvasHelper 按 type 反序列化业务对象
        ↓
⑧ 三条已确证的落地面：
      type=3 → 下载任意内容到固定目录 → 自动播放
      type=2 → 无门禁写入课堂本地库（任意任务行）
      type=1 → 按 taskId 删除任意目录
        ↓
⑨ 形成"下载 → 解压 → 写 launcher 库 → 生成 AppUpdateTask → 静默安装"的闭环
        ✗ 在此处被阻断：资源下载必须由学海服务端授权
```

## 逐环状态

| # | 环节 | 机制 | 代码/证据位置 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | 接入控制 | 设备连接研究者提供的热点/接入点，研究者成为网关与 DNS | 现场网络状态 | 已闭合 |
| 2 | 建立长连接 | 课堂 App 连接课堂服务器 `:8889`，明文 WebSocket | 握手包字节（`GET /` + `Auth` 头 + `DeviceId`） | 已闭合 |
| 3 | 抢占连接 | 伪造 SYNACK 接管 + 双向 RST 风暴抑制真服务器 | 接管日志中 `accept=` 与回执序号一致 | 已闭环（现场复现） |
| 4 | 帧构造 | `{"cId","cmd":3,"smsg":{...}}`，`data` 为业务 JSON 字符串 | 注入器 + 端侧回执 | 已闭合 |
| 5 | 端侧确认 | 设备对每帧回 `cmd:2, rt:1` 回执，`id` 为会话内标识 | 回执字节逐帧比对 | 已观测 |
| 6 | 白名单门 | `interceptMsgEnable` 时仅放行 `UN_INTERCEPT_TYPE_LIST`（含 `0/1/2/1007/2021/...`） | 消息服务 `onHandleIntent` | 已闭合 |
| 7 | 业务分发 | 按 `createTag` 匹配 8 个 handler | `BusinessApp.initSocketActions()` | 已闭合 |
| 8a | 短语落盘 | `type=3` → 下载 URL 到 `ztktv4_resource/<URL 末段>` | `DownLoadPhraseService.downLoad` | 已闭合（现场 95 次拉取） |
| 8b | 自动播放 | 下载完成回调 → `MediaPlayer.setDataSource/prepare/start` | `MediaPlayerUnits.playVoice` | 已闭合（代码级） |
| 8c | 任务写库 | `type=2` → `insertOrReplace`（无门禁） | `TaskDetailDaoHelper.updateTaskDetail` | 已闭合（现场：写坏行致崩溃，删除后恢复） |
| 8d | 目录删除 | `type=1` → `deleteTaskByTaskId` + `deleteDir(getMicroRecordPath(taskId))` | `MessageHandleForCanvasHelper` | 已闭合（代码级） |
| 9 | 下载清关 | 所有下载腿最终走 `GET /api/v4/resource/single?sourceUrl=...`，由服务端签发 `ResourceInfo` | `ResourceHelper.downLoadResourceBySourceId` | **未闭合（服务端信任边界）** |
| 10 | 解压 | 仅 `doHandDownLoadSuccess` 一处，需 `ResourceInfo.zipUrl` 且以 `7z` 结尾 | `ResourceHelper` + `Z7Extractor` | 被第 9 环阻断 |
| 11 | 写 launcher 库 | DB 位于 `/sdcard/xuehai/<schoolId>/databases/...`，但远程无写该路径原语 | `MyDaoMaster$1.getDatabasePath` | 被第 9 环阻断（无中间原语） |
| 12 | 生成更新任务 | `app_update_task` 表由库内数据驱动 | `AppLocalDataSource.getUnFinishAppUpdateTask` | 被第 11 环阻断 |
| 13 | 静默安装 | `AppInstallManager` → 策略代理 → MDM AIDL | 安装链 11 环逐段确认 | 客户端全通，缺任务行 |

## 关键代码位置（脱敏描述）

| 事实 | 位置 |
| --- | --- |
| 课堂信道为明文 WebSocket、握手带 `Auth`/`DeviceId` | 课堂网络客户端 |
| 注入帧的封装结构 | 注入器模板 |
| 白名单拦截门与白名单表 | 课堂消息服务 `onHandleIntent` / `BusinessApp.initUnInterceptMsgType` |
| 消息动作注册表（8 个 handler） | `BusinessApp.initSocketActions()` |
| 短语下载落盘路径与命名规则 | `DownLoadPhraseService.downLoad` |
| 自动播放调用点 | `MediaPlayerUnits.playVoice` |
| 任务无门禁 upsert | `TaskDetailDaoHelper.updateTaskDetail` |
| 删除分支与裸拼接路径 | `MessageHandleForCanvasHelper` / `FilePathUtil.getMicroRecordPath` |
| 资源下载统一入口 | `ResourceHelper.downLoadResourceBySourceId` |
| 资源响应仅在业务码成功时被采用（无回退） | `ResourceHelper` 内部回调 |
| 解压唯一入口 | `ResourceHelper.doHandDownLoadSuccess` |
| 安装链起点 | `HomeViewModel.checkAppUpdate` → `AppInstallManager` |

## 未闭合环节

**第 9 环：资源下载必须由学海服务端授权。**

现场实测（公网可达的受控服务器 + 注入任务行）：

- 平板确实向 `/api/v4/resource/single` 发起了带我方 `sourceUrl` 的请求；
- 服务端返回「资料中心该文件已被删除或不可用」；
- 我方服务器**没有任何外部访问记录**（排除"服务端代理抓取"）。

⇒ 服务端只按自己的资源体系查库签发 `ResourceInfo`，不代理抓取任意 URL。这是服务端的信任边界。

被该边界同时阻断的方向：

| 方向 | 阻断原因 |
| --- | --- |
| 明文 HTTP 内容通道 | 生产环境下载/上传 URL 每次请求都被强制改写为 `https://` |
| MITM 替换内容 | 仅信任系统 CA；`targetSdk 25` 不信任用户 CA；无自定义信任锚 |
| 客户端 0day | 我方字节唯一可进的进程内解析器是 `MediaPlayer`，解码在 `mediaserver`（uid `media`，无 `sdcard_rw`），写不了目标共享存储 |
| 热补丁 | 补丁证书必须等于 App 自身签名证书 |
| 动态加载 | 双 App 全树无 `DexClassLoader`/`PathClassLoader` |
| 目录扫描安装 | 无该逻辑；`PackageReceiver` 只监听安装事件 |
| 物理/调试入口 | MDM 关闭开发者选项 |

## 现场接管配方（可复现）

1. 研究者接入点提供网关与 DNS，设备连入；
2. 启动应答器（课堂通道注入器）监听 `:8889`；
3. 启动**双向 RST 风暴**：对 `pad→server` 与 `server→pad` 两个方向均向设备回 RST，抑制真服务器 SYNACK；
4. 抓包确认设备重连后回执出现 `端侧ack == 我们mine`（`OK` 状态）；
5. 写入注入帧文件，应答器在 ACK 边界注入；端侧逐帧确认；
6. 用 `type=3` 做通道活性探针（观测受控 HTTP 源的请求计数）；
7. 用 `type=2` 做写库实验，实验后必须用 `type=1` 清理注入行，否则残缺任务行会导致桌面反复崩溃。

## 附录：已弃用链路

早期链路走推送通道 `:3200`：接管长连接 → 注入 `assist-notify` → 协助服务执行 `installAppOnline(url)` → MDM 静默安装。

该链路在**客户端全部 11 环代码级闭合**（帧编码、解析、回执、路由、协助分支、跨进程、任务接口、脚本解释器、在线安装、策略代理、AIDL），但现场卡在一个启动时序判定点：**设备侧消息接收器未注册**——帧被解析并回执，业务分支却从不执行。

判定依据与排除项记录在 [STATUS.md](STATUS.md) 第 2~8 节。该链路在当前设备状态下不可用，保留作为历史与方法学参考。
