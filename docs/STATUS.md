# 当前进展

## 1. 结论

链路共 14 环，13 环已取得代码级或字节级证据，1 环待闭合：平台消息接收器的注册状态。

- 推送通道的接管、帧构造、解析与回执已完成线上验证：设备会对注入帧返回标准回执，回执中的关联标识与注入标识一致；
- 消息路由、协助分支、跨进程调用、任务接口、脚本执行、静默安装六段在代码层面完整可读，且各段门禁条件在目标设备状态下均满足；
- 未闭合环节的位置在广播派发之后、业务处理器之前，属于「接收器是否注册」这一类启动时序问题。

## 2. 已验证项

| 项目 | 结论 | 证据级别 |
| --- | --- | --- |
| 通道为明文自定义协议、无证书校验 | 成立 | A |
| 下行消息帧可被完整构造 | 成立 | A + B |
| 设备会解析注入帧并回执 | 成立 | B |
| 回执与业务分发解耦（回执成功不等于已分发） | 成立 | A |
| 消息实体字段名与类型 | 成立 | A |
| 路由前置条件 `appId == subAppId` | 成立 | A |
| 协助分支无登录态/权限前置判断 | 成立 | A |
| 协助服务跨进程入口无额外鉴权 | 成立 | A |
| 任务接口以明文承载（服务端可指定协议） | 成立 | A |
| 脚本解释器无方法白名单 | 成立 | A |
| 在线安装链路落到 MDM 常驻服务（静默语义） | 成立 | A |
| 下载地址与目标包由服务端完全控制 | 成立 | A |
| 注册帧中 `uid` 随账号变化（需动态解析） | 成立 | A + B |

## 3. 未闭合项

**接收器注册状态。**

现有证据只能证明「帧已解析」，不能证明「消息已分发到业务处理器」。已排除的候选原因见 [CHAIN.md](CHAIN.md#未闭合环节)。

当前选用的判定方案：利用注册应答帧中的 `clientId` 字段。客户端实现中，收到与本地不同的 `clientId` 会触发一次服务端注册请求；该请求是真实的业务网络行为，不依赖业务消息本身。因此：

- 若注入新的 `clientId` 后出现该注册请求，则接收器已注册，问题在业务分支内部；
- 若无任何请求，则接收器未注册，问题在启动时序。

注意该判据存在二义性：注册请求还可能被「无账号信息」「动态码登录」两个前置条件拦截。因此第二判据为「客户端保存的 `clientId` 是否变化」，可通过下一次注册帧的内容间接观察。

## 4. 后续工作

1. 完成上述探针的对照实验（注入与不注入两组、各两次）；
2. 若判定为接收器未注册，则转向「不依赖接收器注册」的入口：
   - 面向导出组件的隐式 action 唤起；
   - 面向设备自恢复流程（安全模式页、欢迎页）的行为差异；
   - 面向第三方组件（网络管理类应用、设置类应用）的导出组件面；
3. 若判定为接收器已注册，则将排查集中在协助模型的跨进程发送条件上（绑定状态、信使可用性）。

## 5. 已知环境约束

- 接入点为 Windows 移动热点时，虚拟网卡在部分无线网卡上无法启动，需要外置支持 AP 模式的 USB 无线网卡；
- 观测进程必须提权，否则链路层收发与单播抓取均不可用；
- 应答器与注入器必须同进程维护字节序号。

## 6. 2026-11-13 复核：运行时开关测算与「盒子门」代码级定位

### 6.1 开关测算（只用既有资产 + 反编译代码，不新增实验）

| 开关 | 代码默认/门禁 | 既有资产证据 | 测算结论 |
| --- | --- | --- | --- |
| 消息接收器是否注册 | 注册调用位于「连接推送」之前，且无权限/无过滤条件 | 注入帧均获回执（只证解析）；空载荷探针未见进程终止，但推送为 6 秒短连接轮询，重连节奏会掩盖一次进程重启 ⇒ 探针二义 | 未定（代码上应注册；探针不可用） |
| `getPreDownloadApp()` | 实体构造默认 false，仅登录响应可置真 | 全部抓包/落盘资产中无该字段明文（登录面全程 TLS，中继为 passthrough 不供 body） | 无法离线测定 |
| 盒子可用 `isBoxEnable()` | 地址解析失败即静默 `setEnable(false)`，不发任何请求 | 全部日志中 `_check.xh` 命中数为 0；历史服务表下发时 body 为 0B 或 V1 对象格式 | 失败原因已定位（见 6.2），且可外部满足 |
| MDM 安装是否收外部署名包 | 权限位 `0x20` 在学生端默认授予 | 无安装成功信标 | 无法离线测定 |

### 6.2 盒子门：为什么历史上从未触发，以及如何满足

代码级链路（`com.xh.zhitongyunstu` 构建）：

1. `BoxManager.createCheckBoxChain()` 以 **classId = 0** 构造 `RealCheckBoxInterceptor`；
2. `BaseService.syncCheckStatus(0)` → `FileService.checkStatus(ServiceUrl, cb)`；
3. `ServiceUrl.getDomainOrIp()` → `AddressLoader.getServiceUrl(serverType, 0)`；因 `classId <= 0`，走 **V2** 路径 `XHMicroServerV2.getServerUrl(serverType)`；
4. V2 的缓存键为 **纯 serverType**（不含 classId 后缀）；未命中时回退 `getMicroServerCache()`；
5. V2 的 RESTful 默认地址为**明文** `http://ms.yunzuoye.net/api/v2/pub/microServer/list/`；
6. 响应被 `parseMicroUrl()` 解析为 `List<ServerUrlUnify>`（元素含 `microServerNewDtoList[]`），写入内存表并持久化；
7. `ServiceUrl` 对结果执行 `formatUrl()`：非 `http` 开头则**强制补 `http://`**；
8. `FileService.checkStatus()` 拼出 `http://<地址>/0_check.xh` 并下载落盘；**地址为空则直接 `setEnable(false)`，不发出任何网络请求**；
9. `FileService$1.success()` 要求正文 **恰好等于 `xh`** 才 `setEnable(true)`。

⇒ 历史上「盒子始终不可用」的两个成因：

- 内置默认表里 `FILE_BOX` 被显式置为空串，盒子没有内置地址，只能来自服务表或缓存；
- 此前下发的服务表 body 为 0B / V1 对象格式，V2 解析器（要求数组）无法消费，缓存从未写入 ⇒ 第 8 步静默失败，因此抓包中 `_check.xh` 命中数为 0。

⇒ 外部满足条件（已落到应答器）：服务表按 V2 数组格式下发并包含盒子类型，同时新增 `_check.xh` 应答（正文 2 字节 `xh`）。

### 6.3 本次改动

- `tools/plaintext_http_responder.py`：新增 `*_check.xh` 应答（`200`，正文 `xh`，`Content-Length: 2`）；
- 服务表分支已按 V2/V3 数组格式构表并包含盒子服务类型（既有逻辑，本次核对通过）。

### 6.4 结论

链路每一跳的代码路径已完成代码级确认（见 [CHAIN.md](CHAIN.md)）。仍有两个只能在设备上取值的运行时开关：接收器注册状态、`getPreDownloadApp()`。二者可在一次联网会话内同时判定：

1. 服务表投毒成功 → 出现 `GET /0_check.xh` ⇒ 盒子门已开；
2. 随后注入预下载消息 → 出现对 `agent.apk` 的下载请求 ⇒ 接收器已注册且 `getPreDownloadApp()` 为真。

---

## 7. 现场复核（2026-11-13，真机，研究者侧采集）

### 7.1 网络位置

- 设备通过研究者主机热点接入，主机为设备网关/DNS；
- 设备地址由 DHCP 分配，入口 IP 每次可能变化，需以 ARP 表为准；
- 抓包接口为热点虚拟网卡的 NPF 设备；**BPF 过滤器必须用 `ip`**（端口过滤在本适配器上抓不到包），端口在用户态过滤。

### 7.2 推送通道（3200）实测

| 注入类型 | 帧状态 | 下游观测（30–40 s） |
| --- | --- | --- |
| `app-notification` + `payload=null` | ACK | 进程未崩溃 |
| `app-upgrade` | ACK | 无新连接 |
| `app-upgrade-prepare` | ACK | 无新连接 |
| `app-syncMessage` | ACK | 无新连接 |
| `control-service` | ACK（含重传） | 无新连接 |
| `assist-notify`（ENTRY，含 assistId） | ACK `msgId` 对应 | 无协助心跳请求 |

结论：帧可送达并取得回执，但没有任何业务副作用 ⇒ **不作为主链入口**。

### 7.3 设备空闲态判定（决定性）

对设备源 IP 做 120 秒端口聚合：

```
ports: {'tcp:3200': 23}    dns: {}
```

即除推送短连接外，设备**零 DNS、零 80/443、零 8889**。说明当前没有课堂 App 或 launcher 业务在跑，链 A 的触发面（8889 长连接）不存在。

### 7.4 设备唤醒/触发手段核对

- 课堂 App 的 service 全部 `exported=false`，外部无法拉起；
- 唯一静态 receiver 为 `CONNECTIVITY_CHANGE`，`onReceive` 只发本地 `ContextMessage("net_work_status")`，不建连；
- launcher 拉课堂 App 的唯一映射是首页图标点击（`course://com.xh.smartclassstu/open?...`）；
- 结论：无用户操作时，网络侧无法让课堂 App 启动。

### 7.5 已布设的自动响应

- 明文 HTTP 应答（80）：服务表、`*_check.xh`（正文 `xh`）、`/box/file`、APK 下载；
- 推送应答（3200）：AUTH/心跳/`MESSAGE` 注入；
- 课堂 WS 冒充（8889）：明文 Upgrade 应答 + 帧注入；
- 守候进程：一旦观测到设备的 8889/8888 连接，自动触发注入帧。

### 7.6 结论

- 链路本身（01→23 跳）代码级闭合；
- 端到端自动执行的前置条件是"课堂 App 处于运行态"，该条件无法由网络侧单独满足；
- 剩余需真机确认的两点：7z 越界落盘结果、库替换后的句柄重开时机。

## 8. 卡点 1 根因：课堂端消息拦截白名单（2026-11-13 夜间，代码级）

**现象**：WS 已接管、注入帧全部被端侧 TCP 确认（`ws8889.log` 中 `[ACK] ... OK(端侧已确认我们注入的数据)` 占 94%），但 App 零动作；同一注入在 20:33 成功过一次（平板主动 `GET /..7z`），之后全部失败。

**根因**：`HandleSocketMsgService.onHandleIntent` 在处理消息前先过一道拦截门：

- `sget-boolean v1, HandleSocketMsgService->interceptMsgEnable:Z`
- 为 `true` 时只放行 `UN_INTERCEPT_TYPE_LIST` 内的 type，其余 `return-void`
- 开关唯一写入点：`BigScreenOnLineStatusHelper.setOnline(Z)` → `setInterceptMsgEnable(Z)`，即**大屏在线状态直接控制拦截**
- 白名单（`BusinessApp.initUnInterceptMsgType()`，10 项）：`0, 1, 2, 1007, 2021, 1031005, 1031006, 1031007, 1031008, 1000004`

⇒ 短语 `type=3` 与 PPT 同步 `type=4` **不在白名单**：课堂内大屏在线时被服务层静默丢弃，TCP 仍正常 ACK；20:33 成功那次恰逢拦截未开启（大屏不在线）。此前"房间号/前台 Activity/序号空间"三个假设均可撤回。

**修复方向（已落地代码，待课堂窗口验证）**：
1. 改用白名单 `type=0`（TaskDetail 新建）：`action_socket_create_new_task` → `StudentDeskTopPresenter.recivieNewTask(TaskDetail)`，门禁只有 `parentDeskTopId == task.desktopId` 与 `classRoomId` 非空；`TaskDetail` 内嵌 `resourceInfo.zipUrl` 可直接携带下载源
2. 注入器新增自学习：从平板自己的帧里抓 `desktopId`（实测值 `1349658`/`1594128`）、从握手 `Auth.boundId` 抓房间号，模板用 `__DESKTOP__` / `__ROOM__` 占位替换
3. 备用：若能用白名单状态类消息把"大屏在线"打成离线，`type=3/4` 通道即恢复

**判定点（下一窗口）**：`lab_server.log` 出现 `GET /..7z`，或 8889 上出现后续帧（`type=2` 更新任务等）。

### 8.1 全卡点离线修复台账（2026-11-13 夜）

| 卡点 | 修复/结论（按已有资产） |
|---|---|
| 拦截白名单 | 注入改白名单 `type=0`；`TaskDetail` 内嵌 `resourceInfo.zipUrl` |
| 下载触发 | **已代码级确认**：`StudentDeskTopPresenter.recivieNewTask` 入库后调用 `StartServiceHelper.startDownLoadPptService(TaskDetail)`（4 参重载），由 `AutoDownloadManager.isDownloading(sourceId,...)` 去重；Intent `download_ppt_action` → `ResourceDownLoadService` → `downloadResourceOnly(null,...)` → 本地无记录 → `/api/v4/resource/single` |
| 字段映射 | `ResourceInfo` 字段与伪造响应逐字对齐：`appSubType/convertStatus/createTime/downloadFilePath/extend/localPath/name/numberInLine/sourceId/taskId/type/zipUrl` |
| 解压判定 | `needDecode` 参数为原始 URL，`zipUrl` 以 `..7z` 结尾命中 `endsWith("7z")`；`baseName=".."` → `destDir=/sdcard/xuehai/ztktv4_resource/..` |
| 房间号门禁 | `recivieNewTask` 还校验 `task.classroomId == StudentClassRoomConfig.getClassRoomId()`；注入模板 `__ROOM__` 由握手 `Auth.boundId` 自动填充 |
| desktopId 门禁 | `parentDeskTopId == task.desktopId`；注入器从平板自己的帧学习真实值（实测 `1349658`/`1594128`） |
| 任务去重 | `arm_chain` 每阶段用唯一 `taskId/sourceId`（`make_task(n)`），避免 `isDownloading` 去重短路 |
| schema 版本 | 生成库 `user_version=96`，18 表，`integrity_check=ok` |
| 生效时机 | launcher 持句柄 → 需进程重启或 `clearDbSession`（登录流程）；列为残余风险 |
| 安装腿 | DB 任务 → `executeAppUpdateTask`(0x20 默认授予) → `installApplication`；已绕开 `SysAuthority.preDownloadApp` |

## 9. 2026-11-14 课堂 WS 通道实测与终局边界

本轮把目标从推送通道切换到**课堂实时通道**（`47.99.214.197:8889`），完成真机闭环验证。以下结论全部来自线上字节与设备侧可观测行为。

### 9.1 已确证能力

| 能力 | 结论 | 证据 |
| --- | --- | --- |
| 课堂 WS 确定性接管 | 成立 | 双向 RST 风暴 + 伪造 SYNACK，回执 `端侧ack == 我们mine` |
| 任意消息注入 | 成立 | 端侧逐帧回执，`/..7z` 累计 95 次拉取 |
| `type=3` 短语：任意内容落盘 | 成立 | 受控 HTTP 源 → `/sdcard/xuehai/ztktv4_resource/<URL 末段>` |
| `type=3` 自动播放 | 成立 | 下载完成回调 → `MediaPlayerUnits.playVoice` → `MediaPlayer.setDataSource/prepare/start` |
| `type=2` 无门禁写课堂库 | 成立 | `TaskDetailDaoHelper.updateTaskDetail` → `insertOrReplace`；写入残缺行可稳定复现桌面崩溃，删除后恢复 |
| `type=1` 按 taskId 删目录 | 成立 | `getMicroRecordPath(taskId)` 裸拼接 → `FileUtils.deleteDir` |
| `type=6` 写 teacherLocalAddress | 成立 | 原始字符串直写 `StudentClassRoomConfig`，但无外连副作用 |

### 9.2 接管配方（关键经验）

- 单发 nudge RST 不够：真服务器 SYNACK 先到，端侧会采用真服务器序号，注入帧被当乱序丢弃（回执出现 `落后(未确认我们注入的数据)`）；
- 必须同时运行双向 RST 风暴（对 `pad→server` 与 `server→pad` 两个方向都回 RST 给平板），把真服务器 SYNACK 打掉，才能拿到 `OK`；
- 无管理员权限时 `pydivert` 不可用（`WinError 5`），无法做内核层 SYN 抑制。

### 9.3 终局边界（为什么无法闭环）

1. **资源内容由服务端授权**：所有下载腿最终都经 `GET /api/v4/resource/single?sourceUrl=...`，服务端只认自有资源，不代理抓取任意 URL；已用公网隧道实测——请求确实到达服务端，返回「资料中心该文件已被删除或不可用」，我方服务器零外部访问。
2. **文件服务全 HTTPS**：`XHDownloadOkHttpProxy.replaceFileServerEnvironment` 每次请求强制 `http://` → `https://`；targetSdk 25 不信任用户 CA；MITM 不可行。
3. **解压原语不可达**：`Z7Extractor` 唯一调用者 `ResourceHelper.doHandDownLoadSuccess` 需要 `ResourceInfo`（服务端/DB 授予）。
4. **安装腿需要任务行**：`AppUpdateTask` 只来自 launcher 私有库或 HTTPS 下发，远程无写入原语。
5. **无代码执行原语**：双 App 全树 `DexClassLoader`/`PathClassLoader` 零命中；Tinker 补丁证书必须等于 App 自身签名；无目录扫描安装器；全设备无 APK `intent-filter`。
6. **客户端 0day 入口缺失**：我方字节唯一能进入的进程内解析器是 `MediaPlayer`，其解码在 `mediaserver`（uid `media`，无 `sdcard_rw`），碰不到 `/sdcard/xuehai/...`；pdfium/MyScript/CWP 的输入路径全部来自 `ResourceInfo` 或 UI。
7. **物理/调试入口关闭**：MDM 关闭开发者选项，无法开启 USB 调试。

### 9.4 结论

> 在「无教师端操作、无用户点按、无物理调试入口」的约束下，远程链路的能力边界是：**完全控制课堂实时通道，能写入任意内容到固定目录、写任意任务行到课堂库、删除任意目录，但无法让设备安装任何程序**。安装所需的最后一道门由服务端资源授权把守，属于服务端信任边界，不是客户端缺陷。
