# 系统结构与协议规范

本文描述目标设备（MDM 集中管控教学平板）中与本链路相关的组件、通信协议与调用关系。

## 1. 组件模型

设备上的应用家族按职责可分为四层：

| 层 | 职责 | 典型组件 |
| --- | --- | --- |
| 学生端平台 | 账号、桌面、消息、管控策略 | `com.xh.zhitongyunstu`（平台主应用） |
| 课堂应用 | 课堂互动、屏幕广播 | `com.xh.smartclassstu` |
| MDM 服务 | 设备策略、静默安装、文件服务 | MDM 主服务（AIDL 暴露） |
| 推送 SDK | 长连接、下行消息分发 | `com.xuehai.message.sdk` |

平台主应用通过 Tinker 热修复框架加载，实际业务代码位于补丁包；Manifest 中的 Application 为反射壳，真实 Application 为业务实现类。

## 2. 推送通道协议

### 2.1 传输层

推送通道为一条**自定义二进制 TCP 协议**，端口固定，服务端地址由账号登录响应中的微服务地址表下发。协议本身不启用 TLS，也不做消息签名或时间戳校验。

### 2.2 帧结构

每帧由 4 字节固定头部与变长内容组成：

```
+--------+---------+--------+------------------+-------------------+
| magic  | version |  cmd   | length indicator |     content       |
| 1 byte | 1 byte  | 1 byte | 1 + n bytes      | (len - 3) bytes   |
+--------+---------+--------+------------------+-------------------+
```

- `magic` 恒为 `0x09`，校验失败会抛 `SocketException("获取数据包MAGIC异常")`；
- `version` 由发送方给出，接收端不校验；
- `cmd` 见 2.3；
- 长度字段编码为「内容长度 + 3」，其中 3 字节为长度字段自身开销：

```
value  = len(content) + 3
n      = (value >> 6) 不断右移 8 位所需的次数     // 0、1 或 2
byte0  = ((n & 3) << 6) | ((value >> (8 * n)) & 0x3F)
bytei  = (value >> (8 * (n - i))) & 0xFF          // i = 1..n
```

接收端还原：`n = (byte0 >> 6) & 3`，`value = ((byte0 & 0x3F) << (8 * n)) | tail`，`bodyLength = value - 3`。

### 2.3 命令字

| 命令 | 值 | 方向 | 说明 |
| --- | --- | --- | --- |
| `HEART_BEAT` | `0x01` | 双向 | 心跳 |
| `AUTHORIZATION` | `0x02` | 上行 | 客户端注册 |
| `MESSAGE` | `0x03` | 下行 | 业务消息 |
| `PULL` | `0x05` | 上行 | 离线消息拉取 |
| `ECHO` | `0x32` | 双向 | 链路探测 |
| `AUTH_FB` | `0x82` | 下行 | 注册应答 |
| `MESSAGE_FB` | `0x83` | 上行 | 业务消息回执 |
| `ERROR_FB` | `0x8B` | 双向 | 错误反馈 |

### 2.4 注册帧

`AUTHORIZATION` 内容为 7 个「1 字节长度 + UTF-8」字符串，顺序固定：

```
accessKey, deviceId, clientId, signature, token, uid, tags
```

其中 `uid` 为账号在服务端的用户标识（与学号一一对应，随账号变化），`tags` 形如 `uid,schoolId`。客户端实现会随时更新该值，因此服务端侧任何硬编码的 `uid` 都会在账号切换后失配。

`AUTH_FB` 内容为 `clientId, token, code`（前两个为长度前缀字符串，`code` 为 2 字节有符号整数）。客户端收到后仅做日志与回调，不做证书或签名校验。

### 2.5 业务消息帧

`MESSAGE` 内容结构（大端）：

```
mode      : 1 字节
count     : 2 字节（无符号）
entries   : count 次 {
    msgId      : 8 字节（有符号）
    contentLen : 4 字节（有符号，上限 10MB）
    content    : contentLen 字节（UTF-8 JSON）
}
```

接收流程为：逐条解析 → 生成回执 → **无条件发送回执** → 回执发送成功后才对未处理的 `msgId` 触发分发。因此「收到回执」只证明解析与回执成功，不证明分发完成。

### 2.6 业务消息实体

`content` 反序列化为一个消息实体，字段全部为字符串（除 `style` 为整数）：

```
appId, clientId, msgId, msgType, payload, style, subAppId, subMsgType, userId
```

路由前置条件：`appId == subAppId`。通过后按 `subMsgType` 分发。

## 3. 消息路由表

| `subMsgType` | 处理器 | 后续动作 |
| --- | --- | --- |
| `assist-notify` | 远程协助模型 | 发送跨进程通知，拉起协助服务 |
| `control-service` | 管控模型 | 进入管控模式，拉取管控详情 |
| `app-upgrade` | 盒子管理器 | 触发升级检查 |
| `app-upgrade-prepare` | 应用更新模型 | 预下载升级包（URL 与 MD5 由载荷指定） |
| `app-syncMessage` | 资源更新管理器 | 比对版本号，必要时发起资源拉取 |
| `app-notification` | 通知处理器 | 展示通知 / 按 action 拉起 Activity |

分发链：

```
推送长连接 → 协议解码 → 广播派发(LocalBroadcast) → 平台消息接收器
      → 路由表 → 各业务模型 → 跨进程 IPC / HTTP / 系统服务
```

接收器在平台主进程启动流程中注册，注册点位于「消息模块初始化」方法内，位于账号登录判断之前。

## 4. 远程协助子系统

协助服务运行于独立进程，通过 `Messenger` 与主进程通信：

- 主进程发送「协助通知」（`what` 常量 + `Bundle` 中的 JSON 字符串）；
- 协助进程解析通知，取 `operate` 字段：`ENTRY` 表示进入协助，其他值表示退出；
- 进入协助后：设置屏幕常亮 → 拉取任务列表 → 按固定间隔发送心跳。

任务接口为平台业务 HTTP 接口，历史上以明文 HTTP 承载：

```
GET {base}/api/v1/users/{uid}/devices/{deviceId}/assists
GET {base}/api/v1/users/{uid}/devices/{deviceId}/assists/{assistId}/tasks
GET {base}/api/v1/assists/{assistId}/active
POST {base}/api/v1/users/{uid}/devices/{deviceId}/assist/result
```

任务内容为脚本指令（自有表达式语言），由内置解释器执行。

## 5. 指令执行与安装链

指令解释器支持的方法包含：命令执行、文件下载、在线安装、离线安装、系统配置读取、已装应用枚举等，**无白名单限制**。

其中在线安装方法的完整调用链为：

```
installAppOnline(url)
  → 计算下载路径（app 下载目录/assist/MD5(url).apk）
  → 删除残留文件
  → 下载管理器下载（回调实现为匿名内部类）
  → 回调 onSuccess → 策略管理器.getApplicationPolicyProxy().installApplication(path)
  → 策略管理器为动态代理（构建配置 USE_MDM = true → MDM 策略实现）
  → MDM 策略实现通过 AIDL 调用设备常驻 MDM 服务
  → 服务端安装包安装（静默）
```

关键判定点：

- 构建配置 `USE_MDM` 为 `true`，因此 `DefaultApi`（走系统安装器 UI）分支不会被使用；
- MDM 服务的 AIDL action 在设备 Manifest 中存在且 `directBootAware`；
- 下载 URL 与目标包完全由服务端下发，客户端不做域名或签名白名单校验。

## 6. 网络面

业务接口基址的解析优先级：

1. 登录响应下发的微服务地址表（`protocol://address`，`protocol` 由服务端指定，可为 `http`）；
2. 构建期内置地址表（生产环境默认 HTTPS 域名）。

因此当服务端下发 `http` 协议地址时，业务接口以明文承载，可被同一广播域内的应答器直接伪造。

此外，平台实现了「令牌失效全局拦截」：当本地令牌无效时，`PollInterfaceManager` 对所有业务请求直接返回拦截结果，不发起真实网络请求。该拦截是排查「服务端伪造后设备无反应」时必须先排除的前提。
