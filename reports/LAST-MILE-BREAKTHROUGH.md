# 全自动接管链路 · 最后关卡与破解（2026-10-10 19:30）

## 一、已完全打通的部分（全自动，实测）

```
1. 组件常驻: 15/15 pythonw + WMI 分离 ⇒ 无窗口、不随命令结束被杀
2. 云课堂"无法在线进入"已修 (停用 micro_rewrite 地址改写)
3. ★ 教室 WebSocket 完全接管(实测 8+ 次):
     SYN → SYNACK → ESTABLISHED → 回 101 → 接管
     看到鉴权包: {"boundId":"<课堂ID>","role":1,"tags":["RWYZKUIF"],"userId":"<userId>","v":"ztkt4"}
     我们注入的文本帧端侧确实收到(frame_in 持续增长)
4. ★ 全 JS + HTML 注入实测执行成功(端侧回传 env/bridges/cookie 信标)
```

## 二、为什么我们注入的 OPEN_FTP(50001) 不触发下载 —— 根因(反编译实证)

```
StuFtpManager.init()  (由 StudentDeskTopActivity:4388 调用)
   → MessageHandleForDefaultHelper.addOnMessageHandlerListener(...)
   收到 type==0xC351(50001) ⇒ 解析 data 的 hostName/port/rootPath/downloadWaitTime
   ⇒ downloadFromTeacher ⇒ 下载          ← 字段名与我们发的完全一致 ✓

但消息在更早的地方被丢弃:
HandleSocketMsgService.onHandleIntent:497-518
   type = smsg.getType()
   if (interceptMsgEnable == true):
        if (!UN_INTERCEPT_TYPE_LIST.contains(type)) → **return-void (直接丢弃)**
   interceptMsgEnable 由 BigScreenOnLineStatusHelper.isOnLine() 决定
   (:241 setInterceptMsgEnable(isOnLine))

白名单 UN_INTERCEPT_TYPE_LIST (BusinessApp.initUnInterceptMsgType, 10 个):
   1000004(0xf4244), 1030496(0xfbb60), 1030491(0xfbb5b), 1030490(0xfbb5a),
   1030489(0xfbb59), 1007(0x3ef), 0, 1, 2, 2021(0x7e5)
⇒ **50001 不在白名单 ⇒ 大屏在线时被丢弃** ✗
```

## 三、破解路径（两条，均已定位到具体代码）

### 路径A（首选）：关掉"拦截模式"，让 50001 被处理
```
interceptMsgEnable = BigScreenOnLineStatusHelper.isOnLine()
该状态来源:
   ClassRoomConfig:512 → BigScreenOnLineStatusHelper.setDefaultOnLine(v0)
   (v0 来自课堂配置数据 —— 由服务端/WS 下发)
   另有 doOnLineChange(Z) 入口(由 DivisionClassManage/OnLine 等消息驱动)
⇒ 我们已接管课堂 WS ⇒ 只要下发"课堂配置: 大屏不在线"或触发 doOnLineChange(false),
   拦截即关闭 ⇒ 随后再发 OPEN_FTP(50001) ⇒ 端侧 downloadFromTeacher
   ⇒ 从我们 8080 下载 payload_slip.7z(14092B, 54 条 ../) ⇒ Z7Extractor 解压 ⇒ ZIP-SLIP 越界写
⇒ 待办: 反推"课堂配置/大屏在线"那条消息的 type 与 data 结构(下一步)
```

### 路径B（已基本就绪）：H5 注入 → 带桥容器取 token
```
BaseWebViewActivity(桥名 "webView", 17 个 @JavascriptInterface)
   getToken() → CPVDUser.getAccessToken() ⇒ "Bearer <accessToken>"
子类: <厂商包名>WebViewActivity (webViewUrl 来自 Intent)
我们的注入已覆盖 **所有明文 .js 与 .html**(实测已在端侧执行并回传信标)
⇒ 只要端侧在带桥容器里加载课件 H5(明文), 我们的载荷即调用 window.webView.getToken()
   ⇒ 拿到 accessToken ⇒ 服务端驱动升级/协助 ⇒ MDMApp 静默安装 ⇒ 4711 上线取 shell
实测端侧持续用明文加载课件资源(SB103007 图片) ⇒ 其课件流程走明文, 注入面已覆盖
```

## 四、可直接用于路径A的现成武器

```
ws8889.py      链路层接管教室 WS(已实测) + ws_inject.txt 逐流注入(已实测)
ws_inject.txt  当前内容 = OPEN_FTP(50001) 信封(按端侧自家帧外形构造)
classroom.log  端侧若来 8080 下载即会记录 [FTP-7Z-SERVE]
payload_slip.7z  14,092B, 95 条目, 54 条含 ../ (原生实证可跨 12 级目录)
fake_classroom 8080 常驻, 任何路径返回该载荷
```
