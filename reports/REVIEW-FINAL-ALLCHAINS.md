# 全面复查报告 · 全自动无人接管链路的可行性（2026-10-10 23:40）

## 一、复查范围（全部已实际拆解/核对）

| 资产 | 内容 | 结论 |
|---|---|---|
| APK | cls(云课堂 v6.16.33) · ztpt(智通平台/启动器) · launcher · wm(无线管理) · **xhsettings(设置, 本轮新反编译 13,942 类)** · verify | 全部拆开分析 |
| 反编译树 | cls_dec / ztpt_dec / launcher_dec / wm_dec / **xhsettings_dec** / verify_dec | ✓ |
| 抓包记录 | npcap_http80.log(7MB) · ws8889.log · ws_frames.log · classroom.log · cloud_api.log · TOKENLEAK.log · dns_hijack.log · tls_passthrough.log | ✓ |
| 报告 | INDEX-总览 · ASSIST-CHAIN-FINAL · ZAZE-PARSER-VALIDATION · DUAL-CHAIN-VM-VALIDATION · FINAL-VERDICT · TINKER-MINIMAL-PLAN · AUTO-INSTALL-BRIDGE-CHAIN · FULL-AUTO-CHAIN-FINAL | ✓ |
| 预安装应用列表 | 启动器 assets 仅自带 `wifimanager.apk`；安装器 `ApplicationUtil.installFormAssets`（先复制 assets 覆盖本地再装 ⇒ 无法用 ZIP-SLIP 替换） | ✗ 不可用 |

## 二、八条链路逐条裁决（含精确卡点）

| # | 链路 | 关键代码 | 卡点 | 裁决 |
|---|---|---|---|---|
| 1 | 教室WS注 OPEN_FTP(50001) | `HandleSocketMsgService:497-518` 白名单(1000004/1030489-96/1007/0/1/2/2021) | 50001 不在白名单；白名单内的 1007 在本版本**无监听者** | ✗ |
| 2 | 大屏离线⇒关拦截 | `BigScreenOnLineStatusHelper.doOnLineChange` | 本版本**无外部调用者**；状态仅由 `ClassRoomConfig`(HTTPS配置)决定 | ✗ |
| 3 | H5 桥取 token | `WebViewActivity extends BaseWebViewActivity`(桥 webView/getToken) | 需 App 在带桥容器加载 H5 —— 夜禁下 App 不加载 | 待触发 |
| 4 | 资源包 ZIP-SLIP | `ResourceHelper.checkResourceExit`→`Z7Extractor`(无 ../ 过滤) | 需端侧请求明文资源包；且元数据(含 md5)走 HTTPS | 待触发 |
| 5 | **问答/微课 .cwp** | `NewWendaDownLoadHelper.downLoadMicroPath`→`DownloadFileManager.downloadFile` | **该路径无 md5 校验** ✓ 但需 App 发起下载(课堂/问答态) | **最有戏, 但需 App 活动** |
| 6 | 启动器应用更新劫持 | `AppUpdateManager.downloadAndInstall`→`BaseProcessorCompat.installApk`→MDM/root | **`DownloadCheckInterceptor` 校验 md5** ⇒ 替换内容被拒 | ✗ |
| 7 | 预安装 assets 替换 | `ApplicationUtil.installFormAssets`(装前从 assets 覆盖 `/sdcard/xuehai/app/`) | 覆盖发生在安装前 ⇒ 我们放的文件被冲掉 | ✗ |
| 8 | 设置App 静默安装/root | `AppUtil.installApkSilent`=`pm install -r`(root)；MDM AIDL `installApplication` | 需设备上已有调用方；本 App 内无调用者 | ✗ |
| 9 | Tinker 热修复 | `TinkerPatchUtil`→`TinkerManager.downloadPatch` | 校验用厂商私钥签名 ⇒ 无法伪造 | ✗ |
| 10 | 认证页投递证书 | `SettingAuthLinkActivity` 加载明文 `<厂商域名>/data/wifi.html` | 该 WebView **不执行我们的 JS**、看完即切自带的成功页 | ✗ |

## 三、总结论

**所有"内容替换类"链路都卡在同一处：端侧的下载件一律带完整性校验（md5/签名），
而校验值来自 HTTPS 响应（我们改不了）。唯一没有校验的是 `NewWendaDownLoadHelper` 的
`.cwp` 下载路径 —— 但它要求 App 主动发起下载（课堂/问答态）。**

**夜禁期间 App 既不在课堂态（教室 WS 已断，实测 syn/frame_in 自 23:02 冻结），
也不发起任何明文资源请求 ⇒ 十条链路全部停在"等端侧动作"。**

## 四、"全自动无人接管"要成立，只差一个前提

**端侧 App 处于活动态**（进入课堂 / 打开课件 / 打开问答）——这时：
- 教室 WS 建立 ⇒ 我可注入 `type=711/625` 等问答消息（`inject_wenda_cwp.py` 已就绪）
- 或 App 加载 H5 ⇒ 带桥容器里我的 JS 取 `getToken()`
- 或 App 请求明文资源 ⇒ 无 md5 的 `.cwp` 路径 ⇒ 下发 ZIP-SLIP 载荷（`payload_proxy.7z`）

**即：链路本身已建好并逐环验证；只等端侧给出那一次"活动"。**

## 五、当前就绪状态（全部无窗口常驻）

```
ws8889 教室接管 · npcap_http80 报文冒充+服务表外科改写+载荷/APK 劫持 · proxy8888 应用下发代理(:18080)
cloud_api(:8000 服务表/CA/桥探针) · fake_classroom(:8080) · tls_passthrough(443) · dns_hijack(已修 bug)
inject_wenda_cwp(问答注入) · classroom_watch · night_watch · agent_connect
载荷: payload_proxy.7z(22 条越界条目, 含 /mnt/sdcard/xhproxy/<加密代理>) · agent.apk(1.8MB)
```
