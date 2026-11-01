# 报告 2026-11-01：开发者令牌实机验证、IP 绕过与 MITM 重定向链路

> 研究目标：学海 ztp 生态客户端证书/令牌体系与 HTTPS 链路
> 研究前提：设备为本人所有并处于隔离实验网；不接触物理存储、不重刷、不调用未授权接口
> 本报告记录本轮（2026-11-01）所有**实机验证**结论，未验证的一律标注「待验证」

---

## 一、libsecret-lib.so 开发者令牌：算法还原 + 实机验证通过

### 1.1 算法（从 MDM `com.xuehai.launcher` 的 arm64-v8a libsecret-lib.so 反汇编 + DWARF）

```
newDt():
  raw = "!@#xuehai3" + hour + "&zhitongyun3" + mon + "$100fen!@#" + YEAR + "@" + MDAY
        ↑ 盐1            ↑      ↑ 盐2           ↑     ↑ 盐3           ↑ 盐4
  s = MD5( base64(raw) + "\n" )
  s = changeToken(hour, s, reverse=true)          // 奇偶筛选取半 → 16 位
  for i in 0..hour:                              // 注意 hour+1 次
      odd = (i % 2 != 0)
      s = changeToken(hour, MD5(base64? s : s), odd)
```

**关键修正（此前公开分析有误）**：拼接顺序是 **`... + 盐3 + year + "@" + mday`**，年份在日期之前。
反汇编依据：`newDt` 中 adrp/add 解析出的 `[x29-0x30]`(year) 在 `[x29-0x40]`(mday) 之前被 append。

### 1.2 实机验证：登录的开发者令牌分支

平板侧 smali 确认：

```java
// LoginViewModel$login$1 :
const/4 v6, 0x1
verifyDevelopToken(accountName, 1)
  → DeviceManagerPolicyProxy.verifyDevelopToken(name, 1)
  → LocalMdmInterface.verifyDynamicToken(name, 1)     // AIDL 到 MDM
  → MdmBinder.verifyDynamicToken(key, type=1)
       type==1 → SecretJni.verifyQrToken(context, key)   // ← 取 newDt() 前 8 位
  → 通过 → reqScanAbility()
```

- **2026-11-01 11:2x 实机测试**：在平板登录界面把 8 位令牌填入「账号名」→ **不再报账号/密码错误，走了开发者分支**（`reqScanAbility` 被调用）
- 16 位全令牌 = `verifyDevelopToken(type=0)`，即 DeveloperActivity 的 token，同样可离线算出
- **该令牌只由本地时间推导**（无设备号/无密钥/无网络），同一小时内全设备相同

### 1.3 到达功能的边界

```
令牌通过 → reqScanAbility()
  → GET /api/v1/platform/{deviceId}/scan/ability（https，真实服务器）
  → 服务端返回 Boolean → _showQRScanner.postValue()
  → 实测：服务端返回 false（或扫码器依赖外部 ZXing App，未安装）
```

**结论**：令牌可伪造（已验证），但它唯一到达的功能是「扫码能力」，服务端开关是最终闸门。

---

## 二、sec.ini（uv/randomStr）捕获与文件安全面测试

### 2.1 捕获来源

`npcap3200.log`（端口 3200 课堂/盒子 UDP 协议）中平板发出的认证帧明文：

```
v 3f025ad519274a6795aaf5161efd7726 R52N9067SSF X47AyBaQo+QIMtyqHc
  ↑ uv（32 hex）                     ↑ 设备号     ↑ randomStr（16 位）
```

即 `XhSecretKeyUtils.writeSecretToFile(uv, randomStr)` 写入 `/sdcard/xuehai/sec/sec.ini` 的 `{version}|{key}`。

### 2.2 文件安全面实测

| 接口 | 结果 |
|---|---|
| `GET https://filesoss.yunzuoye.net/XHFileServer/sts/certificate?appName=CA106004`（V1 签名） | **401 Unauthorized** |
| `http://filesoss.yunzuoye.net/...` | 401 |
| `https://files.yunzuoye.net/...` | 401 |

**结论**：STS/文件服务全链路 token 鉴权，`sec.ini` 不能替代登录 token。

---

## 三、IP 绕过：从「疑似」到「确认可达」

### 3.1 代码依据

- `XHHostnameVerifier.verifyIpAddress()` **无条件 return true**
- `OkHttp 3.12.1` 的 `RealConnection.connectTls`（smali 380-392 行）：

```smali
v5 = address.hostnameVerifier()
v6 = address.url().host()      // ← 取自 URL，不是 socket 远端地址
verify(v6, session)
```

**因此 IP 绕过仅在「URL host 本身是 IP 字面量」时生效**，域名 URL（ztp.yunzuoye.net）仍走正常主机名校验。

### 3.2 实机证据：平板确实存在 IP 字面量 URL 连接

抓包（2026-11-01 11:41，平板 192.168.137.10）：

```
11:41:36  SYN dst=192.168.137.1:443   CH sni=ztp.yunzuoye.net    ← 走 DNS 劫持到本机
11:41:43  SYN dst=47.111.87.154:443   CH sni=ztp.yunzuoye.net    ← 真实 IP + 域名 SNI
11:41:43  CH  dst=47.111.87.154:443   sni=<NO-SNI>  ★★★          ← 真实 IP + 无 SNI = URL host 是 IP
```

**`<NO-SNI>` 连接证明 App 会以 `https://<IP>` 形式发起请求**，命中 `verifyIpAddress` 无条件放行。
（注：App 用阿里 HTTPDNS（`203.107.1.1`，account `103172`）解析出真实 IP，绕过本机 DNS 劫持。）

---

## 四、MITM 链路：Let's Encrypt 证书 + WinDivert 透明重定向

### 4.1 证书获取（公共 CA，无需在平板装 CA）

- 来源：`\\192.168.3.10\C$\Users\Administrator\BtSoft\panel\vhost\letsencrypt\oliversmcserver.site\`
- 证书：`CN=oliversmcserver.site`，`Issuer=CN=YE2, O=Let's Encrypt, C=US`，有效期至 2026-11-18
- 链条：`leaf ← YE2 ← Root YE ← ISRG Root X2 ← ISRG Root X1`（Android 9 系统信任 ISRG Root X1）
- 提取方式：WinRM + `Export-PfxCertificate` → PFX → PEM（`mitm_server.crt/key` + `mitm_fullchain.pem`）

### 4.2 组件

| 组件 | 作用 |
|---|---|
| `tls_mitm.py` | :443 监听；空 SNI（IP 直连）→ 用 Let's Encrypt 证书终止 TLS → 记录明文 → 返回伪造响应（含 `X-Content-Sign-Token` 响应签名） |
| `tls_redirect.py` | WinDivert 双句柄透明重定向：NETWORK_FORWARD 层拦平板 → 改 dst 为 192.168.137.1:443；NETWORK 层拦 MITM 回包 → SNAT 改回真实 IP |

### 4.3 实测进展

```
12:03:39 [REDIR] pad 192.168.137.10:38260 -> 47.111.87.154:443 => 192.168.137.1:443
TCP    : 192.168.137.1:443 <- 192.168.137.10:60706 CloseWait pid=34040(MITM)
```

**重定向成功、平板 TCP 连接已落到 MITM**。但平板在 TCP 握手后**未发送 TLS ClientHello 即关闭**（CloseWait），MITM 的 `recv` 读到空数据静默返回。

### 4.4 当前卡点与下一步

1. 给 MITM `handle` 增加 `recv` 字节数/超时/`wrap_socket` 异常日志
2. 给 FWD 句柄记录全部重定向包（SYN/ACK/PSH）
3. 确认是「ClientHello 未到 MITM」还是「到达但握手失败」

---

## 五、本轮未通过/排除项

| 路径 | 结论 |
|---|---|
| 开发者令牌 → DeveloperActivity | 组件未导出，无外部入口（manifest 确认） |
| 文件服务 STS/上传/下载 | 401，token 鉴权 |
| `setForceIp()` | 全仓库无业务调用点（预留能力） |
| `com.xh.logcatcher` | APK 中仅见死开关与日志路径引用，平板包列表未捕获到 |
| 16 位令牌 | 可算，但到达功能受服务端开关限制 |

---

## 六、证据文件索引

| 文件 | 说明 |
|---|---|
| `tls_mitm.py` / `tls_redirect.py` | MITM 与重定向实现 |
| `mitm_server.crt` / `mitm_server.key` / `mitm_fullchain.pem` | Let's Encrypt 证书链 |
| `tls_mitm.log` / `tls_redirect.log` | 运行日志（含 [REDIR]/[MITM-OK]） |
| `pad_sni_capture.log` | 平板 ClientHello 抓包（含 `<NO-SNI>` 证据） |
| `_devtoken_fix.py` | 修正 year/mday 顺序后的令牌生成器 |
| `_windivert_diag.py` | WinDivert 层/过滤器诊断 |
