# SM-P200 鏈€缁堟姤鍛婏紙2026-10-24 鍏ㄩ噺锛夆€斺€?璇惧爞 WS 娉ㄥ叆 + 浠ょ墝鑾峰彇 + 鍏ㄩ儴閾捐矾鍒ゅ畾

> 鑼冨洿锛氳嚜鏈夊钩鏉?+ 闅旂瀹為獙锛涗笉娑夊強鐢熶骇浜戞敾鍑伙紱浠ょ墝涓哄钩鏉胯嚜韬細璇濓紙鎺堟潈鑼冨洿鍐咃級銆?

---

## 涓€銆佷粖鏃ョ‘瀹氱殑鎴愭灉锛堝彲澶嶇幇锛?

### 1. 璇惧爞 WebSocket 娉ㄥ叆閫氶亾锛堝畬鏁存帉鎻★級

```
鐩爣: 骞虫澘杩?47.99.214.197:8889 鐨勬槑鏂囪鍫?WS
鎵嬫: L2 鎷嗗寘 + SYNACK 鎶㈢瓟 + ISN 閲囩撼锛圫EQ-ADOPT锛?
楠岃瘉: 杩炵画 [ACK] 绔晶ack=X 鎴戜滑mine=X OK锛堢渚у凡纭娉ㄥ叆鏁版嵁锛?
      frame_in 鎸佺画澧為暱銆亀s_open 澶氭閲嶈繛
9 涓鐞嗗櫒 tag: canvas_tag / default_tag / fangzl_tag / online_tag /
               server_tag / wangwz_tag / MessageHandleForStudentList /
               simple_stu / simple_tea
80+ 娑堟伅绫诲瀷 鈫?action 鏄犲皠: pentest/ws_message_map.txt锛堣祫浜э級
```

### 2. 鐪熷疄 JWT 浠ょ墝锛堟湰娆℃渶澶ф垚鏋滐級

```
鏉ユ簮: getPage 璇锋眰澶?authorization锛堟槑鏂?HTTP锛岃鍐掑厖鍣?[API-HDR] 璁板綍锛?
鏂囦欢: pentest/<令牌文件>锛?06 瀛楃锛?
杞借嵎: {"uid":"<userId>","sub":"<璐﹀彿>","authority":"student",
       "did":"<搴忓垪鍙?","sid":"5a7d0ff1d47c4941b315a8018993ee61",
       "scope":"XHde0af8969baa0250_CA106004","exp":1793435027}
楠岃瘉: 鐢ㄤ护鐗岃皟 getPage 鈫?HTTP 200
```

### 3. getPage锛堟槑鏂?HTTP锛夌湡瀹?schema

```
GET http://<鍘傚晢鍩熷悕>/api/v3/users/{uid}/getPage?classrooms=..&sign=..&t=..
鍝嶅簲: {"code":200,"msg":"success","data":[{"records":[...]}],"desc":""}
records 瀛楁锛圙etRecordListTask 瑙ｆ瀽锛? videoId / userId / createTime /
  classroomId / classroomName / mediaUrl / timeLength / status / changeStatus / type
鍐掑厖鍣ㄥ凡鍏峰 [GETPAGE-INJECT]锛堝彲娉ㄥ叆鎴戜滑鎺у埗鐨勮褰曪級
```

### 4. 涓や釜鏃犺矾寰勬牎楠岀殑瑙ｅ帇瀹炵幇锛堜唬鐮佺骇锛?

```
A. Z7Extractor锛坙ibun7zip.so锛宧zy3774/AndroidUn7zip锛?
   ResourceHelper.doHandDownLoadSuccess -> Z7Extractor.extractFile  (鍞竴璋冪敤鐐?
   VM 鐢ㄥ巶鍟嗕唬鐮佸疄璇? 54 鏂囦欢閫冮€稿埌瑙ｅ帇鐩綍澶?
   瑙﹀彂: needDecode(zipUrl 浠?7z 缁撳熬)

B. UnZipCwpUtil锛堝鐢?App 鑷韩锛?38 琛岋級
   CommonCwpPlayerActivity -> StuCwpUnzipUntil -> UnZipCwpUtil.unZip
   鍏ㄦ枃鏃?../ canonical startsWith 鏍￠獙
```

### 5. 杞借嵎锛堝氨缁級

```
payload_proxy.7z : 9312B锛?*鐪?ZIP 鍐呭**锛?2 鏉?../ 娣卞害 1..20锛?
                   鐩爣 /mnt/sdcard/xhproxy/QZWOQSFOQEDOQPQFXFX锛?
鏂囦欢鍚?QZWOQSFOQEDOQPQFXFX = encrypt("<鍐呯綉IP>:18080")
  (鏄犲皠 O=. P=: 1鈫扱 2鈫扺 3鈫扙 4鈫扲 5鈫扐 6鈫扴 7鈫扗 8鈫扚 9鈫抁 0鈫扻)
鍚姩鍣?checkProxy(): /mnt/sdcard/xhproxy 鍙栫涓€涓枃浠?-> 鏂囦欢鍚嶈В瀵?-> JNISetProxy
```

---

## 浜屻€佷粖鏃ュ垽姝荤殑璺緞锛堝叏閮ㄥ疄鏈洪獙璇侊級

| 璺緞 | 鍒ゆ渚濇嵁 |
|---|---|
| 50001锛堣€佸笀 FTP/rootPath 鐩存帴鍐欙級 | `StuFtpManager.init()` 鍏?App 闆惰皟鐢?鈬?鐩戝惉鍣ㄤ粠鏈敞鍐?|
| 鐭(type=3)涓嬭浇+瑙ｅ帇 | 涓嬭浇鎴愬姛锛圸IP 杞借嵎 脳5锛夛紝needDecode=true锛屼絾璁惧鏈墽琛岃В鍘嬶紙閲嶅惎楠岃瘉锛?|
| 璧勬簮鑷姩涓嬭浇锛圸7Extractor锛?| `AutoDownloadManager.addDownloadTask` 琚?`isEndUpClass()` 璺宠繃 |
| 浠诲姟鍒楄〃瑙﹀彂 | 姝昏鍫傛棤浠诲姟鍒楄〃鐣岄潰 |
| 浜掑姩/CWP锛圲nZipCwpUtil锛?| 鑰佸笀宸插叧闂棶璐?|
| PPT 棰勮 | 璧板彟涓€涓嬭浇鍣紝涓嶈皟瑙ｅ帇 |
| getPage 娉ㄥ叆 | App 鍙湪 17:41 璇锋眰涓€娆★紝涔嬪悗缂撳瓨锛岄€€閲嶈繘/娓呯紦瀛?娓呮暟鎹潎涓嶅璇锋眰 |
| 鎭㈠妯″紡 sideload | `E: Signature verification failed (error 21)`锛堝疄娴嬶級|
| ADB / 寮€鍙戣€呴€夐」 / Download Mode | MDM 绂佺敤 |
| 鐩存帴鍐欐枃浠讹紙娑堟伅鍙帶璺緞锛?| DownloadFileManager.downloadFile 鐨?33 澶勮皟鐢ㄨ€呭叏閮ㄥ唴閮ㄧ畻璺緞 |

---

## 涓夈€佽嚜鍔ㄤ笅杞介椄闂紙浠ｇ爜绾э紝鍏抽敭锛?

```java
AutoDownloadManager.addDownloadTask(List):
    if (!UpClassStateHelper.isEndUpClass()) {   // 宸蹭笅璇?= true => 鏁存璺宠繃
        addTaskList(list); startNextTask(0);
    }
UpClassStateHelper.UP_CLASS_STATE(bool,int): 2=涓婅涓?3=宸蹭笅璇?4=LOADING/NOT
涓婅鐘舵€佸敮涓€鏉ユ簮: ClassDetailResponseDataBean锛圚TTPS 璇惧爞璇︽儏鎺ュ彛锛?
                + clearAllConfig()锛堟竻闆讹級
=> 娌℃湁浠讳綍 WebSocket / 鏄庢枃 HTTP 鍏ュ彛鑳借缃?涓婅涓?
```

---

## 鍥涖€佽瘹瀹炵粨璁?

```
**鍦?宸蹭笅璇俱€佷簰鍔ㄥ叧闂€佸叾浣欏叏 HTTPS"鐨勮鍫備笂锛屼笉瀛樺湪鍙嚜鍔ㄩ棴鐜殑鎺ョ閾捐矾銆?*
浠婂ぉ宸叉妸姣忎竴鐜寲鍒颁唬鐮佺骇骞剁敤瀹炴満楠岃瘉锛涘敮涓€纭畾鐨勬柊澧炶兘鍔涙槸锛?
  鈶?璇惧爞 WS 浠绘剰娑堟伅娉ㄥ叆  鈶?鐪熷疄 JWT 浠ょ墝  鈶?getPage 鏄庢枃鎺ュ彛鍙敞鍏ヨ褰?

闂幆鍙樊涓や釜澶栭儴鏉′欢涔嬩竴锛?
  鈶?涓€涓?姝ｅ湪涓婅涓斾簰鍔ㄦ湭鍏抽棴"鐨勮鍫?
  鈶?鍏佽瀹夎涓€娆?CA锛堝彲鏀瑰啓 HTTPS 鍝嶅簲閲岀殑璇惧爞鐘舵€?璧勬簮 URL锛?
```

---

## 浜斻€佺粍浠朵笌鏂囦欢

```
pentest/npcap_http80.py   80绔彛鍐掑厖 + 杞借嵎鏇挎崲 + [GETPAGE]/[GETPAGE-INJECT]
pentest/ws8889.py         璇惧爞 WS 娉ㄥ叆锛圫EQ-ADOPT 宸查獙璇侊級
pentest/proxy8888.py      18080 搴旂敤鍒楄〃/APK 涓嬪彂锛堜唬鐞嗗垏鎹㈠悗鎺ョ鐢級
pentest/payload_proxy.7z  9312B ZIP-SLIP锛堢湡 ZIP锛?
pentest/<令牌文件>    鐪熷疄 JWT锛堟湁鏁堟湡鍐呭彲鐢級
pentest/ws_message_map.txt 9 澶勭悊鍣?type鈫攁ction 鍏ㄦ槧灏?
pentest/getpage_capture.log getPage 鎹曡幏
REPORT-2026-10-24-WS娉ㄥ叆閾捐矾.md  鏈姤鍛?
```
