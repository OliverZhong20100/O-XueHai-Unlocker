# 使用协议 / TERMS OF USE

> 版本：v1.0　生效日期：2026-11-21
> 本协议是你（下称「使用者」）与项目作者（下称「作者」）之间关于使用本项目的**法律协议**。
> 与 [DISCLAIMER.md](DISCLAIMER.md)（免责声明）共同构成完整条款；两者冲突时，以更严格者为准。
> **开始使用（克隆、下载、阅读代码、运行脚本、构建载荷）即视为你已阅读、理解并接受本协议全部条款。不同意请立即停止并删除。**

---

## 第 1 条 定义

1.1 **本项目**：仓库 `O-XueHai-Unlocker`（公开）与 `O-XueHai-Unlocker-Private`（私有）下的全部内容，包括文档、脚本、工具、测试用例、载荷（payload）、构建产物、数据集与提交历史。

1.2 **授权环境**：同时满足下列全部条件的实验环境——(a) 目标设备为使用者本人所有，或使用者已取得设备所有者/管理方的**书面授权**；(b) 与生产网络、真实教学活动物理或逻辑隔离；(c) 使用者可随时使设备恢复原状；(d) 使用者未使用他人的账号、凭据、班级或数据。

1.3 **载荷**：能够改变目标终端行为或状态的产物，如 APK、7z 数据库补丁、注入帧脚本、C2 客户端等。

1.4 **研究记录**：仅用于说明与举证的文档、截图、日志、数据库转储与方法学描述。

## 第 2 条 授权范围

2.1 在**授权环境**内，作者授予使用者一项**非独占、不可转让、可撤销、免费**的许可，用于：学习、复现、验证、撰写研究报告、做防护与检测规则。

2.2 **私有仓额外限制**：私有仓内容（含载荷源码与完整链路细节）仅供使用者本人在授权环境内研究；**不得**再分发、公开、镜像、打包进任何产品，亦不得提供给第三方（含同一组织的其他人员，除作者书面同意）。

2.3 **公开仓**：代码部分按 `LICENSE`（MIT）授权；文档部分按 CC BY 4.0 授权（署名即可转载）。**但著作权许可不等于对任何系统的访问授权**，第 3 条限制始终有效。

## 第 3 条 使用者义务

使用者承诺：

1. 在每次实验前**自行完成合法性审查**（身份、授权文件、当地法律、校方规定）；
2. 实验前**完整备份**可恢复点（含物理恢复手段），实验后清理残留与后门；
3. 不在教学、考试、办公等生产时段与生产环境中使用；
4. 妥善保管测试账号与凭据，不将他人凭据写入本项目或任何脚本；
5. 发现第三方产品漏洞时，按负责任披露流程处理，不公开可利用细节；
6. 遵守目标设备厂商的服务条款与保修条款（实验可能导致保修失效）；
7. 对自身行为与后果**承担全部责任**。

## 第 4 条 禁止行为

除 [DISCLAIMER.md](DISCLAIMER.md) 第 3 条外，还禁止：

1. 将本项目用于**代客操作、渗透服务、培训收费**等任何商业或营利场景；
2. 将载荷提交至应用市场、公开网盘、代码托管平台的公开仓库；
3. 去除/篡改本协议、免责声明、版权与署名信息后再分发研究记录；
4. 将本项目与真实学校、真实班级、真实师生的身份或数据关联发布；
5. 以本项目为基础制作**面向不特定对象**的自动化攻击链、批量控制工具或供应链投毒工具；
6. 规避、破坏目标设备的日志与审计机制以掩盖行为。

## 第 5 条 知识产权

5.1 代码：公开仓为 MIT（见 `LICENSE`）；私有仓为 Research-Use-Only（见私有仓 `LICENSE`）。

5.2 文档与研究记录：CC BY 4.0，转载须署名「O-XueHai-Unlocker contributors」并保留原文链接。

5.3 第三方商标、产品名、包名归各自权利人所有；本项目与学海教育及其关联公司**无任何关联、未获授权或背书**。

5.4 本项目不随仓库分发任何第三方闭源二进制（含目标应用 APK）或商业密钥。

## 第 6 条 免责与责任限制

6.1 本项目按「现状」提供，**无任何明示或默示担保**（详见 DISCLAIMER 第 5 条）。

6.2 在适用法律允许的最大范围内，作者与贡献者对使用者使用本项目产生的任何损失**不承担责任**；使用者**自负全部风险**。

6.3 使用者违反第 3、4 条时，应**自行承担**全部行政、民事、刑事责任，并赔偿作者与贡献者因此遭受的损失与合理费用（含律师费）。

## 第 7 条 终止

7.1 使用者违反本协议任一条款，授权**立即自动终止**，无需通知。

7.2 终止后使用者应立即：停止使用、删除全部副本（含派生作品）、销毁载荷。

7.3 第 5、6、8 条在终止后继续有效。

## 第 8 条 适用法律与争议解决

8.1 本协议适用**中华人民共和国法律**（不含冲突法）。

8.2 因本协议产生的争议，双方应先友好协商；协商不成，提交作者所在地有管辖权的人民法院。

8.3 若某条款被认定无效或不可执行，其余条款继续有效，该条款应在最小必要范围内调整以实现其原意。

## 第 9 条 协议更新

9.1 作者可随时修订本协议并在仓库发布；修订自发布之时生效。

9.2 修订后继续使用即视为接受新版本；不接受应停止使用并删除副本。

## 第 10 条 联系

- 仓库自身缺陷：开 Issue（选择 `bug` 模板）。
- 敏感信息泄露：按 [SECURITY.md](SECURITY.md) 私下告知。
- 授权的书面证明、合作与许可咨询：通过 GitHub 主页所列联系方式。

---

## English Summary (non-binding)

You may use this project **only** in an *Authorized Environment*: a device you own or are explicitly authorized in writing to test, isolated from production, using only your own credentials.

The private repository is for the licensee's personal research only and **must not be redistributed**. Public code is MIT-licensed, public documents are CC BY 4.0 — **a copyright license grants no authorization to access any system**.

Commercial use, redistribution of payloads, use against third-party devices or production school environments, and weaponization are prohibited. The project is provided **as-is without warranty**; the authors accept **no liability** for any damage or legal consequence. Violation terminates your license immediately and you must delete all copies.

Governed by the laws of the People's Republic of China.
