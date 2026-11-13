# 文档索引

| 文档 | 内容 | 适合谁 |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 目标 App 的模块划分、进程模型、服务/广播面 | 想先理解整体结构的人 |
| [CHAIN.md](CHAIN.md) | **主链 A 逐跳表（21 跳，代码级）** + 支撑链 B + 已排除入口 | 想核对结论的人 |
| [METHODOLOGY.md](METHODOLOGY.md) | 证据分级（A–E）与判定原则：什么才算"验证过" | 想评估结论可信度的人 |
| [STATUS.md](STATUS.md) | 现状、卡点、修复台账、现场复核记录 | 想知道"现在到哪一步"的人 |
| [CONFIG.md](CONFIG.md) | 全部环境变量：键、默认值、适用脚本、限制 | 要实际跑脚本的人 |

## 阅读顺序建议

1. 根目录 [README](../README.md) 的「简介」与「快速开始」
2. [CHAIN.md](CHAIN.md)：先看 21 跳总表的"门禁"列
3. [METHODOLOGY.md](METHODOLOGY.md)：理解为什么日志不算证据
4. [STATUS.md](STATUS.md)：确认当前可用边界

## 资产说明

- `docs/assets/`：徽章与示意图（全部本地 SVG，无外链）
- `payloads/`：测试载荷（APK 示例、7z、HTML 探针等）
- `payloads/lab-certs/`：**仅本地实验**的自签证书与私钥，见其 [说明](../payloads/lab-certs/README.md)
