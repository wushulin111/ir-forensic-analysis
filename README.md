# ir-forensic-analysis

> 应急响应取证分析 Skill — 静态取证包深度分析，覆盖 11 大检测维度，支持 6 源威胁情报关联 + MITRE ATT&CK 映射 + 因果链攻击路径复盘

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.3.0-green)](CHANGELOG.md)

## 简介

`ir-forensic-analysis` 是一个面向应急响应场景的自动化取证分析工具集，包含：

- **分析引擎** — SKILL.md 驱动的 LLM 11 维深度分析
- **Windows 采集脚本** — `IR_Collect_v4.3.ps1`（945 行，管理员运行）
- **Linux 采集脚本** — `who.sh`（司稽 v8.1，sudo 运行）
- **macOS 采集脚本** — `mac_collect.sh`
- **威胁情报模块** — 6 源查询（微步/OTX/URLhaus/VT/CVERC/AbuseIPDB）
- **检测规则库** — JSON + YARA，含银狐专项 34 条规则 / 5265 恶意域名

## 快速开始

### 1. 采集取证包

```powershell
# Windows（管理员 PowerShell）
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v4.3.ps1
```

```bash
# Linux（root）
sudo ./assets/who.sh -q

# macOS
sudo ./assets/mac_collect.sh
```

采集完成后在 `C:\IR\` 或 `/tmp/ir_evidence/` 下生成 `IR_HOSTNAME_TIMESTAMP.zip`。

### 2. 分析取证包

将取证包导入支持 SKILL.md 的 LLM 环境（如 Codex），直接上传分析：

```
帮我分析这个 IR.zip
```

AI 自动解压 → 数据预处理（timeline + Sigma + 情报查询）→ 11 维逐维分析 → 输出结构化报告。

### 3. 命令行分析（可选）

```bash
pip install -r requirements.txt
python scripts/extract_archive.py IR.zip -o ./extracted
python scripts/analyze_forensics.py ./extracted/IR_HOSTNAME_TIMESTAMP/ -r ./rules -o ./report
```

### 4. 配置威胁情报

```bash
cp config/threat_intel.json.example config/threat_intel.json
# 编辑 config/threat_intel.json 填入你的 API Key
```

## 11 大检测维度

| # | 维度 | ATT&CK |
|---|------|--------|
| 1 | 可疑进程 | T1059, T1218, T1564 |
| 2 | 持久化机制 | T1547, T1053, T1546 |
| 3 | 异常账号（WMI/ProfileList 多源交叉比对） | T1136, T1078, T1548 |
| 4 | 网络外联（延迟二次采样） | T1071, T1571, T1041 |
| 5 | Webshell | T1505, T1059, T1562 |
| 6 | 内存注入（16条规则 + JIT 误报过滤） | T1055, T1620 |
| 7 | 横向移动 | T1021, T1047, T1550 |
| 8 | 高级对抗（银狐 34 条规则） | T1562, T1055, T1014 |
| 9 | 进程名仿冒 + 数字签名 | T1036 |
| 10 | 打包器/载荷（PyInstaller/PyArmor/UPX） | T1027 |
| 11 | 供应链/勒索（8族勒索家族识别） | T1486, T1490 |

## 威胁情报源

| 源 | 类型 | 免费 |
|----|------|------|
| 微步在线 | IP/域名/Hash | 需 Key |
| AlienVault OTX | IP/域名/Hash（Pulse 关联） | ✅ |
| URLhaus | IP/域名（恶意 URL 分发） | ✅ |
| VirusTotal | IP/Hash | 需 Key |
| CVERC | Hash | 需 Key |
| AbuseIPDB | IP（信誉评分） | 1000次/天 |

## 目录结构

```
ir-forensic-analysis/
├── SKILL.md                    # 核心分析 Skill
├── 使用说明.md                 # 详细文档
├── CHANGELOG.md                # 变更记录
├── assets/                     # 采集脚本
│   ├── IR_Collect_v4.3.ps1    # Windows 采集
│   ├── who.sh                  # Linux 采集
│   └── mac_collect.sh          # macOS 采集
├── config/
│   └── threat_intel.json.example  # 情报配置模板
├── scripts/                    # Python 分析引擎
│   ├── analyze_forensics.py
│   ├── extract_archive.py
│   ├── rule_manager.py
│   └── threat_intel_lookup.py
├── rules/                      # 检测规则库
│   ├── silver_fox_rules.json   # 银狐专项
│   ├── injection_rules.json    # 内存注入
│   ├── ransomware_family_rules.json
│   └── yara_rules/
└── references/                 # 参考文档
```

## 威胁评分

| 分数 | 等级 | 处置 |
|------|------|------|
| 0-20 | 🟢 低危 | 观察 |
| 21-50 | 🟡 中危 | 24h 排查 |
| 51-80 | 🟠 高危 | 4h 响应 |
| 81+ | 🔴 危急 | 15min 响应 |

## License

MIT
