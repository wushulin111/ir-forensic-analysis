# ir-forensic-analysis

> 应急响应取证分析 Skill — 静态取证包深度分析，覆盖 11 大检测维度，支持 6 源威胁情报关联 + MITRE ATT&CK 映射 + 因果链攻击路径复盘

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.2.0-green)](CHANGELOG.md)

## 简介

`ir-forensic-analysis` 是一个面向应急响应场景的自动化取证分析工具集，包含：

- **分析引擎** — SKILL.md 驱动的 LLM 11 维深度分析
- **Windows 采集脚本** — `IR_Collect_v5.1.ps1`（稳定版，1010 行）/ `IR_Collect_v5.2.ps1`（定向增强版，支持 `-Target` 按需采集），管理员运行
- **Linux 采集脚本** — `who.sh`（司稽 v8.1，sudo 运行）
- **macOS 采集脚本** — `mac_collect.sh` v2.1（兼容 10.15+ / Intel+Apple Silicon，覆盖系统、网络、进程、持久化、账号、浏览器、日志、安全配置）
- **威胁情报模块** — 6 源查询（微步/OTX/URLhaus/VT/CVERC/AbuseIPDB）
- **检测规则库** — JSON + YARA，含银狐专项 34 条规则 / 5265 恶意域名

## 安装与使用

### 方式一：作为 Codex Skill 使用（推荐）

```bash
# 1. 克隆到 Codex skills 目录
git clone https://github.com/wushulin111/ir-forensic-analysis.git ~/.codex/skills/ir-forensic-analysis

# 2. 配置威胁情报（可选，不配也能用 OTX/URLhaus 免费源）
cp ~/.codex/skills/ir-forensic-analysis/config/threat_intel.json.example \
   ~/.codex/skills/ir-forensic-analysis/config/threat_intel.json
# 编辑 threat_intel.json 填入你的微步/VT Key
```

安装完成后，在 Codex 对话中直接上传取证包即可触发分析：

```
帮我分析这个 IR.zip
分析一下这个取证包
看看这台服务器是不是被入侵了
```

### 方式二：直接上传 SKILL.md（适用于其他 LLM）

下载仓库中的 `SKILL.md` 文件，上传到支持文件引用的 LLM 对话中，再将取证包一并上传分析。

### 方式三：Python 命令行独立运行（不依赖 LLM）

```bash
pip install -r requirements.txt  # 如果仓库中有 requirements.txt

# 解压取证包
python scripts/extract_archive.py IR.zip -o ./extracted

# 分析
python scripts/analyze_forensics.py ./extracted/IR_HOSTNAME_TIMESTAMP/ -r ./rules -o ./report
```

> Python 脚本为参考实现。方式一和方式二的分析深度和准确度更高。

## 采集取证包

### 1. 生成取证包

先选择 Windows 采集脚本：

| 脚本 | 定位 | 什么情况用 |
|------|------|-----------|
| `IR_Collect_v5.1.ps1` | 标准全量采集，9 大阶段 | 常规应急响应、疑似入侵、需要完整主机证据时默认使用 |
| `IR_Collect_v5.2.ps1` | 全量采集 + `-Target` 定向增强 | 需要针对特定软件/组件补充取证时使用，如 VPN、远控、Tailscale、安全软件等 |

```powershell
# Windows 标准版（管理员 PowerShell，无附加参数）
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.1.ps1

# Windows 定向增强版：全量采集 + 针对 Tailscale 定向采集
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.2.ps1 -Target tailscale

# 无规则文件时按关键词兜底扫描
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.2.ps1 -Target anyapp
```

> `IR_Collect_v5.1.ps1` 只做标准全量采集，不需要额外参数；`IR_Collect_v5.2.ps1` 不传 `-Target` 时等价于 v5.1，传入 `-Target 名称` 时会在全量采集基础上追加目标定向采集。

```bash
# Linux（root）
sudo ./assets/who.sh -q

# macOS
sudo ./assets/mac_collect.sh
```

采集完成后，Windows 输出到 `C:\IR\`，macOS 输出到 `/opt/ir_evidence/`，生成 `IR_HOSTNAME_TIMESTAMP` 数据包及 SHA256。

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
│   ├── IR_Collect_v5.1.ps1    # Windows 采集稳定版
│   ├── IR_Collect_v5.2.ps1    # Windows 定向增强版（-Target 按需采集）
│   ├── who.sh                  # Linux 采集
│   └── mac_collect.sh          # macOS 采集
├── config/
│   ├── threat_intel.json.example  # 情报配置模板
│   └── targets/                    # 定向采集规则（tailscale.json 示例）
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
