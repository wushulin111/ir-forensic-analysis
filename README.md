# ir-forensic-analysis

> 应急响应取证分析 Skill — 静态取证包深度分析，覆盖 11 大检测维度，支持 6 源威胁情报关联 + MITRE ATT&CK 映射 + 因果链攻击路径复盘

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.3.3-green)](CHANGELOG.md)

## 简介

`ir-forensic-analysis` 是一个面向应急响应场景的自动化取证分析工具集，包含：

- **分析引擎** — SKILL.md 驱动的 LLM 11 维深度分析
- **Windows 采集脚本** — `IR_Collect_v5.3.ps1`（默认快照 + `-DeepForensic` 深度取证 + `-Target` 定向采集）/ `IR_Collect_v5.3_GUI.exe`（自包含中文选项弹窗版），管理员运行
- **Linux 采集脚本** — `who.sh`（司稽 v8.1，sudo 运行）
- **macOS 采集脚本** — `mac_collect.sh` v2.1（兼容 10.15+ / Intel+Apple Silicon，覆盖系统、网络、进程、持久化、账号、浏览器、日志、安全配置）
- **威胁情报模块** — 6 源查询（微步/OTX/URLhaus/VT/CVERC/AbuseIPDB）
- **检测规则库** — JSON + YARA，含银狐专项 34 条规则 / 5265 恶意域名

## v5.3.3 更新说明

本次发布主要修复 v5.3.2 在部分终端出现的“不能对 Null 值表达式调用方法”弹窗和采集卡死问题，并重新编译自包含 GUI：

- **全局异常兜底**：主脚本增加全局 `trap`，GUI“开始采集”增加整体 `try/catch`，任何阶段出错都会弹出带具体行号的提示并写入 `C:\IR\fatal.log`，不再裸报错
- **空值安全**：定向目标 `$TargetName.Trim()`、数字签名 `VersionInfo` 等改为空值判断，避免个别进程/空参数触发 Null 方法调用
- **定向规则定位修复**：定向规则查找增加 `%TEMP%` 兜底，修复 exe 运行时找不到内嵌 `tailscale.json` 的问题
- **网络枚举超时**：`net view /all` 改用 20 秒超时，避免现场网络枚举长时间挂起
- **GUI exe 自包含**：`IR_Collect_v5.3_GUI.exe` 已内嵌完整 v5.3.3 采集脚本与 Tailscale 定向规则，版本号统一为 5.3.3.0

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
| `IR_Collect_v5.3.ps1` | 默认快照采集，可选 `-DeepForensic` 深度取证 | 常规应急响应默认使用；重大事件、需要离线痕迹/扩展日志时加 `-DeepForensic` |
| `IR_Collect_v5.3_GUI.exe` | 自包含图形化选项启动器（v5.3.3） | 现场不想记命令时，只复制这一个 exe 到目标电脑双击即可，按需求勾选采集模式 |

> v5.1/v5.2 的能力已全部合并进 v5.3（含 `-Target` 定向采集），GitHub 发布版只维护 v5.3 一个脚本。

```powershell
# Windows 默认快速快照（管理员 PowerShell）
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1

# 图形化选项版（自包含单文件，双击运行，按需勾选）
assets/IR_Collect_v5.3_GUI.exe

# 深度取证：离线痕迹 + 扩展日志 + 浏览器深库
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1 -DeepForensic

# 深度取证 + 敏感数据（SAM/SYSTEM hive、浏览器凭据库）
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1 -DeepForensic -IncludeSensitive

# 大磁盘/时间紧：跳过耗时文件扫描
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1 -SkipFileScan

# 定向采集：全量采集 + 针对 Tailscale 定向采集（v5.3 保留 v5.2 能力）
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1 -Target tailscale

# 无规则文件时按关键词兜底扫描
powershell.exe -ExecutionPolicy Bypass -File assets/IR_Collect_v5.3.ps1 -Target anyapp
```

> `IR_Collect_v5.3.ps1` 默认快速快照；`-DeepForensic` 追加 `0_offline/`、`6_logs/extended/`、`browser_artifacts/deep/`。`-IncludeSensitive` 默认关闭，避免采集 SAM/SYSTEM hive 与浏览器凭据库。`-SkipFileScan`、`-IncludeSystemDirs`、`-ScanDepth N`（1-8）可控制文件扫描耗时。传入 `-Target 名称` 会在全量采集基础上追加目标定向采集。

**推荐用法（现场快速采集）**：把 `IR_Collect_v5.3_GUI.exe` 复制到目标 Windows 电脑，双击运行即可。exe 已内嵌完整采集脚本和 Tailscale 定向规则，不需要再携带 `.ps1`；Win10/11 自带 PowerShell 5.1，无需安装环境。首次运行会弹 UAC 管理员确认，属正常；PS2EXE 打包程序可能被杀软误报，建议加入白名单。

```bash
# Linux（root）
sudo ./assets/who.sh -q

# macOS
sudo ./assets/mac_collect.sh
```

采集完成后，Windows 输出到 `C:\IR\IR_主机名_时间戳.zip`（SHA256 见同目录 `.sha256`），macOS 输出到 `/opt/ir_evidence/IR_主机名_时间戳.tar.gz`。

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
│   ├── IR_Collect_v5.3.ps1    # Windows 默认快照 + 深度取证（-DeepForensic）
│   ├── IR_Collect_v5.3_GUI.exe # Windows 自包含图形化选项启动器（自动提权）
│   ├── IR_Collect_GUI_v5.3.ps1 # GUI 启动器源码（ps2exe 重新打包用）
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
