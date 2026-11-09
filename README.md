# ir-forensic-analysis

> 应急响应取证分析 Skill — 静态取证包深度分析，覆盖 11 大检测维度，支持多源威胁情报自动交叉分析 + MITRE ATT&CK 映射 + 因果链攻击路径复盘

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Skill](https://img.shields.io/badge/skill-4.5.5-blue)](CHANGELOG.md)
[![Collector](https://img.shields.io/badge/collector-5.4.0-green)](CHANGELOG.md)

## 简介

`ir-forensic-analysis` 是一个面向应急响应场景的自动化取证分析工具集，包含：

- **分析引擎** — SKILL.md 驱动的 LLM 11 维深度分析
- **Windows 采集脚本** — `IR_Collect_v5.4_GUI.exe` / `IR_Collect_v5.4.ps1`（默认深度取证，含 `-Target`、内存转储、日志恢复，PS4 兼容）+ `IR_Collect_PS2_GUI(老系统).exe`（PowerShell 2.0 精简版），管理员运行
- **Linux 采集脚本** — `who.sh`（司稽 v8.1，sudo 运行）
- **macOS 采集脚本** — `mac_collect.sh` v2.1（兼容 10.15+ / Intel+Apple Silicon，覆盖系统、网络、进程、持久化、账号、浏览器、日志、安全配置）
- **威胁情报模块** — 多源自动交叉分析（微步/OTX/URLhaus/VT/CVERC/AbuseIPDB/Pulsedive/URLScan/ThreatFox 等）
- **检测规则库** — JSON + YARA，含银狐专项 40 条规则 / 28886 恶意域名 / 451 IP / 51 哈希

## v5.4 更新说明（当前发布）

- 采集器默认即深度模式（Amcache/Shimcache/BAM/Prefetch/SRUM/跳转列表/扩展日志/浏览器深层），不再提供快速快照档位
- 新增 `-CaptureDeletedProcessMemory`：对非常驻系统进程做全内存转储（`MiniDumpWithFullMemory`），带 `ImageDeleted` 标记，默认关闭
- 新增 `-RecoverClearedLogs`：从卷影副本恢复已清空的事件日志，默认关闭
- 新增输出：`services_detail.csv`、`startup_folder.csv`、`security_key_events.csv`（4624/4625/4672/4688/4698/4720/4726/1102）、`usb_devices.txt`、`defender_exclusions.txt`、`powershell_history.txt`、`tasks_xml_index.csv`、`run_all_users.txt`、`interesting_files.csv`
- ZIP 生成后先校验条目数 > 0，再清理原始目录，避免压缩失败丢证据
- 修复独立 `.ps1` 非管理员启动时丢参数的问题
- **注意**：仍会释放 `%TEMP%\IR_Collect_v5.4.ps1` 并以 `-ExecutionPolicy Bypass` 子进程执行；下文的 5.3.5/5.3.6 条目为文档先行、未随二进制发布

## v5.3.6（文档先行，未发布二进制）

原计划把 GUI 与采集器合并为单进程、不落地临时脚本。该改动**未进入 v5.4 二进制**，此处保留记录以免与历史文档冲突。

## v5.3.5 更新说明

本次发布重点补齐 Windows “白加黑/DLL 侧载”容易漏报的证据链：

- 新增 `process_tree_enriched.csv` 与 `white_black_process_alerts.csv`，关联父子进程路径、命令行、SHA-256、双方签名和风险分
- 新增 `loaded_modules.csv` 与 `white_black_module_alerts.csv`，记录签名宿主实际加载的 DLL/模块及其哈希、签名和可写路径属性
- 规范化 Security 4688、Sysmon 1/7 为 CSV，并生成 `white_black_history_alerts.csv`，覆盖采集前已经退出的进程和历史模块加载
- 风险分采用多信号组合；单个未签名文件不直接定性为入侵，`HashMismatch`/`NotTrusted` 等强签名失败优先升级
- 修复独立 `.ps1` 非管理员启动时丢失参数的问题；GUI 与内嵌采集器统一为 v5.3.5
- 新增可复现构建脚本 `assets/Build-IR_Collect_GUI.ps1`，编译时校验内嵌采集器与 Tailscale 规则哈希

## v5.3.4 更新说明

本次发布新增 **ps4compat 兼容版**，把 Windows 采集脚本从 PowerShell 5.1+ 降到 **PowerShell 4.0+**，兼容 Server 2012 / 2012 R2：

- `[System.Text.StringBuilder]::new()`、`-Depth`、`Get-NetIPAddress` 等 PS5 专属写法改为 PS4 兼容实现
- 新增 `Get-ChildItemDepth` 深度限定递归函数
- **修复**该函数带 `-Filter` 时无法下钻子目录的问题，勒索扩展名 / 勒索信扫描不再漏掉子文件夹
- v5.3.4 的 `IR_Collect_v5.3.ps1` 与 `IR_Collect_v5.3_GUI.exe` 已升级为 PS4 兼容版（内嵌修好的采集脚本），原 v5.3.3 版本已移除
- 兼容下限为 PowerShell 3.0+（Server 2012 默认 PS3、2012 R2 PS4），PowerShell 2.0 / Server 2008 仍需降级处理

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
| `IR_Collect_v5.4_GUI.exe` | 图形化采集器（v5.4.0，默认即深度） | 现场不想记命令时，只复制这一个 exe 双击即可 |
| `IR_Collect_v5.4.ps1` | 采集器源码（与 exe 内嵌脚本一致） | 需要审计/改参数/被杀软拦截时直接跑脚本 |
| `IR_Collect_PS2_GUI(老系统).exe` | PowerShell 2.0 兼容的**精简版** | 仅用于 Server 2003/2008、Win7 等跑不了 v5.4 的系统 |

> 自 v5.4 起采集器**默认就是深度模式**，不再提供"快速快照"档位。

```powershell
# 图形化（推荐）
assets\IR_Collect_v5.4_GUI.exe

# 脚本方式（管理员 PowerShell），默认即深度
powershell.exe -ExecutionPolicy Bypass -File assets\IR_Collect_v5.4.ps1

# 追加敏感数据（SAM/SYSTEM/SECURITY/SOFTWARE hive、浏览器凭据库）
powershell.exe -ExecutionPolicy Bypass -File assets\IR_Collect_v5.4.ps1 -IncludeSensitive

# 进程内存转储（默认关闭；生成较大 dmp，含敏感数据）
powershell.exe -ExecutionPolicy Bypass -File assets\IR_Collect_v5.4.ps1 -CaptureDeletedProcessMemory

# 从卷影副本恢复已清空的事件日志
powershell.exe -ExecutionPolicy Bypass -File assets\IR_Collect_v5.4.ps1 -RecoverClearedLogs

# 定向采集
powershell.exe -ExecutionPolicy Bypass -File assets\IR_Collect_v5.4.ps1 -Target tailscale
```

> `-SkipFileScan`、`-IncludeSystemDirs`、`-ScanDepth N`（1-8）控制文件扫描耗时。

**已知实现细节（以代码为准）**：v5.4 仍会把内嵌采集脚本释放到 `%TEMP%\IR_Collect_v5.4.ps1`，并用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File` 子进程执行——5.3.6 文档描述的"单进程、不落地"并未进入 v5.4。该 exe 未签名，分发前请核对 SHA256。

构建脚本 `Build-IR_Collect_GUI.ps1` **未随仓库发布**，需要自行用 ps2exe 打包。

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
# 编辑 config/threat_intel.json 填入你的 API Key，或直接设置 TI_* 环境变量
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
| 8 | 高级对抗（银狐 40 条规则） | T1562, T1055, T1014 |
| 9 | 进程名仿冒 + 数字签名 | T1036 |
| 10 | 打包器/载荷（PyInstaller/PyArmor/UPX） | T1027 |
| 11 | 供应链/勒索（8族勒索家族识别） | T1486, T1490 |

## 威胁情报源

分析时会对已配置平台自动交叉比对，报告会标注各平台参与状态和 Key 配置要求。

| 源 | 类型 | 需要 Key |
|----|------|----------|
| 微步在线 | IP/域名/Hash | 是 |
| AlienVault OTX | IP/域名/Hash（Pulse 关联） | 否 |
| URLhaus | IP/域名（恶意 URL 分发） | 否 |
| VirusTotal | IP/Hash | 是 |
| CVERC | Hash | 是 |
| AbuseIPDB | IP（信誉评分） | 是 |
| Pulsedive | IP/域名/Hash（风险评分） | 否（可选 Key） |
| URLScan.io | 域名历史扫描 | 否（可选 Key） |
| ThreatFox | IP/域名/Hash | 是（免费 Auth-Key） |
| MalwareBazaar | Hash | 是（免费 Auth-Key） |
| Kaspersky OpenTIP | IP/域名/Hash | 是（免费 Token） |
| GreyNoise | IP（噪声/威胁分类） | 是（免费社区 Key） |
| Hybrid Analysis | Hash（沙箱情报） | 是（免费 API Key） |
| IPinfo.io | IP 归属/ASN | 否 |

## 目录结构

```
ir-forensic-analysis/
├── SKILL.md                    # 核心分析 Skill
├── 使用说明.md                 # 详细文档
├── CHANGELOG.md                # 变更记录
├── assets/                     # 采集脚本
│   ├── IR_Collect_v5.4_GUI.exe    # Windows 图形化采集器（v5.4.0，默认深度）
│   ├── IR_Collect_v5.4.ps1        # 采集器源码（与 exe 内嵌脚本一致）
│   ├── IR_Collect_GUI_v5.4.ps1    # GUI 启动器源码（ps2exe 重新打包用）
│   ├── IR_Collect_PS2_GUI(老系统).exe  # PowerShell 2.0 兼容精简版
│   ├── IR_Collect_PS2.ps1         # PS2 版源码
│   ├── who.sh                     # Linux 采集（司稽 v8.1）
│   └── mac_collect.sh             # macOS 采集（v2.1）
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

评分 = Σ（维度权重 × 严重等级分），与 `scripts/analyze_forensics.py` 的实现一致：

| 维度 | 权重 |
|------|------|
| 网络外联(C2) / 高级对抗 / 勒索 / 内存注入 | 4 |
| 可疑进程 / 持久化 / Webshell / 横向 / 仿冒签名 / 打包器 / 供应链 | 3 |
| 异常账号 | 2 |

严重等级分：Critical 3 / High 2 / Medium 1 / Low 0.5

| 总分 | 等级 | 处置 |
|------|------|------|
| ≥25 | 🔴 危急 | 立即隔离，全量排查 |
| 15-24 | 🟠 高危 | 优先处置，限制网络 |
| 5-14 | 🟡 中危 | 调查确认，针对性处理 |
| <5 | 🟢 低危 | 记录观察，持续监控 |

## PS2 兼容版（老系统）

`assets/IR_Collect_PS2_GUI(老系统).exe` 是 PowerShell 2.0 语法子集编写的精简采集器（源码 `assets/IR_Collect_PS2.ps1`，265 行），用于跑不了 v5.4 的老系统。

| 操作系统 | 自带 PowerShell | 可用性 |
|---------|----------------|--------|
| Windows 7 / Server 2008 R2 | 2.0 | ✅ 主目标，开箱即用 |
| Windows 8 / 2012 / 10 / 11 | 3.0-5.1 | ✅ 可运行，但应优先 v5.4 |
| Vista / Server 2008（需装 PS2） | 1.0 | ⚠️ 部分可用 |
| Windows XP / Server 2003（需装 PS2） | 无 | ⚠️ 无 `wevtutil`，事件日志采不到 |

**能力差异**：无进程名仿冒、打包器检测、远控端口、COM/DLL 劫持、SAM 克隆、隐藏账号、**勒索扩展名/勒索信扫描**、IIS/Web、浏览器取证、4104；**不打包、不生成 SHA256**。

**已知缺陷**：脚本末尾 `Get-ChildItem $dir -Recurse -File` 的 `-File` 是 PowerShell 3.0+ 参数，在真 PS2 上会报错，导致 `file_manifest.csv` 为空；跑完请自行补哈希。


## License

MIT
