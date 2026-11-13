# 变更记录
## ir-forensic-analysis v4.5.6 / IR_Collect v5.4.0 (2026-11-05)

**当前发布：以实际二进制为准**

采集器：
- 默认即深度模式，取消快速快照档位
- 新增 `-CaptureDeletedProcessMemory`：非常驻进程全内存转储（MiniDumpWithFullMemory），默认关闭
- 新增 `-RecoverClearedLogs`：卷影副本恢复已清空事件日志，默认关闭
- 新增输出：`services_detail.csv`、`startup_folder.csv`、`security_key_events.csv`、`usb_devices.txt`、`defender_exclusions.txt`、`powershell_history.txt`、`tasks_xml_index.csv`、`run_all_users.txt`、`interesting_files.csv`
- ZIP 生成后校验条目数再清理原始目录
- 修复独立 `.ps1` 非管理员启动丢参数

老系统采集脚本（新增）：
- 新增 `assets/IR_Collect_PS2_GUI(老系统).exe`：PowerShell 2.0/3.0 兼容的精简采集器，面向 Server 2003/2008、Windows 7 等装不上 PowerShell 4+ 的机器
- 同步提供源码 `assets/IR_Collect_PS2.ps1`（265 行，全程 PS2 语法：不使用 `Get-CimInstance`、`[pscustomobject]`、`$PSScriptRoot`、`Get-WinEvent`）
- 能力为 v5.4 的子集：不含进程名仿冒、打包器检测、远控端口、COM/DLL 劫持、SAM 克隆、隐藏账号、勒索扩展名/勒索信扫描、IIS/Web、浏览器取证、4104 脚本块
- 输出为目录形式（不压缩、不生成 SHA256），需现场人工补哈希
- 已知限制：脚本末尾 `Get-ChildItem -File` 属于 PS3+ 参数，真 PS2 环境下 `file_manifest.csv` 会为空；XP/2003 无 `wevtutil`，事件日志采不到

分析引擎 v2.2：
- 支持读取 CSV（此前只读 txt/log，采集器主要输出被忽略）
- 补齐第 8-11 维：高级对抗（IOC 库匹配）、仿冒签名、打包器、勒索家族识别
- 输出 Schema v2 机器可读摘要（`report_summary.json` + 报告内 JSON 块）与覆盖率表
- 规则正则非法时跳过该规则而非中断整轮分析
- 持久化分析支持"键名行 + 值行"组合匹配
- `--update-rules` 默认关闭，规则库只读

情报库更新（2026-11-05）：
- `rules/ioc_library.json`：域名 1918→28886、IP 414→451、哈希 45→51（MD5 44 + SHA256 7）、释放路径 207→546，`last_updated` = 2026-11-05
- 主要来源：Detect-DefenseLab/silverfox-ioc 公开数据集（26,656 条域名，2026-09-03）、CCTGA 银狐专项 TOP20（2026-11-02）、cn-sec 批次披露（2026-11-03）、山西网信 CCTGA 第六批（2026-10-15）、奇安信 DeepSeek 仿冒拓线（2026-08-13）、Gurucul 印度税务活动、微步云沙箱攻击事件、看雪样本分析
- 新增 `scripts/update_silver_fox_iocs.py`：从文本/JSON/URL 提取 IOC 并合并入库，记录来源与日期，支持 `--dry-run`
- 分析器 IOC 匹配改为 token 交集：28,886 条域名下整包分析耗时从 93.6s 降到 7.0s
- 修复 `silver_fox_rules.json` 4 处重复 `rule_id`：SFOX-0020 撞号改为 SFOX-0044；SFOX-0024/0025/0026 为同号分批规则已合并（规则数 43→40）
- 修复 IOC 库中 `27.124.21[.131]` 防混淆写法，规范为 IP `27.124.21.131`
- 修复哈希匹配缺陷：库中 44 条为 MD5，分析器此前只比对 SHA256 永远不命中；现按长度同时匹配 MD5/SHA256
- 修复 `.locked` 被三家族共用导致误归属，现要求同时命中勒索信
- 修复 `rules_updated.json` 1 条重复 `rule_id`

文档与规则：
- 修复 `persistence_rules.json` 中 2 条非法正则（PERS-0020/0021）
- 修复 5 个 YARA 文件共 13 处 unreferenced string，全部可编译
- SKILL.md 去除控制字符污染、修复代码围栏、维度编号补至 11、Linux 路径对齐 who.sh 实际输出
- README/使用说明版本号、规则数量（43 条 / 1918 域名）、评分体系与代码统一

## ir-forensic-analysis v4.5.5 / IR_Collect v5.3.6 (2026-09-02) —— 文档先行，未发布二进制
**完整功能单进程低误报封装**
- 保留 RWX 内存扫描、注册表 Hive、VSS、深度文件扫描、白加黑与历史事件等全部取证能力
- GUI 与采集器改为同一 x64 进程内调用，不再向 `%TEMP%` 释放 `IR_Collect_v5.3.5.ps1`
- 移除 GUI 的 `powershell.exe -ExecutionPolicy Bypass -File ...` 子进程链
- Tailscale 定向规则改为进程内内置，不再释放临时 JSON；独立 PS1 仍可读取外部 `config/targets`
- GUI 与采集器双重限制 `ScanDepth` 为 1-8，并返回明确的采集完成状态
- EXE 与脚本版本统一为 v5.3.6 / 5.3.6.0；构建器验证源码/规则指纹、单进程入口和旧落地资源缺失
- 构建器新增可选 Authenticode 证书指纹参数；无证书构建明确保持 `NotSigned`

## ir-forensic-analysis v4.5.4 / IR_Collect v5.3.5 (2026-09-02) —— 文档先行，未发布二进制
**白加黑 / DLL 侧载证据链增强**
- 新增父子进程信任链 `process_tree_enriched.csv` 和组合告警 `white_black_process_alerts.csv`
- 新增加载模块哈希/签名清单 `loaded_modules.csv` 和 `white_black_module_alerts.csv`
- 新增 Security 4688、Sysmon 1/7 规范化 CSV 与 `white_black_history_alerts.csv`，覆盖已退出进程和历史模块加载
- 采用多信号风险分，单个未签名文件不直接定性；强签名失败优先升级
- 修复独立脚本非管理员提权时未携带原参数的问题
- GUI、内嵌采集器与文件版本统一为 v5.3.5 / 5.3.5.0
- 新增 `Build-IR_Collect_GUI.ps1`，编译后校验内嵌采集脚本及 Tailscale 规则 SHA-256
- 修复 `persistence_rules.json` 与 `REPORT_CONTRACT.md` 的格式错误

## IR_Collect v5.3.4 (2026-08-27)
**Windows 采集脚本 PS4 兼容版**
- 兼容 PowerShell 4.0+（Server 2012 / 2012 R2）
- 修复 `Get-ChildItemDepth` 带 `-Filter` 时无法递归子目录的问题，勒索扩展名 / 勒索信扫描不再漏子文件夹
- `::new()`、`-Depth`、`Get-NetIPAddress` 等 PS5 专属写法改为 PS4 兼容实现
- `IR_Collect_v5.3.ps1` 与 `IR_Collect_v5.3_GUI.exe` 升级为 PS4 兼容版（内嵌修好的采集脚本），并移除原 v5.3.3 版本

## ir-forensic-analysis v4.5.3 (2026-08-25)
**威胁情报增强 + who.sh POSIX 兼容修复**
### 威胁情报
- 新增 VirusTotal 域名查询，VT 覆盖 IP/域名/Hash；域名查询顺序加入 VirusTotal
- URLhaus 2025 年起查询需免费 Auth-Key，脚本、配置、文档同步更新
- 修正“情报交叉分析说明”状态：区分 已自动比对/未配置Key/查询失败/未收录，错误 Key 命名统一
- Pulsedive 未收录按 `not_found` 处理，不再误报为查询失败；本地配置 Pulsedive / Hybrid Analysis Key
- 修复 URLhaus 401、VT/Hybrid 错误状态映射、VT IP 总引擎数显示
### who.sh（Linux 采集）
- `#!/bin/bash` → `#!/bin/sh`，23 处 `function` 改为 POSIX `name()`
- 新增 `_match()` / `echoe()`，替换 `[[ ]]` 与 `echo -e`，兼容 dash / busybox / bash
- `set -o pipefail` 增加保护，dash 下不再报错
- 输出目录 `/opt/ir_evidence` 优先，不可写时回退 `/tmp/ir_evidence`，并 `chmod 700`
- 命名恢复 `whoamicheck`，保持与旧取证包目录兼容

## ir-forensic-analysis v4.5.2 (2026-08-13)
**奇安信失陷检测情报接入（REST API）**
### 新增
- `threat_intel_lookup.py` 新增 `query_qianxin_compromise()`，调用 `https://ti.qianxin.com/api/v2/compromise` 查询 IP/域名/URL 的 APT/僵尸网络/C2/勒索关联情报
- 配置新增「奇安信失陷检测情报」源（默认关闭，Key 留空），支持 `TI_QIANXIN_API_KEY` 环境变量，IP/域名查询顺序中加入奇安信
- IP/域名情报 Markdown 表格新增「奇安信」列，展示命中数、攻击团伙与恶意家族
- `threat_intel.json.example` 与 `THREAT_INTEL_PROVIDERS.md` 同步补充奇安信 REST/MCP 接入说明
### 说明
- QTI-MCP 适合 DeepChat/Cherry Studio 等 MCP 客户端；skill 的自动分析优先使用 REST API，仅需一个 API Key

## ir-forensic-analysis v4.5.1 (2026-08-13)
**卡巴斯基 Token 自动续期 + VT Key 本地配置**
### 新增
- 新增 `scripts/kaspersky_token_manager.py`：Token 剩余不足 30 天时自动登录卡巴斯基账号重新生成，写回 `config/threat_intel.json`，查询链路无需手工维护
- `threat_intel_lookup.py` 查询卡巴斯基前自动调用 Token 管理器；卡巴斯基返回 404 时按“未收录”处理
- 本地 `config/threat_intel.json` 已配置 VirusTotal Key 与卡巴斯基账号/Token（仅本地，不入 GitHub）
- 修复两个脚本互相导入时重复包装 stdout 导致 “I/O operation on closed file” 的问题
### 文档
- `THREAT_INTEL_PROVIDERS.md` / `SCRIPTS_GUIDE.md` 补充自动续期说明与 `threat_intel.json.example` 占位字段

## ir-forensic-analysis v4.5.0 (2026-08-13)
**银狐 2026 情报更新 - 最新情报源与 IOC**
### 新增
- 新增 `references/SILVER_FOX_2026_INTEL.md`：汇总 CVERC/CNCERT/奇安信/Cato/瑞星/Foresiet/ThreatFox/MalwareBazaar 等 2026 年银狐情报源、时间线与更新节奏
- `silver_fox_rules.json` 从 34 条扩展至 43 条：新增 CVERC 人事钓鱼、CNCERT SEO 仿冒、Zinst 系列、日本 ValleyRAT 三驱动 BYOVD、瑞星 DoH 变种、海外税务钓鱼及 2026 新增域名/IP/哈希库（SFOX-0027~0035）
- `ioc_library.json` 并入【腾讯文档】开源恶意域名情报库最新域名 1390 个（去重后新增 1352 个），累计域名 1918 个、IP 414 个、哈希 45 个、释放路径 207 个
- SKILL.md / 使用说明.md / DETECTION_RULES.md 同步更新银狐规则数与 2026 变种速览
### 注意
- 腾讯文档情报库为社区共享 OSINT，命中后建议结合微步/奇安信/ThreatFox 等厂商情报交叉验证，避免误报

## ir-forensic-analysis v4.4.0 (2026-08-13)
**威胁情报多源扩展 - 全球平台对比分析**
### 新增
- `threat_intel_lookup.py` 新增 ThreatFox、MalwareBazaar（需免费 Auth-Key）、Pulsedive、Kaspersky OpenTIP、GreyNoise、Hybrid Analysis、URLScan.io 查询函数，支持 IP/域名/Hash 多源对比
- 新增 `ip_query_order`、`domain_query_order`、`hash_query_order` 配置，按 IOC 类型分别控制查询顺序
- 新增域名情报 Markdown 表格，补齐原先只展示 IP/Hash 的缺口
- 报告新增“情报交叉分析说明”，自动列出本次参与比对的平台、覆盖类型、是否需要 Key 及本次状态
- 国内厂商企业 API（奇安信、启明星辰、绿盟、360、腾讯、安恒、深信服、安天）配置后自动接入，不再提供人工复核入口
- 新增环境变量 Key 配置，`TI_*` 环境变量可覆盖配置文件中的 Key，配置文件不再存放任何明文 Key
- 命令行支持 `--ip`、`--domain`、`--hash`、`--raw` 单点查询
### 文档
- 新增 `references/THREAT_INTEL_PROVIDERS.md`，包含全球平台清单、配置步骤、新增平台方法
- `references/SCRIPTS_GUIDE.md` 补充 `threat_intel_lookup.py` 说明
### 注意
- 发布到 GitHub 的版本必须保持 `config/threat_intel.json` 无真实 Key，统一使用 `YOUR_*_KEY_HERE` 或环境变量占位
## v5.3.3 (2026-08-12)
**修复“不能对 Null 值表达式调用方法”弹窗与采集卡死**
### 修复
- 主脚本增加全局 `trap` 兜底：主流程 try 之外（提权、初始化等阶段）发生致命错误时，也会弹出带具体行号的错误提示，并写入 `C:\IR\fatal.log`，不再只显示一句“不能对 Null 值表达式调用方法”
- GUI 点击“开始采集”增加整体 try/catch，定向目标输入改为空值安全写法，出错时提示具体行号，避免无行号裸报错
- 定向采集 `Invoke-TargetedCollection` 的 `$TargetName.Trim()` 改为空值安全写法，避免 `-Target` 传空时触发 Null 方法调用
- 数字签名采集中对 `VersionInfo` 增加空值判断，避免个别进程文件无法读取版本信息时中断
- 定向规则查找增加 `%TEMP%` 兜底路径，修复 exe 运行时内嵌 `tailscale.json` 从临时目录解压后找不到规则的问题
- `net view /all` 改用带 20 秒超时的 `IR-Run-Timed`，避免现场网络枚举长时间挂起导致采集停滞
- 脚本与 GUI 版本号统一更新为 v5.3.3，同步重新编译 GUI exe

## v5.3.2 (2026-08-12)
**GUI 启动器排版再优化 - 扩大窗口与行距**
### 修复
- GUI 窗口从 860x860 放大到 1000x920，支持更大范围调整，内容区不足时自动滚动
- 分区、选项、说明之间的间距整体加大，字号和按钮高度同步提升，避免文字视觉拥挤
- 精简选项说明文案，保留适用场景关键信息，减少一次性堆叠的长文本
- 重新编译 IR_Collect_v5.3_GUI.exe，内嵌采集脚本与 tailscale 定向规则保持一致
- 界面版本号更新为 v5.3.2，避免与旧版混淆

## v5.3.1 (2026-08-12)
**GUI 启动器排版重构 — 解决高分屏下文字挤压**
### 修复
- GUI 界面改为自动布局：采集模式、可选采集项、定向采集分区展示，选项与适用范围说明分组对齐，不再使用固定坐标堆叠
- 窗口加大并支持调整大小，内容区超出时自动滚动；高分屏（125%/150% DPI）下字体和控件随系统缩放，不再相互挤压
- 修正 Windows PowerShell 5.1 将中文弯引号“ ”当作字符串边界解析、导致界面文字错乱的问题
- 每个采集项补充清晰的适用场景说明，底部操作按钮固定显示
### 变更
- GUI 源码 IR_Collect_GUI_v5.3.ps1 与 IR_Collect_v5.3_GUI.exe 已同步更新，内嵌 v5.3 采集脚本与 tailscale 定向规则不变

## v5.3.0 (2026-08-12)
**深度取证增强版 — IR_Collect_v5.3.ps1（v5.1/v5.2 保持稳定版不变）**
### 新增
- **独立脚本 IR_Collect_v5.3.ps1**：以 v5.2 为基座，默认快速快照行为与 v5.2 一致，新增 `-DeepForensic` 深度取证模式
- **GUI 图形化启动器 IR_Collect_v5.3_GUI.exe**：双击弹出中文选项界面，可选常规/深度取证、敏感数据、跳过文件扫描、系统目录、扫描深度与定向目标；自动请求管理员权限并调用内嵌 v5.3 脚本
- **深度取证参数**：`-DeepForensic`（离线痕迹+扩展日志+浏览器深库）、`-IncludeSensitive`（SAM/SYSTEM/SECURITY/SOFTWARE hive 与浏览器凭据库，默认关闭）、`-SkipFileScan`（跳过耗时文件扫描）、`-IncludeSystemDirs`（追加 Windows\Temp/ProgramData/Program Files 扫描）、`-ScanDepth N`（1-8，默认 5）
- **离线痕迹 `0_offline/`**：Amcache.hve、Shimcache/BAM/DAM/SRUM/MountedDevices 注册表导出、ShellBags/UserAssist/RecentDocs（按用户 SID）、跳转列表、Prefetch 原始文件、SRUDB.dat、LSASS 转储指引（不自动转储）
- **扩展日志 `6_logs/extended/`**：TaskScheduler、WMI-Activity、AppLocker、Defender、TerminalServices-RemoteConnectionManager、OpenSSH、CodeIntegrity、Sysmon 等通道
- **浏览器深库 `browser_artifacts/deep/`**：Chrome/Edge/Opera/Brave/360/QQ 等 Downloads/Bookmarks/Top Sites/Favicons，Firefox cookies/permissions/formhistory；`-IncludeSensitive` 时含 Login Data/Cookies/logins.json/key4.db
- **失败占位文件**：事件日志导出失败写入 `.FAILED.txt` 并在 `collection.log` 记录原因；浏览器数据库复制失败标记 `[SKIP] locked`，避免静默丢失
### 变更
- GUI 启动器界面重排：窗口加大，采集模式/可选采集项/定向采集分区展示，并补充每个选项的适用范围说明
- 完整性校验改为压缩包 SHA256 + `IR_metadata.txt` + `file_manifest.csv` + `collection_manifest.json`，不再逐文件生成旧版哈希链
- 超过 1GB 的事件日志通道仅导出最近 7 天，避免压缩包过大
- 进度窗口标题、元数据与模块清单版本号更新为 v5.3
### 文档
- SKILL.md 增加 v5.3 深度取证分析指引、完整性校验差异与取证包目录说明
- 使用说明.md / README.md 增加 v5.3 选型表、参数说明、深度输出目录与版本历史
## mac_collect.sh v2.1.0 (2026-08-11)
**macOS 采集脚本优化版**
### 新增
- **系统采集增强**：sudoers、at 任务、Keychain 列表、Wi-Fi 已知网络、MDM profiles、模块清单 `manifest.txt`、包哈希旁车 `*.tar.gz.sha256`
- **浏览器兼容**：Safari 自动适配 `history_item_id` / `history_item` 两种 schema
### 修复
- **进程签名验证死代码**：移除 `/proc` 逻辑，改用 `ps` + `lsof` + `codesign`
- **隐藏用户误报**：排除 `_` 开头系统账号、系统白名单、UID<500；通过 ShadowHashData 第二列计数判断空密码
- **SUID/SGID 命令**：修正 `find -perm` 语法并排除系统路径
- **循环变量提前展开**：Cron/Safari/浏览器历史等 `run_sys` 内循环变量改为 eval 时展开，避免路径为空导致采集失效
- **IPv6 外联提取**：兼容 `[IPv6]:port` 并去除残留方括号
- **set -e 中断风险**：进程签名查询、IP 提取等失败不再中断采集
### 变更
- 哈希链改为只保留关键清单摘要，现场取证以打包 SHA256 为准，避免逐文件哈希拖慢采集
- `run_sys` 失败时输出 `[STDERR/Failed]` 并写入 manifest，错误可见
## v5.2.0 (2026-08-11)
**定向采集增强版 — IR_Collect_v5.2.ps1（v5.1 保持稳定版不变）**
### 新增
- **独立脚本 IR_Collect_v5.2.ps1**：以 v5.1 为基座新增 `-Target <名称>` 参数，实现按需定向采集，v5.1 保持稳定版不动
- **定向采集规则**：新增 `config/targets/*.json` 规则目录，规则文件名与目标名一致（如 `tailscale.json`），支持进程名/服务名/注册表键/搜索根目录/深度/数量上限配置
- **示例规则**：附带 `config/targets/tailscale.json`，覆盖 Tailscale 进程、服务、注册表、安装目录
- **通用兜底采集**：未提供规则文件时，按目标关键词自动扫描进程、服务、已安装软件与文件
- **敏感文件哈希保护**：`*.state/*.key/*.pem/*.pfx/*.conf/*.config/*.json/*.db/*.sqlite*/*.log/*.bak` 仅记录 SHA256/元数据，不复制原始内容；仅 exe/dll/sys/msi/bat/cmd/ps1/vbs/js/jar/py 复制到 `9_extra/<目标名>/files/`
- **输出目录**：定向采集结果统一写入压缩包 `9_extra/<目标名>/`，含 processes.csv / services.csv / installed.csv / registry_*.txt / files.csv / summary.txt
### 变更
- 进度窗口标题、元数据与模块清单版本号更新为 v5.2
- 主流程第 8.6 阶段调用定向采集，仅当传入 `-Target` 时执行，不影响默认采集流程
### 文档
- 补充 `IR_Collect_v5.1.ps1` / `IR_Collect_v5.2.ps1` 选型说明、真实用法与场景对照
- 修正文档中不存在的 `-Quiet` / `-SkipEventLog` / `-OutputDir` 参数示例
## v5.1.1 (2026-08-11)
### 修复
- **采集完成弹窗误报**：修复完成后弹出“找不到参数‘and’（行998）”的问题。原因为 `Test-Path $ZIP -and ...` 中 `-and` 被 PowerShell 当作 `Test-Path` 的参数名；现改为先 `Get-Item` 判断压缩包存在且非空，再决定是否清理临时目录
- **v5.0 同步修复**：v5.0 中存在相同的清理判断问题，一并修复

## v5.1.0 (2026-08-11)
**v4.3 与 v5.0 合并版 — 账号多源检测补齐 + 中文界面**
### 新增
- **采集脚本 IR_Collect_v5.1**：以 v5.0 为基础，合并 v4.3 的账号取证增强
- **WMI 账号枚举**：新增 `wmi_users.csv`，通过 CIM/WMI 枚举 Win32_UserAccount，可绕过 NetUserEnum API hook
- **ProfileList 注册表用户枚举**：新增 `profilelist_users.csv`，读取 HKLM ProfileList，覆盖所有登录过的用户目录
- **多源账号交叉比对**：新增 `hidden_account_crosscheck.txt`，对比 net user / WMI / ProfileList 三方数据，标记 "net独有 / WMI独有 / Profile独有" 异常
- **中文勒索信关键词**：勒索信检测补充 `勒索/解密/赎金` 关键词，覆盖中文勒索团伙
- **错误弹窗**：顶层异常现在会弹出中文错误框，同时写入 collection.log
### 变更
- 克隆账号检测（SAM F 键值）提示信息中文化
- 进度窗口与全部进度提示保持中文（继承 v5.0 修复）
- 保留 v5.0 增强：带时间戳日志与自动 Flush、签名缓存含 LastWriteTime、RWX 后台 Job + 60 秒超时、ZipFile 压缩与临时目录安全清理
- 脚本版本号：v5.0 → v5.1

## v4.3.0 (2026-07-23)
**威胁情报深度集成 — VirusTotal/CVERC/AbuseIPDB 多源查询 + 文件 Hash 情报关联**
### 新增
- **威胁情报多源扩展**：在原有的微步在线基础上，新增 VirusTotal、CVERC 国家计算机病毒协同分析平台、AbuseIPDB 三个情报源
- **配置文件更新**：config/threat_intel.json 新增 VT/CVERC/AbuseIPDB 三个源配置（Key 为空时自动跳过，用户自行填写启用）
- **脚本升级**：scripts/threat_intel_lookup.py 升级至 v2.0，支持：
  - 微步：IP/域名/Hash 查询（原有）
  - **VirusTotal**：Hash + IP 多维查询，134字节=未收录检测
  - **CVERC**：Hash 查国家平台
  - **AbuseIPDB**：IP 信誉评分（0-100）
  - **IPinfo.io**：免费 IP 归属地补充（无需 Key）
  - 多源自动降级：主源失败→备用源
- **预处理阶段增强**：数据预处理增加"文件 Hash 威胁情报查询"步骤，将可疑文件 SHA256 自动关联情报
- **SKILL.md 增强**：
  - ③ 威胁情报增强章节全面重写：新增 VT/CVERC/AbuseIPDB 数据源说明、多源查询优先级和自动降级流程
  - 查询范围扩展：从仅 IP 查询扩展为 IP/Hash/域名三类
  - 覆盖率检查表中增加 Hash 查询统计项
  - IOC 摘要格式中增加 VT 检测率展示
  - scripts 引用列表新增 	hreat_intel_lookup.py
### 使用方式
- 已有微步 Key 自动生效，无需额外配置
- VT/CVERC/AbuseIPDB 的 Key 留空时自动跳过该源，不影响主流程
- 配置 Key 的方式：编辑 config/threat_intel.json，填入对应源的 pi_key 字段
- 测试命令：python scripts/threat_intel_lookup.py

## v4.2.0 (2026-07-06)

**打包器与载荷识别 — PyInstaller/PyArmor/UPX 检测 + 延迟网络重采 + Cancel 按钮**

### 新增

- **采集脚本 IR_Collect_v4.2**：从 v31_extracted.ps1 改版，支持更多取证场景
- **Cancel 按钮**：进度窗口增加红色"取消(Cancel)"按钮，点击后安全中止采集，清理临时目录
- **打包器检测（第10维）**：检测 PyInstaller/PyArmor/UPX/Enigma 打包进程，输出 `process_packer_detect.csv`：
  - 扫描 %TEMP%\_MEI* 目录（PyInstaller 自解压特征）
  - 检查所有进程模块是否加载 pyarmor_runtime.pyd / python3*.dll / UPX 库
  - 标记每进程的打包器类型（PyInstaller/PyArmor/PythonEmbed/UPX）
- **TEMP 自解压目录快照**：采集前后两次记录 %TEMP%\_MEI* 目录状态，输出 	emp_mei_before.csv / 	emp_mei_after.csv，自动对比差异
- **延迟网络二次采样**：采集结束后 30 秒再次运行 

etstat -ano / 


etstat -anob，输出 

etstat_ano_delayed.txt / 

etstat_new_connections.txt，对比检测延时触发的 C2 外连
- **SKILL.md 新增"新增分析能力（v4.2）"章节**，含打包器检测和延迟采样的完整分析指引

### 变更

- 采集脚本版本号：v4.0 → v4.2
- SKILL.md 检测维度：第10维改为"打包器/代码保护/多阶段载荷"，原第10维（供应链/勒索）顺延至第11维
- 快速评估流程：新增 `process_packer_detect.csv`、TEMP 快照对比、延迟网络采样的读取步骤
- 调查结论顺序：进程 → 持久化 → 账号 → 网络 → Webshell → 注入 → 横向 → 高级对抗 → **打包器/载荷** → 供应链/勒索

### 采集脚本文件变更

| 文件 | 说明 |
|------|------|
| ssets/IR_Collect_v31_extracted.ps1 → IR_Collect_v4.2.ps1 | 原 v31 源码升级至 v4.2（需手动覆盖） |
| SKILL.md | 新增打包器检测指导章节 |
| ssets/BUILD_GUIDE.md | 更新 v4.2 编译说明 |

### 分析能力（第10维）

| 指标 | 检测方式 | 说明 |
|------|----------|------|
| PyInstaller 窗口 | 进程窗口标题含 "PyInstaller" | 单文件打包，运行时自解压 |
| TEMP_MEI 目录 | %TEMP%\_MEI* 采集前后对比 | PyInstaller 解压目录 |
| PyArmor 运行时 | 进程加载 pyarmor_runtime.pyd / pytransform*.pyd | Python 代码加密保护层 |
| Python 嵌入 | 进程加载 python3*.dll + 无签名 | Python 解释器嵌入可疑进程 |
| 多阶段加载 | 进程树中无名子进程 + 打包器标记 | 第一层只是加载器 |
| 隐藏窗口 | 窗口标题含 "Onefile Hidden" | 攻击者意图隐藏 |

---
## v3.6.0 (2026-06-01)

**威胁情报自动关联 — 微步在线 API 集成 + threat_intel_lookup 模块**

### 新增
- **银狐规则大规模更新**：新增 SFOX-0021~SFOX-0026 共6条规则，基于开源恶意域名情报库（腾讯文档 7885行数据），包含5265个仿冒域名、393个恶意IP、1854条释放路径、16个样本哈希
- **silver_fox_rules.json 从20条扩展至34条**（含 IOC 域名库/哈希库/释放路径库）
- **ioc_library.json 大规模更新**：从手动维护改为导入开源情报库数据（季度违纪名单/裁员名单/补偿方案）、SFOX-0022 传播渠道（QQ/微信/飞书/钉钉工作群）、SFOX-0023 攻击目标画像（人事/财务人员），基于2026年5月国家计算机病毒应急处理中心预警
- **威胁情报自动查询**：`scripts/threat_intel_lookup.py` — 分析完成后自动提取 IOC，调微步在线 API 查 IP/域名信誉
- **analyze_forensics.py 集成**：生成报告前自动调用威胁情报模块，结果追加到报告的"威胁情报关联分析"章节
- **ThreatMCP MCP Server 支持**：已注册 `threatbook` MCP Server（15个工具），可手动查 `ip_reputation`/`domain_analysis` 等
- **config/threat_intel.json**：微步 API Key 已配置，开箱即用

### 使用流程

```
9 维分析完成
    ↓
提取 IOC（IP/域名/Hash）
    ↓
调微步在线 API 查信誉 ✓
    ↓
报告追加威胁情报关联结果
```

---

## v3.5.0 (2026-05-24)

**内存注入分析增强 — RWX 误报过滤 + 规则扩展至16条 + DETECTION_RULES 重写**

### 新增
- **内存注入规则扩展 6 条**（INJ-0011~0016）：
  - INJ-0011: 浏览器 JIT 误报过滤（chrome/msedge/firefox，<1MB MEM_PRIVATE 降级为 info）
  - INJ-0012: 合法远控软件 RWX 标注（向日葵/TeamViewer/AnyDesk，降级为 low）
  - INJ-0013: 大块无模块 RWX 检测（>10MB MEM_PRIVATE 升 high）
  - INJ-0014: PowerShell CLR 运行时 RWX 标注（标记为低风险运行时行为）
  - INJ-0015: Electron 框架 JIT 误报过滤（Codex/WeChat/QQ 等，降级为 info）
  - INJ-0016: 系统服务无模块 RWX 检测（cameraservice 等非浏览器 RWX 升 high）
- **DETECTION_RULES.md 新增"内存注入检测"综合章节**：RWX 误报分层过滤策略（浏览器 JIT → Electron → .NET CLR → 合法远控 → 系统服务）、Cobalt Strike / Brute Ratel / Sliver / Nighthawk 内存特征、远程线程/APC注入/反射式DLL/进程空心化检测特征
- **RWX 分析标准化四步法**：分组统计 → 可疑筛选 → 交叉验证 → 输出
- **IR_Collect 工具升级**：从 IR_Collect_v31.exe 提取源脚本重编译为 v4，版本号统一，GUI 进度条 + 完成弹窗 + RWX 扫描 + 自提权
- **assets/IR_Collect_v31_extracted.ps1**：v31 EXE 提取的原始 PS1 源码，供审计和二次开发

### 修复
- 浏览器 JIT 大量 RWX 误报（chrome/msedge 各 40+ 条 RWX 区域，INJ-0011 自动过滤）
- 远控软件 AweSun 106MB+ RWX 误报（INJ-0012 自动标注为合法远控，提醒人工确认）
- 采集脚本报错：修复 Invoke-CommandSafe 中 $null 判断逻辑，修复 wevtutil 变量作用域

### 优化
- injection_rules.json: 10 条 → 16 条规则（+60% 检测覆盖）
- DETECTION_RULES.md: 30,837 bytes → 34,297 bytes（+11% 内容）
- RWX 报告输出格式：按进程分组、三级分类（正常/可疑/恶意）、详细误报标注

### 文件变更
- rules/injection_rules.json — 10→16 条规则
- references/DETECTION_RULES.md — 新增内存注入检测综合章节
- assets/IR_Collect_v4.exe — 从 v31 提取重编译，版本号统一
- assets/IR_Collect_v31_extracted.ps1 — 新增 v31 源码存档

## v3.4.0 (2026-05-23)

**win_collect 取证脚本 v4.0 — 完全离线重写 + 结构修复 + 全版本兼容**

### 新增功能
- 🆕 **完全离线运行**: 移除所有网络依赖，IOC 关键词 Base64 编码存储，运行时解码
- 🆕 **GUI 进度条**: Windows Forms 实时进度窗口，采集进度一目了然
- 🆕 **完成弹窗**: 采集完成后弹出 GUI 窗口，含打开目录和退出按钮
- 🆕 **哈希链完整性**: 对采集目录每个文件计算 SHA256 → 排序拼接 → 顶层完整性哈希
- 🆕 **IOC 扫描**: 离线恶意进程/LOLBin/WebShell 特征匹配（Base64 编码防杀）
- 🆕 **macOS 采集脚本**: mac_collect.sh，兼容 macOS 10.15+，功能对标 Windows 版

### 修复
- 🐛 **PS2EXE 编译崩溃**: 完成弹窗代码嵌入 catch 块导致错误 → 重构控制流为单层 try-catch
- 🐛 **UTF-8 编码**: 从 UTF-8 with BOM 改为 UTF-8 without BOM，解决 PS2EXE 解析问题
- 🐛 **嵌套 try/catch**: 移除完成弹窗中的嵌套 try/catch

### 优化
- 脚本精简: 从 428 行/48KB 精简至 465 行/22KB（格式优化后）
- 全版本兼容: 通过 Get-WmiCompat 兼容 PS 2.0 (Windows 7+)
- 自动提权: 非管理员自动请求提权
- 命令行参数: 新增 -Quiet / -SkipEventLog / -SkipYara / -OutputDir
- IOC 防查杀: 所有 IOC 关键词 Base64 编码，运行时解码

### 文件变更
- win_collect.ps1 — v4.0 重写（修复结构 + 格式化对齐 v3.1 风格）
- IR_Collect_v4.0.exe — PS2EXE 编译版（noConsole）
- mac_collect.sh — 新增 macOS 采集脚本
- BUILD_GUIDE.md — 更新打包与使用指南
- 对比说明.md — 新增新旧版本对比说明


## v3.3.0 (2026-05-23)

**应急响应流程管理 — 事件分级、响应角色、可操作剧本、同步工作表**

### 新增功能
- ✅ **主机严重等级定义**：P0-P3 四级（含响应时限和资源分配）
- ✅ **离线事件分类**：6 种事件类型（勒索/APT/钓鱼/Webshell/数据泄露/DDoS）
- ✅ **响应角色定义**：IC/SME/CISO 等角色职责和汇报路径
- ✅ **可操作剧本（Playbook）**：P0-P3 四级应急剧本，含具体操作步骤
- ✅ **处置同步表**：各阶段动作/责任人/完成状态追踪

### 修复
- 🐛 **SKILL.md 文件被 dedup_skill.py 截断**：从 800+ 行被错误缩减至 333 行，已通过 restore_skill.py 恢复至 810 行
- 🐛 **JSON schema 版本未升级**：report_template.md 引用 schema v1，实际当前为 v2（含 `has_ransomware`/`ransomware_family` 等字段）

### 优化
- SKILL.md 威胁评分表后新增「应急响应流程管理」章节（约 95 行）
- 分析流程与响应流程联动：发现 Critical → 自动映射到 P0 剧本

### 文件变更
- `SKILL.md` — 新增 IR 流程管理章节
- `a assets/report_template.md` — 需要升级 schema v1 → v2（待完成）


## v3.2.0 (2026-05-22)

**数据预处理增强 — 保持 9 维框架不变，优化分析输入质量**

### 新增功能
- ✅ **事件归一化层**：分析前先将散落的进程/网络/文件/注册表事件统一为 `timeline.jsonl` 事件流，各维度优先引用而非逐行读原始文件
- ✅ **Sigma 规则匹配**：8 条内建 Sigma 模式（DownloadString、Squiblydoo、HTA、certutil 等），在 timeline 中标记 `sigma_hit` 字段
- ✅ **威胁情报集成指南**：支持微步在线 API + IPinfo.io + 微步手动查询，维度4(网络外联)自动查询外联 IP 归属地/ASN
- ✅ **实体关联图**：跨维度构建进程←→网络←→文件关联关系，辅助因果链推理
- ✅ **IOC 表格增强**：新增"推理依据"和"来源文件"列，每条 IOC 附带判断依据
- ✅ **覆盖率声明增强**：新增预处理检查清单（timeline/Sigma/威胁情报/实体图）和数据源覆盖表

### 未改动
- 9 大检测维度结构 ✓
- 分析检查清单 ✓
- 威胁评分系统 ✓
- 规则文件 ✓
- 报告输出骨架 ✓

---

## v3.1.1 (2026-05-21)

**规则库增强 — 进程父子关系异常检测 + 银狐父进程异常规则**

### 新增规则
- ✅ **PROC-0012** `parent_process_anomaly`：系统进程父进程异常检测。svchost.exe/rundll32.exe 等系统进程的父进程不是 services.exe 时告警（测试包②的漏检修复）
- ✅ **PROC-0013** `signature_gap_in_tree`：进程树签名链断裂检测。无签名父进程衍生有签名子进程执行可疑命令（白加黑模式）
- ✅ **SFOX-0020** `silver_fox_parent_anomaly`：银狐注入系统进程的父进程异常。父进程名匹配钓鱼特征（税务稽查/违纪名单/发票等）时告警

### 优化
- SKILL.md 维度1 检查清单新增 **1.11 进程父子关系异常** 检查项
- 进程树分析规则：要求遍历 process_tree.csv 检查父子关系 + 签名链

---

## v3.1.0 (2026-05-19)

**win_collect 取证脚本 v3.1.0 — 安全修复 + 勒索专项增强 + 用户体验升级**

### 安全修复
- 🔒 `Invoke-Expression` → `cmd /c` 安全执行，消除 shell 注入风险
- 🔒 SSL 证书验证可配置化（`global.verify_ssl`）
- 🔒 外部命令执行从 `create_subprocess_shell` 改为 `create_subprocess_exec`（防注入）

### 新增：勒索专项增强
- ✅ **24 类勒索家族扩展名扫描**：Phobos/mallox/Hunters/LockBit/Devil/Quantum 等
- ✅ **勒索信中英文搜索**：12 种文件名模式（README/DECRYPT/HOW_TO/勒索/解密/赎金）
- ✅ **回收站深度提取**：`$Recycle.Bin` 内容遍历
- ✅ **完整 VSS 输出**：shadows/writers/providers/volumes 全量保存
- ✅ **VSS 数量统计**：正则提取 `shadow copy ID` 计数

### 新增：横向移动检测
- ✅ `net view /all` — 网络邻居扫描检测
- ✅ `net share` — 共享目录枚举
- ✅ `net use / net session` 已在 v3.0.3 实现，保留

### 新增：进程深度分析
- ✅ **进程数字签名验证**：Authenticode 签名状态 + 签章人/CN + 时间戳服务器
- ✅ **FileVersion 字段**：每条签名记录附文件版本号，快速定位非官方版本
- ✅ **进程名仿冒检测**（增强）：Levenshtein 距离判断 + 已知恶意名库 + 临时目录执行检测
- ✅ **进程树关联分析**：将不在签名列表中的进程提纯告警，减少噪音

### 新增：系统信息增强
- ✅ **环境变量收集**：`Get-ChildItem Env:` → `environment.csv`
- ✅ **Prefetch 计数日志**：快速判断执行痕迹量级
- ✅ **SHA256 文件哈希列表**：所有采集文件的哈希校验

### 新增：完成弹窗 🔥
- ✅ 黑底 (`#1e1e1e`) + 绿字标题 (`#64ff64`)
- ✅ ZIP 路径 / 大小 / SHA256（自动计算截取前 32 位）
- ✅ ZIP 内部文件数（`[ZipFile]::OpenRead` 解析）
- ✅ 数字签名统计（有效 / 无签名）
- ✅ 异常进程数
- ✅ **「打开目录」按钮** → `explorer /select` 定位到文件
- ✅ **「退出」按钮** → 关闭窗口

### 修复
- 🐛 `Get-Date 'yyyy-MM-dd HH:mm:ss'` → `Get-Date -Format 'yyyy-MM-dd HH:mm:ss'`（PS2EXE 参数绑定）
- 🐛 `$null / 1MB` → 加 `if($totalBytes)` 保护，防止 `-f` 格式化空白
- 🐛 `$zipHash.Substring(0,32)` → 加长度判断防止越界
- 🐛 元脚本双层结构 → 简化为独立脚本，消除维护混淆

### 架构简化
- 🗑️ 移除 `$finalScript` 元脚本模式，脚本即本身
- 🗑️ 移除 `Start-Sleep 300ms` 无意义延迟
- 🗑️ 移除未使用的 `$isAdmin` 变量

---

## v3.0.0-switch-1 (2026-05-15)

**版本切换** — 替换为勒索病毒深度分析分支

### 版本切换说明
本版本将之前的「多场景交互版」(v3.0.0, 场景B/C/D: 实时终端/EDR/SIEM) 替换为「静态取证深度分析版」(v3.0.0, 9大检测维度/勒索专项)，前者已备份至 `ir-forensic-analysis_backup/`。

### 移除（相对于上一版本）
- ❌ Scenario B: 实时终端排查（SSH/跳板机场景）
- ❌ Scenario C: EDR 平台查询（青藤/CrowdStrike/SentinelOne/天擎/微步）
- ❌ Scenario D: SIEM 日志关联分析（日志易/Splunk/ELK/NGSOC）
- ❌ `references/LIVE_RESPONSE.md`（实时排查指南）
- ❌ `references/EDR_GUIDE.md`（EDR平台指南）
- ❌ `references/SIEM_GUIDE.md`（SIEM日志分析指南）

### 新增（相对于上一版本）
- ✅ 检测维度从 8 维扩展为 **9 维**（第9维：供应链/勒索专项）
- ✅ `rules/ransomware_family_rules.json`：8个勒索家族（Phobos/Hunters International/mallox/BEAST/MedusaLocker/babyk/.sorry/Hive）
- ✅ `rules/startup_rules.json`：启动项检测规则
- ✅ `rules/yara_rules/ransomware.yar` + `esxi_ransomware.yar`：勒索病毒 YARA 规则
- ✅ `references/ATTACK_CHAIN_REASONING.md`：攻击路径复盘与因果链推理框架
- ✅ `references/REPORT_CONTRACT.md`：JSON 报告契约 v2（含勒索/供应链字段）
- ✅ `references/RULES_FORMAT.md`：规则库格式说明
- ✅ `references/SCRIPTS_GUIDE.md`：脚本使用指南
- ✅ NAS 设备安全检测（Synology/QNAP/Asustor/TerraMaster/WD）
- ✅ AI 驱动攻击检测（极速扫描/AI钓鱼/LLM辅助Webshell）
- ✅ ESXi 虚拟化勒索专项检测
- ✅ 分析自校验清单（9维 64 个检查项）
- ✅ 配置风险独立维度（P0-P3优先级）

### 合并指南
如需同时保留多场景交互能力，可从备份 `ir-forensic-analysis_backup/` 中复制以下文件到当前目录：
- `references/LIVE_RESPONSE.md`
- `references/EDR_GUIDE.md`
- `references/SIEM_GUIDE.md`

然后在 SKILL.md 开头场景识别章节，将多场景架构与当前 9 维检测框架整合。

---

## v3.0.0 (2026-05-14)

**重大升级** — 借鉴 Solar 应急响应团队实战知识体系，从8大检测维度扩展为9大检测维度，新增勒索家族分类检测、供应链入侵排查和因果链攻击路径复盘方法论。

### 新增：勒索病毒家族分类检测（维度9核心）
- 新增 `rules/ransomware_family_rules.json`：8个勒索家族（Phobos/Hunters International/mallox/BEAST/MedusaLocker/babyk/.sorry/Hive）
- 每个家族包含：勒索信格式、加密扩展名、加密算法、入侵方式、IOC特征、横向指标、MITRE ATT&CK映射
- 新增 `rules/yara_rules/ransomware.yar`：5条YARA规则（Phobos/mallox/MedusaLocker/通用勒索行为）
- 新增 `rules/yara_rules/esxi_ransomware.yar`：3条YARA规则（BEAST ESXi/BEAST Windows/ESXi通用）
- 灵感来源：Solar 应急响应团队的勒索家族深度分析系列文章

### 新增：ESXi/虚拟化平台勒索专项
- DETECTION_RULES.md 新增 ESXi 勒索专项章节：7条ESXi特征 + 4条Linux版勒索特征
- 覆盖 VMFS卷异常IO、esxcli异常调用、ESXi SSH爆破、VM快照删除、vCenter API异常
- 灵感来源：Solar「BEAST勒索软件(Linux/ESXi版)加密机制与对抗策略」

### 新增：攻击路径复盘与因果链推理
- 新增 `references/ATTACK_CHAIN_REASONING.md`：完整的因果链推理框架
- 4级因果链等级：强因果(❱) / 弱因果(→) / 关联(➔) / 独立(●)
- 8条必须遵循的推理规则：时间窗口串联、父子关系优先、逆向溯源法、多攻击链分离、空白窗口标注、完整性评分、Dwell Time评估、第三方运维入口标注
- 勒索攻击链专用推理模式（5条Solar案例推理模式）
- 供应链入侵专用推理和检查清单
- 灵感来源：Solar 强调的「深度溯源+攻击路径复盘」方法论

### 新增：供应链/第三方运维入侵排查
- SKILL.md 新增第9检测维度：供应链/第三方运维
- 10个检查项：勒索信检测、家族匹配、卷影删除、ESXi指标、NAS设备、VPN/IPMI暴露、共享账号、第三方远程工具、供应链软件篡改、Dwell Time评估
- DETECTION_RULES.md 新增7条供应链检测规则（SC-0001到SC-0007）
- ip_rules.json 新增 IP-0007：第三方运维管理端口/IP段规则
- 网络外联维度新增4.6/4.7检查项：第三方VPN/IPMI检查、供应链关联IP检查
- 灵感来源：Solar「4月勒索态势月报：第三方运维盲区警示」

### 新增：NAS设备安全检测
- DETECTION_RULES.md 新增NAS设备安全检测章节
- 5条通用NAS检测规则 + 5个平台特定检测（Synology/QNAP/Asustor/TerraMaster/WD）
- 灵感来源：Solar「mallox勒索病毒NAS漏洞入侵24小时解密恢复」

### 新增：AI驱动攻击检测
- DETECTION_RULES.md 新增AI驱动攻击检测章节
- 5条检测规则：极速扫描、AI生成钓鱼、LLM辅助Webshell、自动化漏洞利用链、AI辅助社会工程
- 灵感来源：Solar 2026年多篇AI驱动攻击预警文章

### 改进：JSON报告契约 v1→v2
- Schema 版本从 `ir-forensic-analysis-report-v1` 升级为 `ir-forensic-analysis-report-v2`
- verdict 新增字段：`has_ransomware`、`ransomware_family`、`has_supply_chain_risk`、`dwell_time_hours`
- iocs 新增字段：`ransom_note_files`、`encrypted_extensions`
- timeline 新增字段：`cause`、`effect`、`chain_evidence`、`chain_score`
- findings dimension 枚举新增 `supply_chain`
- self_check 新增：`timeline_has_causal_chain`、`dwell_time_calculated`
- 校验规则更新：维度数从8→9，schema版本校验更新

### 改进：SKILL.md 核心更新
- 检测维度从8扩展为9（新增供应链/勒索维度）
- 威胁评分权重新增：勒索/ESXi勒索→权重4，供应链→权重3
- 分析流程步骤3增加因果链推理和勒索家族识别指令
- 推理逻辑从5条扩展为10条（新增因果链推理、逆向溯源、Dwell Time、第三方运维标注、勒索家族识别）
- 自校验清单从8项扩展为10项（新增因果链标注、Dwell Time、勒索家族识别、供应链评估）
- 检测规则速查索引新增5行（勒索病毒/ESXi/供应链/NAS/AI）
- 维度1新增1.8检查项（勒索/加密进程）
- 维度4新增4.6/4.7检查项（第三方VPN/IPMI、供应链关联IP）

### 改进：IOC库扩展
- ioc_library.json 新增 `ransomware_families`：8个家族的勒索信、扩展名、邮箱、入侵方式
- ioc_library.json 新增 `supply_chain`：远程工具、目标软件、可疑端口、NAS默认端口

### 版本号变更理由
新增2个独立检测维度（勒索家族分类 + 供应链/第三方运维），扩展3个子维度（ESXi/NAS/AI），JSON Schema v1→v2 不兼容升级，重写攻击时间线模型（因果链），扩充IOC库——6项功能级变更，符合 major version bump 标准。

---

## v2.6.0 (2026-05-13)

**工程化改造** — 借鉴 ir-suite-incident-response 的工程化优势，补齐 ir-forensic-analysis 的结构性短板：

### 新增：分析检查清单
- 每个维度定义必须检查项（✅）和可选检查项（⏭），防止 LLM 遗漏关键文件
- 8个维度共 56 个检查项，其中 40 个必检、16 个可选
- 覆盖 Windows + Linux 双平台文件映射
- 灵感来源：ir-suite 的 50 个 check 脚本，但以清单形式适配 LLM 工作模式

### 新增：JSON 报告契约
- 定义 `ir-forensic-analysis-report-v1` JSON Schema
- 包含 `meta`/`verdict`/`findings`/`iocs`/`timeline`/`coverage`/`self_check` 7个必填模块
- 10 条校验规则（fatal/error/warning 三级）
- 新增 `references/REPORT_CONTRACT.md` 详细文档
- 灵感来源：ir-suite 的 `validate_report_contract.py`，但用 Schema+LLM自检 替代脚本校验

### 新增：自校验机制
- 分析步骤从4步扩展为5步，新增「步骤5: 自校验」
- 8 项自校验清单，报告输出前必须全部通过
- 自校验结果写入 JSON 摘要的 `self_check` 字段
- 灵感来源：ir-suite 的 contract-check 端到端验证

### 新增：配置风险独立维度
- 报告模板新增「配置风险（非入侵但需处置）」章节
- JSON 契约新增 `config_risks` 字段（P0-P3优先级）
- 解决之前配置风险混在处置建议中不醒目的问题

### 改进：覆盖率追踪
- 分析检查清单中标记为 ⏭ 的文件自动进入 `coverage.skipped_files`
- 确保「未分析文件」有据可查，不是 LLM 忘了

### 未借鉴的部分（并说明原因）
- ❌ fixture 测试数据：LLM 无法执行回归测试，fixture 对 LLM 无意义。改用自校验清单保障
- ❌ hash manifest：LLM 不执行文件完整性校验，hash 对分析过程无用
- ❌ Python 分析脚本：我们的检测深度依赖 LLM 推理+规则库，正则浅匹配是退步
- ❌ run_manifest.tsv：LLM 分析是单次串行的，不需要步骤执行状态追踪

## v2.5.0 (2026-05-13)

- 拆分 SKILL.md：核心行为指导 + 规则速查索引（~280行），详细规则移入 references/DETECTION_RULES.md
- 新增 `references/DIRECTORY_MAPPING.md`：独立维护 Windows/Linux 取证包目录结构
- 新增 `CHANGELOG.md`：变更记录独立文件
- 报告模板增强：新增 IOC 摘要 + 分析覆盖率声明 + CSV 大文件读取策略
- 误报白名单机制：ip_rules.json / process_rules.json / persistence_rules.json 增加 `known_false_positives` 字段
- RULES_FORMAT.md 增加 `known_false_positives` 字段说明
- 补齐 Linux 检测维度：bashrc/profile 劫持、systemd 用户服务、内核模块持久化、apt/yum hook、XDG 自启动
- 银狐专项（第8维）与远控对抗（第9维）合并为「高级对抗检测」维度，用 `fox_tag` / `generic_rat_tag` 标签区分

## v2.4.0 (2026-05-09)

- 基于多源银狐威胁情报大幅扩展银狐专项检测规则（9→20条）
- 新增 SFOX-0010 ~ SFOX-0020 共11条规则（反沙箱、代码混淆、系统服务持久化、钓鱼诱饵、白加黑、Gh0st/winos远控、微信/QQ劫持、挖矿投递、多阶段加载器、滥用合法软件、进程再生）
- 扩展杀软进程列表（11→30+）
- YARA规则新增3条
- IOC库新增互斥体/样本HASH/C2 IP
- 总规则数：9→20银狐专项 + 73→84总规则

## v2.3.0 (2026-05-09)

- 基于微步《银狐3月攻击活动报告》新增银狐专项检测维度（第8维）和远控对抗检测维度（第9维）
- 新增 `silver_fox_rules.json`：9条银狐专项规则
- MITRE ATT&CK 映射新增：T1189 / T1562.001 扩展 / T1014 扩展 / T1571 扩展 / T1055.012 扩展
- 威胁评分新增银狐专项/远控对抗维度权重（4）

## v2.2.0 (2026-05-08)

- 新增 Linux 取证包目录结构映射（who.sh v8.0+）
- 新增 Windows v3.0+ 文件映射
- 检测规则大幅扩充（Logon Scripts / COM劫持 / 组策略脚本 / SUID / SSH软连接 / OpenSSH后门 / PAM后门 / 命令替换 / 盖茨木马 / 端口复用 / LD_PRELOAD）
- 新增勒索病毒/挖矿病毒检测维度
- MITRE ATT&CK 映射从28→48个技术ID

## v2.1.0 (2026-05-07)

- 补充 LLM 行为指导
- 修正使用方法：明确 LLM 直接读取分析，脚本为参考实现
- 补全 MITRE ATT&CK 映射（28个技术ID）
- 明确威胁评分计算公式
- 添加规则库 fallback 策略
- 添加编码处理指引（UTF-16转码）

## v2.0.0 (2026-05-07)

- 新增持久化/内存注入/横向移动检测维度
- 新增 MITRE ATT&CK 映射
- 新增时间线重建/IOC提取/YARA规则
- 优化威胁评分系统

## v1.0.0 (2026-04-15)

- 初始版本：5大检测维度

## v5.5.0（2026-11-13）

**新增第 12 维：浏览器取证（SQLite 解析）**

### 新增
- `scripts/analyze_browser.py`：解析 `browser_artifacts/` 下的 SQLite
  - Chromium 系（Chrome/Edge/Brave/Opera/360SE/QQBrowser/Chromium/Vivaldi）：`urls` / `visits` / `downloads` / `keyword_search_terms`
  - Firefox：`places.sqlite`（访问历史 + 书签）
  - 兼容被占用/损坏的库（自动复制到临时目录，带 `-wal` / `-shm`）
  - 时间戳换算：Chromium（1601 纪元微秒）/ Firefox（1970 纪元微秒）
- 输出 `browser_history.csv` / `browser_downloads.csv` / `browser_bookmarks.csv` /
  `browser_summary.json` / `browser_report.md`
- 下载风险分级：可执行/脚本 > 安装包/宏文档 > 压缩包；临时/公共目录、浏览器 `danger_type`、
  明文 HTTP 下载可执行文件会升级风险；命中 IOC 库域名直接标 critical
- `analyze_forensics.py` 增加维度 12「浏览器取证」：优先解析浏览器库，再检测
  IOC 命中 / 高危下载 / 历史为空，并计入 `report_summary.json` 的 findings

### 修复
- `actions` 字典缺少 `info` 键导致 `KeyError`（维度新增 info 级发现时触发）
- `dimensions_complete` 不再写死 11，改为按 `dim_map` 动态输出

### 实测（IR_DESKTOP-FJ8A0FE_20261113_144722）
- 4 个浏览器库（Chrome/Edge/Firefox×2），历史 4,725 条、下载 832 条（高风险 156）、书签 20
- 命中 1 条 IOC 域名（Firefox 历史），触发 critical 发现

## v5.6.0（2026-11-13）

**新增第 13 维：计划任务 / 注册表 / 书签解析**

### 新增
- `scripts/analyze_artifacts.py`
  - 计划任务 XML（`3_persistence/tasks_xml/*`，UTF-16、无扩展名）：解析 URI / Command / Arguments /
    UserId / 触发器，按"临时目录、编码执行、LOLBin 转发、脚本文件、通用解释器"分级
  - 注册表导出（`*.reg`）：解析 924+ 条键值，标记 Run/RunOnce、Services ImagePath、
    IFEO Debugger、Winlogon Shell/Userinit 的可疑指向
  - Chromium 书签（`browser_artifacts/**/Bookmarks`，JSON 无扩展名）
  - 输出 `scheduled_tasks.csv` / `registry_keys.csv` / `browser_bookmarks_extra.csv` /
    `artifacts_summary.json` / `artifacts_report.md`，写到取证目录下的 `_artifacts/`
- `analyze_forensics.py` 增加维度 13「计划任务/注册表/书签」，并自动在加载前完成解析

### 修复
- `f-string` 中的 `\{` 触发 SyntaxWarning

### 实测（IR_DESKTOP-FJ8A0FE_20261113_144722）
- 计划任务 26 个（medium 9 / low 17，无 high）
- 注册表 924 条（本包为 userassist/muicache/runmru，无 Run 键）
- 书签 180 条
- 13 个维度全部覆盖，评分 34（critical）

## v5.7.0（2026-11-13）

**补齐四类二进制取证产物：EVTX / Prefetch / JumpList / Amcache**

### 新增
- `scripts/analyze_evtx.py`：解析 `.evtx`（pyevtx-rs）
  - 关键事件：4624/4625/4688/4720/4732/7045/1102/4104/1116 等
  - 检测：失败登录集中、失败后成功登录（同 user+IP、1 小时窗口、≥5 次失败）、
    日志清除、可疑服务安装、创建账号、加入管理员组、可疑命令行、PowerShell 编码执行、Defender 告警
  - 兼容三种 EventData 形态（Data 列表 / Data 单对象 / 平铺键值）与
    `TimeCreated.#attributes.SystemTime`
- `scripts/analyze_prefetch.py`：MAM/XPRESS Huffman 解压（dissect.util）后解析
  - 可执行名、运行次数、最近 8 次运行时间、引用文件路径
  - 风险：临时/用户目录、脚本解释器拉起
- `scripts/analyze_jumplist.py`：OLE 复合文档（olefile）解析 DestList 与 LNK 流
  - 最近访问文件路径 605 条、可疑位置标记
- `scripts/analyze_amcache.py`：注册表 hive（regipy）解析 InventoryApplicationFile / File
  - 程序名、路径、SHA1、时间；可疑路径标记
- `analyze_forensics.py` 新增维度 14「Windows 事件日志」，并把 Prefetch/JumpList/Amcache
  汇总进维度 13「计划任务/注册表/书签」
- 重型解析可用 `IR_SKIP_HEAVY=1` 跳过

### 实测（IR_DESKTOP-FJ8A0FE_20261113_144722）
| 产物 | 数量 | 结果 |
|---|---|---|
| EVTX | 14 个文件 | 124,315 条记录，2,769 条关键事件，2 项检测 |
| Prefetch | 240 个 | 全部解压成功，45 个可疑 |
| JumpList | 147 个 | 605 条路径，158 条可疑位置 |
| Amcache | 1 个 hive | 14,306 条，14,061 条带 SHA1，181 条可疑 |
| 整体 | — | 14 维全覆盖，53 条发现，耗时 48s（原 18s） |

### 依赖
`pip install evtx regipy dissect.util olefile`（仅这四类解析需要，缺失时自动跳过）

## v5.8.0（2026-11-13）

**补齐浏览器站点缓存；Amcache 按真实结构重写**

### 新增
- `analyze_browser.py` 支持无扩展名的 SQLite 站点缓存：
  - `Favicons`（`icon_mapping.page_url`）：历史被清空时仍能还原访问过的站点
  - `Top Sites`（`top_sites`）：常访问站点与排序
  - 输出 `browser_sites.csv`，并写入 `browser_summary.json` 的 `site_cache_count`

### 修复 / 重构
- `analyze_amcache.py` 原来假设 `InventoryApplicationFile` 下有 Name/Path，实测该键只有
  `ProgramId`/`FileId`；改为按真实结构解析：
  - `InventoryApplication`：程序名、版本、发布者、安装时间、安装目录（310 条）
  - `InventoryApplicationFile`：FileId 作为 SHA1（14,306 条）
  - `InventoryDriverBinary`：驱动名、厂商、**是否签名**（497 条）→ 未签名驱动可直接作为
    BYOVD 线索
  - 输出增加 `kind`（application/file/driver）、`signed` 列

### 实测（IR_DESKTOP-FJ8A0FE_20261113_144722）
| 项目 | 结果 |
|---|---|
| 站点缓存 | 6 个库 → `browser_sites.csv` |
| Amcache | 程序 310 / 文件 14,306 / 驱动 497，可疑 25，未签名驱动 0 |
| 全量分析 | 14 维，53 条发现，冷跑 67s |

## v5.9.0（2026-11-13）

**整体收口：解析器注册表 + 统一产物目录 + 维度口径 + 冒烟测试**

### 新增
- `scripts/parsers_registry.py`：6 类派生解析（浏览器/计划任务/EVTX/Prefetch/JumpList/Amcache）
  统一注册，提供依赖检查、输入探测、按需执行、`--only` / `--force` / `--list`
- 统一产物目录：所有派生结果写到 `<取证目录>/_derived/<name>/`，并生成
  `_derived/manifest.json`（每个解析器的状态/耗时/摘要），不再往证据根目录散落 6 个目录
- 旧布局（`_browser/`、`_evtx/` …）通过 `resolve_dir()` 自动回退，老包可直接复用
- `tests/test_smoke.py`：4 类冒烟测试（注册表、空目录降级、旧布局兼容、全量分析 14 维）

### 修复
- **维度口径统一**：`dim_map` 把签名/打包器从 `advanced` 拆成独立维度，
  现在 `dimensions_complete` 是 **14 个互不重复的维度**（此前 14 个条目里 `advanced` 重复 3 次）
- `analyze_forensics.py` 里三段内联派生解析合并为一次 `ensure()` 调用，消除重复代码
- SKILL.md / 使用说明中的「11 维」「9 维」等历史表述统一为 14 维
- requirements 拆分：核心依赖与可选解析依赖（`requirements-optional.txt`）

### 文档
- SKILL.md 新增「数据流与产物」「降级矩阵」「性能档位」三节，维度表补数据来源列
- 性能：冷跑 ~59s、热跑 ~13s、`IR_SKIP_HEAVY=1` ~12s

## v5.9.1（2026-11-13）

**补 CI：两个平台 × 两个 Python 版本**

- `.github/workflows/tests.yml`：ubuntu-latest / windows-latest × py3.11 / py3.12
  - 跑 `unittest discover -s tests`（5 个冒烟测试）
  - 跑 `parsers_registry.py --list` 自检
  - 可选解析依赖**故意不装**，用于验证"缺依赖时跳过而不崩"的降级路径

## v5.10.0（2026-11-13）

**把「加载了但没人分析」的 txt/csv 真正接进检测**

### 背景
可达性审计发现：实包 567 个文件里，433 个二进制产物已解析，但 100 个 txt/csv
只是进了字符串池、没有任何维度专门判断；`browser_artifacts/deep/` 下的
`cookies.sqlite` / `formhistory.sqlite` 也没被扫到。

### 新增
- `scripts/analyze_config.py`（第 7 个派生解析器，并入既有维度而非新增维度）
  - **hosts**：自定义映射 + 是否屏蔽安全厂商域名
  - **DNS 缓存**：命中 IOC 库域名/IP
  - **Defender 排除项**：路径/进程/扩展名（采集失败时不误报）
  - **BITS 任务**：含远程 URL 或进行中的传输
  - **AppInit_DLLs / AppCertDlls**：非空即判（行内正则，避免跨行误吞）
  - **管理员组**：成员列表 + 非默认成员提示
  - **PATH**：包含可写目录（DLL/可执行劫持）
  - **防火墙**：状态关闭
  - **COM 劫持**：InprocServer32 落在 temp/public/programdata/downloads
  - **BAM**：REG_BINARY 前 8 字节 FILETIME 解码 → 程序执行时间
  - **下载目录**：可执行/脚本扩展名统计
- 浏览器解析器：递归 `deep/` 子目录，新增 Firefox `moz_cookies`、`moz_formhistory`

### 修复
- 报告渲染对非账号/非 IP 类发现做字段兜底（原先配置类发现会 KeyError）
- COM 劫持判定从「非系统目录」收紧到「落在可写目录」，避免把 WPS/OneDrive 误报

### 实测（IR_DESKTOP-FJ8A0FE_20261113_144722）
| 项目 | 结果 |
|---|---|
| 浏览器库 | 8 → **14 个**（含 deep/cookies.sqlite、formhistory.sqlite） |
| Cookie / 表单 | 新增 `browser_cookies.csv`、`browser_formhistory.csv` |
| 配置类发现 | hosts 劫持(medium)、管理员组(info)、下载目录 110 个 exe(medium)、BAM 73 条(info) |
| 全量 | 14 维、**55 条发现**、评分 36 |

## v5.11.0（2026-11-13）

**按优先级补齐 6 处取证缺口（解析器 7 → 11 个）**

### 1. 账号交叉验证（`analyze_accounts.py`）
- `local_users.csv` 结构化（启用/密码时间/最后登录）
- `hidden_account_crosscheck.txt`：**当所有账号都被标成「WMI 独有」时判定为对比失败**，
  不再当成隐藏账号（本包即为此种情况）
- 管理员组成员与账号表比对，出现查不到的成员 → 高危（隐藏管理员）

### 2. 注册表导出结构化（`analyze_persistence_exports.py`）
- Run / RunOnce / RunServices / IFEO / Winlogon / Services 全部结构化
- IFEO 只认 `Debugger`（`MitigationOptions` 属正常缓解配置，不告警）
- 实测：108 条（IFEO 53 / Run 22 / Winlogon 33），高危 0、中危 10

### 3. SRUM（`analyze_srum.py`）
- `dissect.esedb` 解析 SRUDB.dat：按程序统计收发字节 + 首末时间
- 实测：**32,835 条记录、512 个程序**，≥100MB 外传 24 个（≥1GB 且非系统进程判高危）
- 缺库时降级为字符串提取，并注明"未完整解析"

### 4. 文件系统时间线（`analyze_filesystem.py`）
- interesting_files / recent_files：双扩展名、临时/公共目录可执行、时间戳倒挂
- 分级校准：下载/AppData 目录可执行降为中危（本包 999 条、可疑 425、高危 0）

### 5. IIS 站点上下文（并入 `config`）
- `iis_sites.txt` 被 appcmd 报错时记为证据缺口，而不是当成"没有站点"

### 6. 采集清单校验（并入 `config`）
- 解析 `collection_manifest.json` 的 modules/status/errors
- 实测：3 个模块 partial（Volatile Data 超时、Defender/Sysmon 日志失败）→ 中危发现
- 证据缺口从 7 处增至 **11 处**（含模块级缺口）

### 修复
- 报告渲染统一 `_normalize_findings()`：派生解析器的发现不再因缺字段触发 KeyError
- `gaps` 初始化顺序错误导致 manifest 缺口被清空

### 实测
14 维、**61 条发现**、评分 36；11 个解析器全部成功；冷跑 68s
