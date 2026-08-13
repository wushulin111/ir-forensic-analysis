# 变更记录
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
