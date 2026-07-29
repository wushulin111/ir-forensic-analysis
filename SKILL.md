---
name: ir-forensic-analysis
description: >
  应急响应取证分析。自动解压分析 Linux/Windows 取证包（IR.tar.gz / IR.zip），
  覆盖11大检测维度（含打包器/多阶段载荷识别、勒索家族分类检测、供应链/第三方运维、高级对抗检测：银狐专项+远控对抗），
  映射MITRE ATT&CK，因果链推理攻击路径复盘，生成含威胁评分、IOC摘要、勒索家族识别与因果链时间线的应急报告。
license: MIT
metadata:
  author: OpenClaw
  version: "4.3.0"
  category: security-forensics
  language: zh-CN
---

# 应急响应取证分析 Skill

## 分析能力（11大检测维度）

| # | 维度 | 检测内容 | ATT&CK 覆盖 |
|---|------|----------|-------------|
| 1 | 可疑进程 | 异常路径/隐藏目录/已知恶意进程名/LotL滥用/进程注入指标/勒索加密进程 | T1059, T1218, T1564 |
| 2 | 持久化机制 | 注册表Run键/计划任务/WMI事件订阅/启动文件夹/crontab/systemd/服务劫持 | T1547, T1053, T1546, T1543 |
| 3 | 异常账号 | 隐藏账号/WMI交叉验证/ProfileList交叉验证/SAM克隆账号(F值对比)/空密码/UID=0后门 | T1136, T1078, T1548 |
| 4 | 网络外联 | C2端口/DNS异常/CLOSE_WAIT累积/反向Shell/大流量外泄 | T1071, T1571, T1041, T1048 |
| 5 | Webshell | 一句话木马/大马/内存马/杀软对抗/常见文件名 | T1505, T1059, T1562 |
| 6 | 内存注入 | RWX区域/反射DLL/进程空心化/Beacon特征/无文件攻击 | T1055, T1620 |
| 7 | 横向移动 | SMB/RDP/SSH扫描/PsExec/WMI远程/哈希传递/WinRM | T1021, T1047, T1550 |
| 8 | 高级对抗 | 银狐专项(34条规则/5265域名)+远控对抗：Unhooking致盲EDR/PoolParty注入/自编写驱动/白加黑/多阶段加载 | T1562, T1055, T1014 |
| 9 | **进程名仿冒+签名** | 字符替换仿冒svch0st→svchost/Levenshtein官方名偏差/数字签名验证/哈希篡改 | T1036.005, T1036.002 |
| 10 | **打包器/载荷** | **PyInstaller/PyArmor/UPX/Enigma检测/TEMP_MEI快照对比/多阶段加载识别(v4.2新增)** | T1027, T1059 |
| 11 | **供应链/勒索** | **勒索家族分类识别(8族)+ESXi虚拟化勒索+NAS漏洞入侵+第三方运维盲区+Dwell Time评估+因果链攻击路径复盘** | T1486, T1490, T1195, T1133 |

> 第10维「打包器/载荷」为 v4.2 新增，第11维「供应链/勒索」为 v3.0 新增，整合了勒索病毒家族深度检测、ESXi/NAS 专项、供应链入侵排查和因果链攻击路径复盘方法论。

> 第8维「高级对抗」合并了银狐专项(34条规则/5265域名)和远控对抗检测，用 `fox_tag`（银狐家族特征）和 `generic_rat_tag`（通用远控对抗）标签区分归属。

---

## LLM 行为指导

### 你的角色

你是应急响应分析专家。用户上传取证包后，你需要**直接读取解压后的文件内容**进行分析并输出报告，**不是执行脚本**。`scripts/` 目录下的脚本是辅助参考实现，你不会调用它们。

### 分析优先级策略

```
收到取证包
│
├─ 第一步：数据预处理（v3.2.0 新增）
│   ├─ 解压 → 统计文件数量和类型
│   ├─ 事件归一化 → 构建 timeline.jsonl（进程+网络+文件+注册表统一事件表）
│   ├─ Sigma 规则匹配命令行参数 → 在 timeline 标记可疑命令
│   ├─ 威胁情报查询外联 IP → 标记已知恶意地址（微步/VT/AbuseIPDB 多源）
│   ├─ 威胁情报查询文件 Hash → 关联已知恶意样本（微步/VT/CVERC）
│   └─ 构建实体关联图（进程←→网络←→文件关系）
│
├─ 第二步：快速评估
│   ├─ 读取 netstat → 立即识别高危外联（C2端口/反向Shell）
│   ├─ 读取进程列表 → 识别已知恶意进程名
│   └─ 从 timeline 中提取最高严重级别事件
│
├─ 第三步：如果发现 Critical 级别指标
│   ├─ 立即在报告中标注 🔴 并置于最前
│   ├─ 给出紧急处置命令（kill进程/封禁IP）
│   ├─ 继续完成其余维度分析（不要停下来等用户确认）
│   └─ 报告末尾汇总所有 Critical 项
│
├─ 第四步：按顺序完成11大维度（预处理结果注入到各维度中）
│   ├─ 进程 → 持久化 → 账号 → 网络 → Webshell → 注入 → 横向 → 高级对抗 → 供应链/勒索
│   └─ 优先引用 timeline 中的归一化事件，而非逐行读原始文件
│
└─ 第五步：生成报告
    ├─ 计算威胁评分
    ├─ 提取 IOC 摘要（IP/域名/Hash/Mutex） — 表格化输出
    ├─ 从 timeline 构建攻击时间线
    ├─ 输出 ATT&CK 映射
    ├─ 声明分析覆盖率（检查了哪些文件、漏了哪些）
    └─ 给出分级处置建议
```

### 不确定时的处理策略

| 情况 | 处理方式 |
|------|----------|
| 发现可疑但可能是正常软件 | 标注为"需确认"，给出判断依据，不直接定性为恶意 |
| 证据不足以判断 | 明确写出"证据不足，无法确定"，列出可能的解释 |
| 进程名匹配规则但路径正常 | 降低风险等级，标注"可能误报"并说明原因 |
| 端口匹配恶意规则但属于已知软件 | 查阅 `known_false_positives` 白名单，保留标记但附加说明（如"4444端口通常为Metasploit，但本例为天融信VPN内部通信"） |
| 无法确定攻击阶段 | 时间线中标注为"未分类事件"，不强归属阶段 |
| **发现 Critical 指标但证据不足** | **仍给出紧急处置命令，标注置信度 `Medium (推定恶意)`，注明"待进一步确认"** |

### 多个高危发现并存的推理逻辑

1. **先判断是否为同一条攻击链**：Webshell → 进程注入 → C2外联 → 横向移动，如果是，在时间线中串联
2. **如果不是同一链路**：分别报告，各自独立评分
3. **如果高危项之间有时间关联**：在时间线中用"→"标注因果关系
4. **优先级排序**：C2通信 > 进程注入 > 持久化 > 信息收集
5. **证据链串联**：对于 Critical 发现，必须在前一项发现的上下文中交叉验证。例如：发现 Webshell → 检查写入时间前后 5 分钟内的进程创建事件 → 检查该进程的网络连接
6. **因果链推理**：时间线中每个事件必须标注 cause/effect 关系（详见 `references/ATTACK_CHAIN_REASONING.md`）：
   - `RDP成功登录 03:00:12 ❱ (因) 03:01:05 certutil.exe下载Payload ❱ (果) 03:01:30 注册表Run键写入`
7. **逆向溯源法**：发现影响事件(加密)后必须逆向推断：加密文件 → 谁加密的(进程) → 加密进程从哪来(父进程/下载源) → 初始访问入口
8. **Dwell Time 评估**：首次入侵到首次发现的时间差→评估损失范围
9. **第三方运维入口专项标注**：如果初始访问来自第三方VPN/IP段/IPMI口，在报告中单独标注"第三方运维风险"
10. **勒索家族识别**：发现勒索特征后必须查阅 `rules/ransomware_family_rules.json` 匹配具体家族

### CSV 大文件读取策略

大型 CSV（如 `process_modules.csv` 可能数千行，`prefetch.csv` 可能数万行）：

1. **先读前 20 行**了解结构和表头
2. **用 grep 搜索特定字段**（如 `grep "kabuto" process_modules.csv`）
3. **针对性读取匹配行**上下文，而非一次性加载整个 CSV
4. 避免将整个大 CSV 写入上下文——用 `grep_files` 做定向检索

### 编码处理

Windows 取证脚本输出通常为 **UTF-16**。分析前必须先转码：

```bash
SRC="/path/to/extracted"
DST="/tmp/ir_utf8"
mkdir -p "$DST"
find "$SRC" -type f \( -name '*.txt' -o -name '*.csv' -o -name '*.xml' \) | while read f; do
    relpath="${f#$SRC/}"
    mkdir -p "$DST/$(dirname "$relpath")"
    iconv -f UTF-16 -t UTF-8 "$f" > "$DST/$relpath" 2>/dev/null || cp "$f" "$DST/$relpath"
done
find "$SRC" -type f \( -name '*.evtx' -o -name '*.dat' -o -name '*.json' -o -name '*.hash' \) | while read f; do
    relpath="${f#$SRC/}"
    mkdir -p "$DST/$(dirname "$relpath")"
    cp "$f" "$DST/$relpath"
done
```

转码后再读取 `/tmp/ir_utf8/` 下的文件。**注意**：v2.1+ 的 `win_collect.ps1` 已使用 `-Encoding UTF8` 输出，大多数文件不需要转码。如果读取时发现乱码，再使用上述命令。

### 规则库处理

- **规则库位置**：`rules/` 目录
- **不存在**：不中断分析，使用本文档中的检测规则速查索引作为内建知识，报告中注明"本次分析未使用经验规则库"
- **存在**：加载 JSON 规则文件辅助检测，注意规则中的 `known_false_positives` 字段做误报排除
- **YARA 规则**：参考 `rules/yara_rules/` 中的规则模式，LLM 不执行 YARA 扫描，而是在读取文件内容时根据规则中的特征模式进行文本匹配
- **IOC库**：`rules/ioc_library.json` 包含银狐C2域名/IP/钓鱼域名/驱动文件名/互斥体/样本HASH等已知IOC
- **规则更新**：分析完成后更新 `rules_updated.json`，按 `rule_id + pattern` 去重

---

## 检测规则速查索引

> 完整规则表格见 `references/DETECTION_RULES.md`。以下为各维度关键触发词，LLM 发现匹配后应查阅对应规则文件。

| 维度 | 关键触发词 | 详细规则位置 |
|------|-----------|-------------|
| 可疑进程 | `/tmp/`执行, `xmrig`, `certutil`, `AppData\Local\Temp\*.exe` | `references/DETECTION_RULES.md#进程检测规则` + `rules/process_rules.json` |
| 持久化 | Run注册表, `schtasks /create`, WMI `__EventFilter`, `* */1 * * * curl`, `UserInitMprLogonScript`, `ExecStart=/tmp/`, `ld.so.preload` | `references/DETECTION_RULES.md#持久化机制检测规则` + `rules/persistence_rules.json` |
| 异常账号 | `admin$`, `UID=0`, SAM克隆, **WMI/ProfileList多源交叉比对** | `references/DETECTION_RULES.md#账号检测规则` + `rules/account_rules.json` |
| 网络外联 | `:4444`, `:8888`, `:8880`, `:670`, `CLOSE_WAIT`, `ESTABLISHED`远控端口 | `references/DETECTION_RULES.md#IP威胁情报规则` + `rules/ip_rules.json` |
| Webshell | `eval($_POST`, `system(`, `base64_decode(`, `shell.php`, `cmd.jsp` | `references/DETECTION_RULES.md#Webshell检测规则` + `rules/webshell_rules.json` |
| 内存注入 | `PAGE_EXECUTE_READWRITE`, `ReflectiveLoader`, `NtUnmapViewOfSection`, `sleeptime` | `references/DETECTION_RULES.md#内存注入检测规则` + `rules/injection_rules.json` |
| 横向移动 | 445扫描, RDP爆破, `PSEXESVC`, `sekurlsa::pth`, `Enter-PSSession` | `references/DETECTION_RULES.md#横向移动检测规则` + `rules/lateral_movement_rules.json` |
| 高级对抗-银狐 | `ntdll.dll`重映射, `kabuto.sys`, `PostQueuedCompletionStatus`, `UserDataSvc_`, `SyncCreate`, 银狐C2端口时间线, 反沙箱16项 | `references/DETECTION_RULES.md#高级对抗检测规则` + `rules/silver_fox_rules.json` |
| 高级对抗-远控 | 杀软进程异常缺失, 非微软驱动, `explorer.exe`注入, `svchost`注入 | `references/DETECTION_RULES.md#高级对抗检测规则` + `rules/silver_fox_rules.json` |
| 挖矿病毒 | `xmrig`, `minerd`, `*/1 * * * * curl`, `/tmp/.X11-unix/` | `references/DETECTION_RULES.md#挖矿病毒检测规则` |
| 勒索病毒 | `vssadmin delete shadows`, `.phobos`, `.mallox`, `.hunters`, `.beast`, `.medusalocker`, `.babyk`, `.sorry`, 勒索信文件名, RDP入口, NAS漏洞入口, ESXi加密.vmdk, 卷影删除+批量加密 | `rules/ransomware_family_rules.json` + `references/DETECTION_RULES.md#勒索病毒检测规则` |
| ESXi/虚拟化勒索 | `.vmdk`批量重命名, `esxcli vm process kill`, `vim-cmd power.off`, VM快照删除, VMFS异常IO | `rules/yara_rules/esxi_ransomware.yar` + `references/DETECTION_RULES.md#ESXi/虚拟化勒索专项` |
| 供应链/第三方运维 | VPN/IPMI暴露, 共享账号, 第三方运维IP异常, 非标准管理端口, 用友NC等软件漏洞, NAS Web面板暴露 | `references/DETECTION_RULES.md#供应链/第三方运维检测规则` |
| NAS设备安全 | 5000/5001(Synology)/8080(QNAP)端口暴露, NAS弱口令, /volume1/@tmp/异常文件 | `references/DETECTION_RULES.md#NAS设备安全检测规则` |
| AI驱动攻击 | 极速扫描间隔<10秒, AI生成钓鱼, LLM辅助Webshell, 自动化漏洞利用链 | `references/DETECTION_RULES.md#AI驱动攻击检测规则` |
| 后门检测(Linux) | SSH软连接, OpenSSH/PAM完整性, `command_integrity`, 盖茨木马 | `references/DETECTION_RULES.md#后门检测规则` |

### 取证包目录结构

详见 `references/DIRECTORY_MAPPING.md`。收到取证包后按该文档识别来源格式并定位文件。

---

## 快速评估路径

解压后立即读取以下文件做快速评估（优先级排序）：

| 优先级 | Windows 文件 | Linux 文件 | 检测目标 |
|--------|-------------|-----------|----------|
| P0 | `02_Process/ioc_alerts.txt` **★v4.0** | — | **IOC告警进程**（离线扫描已知恶意进程） |
| P0 | `04_FileSystem/lolbin_alerts.txt` **★v4.0** | — | **LOLBin 滥用告警**（certutil/mshta/powershell -enc 等） |
| P0 | `12_Metadata/top_hash.txt` **★v4.0** | — | **证据完整性哈希链**（顶层完整性校验） |
| P0 | `1_volatile/netstat_anob.txt` | `1_volatile/netstat_ano.txt` + `ss_tlnp.txt` | C2外联/反Shell/银狐端口 |
| P0 | `1_volatile/process_tree.csv` | `1_volatile/process_tree.txt` | 进程注入/父子异常 |
| P0 | `1_volatile/process_authenticode.csv` **★** | — | 进程数字签名验证 |
| P0 | `1_volatile/process_name_anomalies.csv` **★** | — | 进程名仿冒检测 |
| P0 | `1_volatile/process_tree_anomalies.csv` **★v3.0.3** | — | 进程树关联异常(已退出的可疑进程) |
| P0 | `5_filesystem/static_scan/static_exe_suspicious.csv` **★v3.0.3** | — | 静态EXE扫描(桌面/下载目录未签名可疑EXE) |
| P0 | `3_persistence/wmi_*.txt` | — | WMI隐蔽持久化 |
| P1 | `3_persistence/ifeo.txt` | `3_persistence/ld_so_preload.txt` | 映像劫持/隐藏进程 |
| P1 | `3_persistence/logon_scripts.txt` | `3_persistence/suid_sgid.txt` | 登录后门/SUID提权 |
| P1 | `3_persistence/com_hijack.csv` | `3_persistence/ssh_authorized_keys.txt` | COM劫持/SSH后门 |
| P1 | `2_accounts/sam_users.csv` | `2_accounts/shadow.txt` | 克隆账号/弱口令 |
| P2 | `5_filesystem/temp_executables.csv` | `7_filesystem/tmp_executables.txt` | 临时目录恶意文件 |
| P2 | `6_logs/powershell_scriptblock.txt` | `6_logs/auth.log` | PS混淆命令/暴力破解 |
| P2 | `1_volatile/process_modules.csv` | `4_backdoor/command_integrity.txt` | ntdll Unhooking/命令替换 |
| P2 | `3_persistence/services_detail.csv` | `7_filesystem/hidden_files.txt` | 非微软驱动/隐藏文件 |
| P2 | `1_volatile/tasklist.csv` | `3_persistence/bashrc_profile.txt` | 杀软缺失/Shell劫持 |
| P2 | `vss_shadows.txt` | `3_persistence/modules_load.txt` | 卷影删除/内核模块后门 |

---

## 威胁评分系统

### 计算公式

```
总分 = Σ (每个发现的维度权重 × 严重等级分)

维度权重:
  网络外联(C2) → 权重 4
  高级对抗(银狐/远控) → 权重 4
  勒索病毒/ESXi勒索 → 权重 4
  可疑进程/持久化/Webshell/横向/内存注入 → 权重 3
  供应链/第三方运维 → 权重 3
  异常账号 → 权重 2

严重等级分:
  Critical → 3分
  High → 2分
  Medium → 1分
  Low → 0.5分
```

**举例**：发现 1个C2外联(Critical) + 2个可疑进程(High) + 1个持久化(Critical)
= (4×3) + (3×2) + (3×2) + (3×3) = 12 + 6 + 6 + 9 = **33分 → 危急**

### 等级划分

| 总分 | 等级 | 建议措施 |
|------|------|----------|
| ≥25 | 🔴 危急 | 立即隔离，全量排查 |
| 15-24 | 🟠 高危 | 优先处置，限制网络 |
| 5-14 | 🟡 中危 | 调查确认，针对性处理 |
| <5 | 🟢 低危 | 记录观察，持续监控 |

---

## 应急响应流程管理

### 主机入侵严重等级

> 基于离线取证分析的威胁评分，确定主机自身的入侵严重程度，不涉及全网影响评估。

| 威胁评分 | 严重等级 | 含义 |
|---------|---------|------|
| >=25 🔴 危急 | **主机已沦陷** | 存在活跃 C2/勒索加密/横向移动，需立即断网隔离 |
| 15-24 🟠 高危 | **高度可疑入侵** | 存在后门/持久化/Webshell，需优先处置 |
| 5-14 🟡 中危 | **潜在威胁** | 存在可疑痕迹但证据不足，需进一步确认 |
| <5 🟢 低危 | **未发现入侵** | 未发现明显恶意痕迹，持续观察 |

### 事件分类（离线可判断的）

| 类别 | 判定依据（取证包中可找到的证据） |
|------|-------------------------------|
| 勒索病毒 | VSS 被删除 + 文件批量加密 + 勒索信 |
| Webshell 渗透 | 网站目录可疑文件 + 异常进程 + C2 外联 |
| 远控木马 | 反向 Shell + C2 通信 + 持久化机制 |
| 挖矿病毒 | 挖矿进程 + 矿池 C2 + CPU 高占用痕迹 |
| 暴力破解 | 大量登录失败日志 + 多 IP 尝试 |
| 数据泄露 | 大流量外传记录 + 数据库查询日志 |

### 响应角色（供现场指挥参考）

| 角色 | 职责 |
|------|------|
| Incident Commander (IC) | 统筹指挥，调度资源，判断全网影响 |
| Scribe | 记录时间线和行动 |
| 主机负责人 | 执行主机级处置动作 |
| SMEs（系统/网络/安全） | 技术支持 |

### 处置建议（按主机可执行的操作）

每个发现的处置建议映射为具体、可打勾的**单机操作项**，IC 可据此分配任务。

```
## 处置建议

### 🔴 紧急 - P0（需立即通知安全团队）
P0-001 □ 通知安全负责人：主机 {hostname} 确认存在 {发现类型}，建议启动 P0 应急
P0-002 □ 提取内存镜像（目标机若仍在运行）
P0-003 □ 保存完整取证包作为证据归档

### 🟠 优先 - P1（可远程或现场执行）
P1-001 □ 隔离主机：断网或防火墙封禁出口
P1-002 □ 封禁 C2 IP: {ioc_ips}
P1-003 □ 清除持久化机制: {发现路径}
P1-004 □ 重置异常账号口令: {异常账号}
P1-005 □ 删除 Webshell 文件: {文件路径}

### 🟡 调查中 - P2（需人工确认）
P2-001 □ 人工复核可疑进程: {可疑进程名}
P2-002 □ 检查同网段其他主机是否存在相同 IOC
P2-003 □ 溯源入侵路径: 分析 {时间窗口} 内的登录来源

### 🟢 观察 - P3（记录在案）
P3-001 □ 将 IOC 添加到监控规则
P3-002 □ 观察期 7 天，无新增发现则关闭事件
P3-003 □ 周报中跟踪
```

### 事件同步单

报告末尾附加，方便将分析结论同步给事件响应组。

```
## 事件同步单

**事件编号**: IR-{timestamp}-{hostname}
**主机**: {hostname} ({ip})
**分析时间**: {timestamp}
**主机状态**: 已沦陷 / 高度可疑 / 潜在威胁 / 未发现入侵

**关键发现**:
  1. [P0] {F001: 发现标题}
  2. [P1] {F002: 发现标题}

**建议行动**:
  IC 应立即安排: {P0 操作项}
  主机负责人应执行: {P1 操作项}

**IOC 清单**:
  IP: {ip_list}
  文件 Hash: {hash_list}
  域名: {domain_list}
  端口: {port_list}

**附件**: 完整分析报告见上文
## 分析流程

### 步骤1: 解压取证包

```bash
# Linux (tar.gz)
mkdir -p /tmp/ir_extracted && tar xzf IR.tar.gz -C /tmp/ir_extracted

# Windows (zip)
mkdir -p /tmp/ir_extracted && cd /tmp/ir_extracted && unzip -o IR.zip
```

解压后检查文件编码，按需转码（见"编码处理"章节）。识别取证包来源格式（见 `references/DIRECTORY_MAPPING.md`）。

### 步骤2: 快速评估

按「快速评估路径」表逐文件读取，先看 P0 → 发现 Critical 立即标注 → 继续 P1/P2。

### 步骤3: 逐维度深度分析

**直接读取文件内容**，按11大维度逐一分析。每个文件的内容即为检测目标，通过阅读内容+规则匹配来识别威胁。

**v3.0 因果链推理**：分析过程中遵循 `references/ATTACK_CHAIN_REASONING.md` 的方法论，每个 Critical/High 发现必须执行逆向溯源（至少3层），时间线条目之间标注 cause→effect 因果关系。

**v3.0 勒索家族识别**：如果发现勒索特征（卷影删除+批量加密+勒索信），必须查阅 `rules/ransomware_family_rules.json` 匹配具体家族，在 verdict 中填写 `ransomware_family` 和 `has_ransomware`。

**evtx文件处理**：evtx为二进制格式，LLM无法直接读取。优先读取 `6_logs/security_key_events.csv`（已提取的关键事件CSV）和 `6_logs/powershell_scriptblock.txt`（已提取的PS脚本块）。如需分析原始evtx，使用 `evtxdump` 或 `python-evtx` 工具提取。

### 步骤4: 生成报告

输出 Markdown 格式的应急报告。**同时**在报告末尾输出结构化 JSON 摘要（见 `references/REPORT_CONTRACT.md`），供程序化消费和自动化校验。

### 步骤5: 自校验

报告生成后，**必须**执行自校验清单，确保分析完整性：

```markdown
## 自校验清单
| # | 检查项 | 状态 |
|---|--------|------|
| 1 | 11大维度均有分析结论（至少"未发现"） | ☐ |
| 2 | 所有 Critical/High 发现均有对应的 ATT&CK 技术 ID | ☐ |
| 3 | 威胁评分已按公式计算（非主观估计） | ☐ |
| 4 | IOC 摘要已提取（若无则为空表） | ☐ |
| 5 | 攻击时间线已构建（若无则为"未发现攻击事件"） | ☐ |
| 5b | 时间线条目之间标注了cause/effect因果链 | ☐ |
| 5c | Dwell Time（驻留时间）已计算（若无法确定则为"未知"） | ☐ |
| 6 | 覆盖率表已填写（含未分析文件列表） | ☐ |
| 7 | JSON 摘要字段完整且合法（Schema v2） | ☐ |
| 8 | 配置风险项（非入侵但需处置）已单独列出 | ☐ |
| 9 | 进程名仿冒+签名 维度已分析（至少"未发现"） | ☐ |
| 10 | 勒索家族已识别（若有勒索特征但未匹配家族则标注"未识别家族"） | ☐ |
| 11 | 供应链/第三方运维风险已评估 | ☐ |
```

如果任何检查项未通过，**返回修正报告后再输出**。不要输出未通过校验的报告。

---

## 数据预处理增强（v3.4.0）

> 在进入 9 维分析之前，先对原始数据进行一次预处理。这能极大提升分析效率，**不等同于跳过维度分析**——预处理的结果会注入到每个维度的检查中。

### ① 事件归一化（跨维度关联基础）

将散落在各文件中的进程、网络、文件、注册表事件，统一为 `timeline.jsonl` 格式：

```jsonl
{"time":"2026-05-20T14:25:00","type":"process_create","pid":6200,"ppid":4568,"image":"powershell.exe","cmdline":"-NoP -W Hidden -Enc ...","severity":"info"}
{"time":"2026-05-20T14:25:01","type":"network_connect","pid":6200,"local":"192.168.1.100:49157","remote":"45.33.32.156:6666","state":"ESTABLISHED","severity":"high"}
```

**在 9 维分析中**，优先引用归一化事件，而不是从零读原始文件。例如分析维度1（可疑进程）时，直接看 timeline 中所有 `type=process_create` 的事件，而不是去 tasklist.csv 里逐行看。

> **如何做**：解包后，提取 process_tree.csv、netstat_ano.txt、powershell_scriptblock.txt 等关键文件，将相关信息拼成一张"事件表"。**不需要额外脚本**，LLM 直接在思考过程中完成。

### ② Sigma 命令行规则匹配（增强维度1/维度8）

在分析维度1（可疑进程）之前，先对进程的命令行参数做 Sigma 规则匹配。重点关注：

| Sigma 模式 | 命中的含义 | 对应维度 |
|-----------|-----------|---------|
| `powershell.*-Enc.*[A-Za-z0-9+/=]{50,}` | PowerShell 远程下载执行 | 维度1 |
| `powershell.*-W Hidden` | 隐藏窗口执行 | 维度1 |
| `regsvr32.*/s.*/u.*/i:http` | Squiblydoo 绕过 AppLocker | 维度1/维度8 |
| `rundll32.*javascript:` | js 执行白加黑 | 维度1/维度6 |
| `mshta.*http` | HTA 远程执行 | 维度1 |
| `certutil.*-decode` | certutil 下载混淆 | 维度1 |
| `wmic.*process.*call.*create` | WMI 远程执行 | 维度7 |
| `schtasks.*/create.*/tn.*/tr.*` | 计划任务持久化 | 维度2 |

匹配到的事件在 timeline 中标记 `sigma_hit` 字段，各维度分析时优先关注。

### ③ 威胁情报增强（增强维度4 + 扩展至文件Hash）
分析维度4（网络外联）时，对外联 IP 增加威胁情报查询。同时新增**文件 Hash 查询**：取证包中的可疑文件 SHA256 也自动查情报，辅助维度1（可疑进程）和维度8（高级对抗）的判断。
**查询范围**：
| 查询类型 | 查询对象 | 覆盖来源 | 对应维度 |
|---------|---------|---------|---------|
| IP 信誉 | 非本地外联 IP | 微步 / VT / AbuseIPDB / IPinfo | 维度4 |
| Hash 检测 | 可疑文件 SHA256 | 微步 / VT / CVERC | 维度1/维度8 |
| 域名信誉 | 远程域名 | 微步域名 API | 维度4 |
**两种查询方式**：
| 方式 | 说明 | 适用场景 |
|------|------|----------|
| **自动化脚本** | scripts/threat_intel_lookup.py | 调用 nalyze_forensics.py 时自动执行 |
| **ThreatMCP 工具** | 	hreatbook MCP Server（15个工具） | 手动调 ip_reputation/domain_analysis 等 |
**支持的数据源**：
| 数据源 | 类型 | 免费额度 | 查询方式 | 适用 |
|--------|------|---------|----------|------|
| **微步在线 API** | API | 基础免费 | POST pi.threatbook.cn/v3/scene/ip_reputation | 国内首选，最快最稳定（IP/域名/Hash） |
| **VirusTotal** | API | 4次/分（免费） | GET irustotal.com/api/v3/files/{hash} / ip_addresses/{ip} | 全球最大，Hash 检测率最高；134字节=未收录 |
| **AbuseIPDB** | API | 1000次/天（免费） | GET pi.abuseipdb.com/api/v2/check | IP 信誉评分专用，0-100分 |
| **CVERC 国家平台** | API | 免费 | POST pi.cverc.org.cn/api/v1/file/check | 国内官方 Hash 查询/上传 |
| **IPinfo.io** | 免费API | 完全免费 | GET ipinfo.io/{ip}/json | IP归属地/ASN/主机名 |
| **微步在线手动查** | 手动 | 完全免费 | x.threatbook.com 手动输入 | API不可用时的备选 |
**多源查询优先级（自动降级）**：
`
IP 查询：微步 → VT → AbuseIPDB → IPinfo.io
Hash 查询：微步 → VT → CVERC
域名查询：微步（仅此源）
`
> 任一数据源失败（无 Key/限流/超时），自动降级到下一个可用源。不会因为某个源不可用而中断查询。
**自动化流程**（已集成到 	hreat_intel_lookup.py 和 nalyze_forensics.py）：
`
分析完成 11 大维度
    ↓
提取 IOC（ips/domains/hashes）
    ↓
多源并查：
  ├─ IP → 微步 → VT → AbuseIPDB → IPinfo
  ├─ Hash → 微步 → VT → CVERC
  └─ 域名 → 微步
    ↓
查询结果格式化 → 追加到报告的"威胁情报关联分析"章节
`
**手动查询步骤（LLM 分析时使用）**：
1. 从 timeline 中提取所有非本地外联 IP（排除 127.0.0.1/192.168.x.x/10.x.x.x 等）
2. 从 file_hashes.csv / process_authenticode.csv 中提取可疑文件 SHA256
3. 使用 	hreatbook MCP Server 的 ip_reputation 工具查 IP 信誉
4. 可疑域名调 domain_analysis 查域名信息
5. 文件 Hash 通过 VT / 微步查检测率
6. 命中恶意标记 → 维度4/维度1 输出中加入威胁情报标签，注明来源
**威胁情报来源格式**（在 IOC 摘要中标记来源）：
`
| IP | 微步 | VT恶意数 | AbuseIPDB | IPinfo |
|----|------|---------|----------|--------|
| 45.33.32.156 | 高危 | 12/68 | 85/100 | Los Angeles,US |
| 8.8.8.8 | 安全 | 0/69 | 0/100 | Mountain View,US |
| Hash | VT检测 | 微步 | CVERC |
|------|--------|------|-------|
| d4ac4633... | 18/72 | 高危 | 恶意 |
`
> 微步 API Key 已配置在 config/threat_intel.json 中。VT/CVERC/AbuseIPDB 的 Key 如配置则自动启用，未配置时自动跳过该源。
> scripts/threat_intel_lookup.py 可在命令行独立运行测试。
### ④ 哈希链完整性验证（v3.4.0 新增）

> **适用场景**：win_collect v4.0 采集的取证包中包含 `12_Metadata/hash_chain.txt` 和 `top_hash.txt`

**验证步骤**：
1. 读取 `top_hash.txt`，获取声明顶层哈希
2. 读取 `hash_chain.txt`，获取每个文件的 SHA256 列表
3. 将 `hash_chain.txt` 内容重新计算 SHA256
4. 比较结果与 `top_hash.txt` 中的值是否一致
   - 一致 → 证据完整性通过，标记 hash_chain: ✅
   - 不一致 → 证据可能被篡改，标记 hash_chain: ❌ 并在报告中高亮

**验证通过的意义**：
- 所有采集文件自生成后未被修改
- 可对 ZIP 包整体做 Get-FileHash 交叉验证

### ⑤ 实体关联图（跨维度关联）

> 不增加维度，但在分析过程中构建实体关联，辅助 9 维之间的因果推理。

```text
进程: invoice.doc.exe(4568)
  ├─ 子进程: powershell.exe(6200) [Sigma: DownloadString]
  │    └─ 网络: 45.33.32.156:6666 [威胁情报: C2]
  ├─ 子进程: svchost.exe(6201) [父进程异常]
  └─ 文件: C:\Temp\beacon.dll
```

**在 9 维分析中各维度引用**：
- 维度1 看到 powershell.exe(6200) 可疑 → 去实体图看它的父进程是谁
- 维度4 看到 45.33.32.156:6666 外联 → 去实体图看哪个进程连的
- 维度7 看到 SMB 外联 → 去实体图看进程是谁衍生的

> **不分步做**：归一化 → Sigma → 威胁情报 → 实体图 → 进入 9 维分析。所有预处理在 LLM 思考过程中完成，不需要额外脚本。

---

## 分析检查清单（每个维度的必须检查项）

> 借鉴 ir-suite 的 check 脚本理念。LLM 在分析每个维度时**必须逐项确认**，防止遗漏。未读到的文件标记为 `⏭跳过` 并在覆盖率表中说明原因。

### 维度1：可疑进程

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 1.1 | 进程列表（异常路径/恶意名） | `1_volatile/tasklist.csv` + `process_detail.txt` | `live_response/processes.txt` + `ps_ef.txt` | ✅ |
| 1.2 | 进程可执行路径（/tmp/等） | `1_volatile/process_full.txt` | `live_response/proc_exe_links.txt` | ✅ |
| 1.3 | 进程内存映射（注入指标） | `1_volatile/process_modules.csv` | `live_response/proc_maps.txt` | ✅ |
| 1.4 | 进程环境变量（LD_PRELOAD等） | — | `live_response/proc_environ.txt` | ✅ |
| 1.5 | 进程fd（异常文件访问） | — | `live_response/proc_fd.txt` | ⏭ |
| 1.6 | /tmp可执行文件 | `5_filesystem/temp_executables.csv` | `system/tmp_executable.txt` + `tmp_executable_hash.txt` | ✅ |
| 1.7 | 隐藏进程检测 | — | `system/unhide.txt` | ✅ |
| 1.8 | 勒索/加密进程（ELF静态编译/异常批量IO） | — | `1_volatile/process_full.txt` + `5_filesystem/recent_modified_system.csv` | ✅ |
| 1.9 | **进程数字签名验证 \*v3.0.1** | `1_volatile/process_authenticode.csv` | — | ✅ |
| 1.10 | **进程名仿冒检测 \*v3.0.1** | `1_volatile/process_name_anomalies.csv` | — | ✅ |
| 1.11 | **进程父子关系异常 \*v3.1.0** | `1_volatile/process_tree.csv` + `process_authenticode.csv` | `ps_ef.txt` + `proc_tree.txt` | ✅ |

> **1.11 检测方法**：遍历进程树，检查系统进程（svchost.exe/rundll32.exe/conhost.exe等）的父进程是否是 services.exe/wininit.exe。如果父进程是钓鱼文件（如 发票清单.doc.exe、2026年税务稽查名单.exe），则判定为白加黑注入。同时检查「无签名父进程→有签名子进程」的签名链断裂模式。

### 维度2：持久化机制

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 2.1 | 注册表Run键 | `3_persistence/run_hklm.txt` + `run_hkcu.txt` | — | ✅ |
| 2.2 | 计划任务 | `3_persistence/schtasks.csv` + `schtasks.xml` | `persistence/crontab_root.txt` + `crontab_system.txt` + `cron_d.txt` | ✅ |
| 2.3 | WMI事件订阅 | `3_persistence/wmi_*.txt` | — | ✅ |
| 2.4 | 启动文件夹 | `3_persistence/startup_folder.csv` | `persistence/rc_local.txt` + `rc3d.txt` | ✅ |
| 2.5 | 服务劫持 | `3_persistence/services_detail.csv` + `service_dlls.csv` | `persistence/systemd_enabled.txt` + `systemd_running.txt` | ✅ |
| 2.6 | Winlogon/IFEO/AppInit | `3_persistence/winlogon.txt` + `ifeo.txt` + `appinit_dlls.txt` | — | ✅ |
| 2.7 | COM劫持 | `3_persistence/com_hijack.csv` | — | ✅ |
| 2.8 | 登录脚本 | `3_persistence/logon_scripts.txt` | `persistence/profile_d.txt` | ✅ |
| 2.9 | LD_PRELOAD | — | `persistence/ld_so_preload.txt` + `ld_so_conf.txt` | ✅ |
| 2.10 | Shell配置劫持 | `3_persistence/ps_profiles.txt` | `persistence/bashrc_profile.txt` | ⏭ |
| 2.11 | 用户级systemd | — | `persistence/user_systemd.txt` | ⏭ |
| 2.12 | 内核模块持久化 | — | `persistence/modules_load.txt` | ⏭ |
| 2.13 | XDG自启动 | — | `persistence/xdg_autostart.txt` | ⏭ |
| 2.14 | 包管理器hook | — | `persistence/pkg_hooks.txt` | ⏭ |

### 维度3：异常账号

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 3.1 | UID0/root账号 | `2_accounts/sam_users.csv` | `accounts/uid0_accounts.txt` | ✅ |
| 3.2 | 空密码账号 | `2_accounts/sam_users.csv` | `accounts/empty_password_accounts.txt` | ✅ |
| 3.3 | `$`后缀隐藏账号 | `2_accounts/hidden_accounts.txt` | — | ✅ |
| 3.4 | SAM克隆账号(F值对比) | `2_accounts/sam_clone_accounts.txt` | — | ✅ |
| 3.5 | **WMI账号枚举(v4.3新增)** | `2_accounts/wmi_users.csv` | — | ✅ |
| 3.6 | **ProfileList注册表(v4.3新增)** | `2_accounts/profilelist_users.csv` | — | ✅ |
| 3.7 | **多源交叉比对(v4.3新增)** | `2_accounts/hidden_account_crosscheck.txt` | `accounts/shadow.txt` | ✅ |
| 3.8 | SSH密钥 | — | `accounts/ssh_authorized_keys.txt` | ✅ |
| 3.9 | SSHD配置 | — | `accounts/sshd_config_audit.txt` | ✅ |
| 3.10 | sudoers | — | `accounts/sudoers.txt` | ✅ |

**v4.3 多源交叉比对检测逻辑**：

`net user` 走 NetUserEnum API（可被 Hook 绕过），不可作为唯一检测依据。必须交叉比对三个独立数据源：

| 数据源 | 代码路径 | 权限要求 | 能检测什么 |
|--------|---------|---------|-----------|
| `net user` (NetUserEnum) | netapi32.dll → SAMSRV | 普通用户 | 标准用户列表 (可被API Hook过滤) |
| WMI `Win32_UserAccount` | WMI → SAM 注册表 (独立路径) | 管理员 | 绕过NetUserEnum钩子的隐藏账号 |
| 注册表 `ProfileList` | 直接读注册表 hive | 管理员 | 所有登录过的用户 (不依赖任何API) |

**检测规则**：
- WMI有但net user没有 → 🚨 HIGH: NetUserEnum API可能被Hook
- ProfileList有但net/WMI都没有 → 🚨 CRITICAL: 登录过的账号被系统性隐藏 (疑似rootkit)
- net user有但WMI没有 → ⚠️ 排查WMI服务是否正常 (也可能是反取证)
- SAM F键值=管理员权限但SID≠管理员组 → 🚨 CLONE ACCOUNT

### 维度4：网络外联

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 4.1 | 网络连接 | `1_volatile/netstat_anob.txt` | `network/netstat.txt` + `ss.txt` | ✅ |
| 4.2 | /proc隐藏连接 | — | `network/proc_net_tcp.txt` + `proc_net_udp.txt` | ✅ |
| 4.3 | 防火墙/iptables | `1_volatile/firewall_rules_in.txt` | `network/iptables.txt` | ✅ |
| 4.4 | ARP/路由 | `1_volatile/route.txt` + `arp.txt` | `network/arp.txt` + `route.txt` | ✅ |
| 4.5 | 暴力破解 | — | `logs/lastb_bruteforce.txt` + `logs/auth_log.txt` | ✅ |
| 4.6 | 第三方VPN/IPMI/IP段检查 | `1_volatile/netstat_anob.txt` + `1_volatile/firewall_rules_in.txt` | `network/iptables.txt` + `5_system/system_info.txt` | ✅ |
| 4.7 | 供应链关联IP检查 | `1_volatile/arp.txt` + `1_volatile/net_sessions.txt` | `network/arp.txt` + `1_volatile/last.txt` | ✅ |

### 维度5：Webshell

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 5.1 | 可疑Web请求 | `7_web/iis_log_files.csv` | `web/web_suspicious_requests.txt` | ✅ |
| 5.2 | Web配置 | `7_web/applicationHost.config` | `web/nginx_conf.txt` + `apache_conf.txt` | ✅ |
| 5.3 | Web根目录 | `7_web/web_scripts.csv` | `web/web_wwwroot.txt` + `web_directory.txt` | ⏭ |

### 维度6：内存注入

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 6.1 | 进程内存映射 | `1_volatile/process_modules.csv` | `live_response/proc_maps.txt` | ✅ |
| 6.2 | RWX区域检测 | `1_volatile/process_modules.csv` | `live_response/proc_maps.txt` | ✅ |

### 维度7：横向移动

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 7.1 | 网络扫描迹象 | `1_volatile/netstat_anob.txt` | `network/netstat.txt` | ✅ |
| 7.2 | RDP/SMB会话 | `1_volatile/net_sessions.txt` | — | ✅ |
| 7.3 | ARP异常 | `1_volatile/arp.txt` | `network/arp.txt` | ⏭ |

### 维度8：高级对抗

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 8.1 | SSH软连接后门 | — | `system/ssh_softlink.txt` | ✅ |
| 8.2 | OpenSSH完整性 | — | `system/openssh_integrity.txt` | ✅ |
| 8.3 | PAM完整性 | — | `system/pam_integrity.txt` | ✅ |
| 8.4 | 盖茨木马 | — | `system/gates_trojan.txt` | ✅ |
| 8.5 | 杀软状态 | `1_volatile/tasklist.csv` | — | ✅ |
| 8.6 | 包完整性 | `5_filesystem/recent_modified_system.csv` | `system/debsums_check.txt` + `rpm_verify.txt` | ✅ |
| 8.7 | SUID/Capabilities | — | `system/suid_files.txt` + `capabilities.txt` | ✅ |
| 8.8 | ntdll Unhooking | `1_volatile/process_modules.csv` | — | ✅ |

### 维度9：进程名仿冒 + 数字签名（v3.0.1 新增）

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 9.1 | 进程名仿冒检测（svch0st/scvhost等字符替换） | `1_volatile/process_name_anomalies.csv` | — | ✅ |
| 9.2 | 数字签名验证（系统目录进程签名） | `1_volatile/process_authenticode.csv` | — | ✅ |
| 9.3 | 数字签名异常：知名厂商签名不匹配 | `1_volatile/process_authenticode.csv` | — | ✅ |
| 9.4 | 数字签名异常：文件哈希被篡改 | `1_volatile/process_authenticode.csv` | — | ✅ |

> **分析要点**：
> - `SignatureStatus` 列：`Valid` = 正常，`NotSigned` = 未签名（开源软件常见），`HashMismatch` = **文件被篡改**
> - 系统目录（C:\Windows\*）下的进程如果签名无效（除NotSigned外）应立即标记为 Critical
> - `SignerCN` 应与进程声称的厂商一致（如 chrome.exe 应为 Google LLC）
> - `process_name_anomalies.csv` 的 `Anomalies` 列列出具体异常原因

### 维度10：供应链/勒索专项（v3.0 新增）

| # | 检查项 | 对应文件(Win) | 对应文件(Linux) | 必须 |
|---|--------|-------------|----------------|------|
| 9.1 | 勒索信文件检测 | `5_filesystem/` 递归搜索 | `7_filesystem/` 递归搜索 | ✅ |
| 9.2 | 勒索家族特征匹配 | `5_filesystem/recent_modified_system.csv` | `7_filesystem/recent_modified.txt` | ✅ |
| 9.3 | 卷影删除/VSS服务停止 | `1_volatile/tasklist.csv` + `vss_shadows.txt` | — | ✅ |
| 9.4 | ESXi虚拟化勒索指标 | — | `system/esxi_logs.txt`（如有） | ⏭ |
| 9.5 | NAS设备异常 | — | `network/netstat.txt`（NAS端口） | ⏭ |
| 9.6 | VPN/IPMI/带外管理暴露 | `1_volatile/firewall_rules_in.txt` | `network/iptables.txt` + `system_info.txt` | ✅ |
| 9.7 | 共享账号/通用密码 | `2_accounts/sam_users.csv` | `2_accounts/shadow.txt` | ✅ |
| 9.8 | 第三方远程管理工具 | `1_volatile/tasklist.csv` + `3_persistence/schtasks.csv` | `1_volatile/ps_ef.txt` + `persistence/crontab_root.txt` | ✅ |
| 9.9 | 供应链软件漏洞/篡改 | `5_filesystem/recent_modified_system.csv` + `installed_software.csv` | `7_filesystem/recent_modified.txt` + `5_system/debsums_check.txt` | ✅ |
| 9.10 | Dwell Time 评估 | 对比首次异常时间与加密/发现时间 | 同左 | ✅ |

---

## 报告模板

### Markdown 报告

```markdown
# 应急响应分析报告

## 基本信息
| 项目 | 内容 |
|------|------|
| 分析时间 | {timestamp} |
| 取证来源 | {source_type} |
| 主机名 | {hostname} |
| IP地址 | {ip_addresses} |
| OS | {os_info} |
| 威胁等级 | {threat_emoji} {threat_level} (评分: {score}) |

## 摘要统计
| 检测项 | 数量 | 状态 |
|--------|------|------|
| 可疑进程 | {count} | {status} |
| 持久化机制 | {count} | {status} |
| 异常账号 | {count} | {status} |
| 可疑外联 | {count} | {status} |
| Webshell | {count} | {status} |
| 内存注入 | {count} | {status} |
| 横向移动 | {count} | {status} |
| 高级对抗 | {count} | {status} |
| 进程名仿冒+签名 | {count} | {status} |

## IOC 摘要（v3.2.0增强：推理依据列 + 来源文件列）
| 类型 | 值 | 置信度 | 推理依据 | 来源文件 | 对应维度 |
|------|-----|--------|----------|---------|---------|
| IP:Port | 45.xx.xx.xx:8880 | High | 银狐 C2 端口时间线 2026-03 至今，timeline 中关联进程 svch0st.exe(4568) | netstat_anob.txt / timeline.jsonl | 维度4 |
| Domain | sckca.top | High | 匹配银狐钓鱼域名规则 SFOX-0002，timeline 中关联 powershell 下载 | powershell_scriptblock.txt | 维度8 |
| FileHash | d4ac4633... | Medium | 临时目录下无签名 EXE，timeline 中进程创建时间与 C2 连接时间吻合 | file_hashes.csv | 维度1 |
| Mutex | dba8937c | High | 已知银狐互斥体（ioc_library.json） | process_modules.csv | 维度1/维度8 |
| FilePath | C:\Windows\...\kabuto.sys | High | 已知银狐驱动文件名（ioc_library.json），timeline 中标记 sigma: kernel_driver_load | tasklist_svc.txt | 维度8 |

## 详细发现
[按维度逐一列出，Critical在前，标注 fox_tag / generic_rat_tag 区分银狐和通用远控]

## MITRE ATT&CK 映射
| 技术ID | 技术 | 命中次数 | 标签 |
|--------|------|----------|------|
| T1571 | 非标准端口 | 3 | fox_tag |
| T1562.001 | 禁用安全工具 | 2 | fox_tag |

## 攻击时间线
| 阶段 | 事件描述 | ATT&CK | 置信度 |
|------|----------|--------|--------|
| {phase} | {description} | {technique_id} | H/M/L |

## 分析覆盖率（v3.2.0增强：数据完整性 + 预处理说明）

### 检查清单

| 检查项 | 结果 | 说明 |
|--------|------|------|
| timeline.jsonl 构建 | ✅ / ⏭ 跳过 | 进程+网络+文件+注册表事件已归一化 |
| Sigma 规则匹配 | ✅ 命中 N 条 / 无命中 | 覆盖 SIGMA_PATTERNS 中的命令行模式 |
| 威胁情报查询 | ✅ 已查 N 个 IP、N 个 Hash / ⏭ 无 API 密钥 | 微步/VT/AbuseIPDB/CVERC 查询了外联 IP 和文件 Hash |
| 实体关联图 | ✅ / ⏭ 无关联事件 | 进程←→网络←→文件跨维度关联 |
| **哈希链完整性** | **✅ / ❌ 不匹配** **★v4.0** | **top_hash.txt vs `hash_chain.txt` 重新计算对比** |

### 数据源覆盖

| 维度 | 已检查文件 | 发现数 | 未覆盖项（原因） |
|------|-----------|--------|----------------|
| 可疑进程 | process_tree.csv / tasklist.csv / process_authenticode.csv / process_name_anomalies.csv / **ioc_alerts.txt** **★v4.0** / **lolbin_alerts.txt** **★v4.0** | N | — |
| 持久化 | Run.txt / schtasks.csv / services.txt / wmi_*.txt / ... | N | services_detail.csv（源数据缺失） |
| 异常账号 | users.txt / wmi_users.csv / profilelist_users.csv / hidden_account_crosscheck.txt / sam_clone_accounts.txt | N | — |
| 网络外联 | netstat_ano.txt / dns_cache.txt / rat_port_connections.txt | N | — |
| ... | ... | ... | ... |

| **证据完整性** | `12_Metadata/hash_chain.txt` / `top_hash.txt` **★v4.0** | N | —（所有文件 SHA256 已校验） |

> 覆盖率声明：本报告基于已读取文件 + timeline.jsonl 生成。
> 标注为"未覆盖"的项因源数据缺失无法分析，不影响已发现结论。
> 建议条件允许时补充缺失数据源。.

## 配置风险（非入侵但需处置）
| 优先级 | 风险项 | 说明 |
|--------|--------|------|
| P0 | {risk} | {detail} |

## 处置建议
### 紧急(Critical)
- [ ] 封禁 IP: xxx
- [ ] 隔离主机: xxx
### 优先(High)
- [ ] ...
### 建议(Medium)
- [ ] ...
### 观察(Low)
- [ ] ...
```

### JSON 报告摘要

每份 Markdown 报告末尾**必须**附带一个结构化 JSON 摘要，格式见 `references/REPORT_CONTRACT.md`。该摘要供自动化管道消费，确保报告结构的一致性和可校验性。

```json
{
  "schema": "ir-forensic-analysis-report-v1",
  "meta": {
    "analysis_time": "ISO8601",
    "source_type": "linux|windows",
    "hostname": "",
    "ip_addresses": [],
    "os": "",
    "collection_time": "ISO8601"
  },
  "verdict": {
    "threat_score": 0,
    "threat_level": "low|medium|high|critical",
    "max_severity": "none|low|medium|high|critical",
    "has_c2": false,
    "has_backdoor": false,
    "has_persistence": false,
    "has_lateral": false
  },
  "findings": [
    {
      "id": "F001",
      "dimension": "process|persistence|account|network|webshell|injection|lateral|advanced",
      "severity": "low|medium|high|critical",
      "confidence": "low|medium|high",
      "title": "",
      "detail": "",
      "attck_ids": [],
      "tags": [],
      "ioc": []
    }
  ],
  "iocs": {
    "ips": [],
    "domains": [],
    "file_hashes": [],
    "file_paths": [],
    "mutexes": [],
    "ports": []
  },
  "timeline": [
    {
      "phase": "recon|initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|lateral_movement|c2|exfiltration|impact",
      "event": "",
      "attck_id": "",
      "confidence": "low|medium|high"
    }
  ],
  "coverage": {
    "total_files": 0,
    "analyzed_files": 0,
    "skipped_files": [],
    "dimensions_complete": []
  },
  "config_risks": [],
  "actions": {
    "critical": [],
    "high": [],
    "medium": [],
    "low": []
  },
  "self_check": {
    "all_dimensions_covered": true,
    "all_critical_have_attck": true,
    "score_calculated_by_formula": true,
    "ioc_extracted": true,
    "timeline_built": true,
    "coverage_table_filled": true,
    "json_fields_valid": true,
    "config_risks_listed": true
  }
}
```

---

## 银狐攻击链参考（7阶段）

> 完整银狐检测规则见 `rules/silver_fox_rules.json`（20条）和 `references/DETECTION_RULES.md#高级对抗检测规则`

1. **钓鱼传播** → 仿冒税务/违纪名单/补贴福利/金税四期五期/放假通知下载 MSI/ZIP/CHM
2. **白加黑/多阶段加载** → 白程序入口篡改→Shellcode→解密DLL→调用 SyncCreate
3. **反沙箱反调试** → 16种技术检测沙箱/虚拟机/调试环境+Hook NtTraceEvent 关闭 ETW
4. **对抗杀软** → ntdll Unhooking 绕过 EDR HOOK + TrueSightKiller/自编写驱动关闭杀软
5. **进程注入持久化** → PoolParty 注入 svchost/explorer + 计划任务+启动文件夹+UserDataSvc_服务多重守护
6. **C2通信** → 670→5676→8880端口变迁，20+C2服务器 + Gh0st/winos 远控功能模块上线
7. **横向利用** → 劫持微信/QQ账号冒充身份内网传播 + 投递挖矿模块盗窃算力

---

## 相关文件

### 参考文档
- [检测规则参考](references/DETECTION_RULES.md) — 8大维度完整检测规则表
- [取证包目录映射](references/DIRECTORY_MAPPING.md) — Windows/Linux 目录结构
- [规则库格式说明](references/RULES_FORMAT.md)
- [脚本使用说明](references/SCRIPTS_GUIDE.md) — 脚本参考实现
- [报告契约定义](references/REPORT_CONTRACT.md) — JSON报告Schema与校验规则

### 规则库
- `rules/process_rules.json` / `rules/persistence_rules.json` / `rules/account_rules.json`
- `rules/ip_rules.json` / `rules/webshell_rules.json` / `rules/injection_rules.json`
- `rules/lateral_movement_rules.json` / `rules/silver_fox_rules.json`
- `rules/ioc_library.json` / `rules/yara_rules/`

### 脚本（参考实现，LLM 不调用）
- `scripts/extract_archive.py` / `scripts/analyze_forensics.py` / `scripts/rule_manager.py` / `scripts/threat_intel_lookup.py`

### 变更记录
- [CHANGELOG.md](CHANGELOG.md) — 完整版本变更历史

---

## 故障排查

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 解压失败 | 文件损坏/格式错误 | `md5sum` 验证完整性，检查磁盘空间 |
| 中文乱码 | Windows取证输出UTF-16 | `iconv -f UTF-16 -t UTF-8` 转码后再分析 |
| 分析结果为空 | 取证脚本收集不完整 | 检查文件编码和内容，确认取证脚本版本 |
| 规则库不存在 | 首次使用/路径错误 | 不中断分析，使用内建规则速查索引，报告中注明 |
| 进程名匹配但路径正常 | 误报 | 降低风险等级，标注"可能误报"并说明原因 |
| 端口匹配但属已知软件 | 误报 | 查阅规则 `known_false_positives` 字段，保留标记但附加解释 |
| 大CSV加载过慢 | 文件过大 | 先grep定向搜索关键字段，再针对性读取匹配行 |
