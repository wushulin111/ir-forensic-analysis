# 检测规则参考 v3.0

## 目录

1. [进程检测规则](#进程检测规则)
2. [持久化机制检测规则](#持久化机制检测规则)
3. [账号检测规则](#账号检测规则)
4. [IP威胁情报规则](#ip威胁情报规则)
5. [Webshell检测规则](#webshell检测规则)
6. [内存注入检测规则](#内存注入检测规则)
7. [横向移动检测规则](#横向移动检测规则)
8. [高级对抗检测规则](#高级对抗检测规则) — 银狐专项 + 远控对抗
9. [挖矿病毒检测规则](#挖矿病毒检测规则)
10. [勒索病毒检测规则](#勒索病毒检测规则) — **v3.0 重大升级：家族分类检测**
11. [ESXi/虚拟化勒索专项](#esxivirtualization勒索专项) — **v3.0 新增**
12. [Linux后门检测规则](#linux后门检测规则)
13. [Linux持久化扩展规则](#linux持久化扩展规则)
14. [供应链/第三方运维检测规则](#供应链第三方运维检测规则) — **v3.0 新增**
15. [NAS设备安全检测规则](#nas设备安全检测规则) — **v3.0 新增**
16. [AI驱动攻击检测规则](#ai驱动攻击检测规则) — **v3.0 新增**
17. [MITRE ATT&CK完整映射](#mitre-attck完整映射)
18. [规则置信度说明](#规则置信度说明)

---

## 进程检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `suspicious_path` | 可疑执行路径 | high | T1059 |
| `hidden_directory` | 隐藏目录执行 | medium | T1564.001 |
| `windows_temp` | Windows临时目录执行 | high | T1204.002 |
| `known_malware` | 已知恶意进程名 | critical | T1498 |
| `process_injection` | 进程注入 | critical | T1055 |
| `living_off_land` | 滥用合法工具 | high | T1218 |

### Linux 可疑路径

```regex
^/(tmp|var/tmp|dev/shm|run)/
```
进程在系统临时目录中执行，常见于内存驻留型恶意软件。

### 隐藏目录执行

```regex
/\.[^/]+/
```
进程在隐藏目录（以`.`开头）中执行。

### Windows 临时目录

```regex
(C:\\Users\\[^\\]+\\AppData\\(Local\\)?Temp|C:\\Windows\\Temp)\\.*\\.exe
```

### 已知恶意进程

```regex
(xmrig|minerd|kworkerds|ddgs|systemten|sysguard|watchdogs|kdevtmpfsi|kinsing|cloud-mqtt|pwnrig|str2)
```

### 进程名仿冒检测（v3.0.1 新增）

```regex
# 系统进程名仿冒（字符替换）
svch0st|scvhost|expl0rer|winlog0n|csrss0|taskmrg|lsasss|svchosts|sp00lsv|lsass0|smss0|win1ogon|winl0g0n

# SETUP拼写变异
SETUO|Setuo|setuo

# 知名软件名+尾缀变体
(DingTalk|WeChat|QQMusic|QQPinyin|WXWork|Chrome|Firefox|Edge).*(64|86|32|Setup|Install|Update)
```

### 数字签名异常检测（v3.0.1 新增）

| 条件 | 严重等级 | 说明 |
|------|----------|------|
| 系统目录(C:\Windows\*)下进程SignatureStatus != Valid | Critical | 系统文件可能被恶意替换 |
| 知名厂商进程签名无效 | High | 盗用身份/侧加载攻击可能 |
| SignatureStatus == HashMismatch | Critical | 文件已被篡改 |
| SignatureStatus == NotSigned 且路径非标准 | Medium | 需人工确认 |

### Living-off-the-Land 滥用

```regex
(certutil|bitsadmin|mshta|mavinject|pcalua|rasautou|sdclt|wab|forfiles|schtasks|wmic)\\.exe
```
可疑特征：下载远程文件、Base64解码执行、创建计划任务等。

---

## 持久化机制检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `registry_run` | 注册表自启动 | critical | T1547.001 |
| `scheduled_task` | 计划任务 | high | T1053.005 |
| `wmi_persistence` | WMI事件订阅 | critical | T1546.003 |
| `startup_folder` | 启动文件夹 | high | T1547.004 |
| `service_hijack` | 服务劫持 | critical | T1543.003 |
| `shell_extension` | Shell扩展 | high | T1646 |
| `boot_key` | 引导键值 | critical | T1542 |
| `cron_persistence` | Linux crontab持久化 | high | T1053.003 |
| `systemd_persistence` | systemd服务持久化 | high | T1543.002 |
| `logon_script` | 登录脚本后门 | critical | T1037.001 |
| `com_hijack` | COM对象劫持 | high | T1546.015 |
| `shell_config_hijack` | Shell配置劫持（bashrc/profile/zshrc） | high | T1546.004 |
| `user_systemd` | 用户级systemd服务 | high | T1543.002 |
| `kernel_module_persist` | 内核模块持久化 | critical | T1547.006 |
| `xdg_autostart` | XDG自启动 | high | T1547.004 |
| `pkg_hook` | 包管理器钩子劫持 | high | T1574.006 |

### 注册表自启动

```regex
(Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce))
```
可疑特征：指向临时目录、使用编码命令、rundll32调用非系统DLL。

### 计划任务异常

```regex
(schtasks\\.exe.*/create|powershell.*Register-ScheduledTask|at\\.exe.*\\d{1,2}:\\d{2})
```
可疑特征：SYSTEM权限非系统任务、触发器为登录/空闲、执行编码命令、间隔<5分钟。

### WMI持久化

```regex
(__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding)
```

### Linux crontab异常

```regex
(crontab.*-e|/etc/cron\\.(d|daily|hourly|weekly|monthly)/)
```
可疑特征：间隔极短(`*/1`)、网络下载脚本(`curl|wget pipe bash`)、隐藏目录脚本、base64解码执行。

### systemd持久化

```regex
(\\[Unit\\].*\\[Service\\].*ExecStart=|systemctl.*enable)
```
可疑特征：用户级服务(`~/.config/systemd/user/`)、ExecStart指向临时目录、Restart=always。

### 登录脚本后门 (UserInitMprLogonScript)

```regex
UserInitMprLogonScript|HKCU\\\\Environment.*LogonScript
```
可疑特征：指向非系统路径的脚本/可执行文件、编码命令。

### COM劫持

可疑特征：CLSID的`InprocServer32`指向非系统路径、DLL不在`C:\Windows\System32\`。

### Shell配置劫持

```regex
(~/\\.(bashrc|profile|zshrc|bash_profile)|/etc/(profile|bash\\.bashrc))
```
可疑特征：文件末尾追加`curl|wget`下载执行、base64编码命令、修改PATH指向恶意目录。

### 用户级systemd

```regex
~/\\.config/systemd/user/.*\\\\.service
```
可疑特征：非标准用户服务、ExecStart指向临时目录。

### 内核模块持久化

```regex
/etc/modules-load\\.d/.*\\\\.conf
```
可疑特征：加载非标准内核模块、模块路径指向用户目录。

### XDG自启动

```regex
~/\\.config/autostart/.*\\\\.desktop
```
可疑特征：非标准`.desktop`文件、Exec指向隐藏目录。

### 包管理器钩子

```regex
/etc/(apt/apt\\.conf\\.d|yum/pluginconf\\.d|dnf/plugins)
```
可疑特征：非标准钩子脚本、`Post-Invoke`执行下载命令。

---

## 账号检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `spoofed_system` | 仿冒系统账号 | high | T1136.001 |
| `hidden_account` | 隐藏账号 | critical | T1136.001 |
| `suspicious_name` | 可疑命名账号 | medium | T1136.001 |
| `privilege_escalation` | 权限提升 | critical | T1548 |
| `empty_password` | 空密码账号 | critical | T1078.001 |
| `unusual_login` | 异常登录 | high | T1078 |
| `cloned_account` | 克隆账号（SAM F值相同） | critical | T1136.001 |
| `uid0_backdoor` | UID=0后门账号 | critical | T1548.001 |

### 仿冒系统账号

```regex
^(administrator|root|system|guest|admin)\\d+$
```

### 隐藏账号

```regex
(^\\.|.*\\$$)
```
用户名以点开头或以`$`结尾（Windows隐藏账号）。

### 空密码/UID=0后门

```regex
^[^:]+::\\d+:\\d+:|^[^:]+:x:0:0:
```

### Windows克隆账号

SAM中不同RID但F值相同的账号 → 克隆账号后门。

---

## IP威胁情报规则

| 类型 | 说明 | 风险等级 | 误报白名单 |
|------|------|----------|-----------|
| `malicious_port` | 已知恶意端口 | critical | 4444→天融信VPN; 11111→WPS; 6379→合法Redis; 8443→合法HTTPS |
| `known_c2` | 已知C2服务器 | critical | — |
| `tor_exit` | Tor出口节点 | medium | — |
| `cryptomining_pool` | 挖矿矿池 | high | — |
| `close_wait_flood` | CLOSE_WAIT大量累积 | high | — |
| `dns_anomaly` | DNS异常查询 | high | — |
| `reverse_shell` | 反向Shell连接 | critical | 同malicious_port |
| `data_exfil` | 数据外泄目标 | critical | — |

### 恶意端口列表（2026年更新）

| 端口 | 常见用途 | ATT&CK | 已知误报 |
|------|----------|---------|----------|
| 4444 | Metasploit默认 | T1059 | 天融信VPN内部通信 |
| 5555 | 安卓ADB/恶意软件 | T1571 | — |
| 6666 | IRC/后门 | T1071 | — |
| 7777 | 木马常用 | T1571 | — |
| 8888 | 代理/木马 | T1090 | Jupyter Notebook |
| 9999 | 远程控制 | T1021 | — |
| 11111 | 自定义远控 | T1021 | WPS Office内部通信 |
| 12345 | NetBus木马 | T1059 | — |
| 31337 | Back Orifice | T1059 | — |
| 6379 | Redis未授权 | T1190 | 合法Redis服务 |
| 670/8670 | 银狐C2（2025.08~11） | T1571 | — |
| 5676/58676 | 银狐C2（2025.11~2026.01） | T1571 | — |
| 8880 | 银狐C2（2026.03至今） | T1571 | — |
| 5050 | 银狐C2（2026.03） | T1571 | — |

### CLOSE_WAIT 检测

**阈值**：单IP CLOSE_WAIT连接 ≥10
**说明**：通常表示后门程序未正确关闭连接、反向Shell保持连接、C2心跳异常。

### DNS异常检测

```regex
([a-z0-9]{16,}\\.(tk|ml|ga|cf|gq)|[a-f0-9]{32,}\\.|x\\.[a-z]+\\.[a-z]+)
```

---

## Webshell检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `eval_function` | eval代码执行 | high | T1505.003 |
| `system_exec` | 系统命令执行 | high | T1059 |
| `base64_decode` | Base64解码 | medium | T1027 |
| `file_operation` | 可疑文件操作 | medium | T1105 |
| `common_name` | 常见Webshell文件名 | high | T1505.003 |
| `one_liner` | 一句话木马 | critical | T1505.003 |
| `memory_shell` | 内存马特征 | critical | T1505.003 |
| `antivirus_kill` | 杀软对抗 | critical | T1562.001 |

### 一句话木马

```regex
(\\$_(POST|GET|REQUEST|COOKIE)\\[.*\\]\\s*\\(|assert\\s*\\(\\s*\\$_(POST|GET|REQUEST)|eval\\s*\\(\\s*\\$_(POST|GET|REQUEST))
```

### 内存马(Java)

```regex
(Application\\.setAttribute|ClassLoader\\.defineClass|Instrumentation\\.redefineClasses|java\\.lang\\.reflect\\.Proxy.*invoke)
```

### 杀软对抗

```regex
(taskkill.*(/f|/F).*(av|360|safe|huorong|kwatch|mcafee|norton|defender)|net\\s+stop\\s+(av|360|safe|huorong|kwatch|mcafee|norton|defender))
```

---

## 内存注入检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `page_rwx` | RWX内存区域 | critical | T1055 |
| `reflective_dll` | 反射式DLL加载 | critical | T1055.001 / T1620 |
| `process_hollowing` | 进程空心化 | critical | T1055.012 |
| `thread_hijack` | 线程劫持 | critical | T1055.003 |
| `beacon_pattern` | C2 Beacon特征 | critical | T1071 |
| `code_cave` | 代码洞穴 | high | T1055 |
| `ntdll_unhooking` | ntdll Unhooking（EDR致盲） | critical | T1562.001 |
| `pool_party` | PoolParty线程池注入 | critical | T1055.012 |
| `svchost_injection` | svchost进程注入 | critical | T1055.001 |
| `ld_preload_hide` | LD_PRELOAD隐藏进程 | high | T1014 |

### RWX内存区域

```regex
PAGE_EXECUTE_READWRITE|rwxrwxrwx|0x40\\s*\\(PAGE_EXECUTE_READWRITE\\)
```

### ntdll Unhooking

```regex
ntdll\\.dll.*re-?map|ReadFile.*ntdll|NtCreateSection.*ntdll|NtMapViewOfSection.*ntdll
```
银狐从磁盘重新读取ntdll.dll覆盖已加载ntdll的`.text`节，绕过EDR的API HOOK。

### PoolParty线程池注入

```regex
PostQueuedCompletionStatus|ZwSetIoCompletion|NtSetIoCompletion
```
银狐通过线程池I/O完成端口注入shellcode到svchost等系统进程。

### svchost进程注入

```regex
OpenProcess.*svchost|WriteProcessMemory.*svchost|CreateRemoteThread.*svchost
```
提权后打开svchost写入shellcode，是远端拉取shellcode攻击链的典型环节。

---


### RWX 误报过滤策略 (v3.3.0)

实际 IR 分析中 RWX 区域极其常见（浏览器 JIT、Electron、.NET CLR 等），需分层过滤：

| 类别 | 进程 | 过滤条件 | 处理 |
|------|------|----------|------|
| 浏览器 JIT | chrome, msedge, firefox, opera, brave | sizeKB < 1024 AND type=MEM_PRIVATE | 降级为 info |
| Electron JIT | Codex, WeChat, Weixin, Douyin, QQ, qmbrowser | sizeKB < 102400 (100MB) | 降级为 info |
| .NET CLR | powershell, dotnet, any CLR host | 包含 clr.dll 模块 | 降级为 info |
| 合法远控 | AweSun(向日葵), TeamViewer, AnyDesk | MEM_IMAGE + 数字签名有效 | 保留 medium，标注"需确认" |
| **重点关注** | 系统服务(cameraservice等) | MEM_PRIVATE + 无模块名 + 非系统路径 | **升为 high** |
| **重点关注** | 任意进程 | MEM_PRIVATE + 无模块名 + >10MB | **升为 high** |

### RWX 分析流程

```
收到 process_modules.csv / rwx_regions.csv
  │
  ├─ 第一步：按进程名分组统计
  │   ├─ 浏览器类 → 应用 JIT 过滤
  │   ├─ 系统进程 → 检查模块名
  │   └─ 未知进程 → 保留高优先级
  │
  ├─ 第二步：筛选可疑项
  │   ├─ MEM_PRIVATE + 无模块名 → 可疑注入
  │   ├─ MEM_IMAGE + 非预期路径 → DLL劫持
  │   └─ 单进程总RWX > 200MB → 异常
  │
  ├─ 第三步：交叉验证
  │   ├─ 该进程是否有网络连接？
  │   ├─ 启动路径是否在临时目录？
  │   ├─ 是否有数字签名？
  │   └─ 是否在计划任务/服务中？
  │
  └─ 第四步：输出
      ├─ 无异常 → "未发现内存注入迹象"
      ├─ 有可疑 → 列出 PID/大小/类型/模块
      └─ 确认恶意 → 给出处置命令
```

### Cobalt Strike / Brute Ratel 内存特征

```regex
# Cobalt Strike Beacon
beacon\.(dll|x64\.dll|x86\.dll)|%s \(admin\)|MZ.*beacon|MZ.*this program cannot

# Brute Ratel C4 (Badger)
BadgerConfig|MZ.*brute.?ratel|BRC4_.*Config

# Sliver
sliver_(dll|exe|service)|ImplantConfig|Sliver.*C2

# Nighthawk
Nighthawk.*C2|nighthawk_init
```

### 远程线程 / APC 注入检测

```regex
CreateRemoteThread|NtCreateThreadEx.*RWX|QueueUserAPC.*PAGE_EXECUTE|NtQueueApcThread.*PAGE_EXECUTE
```

### 反射式 DLL 加载

```regex
ReflectiveLoader|LoadLibraryA.*memcpy|LoadLibraryA.*VirtualAlloc|fIWzqBKO  # 开源反射加载器特征
```

### 进程空心化

```regex
NtUnmapViewOfSection|ZwUnmapViewOfSection.*PAGE_EXECUTE|CreateProcess.*CREATE_SUSPENDED.*SetThreadContext.*ResumeThread
```

### 进程注入检测综合特征

```regex
# 打开进程获取句柄
OpenProcess.*0x001F0FFF|OpenProcess.*PROCESS_ALL_ACCESS

# 写入远程进程内存
WriteProcessMemory.*PAGE_EXECUTE|VirtualAllocEx.*PAGE_EXECUTE

# 创建远程线程
CreateRemoteThread|RtlCreateUserThread|NtCreateThreadEx
```

### 银狐专项 - ntdll Unhooking 致盲EDR

```regex
# 磁盘→内存重新映射ntdll
ntdll\.dll.*re-?map|ReadFile.*ntdll|NtCreateSection.*ntdll|NtMapViewOfSection.*ntdll
```
银狐从磁盘重新读取ntdll.dll覆盖已加载ntdll的`.text`节，绕过EDR的API HOOK。

### PoolParty 线程池注入

```regex
PostQueuedCompletionStatus|ZwSetIoCompletion|NtSetIoCompletion
```
银狐通过线程池I/O完成端口注入shellcode到svchost等系统进程。

### svchost 进程注入

```regex
OpenProcess.*svchost|WriteProcessMemory.*svchost|CreateRemoteThread.*svchost
```
## 横向移动检测规则

| 类型 | 说明 | 风险等级 | ATT&CK |
|------|------|----------|---------|
| `smb_scan` | SMB内网扫描 | high | T1021.002 |
| `rdp_bruteforce` | RDP暴力破解 | critical | T1021.001 |
| `ssh_bruteforce` | SSH暴力破解 | critical | T1021.004 |
| `psexec_deploy` | PsExec部署 | high | T1021.002 |
| `wmi_remote` | WMI远程执行 | high | T1047 |
| `pass_the_hash` | 哈希传递攻击 | critical | T1550.002 |
| `arp_anomaly` | ARP/MAC异常 | high | T1595.002 |
| `winrm_remote` | WinRM远程管理 | high | T1021.006 |

---

## 高级对抗检测规则

> 合并原 v2.3 银狐专项和远控对抗两大维度。`fox_tag` 标识银狐家族特征，`generic_rat_tag` 标识通用远控对抗特征。

| 规则ID | 名称 | 风险 | 标签 | ATT&CK |
|--------|------|------|------|---------|
| SFOX-0001 | 银狐C2通信端口（670/8670/5676/58676/8880/5050） | critical | fox_tag | T1571 |
| SFOX-0002 | 银狐钓鱼域名（sckca.top等） | high | fox_tag | T1189 |
| SFOX-0003 | ntdll Unhooking致盲EDR | critical | fox_tag | T1562.001 |
| SFOX-0004 | PoolParty线程池注入 | critical | fox_tag | T1055.012 |
| SFOX-0005 | 自编写内核驱动/TrueSightKiller | critical | fox_tag | T1014 |
| SFOX-0006 | 杀软对抗线程（While True循环） | critical | fox_tag | T1562.001 |
| SFOX-0007 | 远端拉取加密shellcode | critical | fox_tag | T1059.001 |
| SFOX-0008 | 虚假弹窗诱导下载 | high | fox_tag | T1189 |
| SFOX-0009 | 空壳公司域名注册 | medium | fox_tag | T1583.001 |
| SFOX-0010 | 反沙箱/反调试（16种技术） | high | fox_tag | T1497 |
| SFOX-0011 | OLLVM+VMP代码混淆 | high | fox_tag | T1027 |
| SFOX-0012 | 系统服务持久化（UserDataSvc_） | critical | fox_tag | T1543.003 |
| SFOX-0013 | 钓鱼诱饵主题（金税/税务/补贴） | high | fox_tag | T1566.001 |
| SFOX-0014 | 白加黑加载（入口篡改/DLL侧加载） | critical | fox_tag | T1574.001 |
| SFOX-0015 | Gh0st/winos远控模块 | critical | fox_tag | T1071 |
| SFOX-0016 | 微信/QQ账号劫持 | critical | fox_tag | T1534 |
| SFOX-0017 | 投递挖矿模块 | high | fox_tag | T1496 |
| SFOX-0018 | 多阶段加载器（6阶段） | critical | fox_tag | T1105 |
| SFOX-0019 | 滥用合法企业管理软件 | high | fox_tag | T1195 |
| SFOX-0020 | 进程再生机制 | critical | fox_tag | T1562 |
| RAT-0001 | 杀软进程异常缺失 | critical | generic_rat_tag | T1562.001 |
| RAT-0002 | 非微软签名驱动加载 | critical | generic_rat_tag | T1014 |
| RAT-0003 | explorer.exe被注入 | critical | generic_rat_tag | T1055.001 |
| RAT-0004 | 进程提权后注入svchost | critical | generic_rat_tag | T1055.001 |
| SFOX-0027 | 2026年5月CVERC新变种（人事主题钓鱼+log.dll+8880） | critical | fox_tag | T1566.002 |
| SFOX-0028 | 2026年5月CNCERT风险提示（SEO仿冒软件+系统进程注入） | critical | fox_tag | T1189 |
| SFOX-0029 | UTG-Q-1000 Zinst仿冒系列（ZwTraceEvent hook+hosts篡改） | critical | fox_tag | T1562.002 |
| SFOX-0030 | 2026年7月Cato分析（三驱动BYOVD+FaCai2024+双恢复） | critical | fox_tag | T1574.002 |
| SFOX-0031 | 2026年7月瑞星DoH变种（DoH隧道+Telegram窃密） | critical | fox_tag | T1071.004 |
| SFOX-0032 | 2026年海外税务钓鱼（ValleyRAT+ABCDoor+RustSL） | critical | fox_tag | T1566.001 |
| SFOX-0033 | 2026新增恶意域名库（CNCERT/CN-SEC/奇安信等） | critical | fox_tag | T1071 |
| SFOX-0034 | 2026新增C2/IP库 | critical | fox_tag | T1071 |
| SFOX-0035 | 2026新增样本哈希库 | critical | fox_tag | T1204.002 |

### 2026 新增银狐变种速览

> 详细情报源与 IOC 见 `references/SILVER_FOX_2026_INTEL.md`。

| 变种/活动 | 时间 | 关键指标 | 排查入口 |
|-----------|------|----------|----------|
| CVERC 人事主题钓鱼 | 2026-05 | `log.dll`+`installer.exe`，`:8880/getinstall64` | 进程模块、netstat |
| CNCERT SEO 仿冒投递 | 2026-05 | 仿 Chrome/WPS/Clash/VPN，注入 `ctfmon/sihost/svchost/elevation_service`，C2 443/22 | 进程树、下载记录 |
| Zinst 系列（UTG-Q-1000） | 2026-06~07 | `zinst.*`/`zinstaller-*`，`TCLService`，hosts 篡改，`ranchserv.jpg` 驱动 | 计划任务、服务、hosts |
| 日本制造业 ValleyRAT | 2026-07 | `ConvertToPDF.exe`/`PDFDirect.exe` 侧加载 `PDFCORE8.dll`，`BootRepair.sys`/`EnPortv.sys`/`wsftprm.sys`，`FaCai2024`，`HKCU\Console\0` | 驱动服务、注册表、进程模块 |
| 瑞星 DoH 变种 | 2026-07 | 雷电模拟器伪装，`wjcapture.dll`，`oidng2.duoshit.com`，DoH 223.5.5.5/8.8.8.8，`netcssv` 服务 | DoH 流量、服务、Telegram tdata |
| 海外税务钓鱼 | 2026-01~07 | `teamspeak_control.dll`，`adreses.vip` 集群，`AppClient` 计划任务，`C:\ProgramData\Tailscale` | 计划任务、隐藏目录、网络外联 |

### 银狐C2端口变迁时间线

| 端口 | 活跃周期 | 样本量 |
|------|----------|--------|
| 670/8670 | 2025-08 ~ 2025-11 | 552 |
| 5676/58676 | 2025-11 ~ 2026-01 | 409 |
| 8880 | 2026-03至今 | 184 |
| 5050 | 2026-03 | — |

### 银狐攻击链（完整7阶段）

1. **钓鱼传播** → 仿冒税务/违纪名单/补贴福利/金税四期五期/放假通知下载MSI/ZIP/CHM
2. **白加黑/多阶段加载** → 白程序入口篡改→Shellcode→解密DLL→调用SyncCreate
3. **反沙箱反调试** → 16种技术检测沙箱/虚拟机/调试环境+Hook NtTraceEvent关闭ETW
4. **对抗杀软** → ntdll Unhooking绕过EDR HOOK + TrueSightKiller/自编写驱动关闭杀软
5. **进程注入持久化** → PoolParty注入svchost/explorer + 计划任务+启动文件夹+UserDataSvc_服务多重守护
6. **C2通信** → 670→5676→8880端口变迁，20+C2服务器 + Gh0st/winos远控功能模块上线
7. **横向利用** → 劫持微信/QQ账号冒充身份内网传播 + 投递挖矿模块盗窃算力

### 银狐杀软进程检测表（30+进程）

```
360Safe.exe, 360tray.exe, ZhuDongFangYu.exe, 360sd.exe, 360rp.exe,
360rps.exe, 360leakfixer.exe, 360sdrun.exe, 360sdupd.exe, 360FileGuard.exe,
dep360.exe, SafeDog.exe, SoftMgr.exe, kxes.exe, QMDownload.exe,
QHSafeMain.exe, QHSafeTray.exe, QQPCTray.exe, QQPCRTP.exe, TrojanHunter.exe,
HipsDaemon.exe, HipsMain.exe, HipsTray.exe, HRUpdate.exe, rfw.exe,
Bka.exe, BLuPro.exe, BkavService.exe, LenovoPcManager.exe, LAVService.exe,
wsctrl7.exe, wsctrl10.exe, wsctrl11.exe
```

### 反沙箱技术16项

QueryPerformanceCounter/GetTickCount64(时间流速)、rdtsc(虚拟机检测)、GlobalMemoryStatusEx(内存<2GB)、GetSystemInfo(CPU核心<2)、PfxInitialize(0x200)、DllGetClassObject(pid.dll)、SxIn.dll加载检测、NtTraceEvent Hook(关闭ETW)、NtSetInformationThread(反调试)、CheckRemoteDebuggerPresent、IsDebuggerPresent、OutputDebugStringA崩溃、进程双开检测、窗口枚举检测沙箱窗口名、CPUID检测Hypervisor、WMI查询BIOS版本

---

## 挖矿病毒检测规则

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| 已知挖矿进程 | critical | xmrig, minerd, kworkerds, ddgs, kinsing, pwnrig, sysguard, sysupdate |
| CPU持续高占用 | high | 单进程CPU >80% 持续运行 |
| 定时任务下载脚本 | critical | `*/1 * * * * curl http://...\\|bash` |
| 隐藏目录挖矿 | high | `/tmp/.X11-unix/`, `/usr/bin/.sshd/`, `/.cache/` |
| 盖茨木马(DDoS+挖矿) | critical | `/etc/rc.d/rc3.d/S97DbSecurity*`，命令替换 |
| stratum矿池连接 | high | 连接已知矿池端口(3333/4444/5555/14444/14433) |

---

## 勒索病毒检测规则 v3.0

> v3.0 重大升级：借鉴 Solar 应急响应团队实战经验，从4条通用特征扩展为家族分类深度检测。
> 详细家族规则见 `rules/ransomware_family_rules.json`，YARA 规则见 `rules/yara_rules/ransomware.yar`。

### 通用检测指标（所有家族）

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| 卷影副本被删除 | critical | `vssadmin delete shadows /all`，`wmic shadowcopy delete` |
| 批量文件修改/重命名 | critical | 短时间内大量文件写入，扩展名变更 |
| 勒索信文件 | critical | README.txt / HOW_TO_DECRYPT.txt / !!!YOUR_FILES_ARE_ENCRYPTED!!! / info.hta / 家族名.txt |
| 备份清除 | critical | `wbadmin delete catalog`, `bcdedit /set recoveryenabled No`, `wmic.exe backup delete` |
| VSS服务停止 | critical | `net stop vss` / `sc stop vss` |
| 注册表DisableRestore | critical | `SystemRestore\DisableSR` / `DisableConfig` |
| ESXi VM批量关机 | critical | `vim-cmd vmsvc/power.off` / `esxcli vm process kill` |

### 家族专项检测

| 规则ID | 家族 | 特征模式 | 风险 | 置信度 |
|--------|------|----------|------|--------|
| RANS-F001 | Phobos | 勒索信bestcor@tutanota.com / .phobos后缀 / RDP入口 | critical | 0.95 |
| RANS-F002 | Hunters International | .hunters后缀 / DLS网站 / Hive演变特征 | critical | 0.90 |
| RANS-F003 | mallox | .mallox后缀 / NAS漏洞入口 / Markdown格式勒索信 | critical | 0.95 |
| RANS-F004 | BEAST/Monster(Windows) | .beast后缀 / 驱动级加密 / 含VirtualBox检测 | critical | 0.90 |
| RANS-F005 | BEAST/Monster(ESXi) | .beast后缀 / 加密.vmdk/.vmx / ESXi漏洞入口 | critical | 0.95 |
| RANS-F006 | MedusaLocker | .medusalocker后缀 / 内嵌受害人ID / 递增勒索 | critical | 0.90 |
| RANS-F007 | babyk | .babyk后缀 / 用友NC漏洞入口 / 国产内网工具辅助 | critical | 0.85 |
| RANS-F008 | .sorry | .sorry后缀 / 银狐木马关联 / 定向企业 | critical | 0.85 |
| RANS-F009 | 通用勒索行为 | `vssadmin delete shadows` + 批量file rename | critical | 0.90 |
| RANS-F010 | 勒索预防检测 | `DisableRestore` / `wbadmin delete` / `bcdedit`恢复禁用 | critical | 0.80 |

### 勒索攻击链推理（v3.0 新增）

| 入口 → 执行 → 防规 → 加密 | 家族 | 置信度 |
|---------------------------|------|--------|
| RDP弱口令→登录→部署后门→卷影删除→加密 | Phobos | High |
| NAS Web漏洞→Webshell→内网代理→横向→加密 | mallox | High |
| 用友NC漏洞→内网工具→横向数十台→虚拟机加密 | babyk | High |
| ESXi SSH暴破→登录→批量VM关机→.vmdk加密 | BEAST | High |
| 银狐木马→C2→远控→投放勒索→加密 | .sorry | Medium |
| RDP/VPN→多后门→凭据窃取→横向→双重勒索 | Hunters | High |

---

## ESXi/虚拟化勒索专项

> v3.0 新增。Solar 有 BEAST 勒索 Linux/ESXi 版专项分析，企业虚拟化平台勒索是高发高危场景。

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| VMFS卷异常文件IO | critical | 短时间内大量.vmdk文件被修改且扩展名变更 |
| esxcli异常调用 | critical | `esxcli vm process kill --type=force`, `esxcli system shutdown` |
| ESXi SSH爆破成功 | high | auth.log 中 SSH登录成功前后伴随异常esxcli命令 |
| VM快照被删除 | critical | `vim-cmd vmsvc/snapshot.removeall` |
| ESXi防火墙规则变更 | critical | `esxcli network firewall ruleset set` 开放ICMP/SSH |
| vCenter API异常调用 | high | 大量虚拟机断电API调用（`power.off`, `shutdown`） |
| .vmdk批量重命名 | critical | vmfs卷中不符合命名规则的VM磁盘文件 |

### Linux版勒索补充

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| ELF静态编译勒索 | critical | 非标准glibc依赖的可执行文件在/tmp运行 |
| 加密目标文件类型 | critical | 检测是否尝试加密 .doc .xls .pdf .jpg .sql .db .bak .tar.gz .vmdk .vmx |
| 停止数据库服务 | critical | `systemctl stop mysql\|postgresql\|mariadb\|mongod\|elasticsearch` |
| 卸载备份存储 | critical | `umount /backup` / `umount /mnt/backup*` |

---

## 供应链/第三方运维检测规则

> v3.0 新增。Solar 多次强调第三方运维盲区作为入侵入口，企业勒索事件中供应链/第三方运维攻击占比显著上升。

| 规则ID | 检测项 | 特征 | 风险 | ATT&CK |
|--------|--------|------|------|--------|
| SC-0001 | VPN/IPMI/带外管理暴露 | 防火墙规则放行623(IPMI)/7578(SoL)/非标准VPN端口 | high | T1133 |
| SC-0002 | 第三方运维IP异常活动 | 非工作时间的RDP/SSH来自第三方IP段 | high | T1078 |
| SC-0003 | 共享/通用密码 | SAM中多个用户相同NTLM Hash | critical | T1078 |
| SC-0004 | 非标准管理端口暴露 | 3389/22/5900/9090/10000映射到公网 | high | T1190 |
| SC-0005 | 供应链软件漏洞 | 用友NC/金蝶/OA系统已知CVE被利用 | critical | T1190 |
| SC-0006 | 供应链软件后门/篡改 | 系统文件被修改(debsums/rpm -Va) + 安装时间异常 | critical | T1195 |
| SC-0007 | 第三方远程桌面工具 | ToDesk/向日葵/TeamViewer异常安装或运行 | high | T1219 |

### 检查清单

1. 防火墙规则中是否有过于宽泛的放行规则（0.0.0.0/0 → 3389/22）
2. 第三方运维IP是否有非工作时间访问记录
3. VPN账号是否存在共享/通用密码
4. IPMI/BMC是否暴露到公网
5. NAS设备Web管理面板是否暴露
6. 供应链软件（用友/金蝶/OA）是否有未修补漏洞
7. 近期安装的软件是否有可疑来源

---

## NAS设备安全检测规则

> v3.0 新增。Solar 有 mallox 勒索通过 NAS 漏洞入侵的实战案例。

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| NAS Web面板暴露 | high | 5000/5001(Synology)/8080(QNAP)端口对外开放 |
| NAS异常SSH登录 | high | NAS设备auth.log异常登录 |
| NAS Web漏洞利用 | critical | Web日志中的目录遍历/命令注入/RCE路径 |
| NAS弱口令 | high | admin空密码/默认密码 |
| NAS进程异常 | high | /volume1/@tmp/下异常可执行文件 |
| SMB共享弱访问控制 | medium | 匿名SMB共享可写入 |

### NAS平台特定检测

| 平台 | 默认端口 | 已知漏洞模式 |
|------|----------|-------------|
| Synology DSM | 5000/5001 | CVE-2022-27556远程代码执行 |
| QNAP QTS | 8080 | CVE-2022-27596/QLocker |
| Asustor ADM | 8000/8001 | CVE-2022-26693 |
| TerraMaster TOS | 8181 | CVE-2022-24990 |
| WD My Cloud | 80/443 | CVE-2018-17153 |

---

## AI驱动攻击检测规则

> v3.0 新增。Solar 2026年多次发布AI驱动攻击预警，攻击者利用AI加速零日漏洞开发与自动化攻击。

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| 极速扫描-利用间隔<10秒 | high | auth.log相邻登录尝试间隔<10秒，非人类行为模式 |
| AI生成钓鱼邮件 | high | 邮件内容无语法错误、翻译自然、从可疑IP来源 |
| LLM辅助Webshell | medium | 代码注释风格一致、无传统混淆特征、使用高级API调用 |
| 自动化漏洞利用链 | high | 入侵时间窗口内多条不同类型CVE的快速尝试 |
| AI辅助社会工程 | medium | 引用真实人员信息、定制化钓鱼模板 |

---

## Linux后门检测规则

| 特征 | 风险 | 检测方法 |
|------|------|----------|
| SSH软连接后门 | critical | `ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=8888` |
| OpenSSH后门 | critical | sshd二进制被替换，含ILOG/OLOG/SECRETPW |
| PAM后门 | critical | pam_unix_auth.so被替换 |
| 系统命令替换 | critical | ps/netstat/ls被替换为恶意版本 |
| 盖茨木马特征 | critical | `/etc/rc.d/rc3.d/S97DbSecurity*` |
| LD_PRELOAD隐藏进程 | high | `/etc/ld.so.preload`加载libprocesshider.so |

---

## MITRE ATT&CK完整映射

### 初始访问 (Initial Access)

| 技术ID | 技术名称 | 对应检测 | 标签 |
|--------|----------|----------|------|
| T1190 | 利用面向公众的应用 | Webshell检测 | — |
| T1133 | 外部远程服务 | 异常外联/远控软件检测 | — |
| T1189 | 驱动式妥协 | 银狐钓鱼域名/虚假弹窗诱导下载检测 | fox_tag |
| T1566.001 | 鱼叉式钓鱼附件 | 银狐钓鱼诱饵主题(金税/税务/补贴) | fox_tag |
| T1195 | 供应链攻击 | 滥用合法企业管理软件(ip-guard/固信/阳途) | fox_tag |

### 执行 (Execution)

| 技术ID | 技术名称 | 对应检测 | 标签 |
|--------|----------|----------|------|
| T1059.001 | PowerShell | 编码命令/无文件攻击/远端shellcode | fox_tag |
| T1059.003 | Windows命令行 | 可疑进程检测 | — |
| T1059.004 | Unix Shell | 临时目录执行检测 | — |
| T1204.002 | 恶意文件执行 | 临时目录/用户目录执行检测 | — |
| T1105 | 入口工具传输 | 多阶段加载器(6阶段) | fox_tag |

### 持久化 (Persistence)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1547.001 | 注册表Run键 | 持久化检测 |
| T1547.004 | 启动文件夹 | 持久化检测 / XDG自启动 |
| T1547.005 | Security Support Provider | LSA配置检测 |
| T1547.006 | 内核模块和扩展 | Linux内核模块持久化 |
| T1053.003 | Linux crontab | 持久化检测 |
| T1053.005 | 计划任务 | 持久化检测 |
| T1543.002 | systemd服务 | 持久化检测 / 用户级systemd |
| T1543.003 | Windows服务 | 服务劫持检测 / UserDataSvc_服务 |
| T1546.003 | WMI事件订阅 | 持久化检测 |
| T1546.004 | Unix Shell配置 | bashrc/profile/zshrc劫持 |
| T1546.010 | AppInit_DLLs | DLL注入持久化 |
| T1546.011 | Application Shimming | AppCompatCache/Shim |
| T1546.012 | COM劫持 | COM对象InprocServer32异常 |
| T1546.015 | 组件对象模型劫持 | ExcludeFromKnownDlls |
| T1037.001 | 登录脚本 | UserInitMprLogonScript后门 |
| T1037.004 | 组策略脚本 | 组策略启动/关机脚本 |
| T1037.005 | 启动项 | 启动文件夹异常 |
| T1136.001 | 创建账号 | 异常账号/克隆账号检测 |
| T1505.003 | Web Shell | Webshell检测 |
| T1574.001 | DLL搜索顺序劫持 | 白加黑加载 |
| T1574.002 | DLL侧加载 | 白加黑加载(入口点篡改) |
| T1574.006 | 动态链接器劫持 | apt/yum hook劫持 |
| T1574.011 | 服务注册表权限弱 | ExcludeFromKnownDlls |

### 权限提升 (Privilege Escalation)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1548 | 滥用提权机制 | 异常账号/UID=0检测 |
| T1548.001 | Setuid和Setgid | SUID Shell检测 |
| T1548.002 | Bypass UAC | UAC绕过检测 |
| T1068 | 漏洞利用提权 | 内核漏洞/服务漏洞检测 |

### 防御规避 (Defense Evasion)

| 技术ID | 技术名称 | 对应检测 | 标签 |
|--------|----------|----------|------|
| T1055 | 进程注入 | 内存注入检测 | — |
| T1055.001 | DLL注入 | 反射式DLL检测 / svchost注入 | generic_rat_tag |
| T1055.003 | 线程劫持 | 注入检测 | — |
| T1055.012 | 进程空心化 | 空心化/PoolParty线程池注入检测 | fox_tag |
| T1562.001 | 禁用安全工具 | 杀软对抗检测/ntdll Unhooking/Rootkit关闭杀软 | fox_tag |
| T1027 | 混淆文件/信息 | 编码命令检测/OLLVM+VMP代码混淆 | fox_tag |
| T1564.001 | 隐藏文件/目录 | 隐藏目录检测 | — |
| T1564.002 | 隐藏用户 | $后缀账号/克隆账号检测 | — |
| T1620 | 反射式代码加载 | 反射DLL检测 | — |
| T1218 | 签名二进制代理执行 | LotL滥用检测 | — |
| T1014 | Rootkit | LD_PRELOAD/命令替换/自编写内核驱动(kabuto.sys)/VMP加壳驱动 | fox_tag |
| T1574.011 | 服务注册表权限弱 | ExcludeFromKnownDlls | — |
| T1497 | 虚拟化/沙箱规避 | 反沙箱16项技术(时间流速/内存/CPU/CPUID/窗口枚举) | fox_tag |

### 凭据访问 (Credential Access)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1550.002 | 哈希传递 | 横向移动检测 |
| T1003 | 操作系统凭据转储 | 内存分析 |
| T1534 | 内部鱼叉式钓鱼 | 微信/QQ账号劫持 |

### 横向移动 (Lateral Movement)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1021.001 | RDP | 横向移动检测 |
| T1021.002 | SMB | 横向移动检测 |
| T1021.004 | SSH | 横向移动检测 |
| T1021.006 | WinRM | 横向移动检测 |
| T1047 | WMI远程执行 | 横向移动检测 |
| T1560 | 数据暂存 | 网络共享访问检测 |
| T1595.002 | 网络扫描 | ARP/MAC异常 |

### 命令与控制 (Command and Control)

| 技术ID | 技术名称 | 对应检测 | 标签 |
|--------|----------|----------|------|
| T1071.001 | Web协议C2 | 异常外联检测 | — |
| T1090 | 代理 | 代理连接检测 | — |
| T1571 | 非标准端口 | 恶意端口检测/银狐C2端口(670/8670/5676/58676/8880/5050) | fox_tag |
| T1219 | 远程访问软件 | 远控工具检测 | — |

### 数据外泄 (Exfiltration)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1041 | C2通道外泄 | 异常外联检测 |
| T1048 | 替代协议外泄 | 异常外联检测 |
| T1048.003 | DNS外泄 | DNS异常检测 |
| T1496 | 资源劫持 | 挖矿进程检测 |

### 影响 (Impact)

| 技术ID | 技术名称 | 对应检测 |
|--------|----------|----------|
| T1490 | 禁止系统恢复 | 勒索病毒卷影删除检测 |
| T1486 | 数据加密造成影响 | 勒索病毒批量加密检测 |
| T1583.001 | 获取域名 | 空壳公司域名注册 |

---

## 规则置信度说明

| 置信度 | 说明 | 建议操作 |
|--------|------|----------|
| 0.9-1.0 | 极高 | 立即处置 |
| 0.8-0.9 | 高 | 优先调查 |
| 0.6-0.8 | 中等 | 人工确认 |
| 0.4-0.6 | 低 | 参考使用 |
| <0.4 | 极低 | 可能误报 |

