# 规则库格式说明 v2.5

本文档详细说明经验规则库的数据格式和结构。

---

## 目录结构

```
rules/
├── process_rules.json          # 进程检测规则
├── startup_rules.json          # 启动项检测规则
├── persistence_rules.json      # 持久化机制检测规则
├── account_rules.json          # 账号检测规则
├── ip_rules.json               # IP威胁情报规则
├── webshell_rules.json         # Webshell检测规则
├── injection_rules.json        # 内存注入检测规则
├── lateral_movement_rules.json # 横向移动检测规则
├── silver_fox_rules.json       # 银狐专项+远控对抗规则 (v2.3+)
├── yara_rules/                 # YARA扫描规则
│   ├── webshell.yar
│   ├── malware.yar
│   ├── injection.yar
│   └── silver_fox.yar
├── ioc_library.json            # IOC库
├── historical_findings.json    # 历史发现记录
└── rules_updated.json          # 最新更新规则（自动生成）
```

---

## 通用字段说明

所有规则类型共享以下通用字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `rule_id` | string | 是 | 规则唯一标识符 |
| `type` | string | 是 | 规则类型 |
| `name` | string | 是 | 规则名称 |
| `description` | string | 否 | 规则描述 |
| `severity` | string | 是 | 风险等级 |
| `confidence` | float | 是 | 置信度 (0-1) |
| `mitre_attack` | string | 否 | MITRE ATT&CK技术ID |
| `created_at` | string | 是 | 创建时间 (ISO 8601) |
| `hit_count` | integer | 是 | 命中次数 |
| `last_hit` | string | 否 | 最后命中时间 |
| `known_false_positives` | array | 否 | 已知误报列表，每个条目包含 `condition`（匹配条件）、`note`（说明） |

### 风险等级 (severity)

| 等级 | 说明 | 颜色标识 |
|------|------|----------|
| `critical` | 危急 | 🔴 |
| `high` | 高危 | 🟠 |
| `medium` | 中危 | 🟡 |
| `low` | 低危 | 🟢 |

### 置信度 (confidence)

| 范围 | 说明 |
|------|------|
| 0.9-1.0 | 极高置信度 |
| 0.8-0.9 | 高置信度 |
| 0.6-0.8 | 中等置信度 |
| 0.4-0.6 | 低置信度 |
| <0.4 | 极低置信度 |

### 误报白名单 (known_false_positives) v2.5+

```json
{
  "known_false_positives": [
    {"condition": "process=TopSAP|天融信", "note": "天融信VPN内部通信"},
    {"condition": "process=WPS|wps", "note": "WPS Office内部通信"},
    {"condition": "path=C:\\Program Files\\", "note": "Program Files合法安装路径"}
  ]
}
```

- `condition`：匹配条件，支持 `process=xxx`、`path=xxx`、`port=xxx` 格式，用 `|` 分隔多个 OR 条件
- LLM 在匹配到规则后应检查 `known_false_positives`，若上下文匹配任一 condition，则标注为误报并引用对应的 `note`

---

## 进程检测规则 (process_rules.json)

### 数据结构

```json
[
  {
    "rule_id": "PROC-0001",
    "type": "suspicious_path",
    "name": "临时目录执行",
    "description": "进程在/tmp或/var/tmp目录执行",
    "pattern": "^/(tmp|var/tmp|dev/shm|run)/",
    "severity": "high",
    "confidence": 0.8,
    "known_false_positives": [],
    "created_at": "2024-01-01T00:00:00",
    "hit_count": 5,
    "last_hit": "2024-01-15T14:30:00"
  }
]
```

### 规则类型 (type)

| 类型 | 说明 |
|------|------|
| `suspicious_path` | 可疑执行路径 |
| `hidden_directory` | 隐藏目录执行 |
| `windows_temp` | Windows临时目录执行 |
| `known_malware` | 已知恶意进程名 |
| `living_off_land` | 滥用合法工具 |
| `suspicious_userdir` | 用户目录执行 |
| `av_kill_process` | 杀软/EDR进程被异常终止 |
| `xor_decrypted_process` | 异或解密进程名 |

---

## 持久化检测规则 (persistence_rules.json)

### 规则类型 (type)

| 类型 | 说明 |
|------|------|
| `registry_run` | 注册表Run键持久化 |
| `encoded_startup` | 编码命令启动 |
| `scheduled_task` | 可疑计划任务 |
| `wmi_persistence` | WMI事件订阅持久化 |
| `service_hijack` | 服务DLL劫持 |
| `cron_persistence` | Linux crontab持久化 |
| `systemd_persistence` | systemd服务持久化 |
| `startup_folder` | 启动文件夹异常 |
| `rootkit_driver_load` | 自编写内核驱动加载 |
| `explorer_injection` | explorer.exe进程注入 |
| `shell_config_hijack` | Shell配置劫持 (v2.5+) |
| `user_systemd_service` | 用户级systemd服务 (v2.5+) |
| `kernel_module_persist` | 内核模块持久化 (v2.5+) |
| `xdg_autostart` | XDG自启动 (v2.5+) |
| `pkg_hook_hijack` | 包管理器钩子劫持 (v2.5+) |

---

## IP威胁情报规则 (ip_rules.json)

### 专用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `ports` | array | 恶意端口列表 |
| `ip` | string | 恶意IP地址 |
| `port` | integer | 端口（可选） |
| `port_context` | object | 端口含义说明（如银狐C2时间线） |
| `known_false_positives` | array | 端口误报白名单 |

### 规则类型 (type)

| 类型 | 说明 |
|------|------|
| `malicious_port` | 已知恶意端口 |
| `malicious_ip` | 已知恶意IP |
| `close_wait_flood` | CLOSE_WAIT大量累积 |
| `dns_anomaly` | DNS异常查询 |
| `high_volume_exfil` | 大流量外联 |
| `reverse_shell` | 反向Shell连接 |
| `silver_fox_c2` | 银狐C2通信检测 |

---

## 银狐专项规则 (silver_fox_rules.json) v2.3+

### 专用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `tag` | string | `fox_tag`(银狐家族特征) / `generic_rat_tag`(通用远控对抗) |
| `ports` | array | C2端口列表 |
| `port_timeline` | object | 端口变迁时间线 |
| `patterns` | array | 域名/IP模式 |
| `indicators` | array | 检测指标列表 |
| `techniques` | array | 技术列表（如反沙箱16项） |
| `target_processes` | object | 目标进程名→用途映射 |
| `driver_indicators` | array | 驱动检测指标 |
| `detection_method` | string | 检测方法说明 |
| `tactic` | string | 攻击策略说明 |

---

## 规则ID生成规则

规则ID格式: `{TYPE_PREFIX}-{SEQUENCE}`

| 规则类型 | 前缀 |
|----------|------|
| 进程规则 | PROC |
| 启动项规则 | START |
| 账号规则 | ACCT |
| IP规则 | IP |
| Webshell规则 | WEB |
| 持久化规则 | PERS |
| 内存注入规则 | INJ |
| 横向移动规则 | LM |
| 银狐专项规则 | SFOX |
| 远控对抗规则 | RAT |
| IOC库条目 | IOC |

---

## 规则合并策略

当合并新规则时：

1. **去重**：基于 `rule_id + pattern` 去重，相同 rule_id 只更新 `hit_count` 和 `last_hit`
2. **保留高置信度**：相同pattern保留置信度高的规则
3. **更新hit_count**：合并命中次数
4. **保留最早创建时间**：使用最早的 `created_at`
5. **误报白名单保留**：合并时保留所有 `known_false_positives` 条目

---

## 规则优化建议

### 提高检测准确率

1. **精确匹配**：使用更精确的正则表达式
2. **多特征组合**：结合多个特征降低误报
3. **上下文分析**：考虑文件路径、时间等上下文
4. **误报白名单**：利用 `known_false_positives` 字段记录经验性误报

### 降低误报率

1. **白名单**：在规则中添加 `known_false_positives` 字段
2. **置信度调整**：根据实际命中情况调整置信度
3. **人工确认**：对高置信度规则进行人工确认

### 规则维护

1. **定期审查**：每月审查规则有效性
2. **更新威胁情报**：及时更新恶意IP/端口列表
3. **清理过期规则**：删除不再有效的规则
4. **误报反馈**：每次分析后将确认的误报写入 `known_false_positives`
