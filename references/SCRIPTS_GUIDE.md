# 脚本使用说明

本文档详细介绍应急响应取证分析Skill中各个脚本的使用方法。

---

## 脚本列表

| 脚本 | 功能 | 位置 |
|------|------|------|
| `extract_archive.py` | 解压取证文件 | `scripts/extract_archive.py` |
| `analyze_forensics.py` | 主分析脚本 | `scripts/analyze_forensics.py` |
| `rule_manager.py` | 规则库管理 | `scripts/rule_manager.py` |
| `threat_intel_lookup.py` | 多源威胁情报查询 | `scripts/threat_intel_lookup.py` |

> 威胁情报平台清单、API 配置与新增平台方法见 [THREAT_INTEL_PROVIDERS.md](THREAT_INTEL_PROVIDERS.md)。

---

## extract_archive.py - 解压脚本

### 功能

自动识别并解压Linux (tar.gz) 和 Windows (zip) 取证文件。

### 基本用法

```bash
# 自动识别格式
python scripts/extract_archive.py /path/to/IR.tar.gz

# 指定输出目录
python scripts/extract_archive.py /path/to/IR.zip -o ./extracted/

# 指定格式
python scripts/extract_archive.py /path/to/archive -t tar.gz
```

### 参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `archive` | - | 取证文件路径 | 必填 |
| `--output` | `-o` | 输出目录 | `./extracted` |
| `--type` | `-t` | 压缩包类型 | `auto` |

### 输出示例

```
[+] 成功解压: /data/IR.tar.gz
[+] 解压路径: ./extracted/IR
[+] 发现 15 个 txt 文件

[+] 解压完成!
    路径: ./extracted/IR
    TXT文件数: 15
```

### 返回值

脚本返回JSON格式的结果：

```json
{
  "success": true,
  "extracted_path": "./extracted/IR",
  "txt_files": [
    "./extracted/IR/processes.txt",
    "./extracted/IR/network.txt",
    "..."
  ],
  "error": ""
}
```

---

## analyze_forensics.py - 主分析脚本

### 功能

执行完整的取证分析，包括进程、启动项、账号、网络和Webshell检测。

### 基本用法

```bash
# 完整分析
python scripts/analyze_forensics.py ./extracted/IR/

# 指定规则库和输出目录
python scripts/analyze_forensics.py ./extracted/IR/ -r ./rules -o ./report

# 仅分析特定类型
python scripts/analyze_forensics.py ./extracted/IR/ --only processes,ips

# 与历史分析对比
python scripts/analyze_forensics.py ./extracted/IR/ -c ./historical/
```

### 参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `extracted_path` | - | 解压后的取证目录 | 必填 |
| `--rules` | `-r` | 规则库目录 | `./rules` |
| `--output` | `-o` | 报告输出目录 | `./report` |
| `--compare-with` | `-c` | 历史分析结果目录 | 可选 |
| `--only` | - | 仅分析指定类型 | 可选 |

### 分析类型选项

`--only` 参数支持以下类型（逗号分隔）：

- `processes` - 仅分析可疑进程
- `startup` - 仅分析启动项
- `accounts` - 仅分析账号
- `ips` - 仅分析网络连接
- `webshell` - 仅分析Webshell

### 输出文件

执行后会在输出目录生成以下文件：

| 文件 | 说明 |
|------|------|
| `incident_report.md` | 完整应急报告（Markdown格式） |
| `suspicious_processes.json` | 可疑进程详情 |
| `anomaly_startup.json` | 异常启动项详情 |
| `anomaly_accounts.json` | 异常账号详情 |
| `suspicious_ips.json` | 可疑外联IP详情 |
| `webshell_traces.json` | Webshell痕迹详情 |

### 输出示例

```
============================================================
应急响应取证分析
============================================================

[*] 正在加载取证文件...
    [+] 已加载: processes.txt
    [+] 已加载: network.txt
    [+] 已加载: users.txt
    ...
[*] 共加载 15 个文件

[*] 正在分析进程...
    [+] 发现 5 个可疑进程

[*] 正在分析启动项...
    [+] 发现 2 个异常启动项

[*] 正在分析账号...
    [+] 发现 1 个异常账号

[*] 正在分析网络连接...
    [+] 发现 8 个可疑外联

[*] 正在分析Webshell痕迹...
    [+] 发现 2 个Webshell痕迹

[*] 正在生成应急报告...
    [+] Markdown报告已保存: ./report/incident_report.md
    [+] suspicious_processes.json 已保存
    ...

[*] 正在更新经验规则库...
    [+] 经验规则已更新: ./rules/rules_updated.json
    [+] 新增进程规则: 5
    [+] 新增IP规则: 8
    [+] 新增Webshell规则: 3

============================================================
分析完成!
报告位置: ./report/incident_report.md
============================================================
```

---

## rule_manager.py - 规则库管理脚本

### 功能

管理、更新、合并和查询经验规则库。

### 基本用法

```bash
# 列出所有规则
python scripts/rule_manager.py -d ./rules list

# 列出特定类型规则
python scripts/rule_manager.py -d ./rules list -t process

# 添加新规则
python scripts/rule_manager.py -d ./rules add process \
    --name "自定义规则" \
    --pattern "/tmp/suspicious" \
    --severity high \
    --confidence 0.8

# 删除规则
python scripts/rule_manager.py -d ./rules delete process PROC-0001

# 合并外部规则
python scripts/rule_manager.py -d ./rules merge ./new_rules.json webshell

# 导出规则
python scripts/rule_manager.py -d ./rules export ./backup_rules.json

# 与历史对比
python scripts/rule_manager.py -d ./rules compare ./report/suspicious_processes.json

# 重置规则库
python scripts/rule_manager.py -d ./rules reset
```

### 命令详解

#### list - 列出规则

```bash
python scripts/rule_manager.py list [选项]
```

选项：
- `--type`, `-t`: 指定规则类型

#### add - 添加规则

```bash
python scripts/rule_manager.py add <类型> [选项]
```

选项：
- `--name`: 规则名称（必填）
- `--pattern`: 匹配模式（必填）
- `--severity`: 风险等级（默认: medium）
- `--confidence`: 置信度（默认: 0.7）
- `--description`: 规则描述

#### delete - 删除规则

```bash
python scripts/rule_manager.py delete <类型> <规则ID>
```

#### merge - 合并规则

```bash
python scripts/rule_manager.py merge <源文件> <目标类型>
```

#### export - 导出规则

```bash
python scripts/rule_manager.py export <输出文件> [选项]
```

选项：
- `--type`, `-t`: 指定导出类型

#### compare - 历史对比

```bash
python scripts/rule_manager.py compare <发现文件>
```

#### reset - 重置规则

```bash
python scripts/rule_manager.py reset
```

**注意**: 此操作会删除所有自定义规则，恢复默认规则。

---

## 使用流程示例

### 完整分析流程

```bash
# 1. 解压取证文件
python scripts/extract_archive.py /data/IR.tar.gz -o ./extracted/

# 2. 执行完整分析
python scripts/analyze_forensics.py ./extracted/IR/ -r ./rules -o ./report/

# 3. 查看报告
cat ./report/incident_report.md

# 4. 查看更新的规则
cat ./rules/rules_updated.json
```

### 自动化脚本示例

```bash
#!/bin/bash
# auto_analyze.sh - 自动化分析脚本

ARCHIVE=$1
EXTRACT_DIR="./extracted/$(basename $ARCHIVE .tar.gz .zip)"
REPORT_DIR="./report/$(date +%Y%m%d_%H%M%S)"
RULES_DIR="./rules"

# 解压
python scripts/extract_archive.py "$ARCHIVE" -o "$EXTRACT_DIR"
if [ $? -ne 0 ]; then
    echo "解压失败"
    exit 1
fi

# 分析
python scripts/analyze_forensics.py "$EXTRACT_DIR" -r "$RULES_DIR" -o "$REPORT_DIR"

# 发送报告（可选）
# mail -s "应急报告" admin@example.com < "$REPORT_DIR/incident_report.md"

echo "分析完成: $REPORT_DIR"
```

---

## 故障排查

### 解压失败

**问题**: `不支持的文件格式`

**解决**: 检查文件扩展名，使用 `--type` 参数指定格式

```bash
python scripts/extract_archive.py /data/IR.data -t tar.gz
```

### 分析结果为空

**问题**: 所有检测项都为0

**解决**: 
1. 检查txt文件是否正确加载
2. 确认取证文件包含所需数据
3. 查看文件编码是否为UTF-8

### 规则库加载失败

**问题**: `加载规则文件失败`

**解决**:
1. 检查规则目录路径
2. 初始化默认规则库

```bash
python scripts/rule_manager.py -d ./rules list
```

---

## 高级用法

### 批量分析

```bash
for archive in /data/IR_*.tar.gz; do
    python scripts/extract_archive.py "$archive"
done

for dir in ./extracted/IR_*/; do
    python scripts/analyze_forensics.py "$dir" -o "./report/$(basename $dir)"
done
```

### 定时任务

```bash
# crontab -e
# 每小时检查新取证文件
0 * * * * /path/to/auto_analyze.sh /data/incoming/IR_*.tar.gz
```
