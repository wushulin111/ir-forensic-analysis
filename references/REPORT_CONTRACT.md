# 报告契约定义 v2.0

> 借鉴 ir-suite 的 `validate_report_contract.py` 理念。定义 JSON 报告摘要的结构契约，确保每次分析的输出一致、可校验、可程序化消费。

---

## 设计目标

1. **结构一致性**：每次分析输出相同的 JSON 结构，不因 LLM 非确定性而缺失字段
2. **可校验性**：自动化管道可校验 JSON 是否符合契约（必填字段是否存在、枚举值是否合法）
3. **可消费性**：SIEM/SOAR 系统可直接解析 JSON 摘要做自动化响应
4. **自检闭环**：`self_check` 字段强制 LLM 在输出前自校验

---

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "IR Forensic Analysis Report",
  "version": "2.0.0",
  "type": "object",
  "required": ["schema", "meta", "verdict", "findings", "iocs", "timeline", "coverage", "self_check"],
  "properties": {
    "schema": {
      "type": "string",
      "const": "ir-forensic-analysis-report-v2"
    },
    "meta": {
      "type": "object",
      "required": ["analysis_time", "source_type", "hostname", "os"],
      "properties": {
        "analysis_time": { "type": "string", "format": "date-time" },
        "source_type": { "type": "string", "enum": ["linux", "windows", "unknown"] },
        "hostname": { "type": "string" },
        "ip_addresses": { "type": "array", "items": { "type": "string" } },
        "os": { "type": "string" },
        "collection_time": { "type": "string", "format": "date-time" }
      }
    },
    "verdict": {
      "type": "object",
      "required": ["threat_score", "threat_level", "max_severity", "has_c2", "has_backdoor", "has_persistence", "has_lateral"],
      "properties": {
        "threat_score": { "type": "number", "minimum": 0 },
        "threat_level": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
        "max_severity": { "type": "string", "enum": ["none", "low", "medium", "high", "critical"] },
        "has_c2": { "type": "boolean" },
        "has_backdoor": { "type": "boolean" },
        "has_persistence": { "type": "boolean" },
        "has_lateral": { "type": "boolean" },
        "has_ransomware": { "type": "boolean" },
        "ransomware_family": { "type": "string" },
        "has_supply_chain_risk": { "type": "boolean" },
        "dwell_time_hours": { "type": "number", "minimum": 0 }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "dimension", "severity", "confidence", "title"],
        "properties": {
          "id": { "type": "string", "pattern": "^F\\d{3}$" },
          "dimension": {
            "type": "string",
            "enum": ["process", "persistence", "account", "network", "webshell", "injection", "lateral", "advanced", "supply_chain"]
          },
          "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
          "confidence": { "type": "string", "enum": ["low", "medium", "high"] },
          "title": { "type": "string" },
          "detail": { "type": "string" },
          "attck_ids": { "type": "array", "items": { "type": "string" } },
          "tags": { "type": "array", "items": { "type": "string" } },
          "ioc": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "iocs": {
      "type": "object",
      "required": ["ips", "domains", "file_hashes", "file_paths", "mutexes", "ports"],
      "properties": {
        "ips": { "type": "array", "items": { "type": "string" } },
        "domains": { "type": "array", "items": { "type": "string" } },
        "file_hashes": { "type": "array", "items": { "type": "string" } },
        "file_paths": { "type": "array", "items": { "type": "string" } },
        "mutexes": { "type": "array", "items": { "type": "string" } },
        "ports": { "type": "array", "items": { "type": "integer" } },
        "ransom_note_files": { "type": "array", "items": { "type": "string" } },
        "encrypted_extensions": { "type": "array", "items": { "type": "string" } }
      }
    },
    "timeline": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["phase", "event", "confidence"],
        "properties": {
          "phase": {
            "type": "string",
            "enum": ["recon", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "c2", "exfiltration", "impact"]
          },
          "event": { "type": "string" },
          "attck_id": { "type": "string" },
          "confidence": { "type": "string", "enum": ["low", "medium", "high"] }
          "cause": { "type": "string", "description": "本事件的原因/前因" },
          "effect": { "type": "string", "description": "本事件导致的后果" },
          "chain_evidence": { "type": "string", "enum": ["time_overlap", "process_parent", "network_same_session", "file_same_hash", "none"] },
          "chain_score": { "type": "number", "minimum": 0, "maximum": 1, "description": "0.0=独立 0.5=弱关联 0.8=强因果" }
        }
      }
    },
    "coverage": {
      "type": "object",
      "required": ["total_files", "analyzed_files", "dimensions_complete"],
      "properties": {
        "total_files": { "type": "integer" },
        "analyzed_files": { "type": "integer" },
        "skipped_files": { "type": "array", "items": { "type": "string" } },
        "dimensions_complete": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["process", "persistence", "account", "network", "webshell", "injection", "lateral", "advanced", "supply_chain"]
          }
        }
      }
    },
    "config_risks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["priority", "risk", "detail"],
        "properties": {
          "priority": { "type": "string", "enum": ["P0", "P1", "P2", "P3"] },
          "risk": { "type": "string" },
          "detail": { "type": "string" }
        }
      }
    },
    "actions": {
      "type": "object",
      "properties": {
        "critical": { "type": "array", "items": { "type": "string" } },
        "high": { "type": "array", "items": { "type": "string" } },
        "medium": { "type": "array", "items": { "type": "string" } },
        "low": { "type": "array", "items": { "type": "string" } }
      }
    },
    "self_check": {
      "type": "object",
      "required": ["all_dimensions_covered", "all_critical_have_attck", "score_calculated_by_formula", "ioc_extracted", "timeline_built", "coverage_table_filled", "json_fields_valid", "config_risks_listed"],
      "properties": {
        "all_dimensions_covered": { "type": "boolean" },
        "all_critical_have_attck": { "type": "boolean" },
        "score_calculated_by_formula": { "type": "boolean" },
        "ioc_extracted": { "type": "boolean" },
        "timeline_built": { "type": "boolean" },
        "timeline_has_causal_chain": { "type": "boolean" },
        "dwell_time_calculated": { "type": "boolean" },
        "coverage_table_filled": { "type": "boolean" },
        "json_fields_valid": { "type": "boolean" },
        "config_risks_listed": { "type": "boolean" }
      }
    }
  }
}
```

---

## 契约校验规则

| # | 规则 | 错误级别 |
|---|------|----------|
| 1 | `schema` 必须为 `"ir-forensic-analysis-report-v2"` | fatal |
| 2 | `meta` 的 `analysis_time`、`source_type`、`hostname`、`os` 不能为空 | fatal |
| 3 | `verdict.threat_level` 必须为 low/medium/high/critical 之一 | fatal |
| 4 | `verdict.threat_score` 必须 ≥ 0 且与 findings 计算结果一致 | error |
| 5 | 每个 finding 的 `id` 格式为 `F001`、`F002`... | error |
| 6 | 每个 finding 的 `severity=critical` 时必须有 `attck_ids` | error |
| 7 | `iocs` 的 6 个子字段必须存在（可为空数组） | fatal |
| 8 | `coverage.dimensions_complete` 必须包含所有 9 个维度 | error |
| 9 | `self_check` 所有字段必须为 `true` | fatal |
| 10 | `config_risks` 中的 `priority` 必须为 P0-P3 之一 | warning |

**fatal** = 不通过则报告无效，必须修正
**error** = 不通过则报告质量不足，强烈建议修正
**warning** = 不通过则提示，可接受

---

## 与 ir-suite 的对比

| 维度 | ir-suite | ir-forensic-analysis v2.6+ |
|------|----------|---------------------------|
| 结构化输出 | `summary.json`（Python脚本生成） | JSON摘要（LLM生成，Schema校验） |
| 字段校验 | `validate_report_contract.py`（程序化） | `self_check`（LLM自检）+ Schema（程序化） |
| 覆盖率追踪 | `run_manifest.tsv`（脚本记录每步状态） | `coverage` 字段（LLM记录已分析文件） |
| 一致性保证 | ✅ 完全确定性（脚本） | ⚠️ LLM自检 + Schema约束双重保障 |

**核心差异**：ir-suite 的确定性来自脚本，我们来自 Schema 约束 + LLM 自检。确定性不如脚本，但比纯自由输出强得多——至少保证了字段不缺失、枚举值合法、评分可追溯。

---

## 使用方式

### LLM 生成时

1. 分析完成后，先输出 Markdown 报告
2. 在 Markdown 报告末尾，用 ```json 代码块输出 JSON 摘要
3. 生成 JSON 前逐项检查 `self_check`，确保全为 true

### 程序化消费时

```python
import json

def validate_report(report_json):
    errors = []
    r = report_json
    
    # Rule 1
    if r.get("schema") != "ir-forensic-analysis-report-v2":
        errors.append(("fatal", "schema version mismatch"))
    
    # Rule 3
    if r.get("verdict", {}).get("threat_level") not in ["low", "medium", "high", "critical"]:
        errors.append(("fatal", "invalid threat_level"))
    
    # Rule 6
    for f in r.get("findings", []):
        if f.get("severity") == "critical" and not f.get("attck_ids"):
            errors.append(("error", f"finding {f['id']}: critical without ATT&CK ID"))
    
    # Rule 9
    for k, v in r.get("self_check", {}).items():
        if not v:
            errors.append(("fatal", f"self_check.{k} is false"))
    
    return errors

# Usage
report = json.loads(report_string)
errors = validate_report(report)
fatals = [e for e in errors if e[0] == "fatal"]
if fatals:
    print("❌ Report invalid:", fatals)
else:
    print("✅ Report valid")
```
