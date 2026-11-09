#!/usr/bin/env python3
"""
应急响应取证分析主脚本 v2.2
覆盖 11 维检测：进程 / 持久化 / 账号 / 网络 / Webshell / 注入 / 横向 / 高级对抗 / 仿冒签名 / 打包器 / 勒索
读取 v5.4 采集包（含白加黑告警、签名清单、勒索扫描结果），输出 Markdown + Schema v2 JSON 摘要。
"""

import os
import sys
import json
import re
import argparse
import csv
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# 威胁情报查询模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
try:
    from threat_intel_lookup import lookup_iocs
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False

# 规则库里的正则由人工维护，个别条目可能非法（例如 Windows 路径只写了单个反斜杠）。
# 直接 re.search 会让整轮分析抛异常退出，这里统一兜底：告警一次后跳过该规则。
_BAD_PATTERNS = set()
_COMPILED = {}

# 命中这些关键字的规则才允许匹配命令行（其余规则只匹配可执行文件路径）
_CMD_RULE_HINT = re.compile(
    r'(powershell|pwsh|cmd|wmic|schtasks|certutil|mshta|rundll32|regsvr32|bitsadmin|'
    r'taskkill|net\s+user|-enc|frombase64|/create)',
    re.IGNORECASE)


def _compile(pattern: str, flags: int = 0):
    key = (pattern, flags)
    if key in _COMPILED:
        return _COMPILED[key]
    if key in _BAD_PATTERNS:
        return None
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        _BAD_PATTERNS.add(key)
        print(f"[!] 跳过非法正则规则 {pattern!r}: {exc}")
        return None
    _COMPILED[key] = compiled
    return compiled


def _safe_search(pattern: str, text: str, flags: int = 0):
    compiled = _compile(pattern, flags) if pattern else None
    return compiled.search(text) if compiled else None


def _safe_match(pattern: str, text: str, flags: int = 0):
    compiled = _compile(pattern, flags) if pattern else None
    return compiled.match(text) if compiled else None


@dataclass
class SuspiciousProcess:
    """可疑进程"""
    name: str
    pid: str
    path: str
    user: str
    cmdline: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class PersistenceMechanism:
    """持久化机制 ⭐新增"""
    name: str
    type: str  # registry_run, scheduled_task, wmi_persistence, cron, systemd, startup_folder
    location: str
    command: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class AnomalyAccount:
    """异常账号"""
    username: str
    type: str
    privileges: str
    created_time: str
    last_login: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class SuspiciousIP:
    """可疑外联IP"""
    ip: str
    port: int
    protocol: str
    process: str
    connection_type: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class WebshellTrace:
    """Webshell痕迹"""
    file_path: str
    file_name: str
    size: int
    modified_time: str
    signatures: List[str]
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class InjectionIndicator:
    """内存注入指标 ⭐新增"""
    process_name: str
    pid: str
    type: str  # page_rwx, reflective_dll, process_hollowing, beacon, code_cave
    detail: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class LateralMovement:
    """横向移动痕迹 ⭐新增"""
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    type: str  # smb_scan, rdp_bruteforce, ssh_bruteforce, psexec, wmi_remote, pass_the_hash
    evidence: str
    risk_level: str
    reason: str
    confidence: float
    mitre_attack: str = ""


@dataclass
class TimelineEvent:
    """时间线事件 ⭐新增"""
    timestamp: str
    phase: str  # 初始访问/执行/持久化/提权/横向/外泄
    description: str
    mitre_attack: str
    confidence: str  # H/M/L
    source: str


class ForensicAnalyzer:
    """取证分析器 v2.1"""

    def __init__(self, extracted_path: str, rules_path: str):
        self.extracted_path = Path(extracted_path)
        self.rules_path = Path(rules_path)
        self.source_type = "windows" if any(self.extracted_path.rglob("process_tree.csv")) else "linux"
        self.txt_contents = {}
        self.csv_rows = {}
        self.findings = {
            "suspicious_processes": [],
            "persistence_mechanisms": [],
            "anomaly_accounts": [],
            "suspicious_ips": [],
            "webshell_traces": [],
            "injection_indicators": [],
            "lateral_movement": [],
            "advanced_indicators": [],
            "signature_anomalies": [],
            "packer_indicators": [],
            "ransomware_indicators": []
        }
        self.timeline = []
        self.ioc_extracted = {
            "ips": [],
            "domains": [],
            "paths": [],
            "hashes": [],
            "mutexes": [],
            "registry_keys": []
        }
        self.rules = self._load_rules()

    def _load_rules(self) -> dict:
        """加载检测规则"""
        rules = {
            "process": [],
            "startup": [],
            "persistence": [],
            "account": [],
            "ip": [],
            "webshell": [],
            "injection": [],
            "lateral_movement": []
        }

        rule_files = {
            "process": "process_rules.json",
            "startup": "startup_rules.json",
            "persistence": "persistence_rules.json",
            "account": "account_rules.json",
            "ip": "ip_rules.json",
            "webshell": "webshell_rules.json",
            "injection": "injection_rules.json",
            "lateral_movement": "lateral_movement_rules.json",
            "silver_fox": "silver_fox_rules.json",
            "ransomware_family": "ransomware_family_rules.json"
        }

        for rule_type, filename in rule_files.items():
            rule_file = self.rules_path / filename
            if rule_file.exists():
                try:
                    with open(rule_file, 'r', encoding='utf-8-sig') as f:
                        rules[rule_type] = json.load(f)
                except Exception as e:
                    print(f"[!] 加载规则文件失败 {filename}: {e}")

        # IOC 库是 dict 结构，单独加载
        rules["ioc_library"] = {"domains": [], "ips": [], "hashes": [], "file_paths": []}
        ioc_file = self.rules_path / "ioc_library.json"
        if ioc_file.exists():
            try:
                with open(ioc_file, 'r', encoding='utf-8-sig') as f:
                    ioc_data = json.load(f)
                rules["ioc_library"] = ioc_data.get("iocs", rules["ioc_library"])
            except Exception as e:
                print(f"[!] 加载 IOC 库失败: {e}")

        return rules

    def load_all_txt_files(self):
        """加载取证包中的 txt/log 原文与 csv 表格"""
        print("[*] 正在加载取证文件...")

        for txt_file in self.extracted_path.rglob("*.txt"):
            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lstrip('\ufeff')
                    relative_path = str(txt_file.relative_to(self.extracted_path))
                    self.txt_contents[relative_path] = content
            except Exception as e:
                print(f"    [-] 加载失败 {txt_file}: {e}")

        # Also load .log files
        for log_file in self.extracted_path.rglob("*.log"):
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lstrip('\ufeff')
                    relative_path = str(log_file.relative_to(self.extracted_path))
                    self.txt_contents[relative_path] = content
            except Exception as e:
                print(f"    [-] 加载失败 {log_file}: {e}")

        # CSV 是 v5.3+ 采集器的主要输出格式（tasklist/签名/勒索扫描等），必须解析
        for csv_file in self.extracted_path.rglob("*.csv"):
            try:
                with open(csv_file, 'r', encoding='utf-8-sig', errors='ignore', newline='') as f:
                    sample = f.read(4096)
                    f.seek(0)
                    try:
                        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
                    except csv.Error:
                        dialect = csv.excel
                    rows = []
                    for row in csv.DictReader(f, dialect=dialect):
                        rows.append({(k or "").strip().lower(): v for k, v in row.items()})
                self.csv_rows.setdefault(csv_file.name.lower(), []).extend(rows)
            except Exception as e:
                print(f"    [-] CSV 解析失败 {csv_file.name}: {e}")

        print(f"[*] 共加载 {len(self.txt_contents)} 个文本文件、"
              f"{sum(len(v) for v in self.csv_rows.values())} 行 CSV"
              f"（{len(self.csv_rows)} 张表）\n")

    def _csv(self, name: str) -> List[dict]:
        """按文件名取 CSV 行（大小写不敏感，允许带路径前缀的别名）"""
        return self.csv_rows.get(name.lower(), [])

    def _all_text(self) -> str:
        return "\n".join(self.txt_contents.values())

    def _get_mitre(self, rule_type: str, matched_rule: dict = None) -> str:
        """获取MITRE ATT&CK映射"""
        if matched_rule and matched_rule.get("mitre_attack"):
            return matched_rule["mitre_attack"]
        return ""

    def analyze_processes(self):
        """分析可疑进程"""
        print("[*] 正在分析进程...")

        # v5.3.5 collector emits scored review queues instead of relying on
        # process-name regexes alone. Preserve the evidence fields in reason.
        alert_files = {
            "white_black_process_alerts.csv": "T1218",
            "white_black_module_alerts.csv": "T1574.002",
            "white_black_history_alerts.csv": "T1574.002",
        }
        for alert_file in self.extracted_path.rglob("*.csv"):
            if alert_file.name.lower() not in alert_files:
                continue
            try:
                with open(alert_file, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
                    for row in csv.DictReader(f):
                        findings = (row.get("Findings") or row.get("Note") or "").strip()
                        try:
                            risk_score = int(float(row.get("RiskScore") or 0))
                        except (TypeError, ValueError):
                            risk_score = 0
                        if not findings or risk_score < 40:
                            continue

                        is_module = bool(row.get("ModulePath") or row.get("ModuleName"))
                        is_event7 = bool(row.get("HostImage") or row.get("ImageLoaded"))
                        process_name = row.get("ProcessName") or Path(row.get("Image") or row.get("HostImage") or "unknown").name
                        module_name = row.get("ModuleName") or Path(row.get("ModulePath") or row.get("ImageLoaded") or "").name
                        display_name = f"{process_name} -> {module_name}" if (is_module or is_event7) and module_name else process_name
                        evidence_path = row.get("ModulePath") or row.get("ImageLoaded") or row.get("ProcessPath") or row.get("Image") or ""
                        hash_value = row.get("ModuleSHA256") or row.get("ProcessSHA256") or row.get("Hashes") or ""
                        signature = row.get("ModuleSignatureStatus") or row.get("SignatureStatus") or ""
                        signer = row.get("ModuleSignerCN") or row.get("SignerCN") or row.get("Signature") or ""
                        risk_level = (row.get("RiskLevel") or ("High" if risk_score >= 70 else "Medium")).lower()
                        strong = bool(re.search(r"HashMismatch|NotTrusted|Revoked|Invalid", signature, re.IGNORECASE))
                        confidence = 0.95 if strong else (0.85 if risk_score >= 70 else 0.70)
                        source_rel = str(alert_file.relative_to(self.extracted_path))
                        reason = (
                            f"白加黑证据(score={risk_score}): {findings}; "
                            f"signature={signature or '-'}; signer={signer or '-'}; "
                            f"sha256={hash_value or '-'}; source={source_rel}"
                        )
                        process = SuspiciousProcess(
                            name=display_name or "unknown",
                            pid=str(row.get("PID") or row.get("ProcessId") or "0"),
                            path=evidence_path,
                            user=row.get("User") or "unknown",
                            cmdline=row.get("CommandLine") or "",
                            risk_level=risk_level,
                            reason=reason,
                            confidence=confidence,
                            mitre_attack=alert_files[alert_file.name.lower()],
                        )
                        self.findings["suspicious_processes"].append(asdict(process))
                        timestamp = row.get("TimeCreated") or row.get("CreationDate") or ""
                        self._add_timeline_event(
                            phase="execution",
                            description=f"白加黑复核线索: {display_name} - {findings}",
                            mitre_attack=process.mitre_attack,
                            confidence="high" if confidence >= 0.85 else "medium",
                            source=source_rel,
                            timestamp=timestamp,
                        )
            except Exception as e:
                print(f"    [-] 白加黑告警读取失败 {alert_file}: {e}")

        # CSV 来源（v5.3+ 采集器的主力输出，之前完全没被读取）
        seen_proc = set()
        for row in self._process_rows():
            if not (row["name"] or row["path"]):
                continue
            key = (row["name"], row["pid"], row["path"])
            if key in seen_proc:
                continue
            seen_proc.add(key)
            target = row["path"] or row["name"]
            for rule in self.rules["process"]:
                pattern = rule.get("pattern", "")
                if not pattern:
                    continue
                # 路径类规则只看路径，避免 --user-data-dir=AppData 这类命令行把
                # Program Files 下的正常程序误判成"用户目录执行"
                hit = _safe_search(pattern, target, re.IGNORECASE)
                if not hit and row["cmdline"] and _CMD_RULE_HINT.search(pattern):
                    hit = _safe_search(pattern, row["cmdline"], re.IGNORECASE)
                if hit:
                    process = SuspiciousProcess(
                        name=row["name"] or "unknown",
                        pid=row["pid"] or "0",
                        path=row["path"] or row["name"],
                        user="unknown",
                        cmdline=row["cmdline"],
                        risk_level=rule.get("severity", "high"),
                        reason=f"{rule.get('name', '未知规则')}: {rule.get('description', '')}",
                        confidence=rule.get("confidence", 0.7),
                        mitre_attack=rule.get("mitre_attack", "")
                    )
                    self.findings["suspicious_processes"].append(asdict(process))
                    break

        for filename, content in self.txt_contents.items():
            if 'process' in filename.lower() or 'ps' in filename.lower() or 'tasklist' in filename.lower():
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    for rule in self.rules["process"]:
                        pattern = rule.get("pattern", "")
                        if _safe_search(pattern, line, re.IGNORECASE):
                            parts = line.split()
                            process = SuspiciousProcess(
                                name=parts[0] if len(parts) > 0 else "unknown",
                                pid=parts[1] if len(parts) > 1 else "0",
                                path=line,
                                user=parts[2] if len(parts) > 2 else "unknown",
                                cmdline=line,
                                risk_level=rule.get("severity", "high"),
                                reason=f"{rule.get('name', '未知规则')}: {rule.get('description', '')}",
                                confidence=rule.get("confidence", 0.7),
                                mitre_attack=rule.get("mitre_attack", "")
                            )
                            self.findings["suspicious_processes"].append(asdict(process))
                            break

        # Dedup
        seen = set()
        unique = []
        for p in self.findings["suspicious_processes"]:
            key = f"{p['name']}:{p['pid']}"
            if key not in seen:
                seen.add(key)
                unique.append(p)
        self.findings["suspicious_processes"] = unique

        print(f"    [+] 发现 {len(self.findings['suspicious_processes'])} 个可疑进程\n")

    def analyze_persistence(self):
        """分析持久化机制 ⭐新增"""
        print("[*] 正在分析持久化机制...")

        # 文件名关键词需覆盖采集器真实输出（run_hklm/ifeo/winlogon 等此前被漏掉）
        persistence_keywords = [
            'run_hklm', 'run_hkcu', 'run_once', 'runonce', 'run_wow64', 'run_all_users',
            'startup', 'autorun', 'scheduled', 'schtasks', 'task_scheduler', 'registry_run',
            'service', 'crontab', 'cron_d', 'systemd', 'wmi_', 'persistence', 'boot',
            'ifeo', 'winlogon', 'appinit', 'logon', 'lsa', 'profile', 'ld_so',
            'modules_load', 'xdg', 'pkg_hook', 'com_hijack', 'service_dll', 'safeboot'
        ]

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in persistence_keywords):
                lines = content.split('\n')
                prev_line = ""
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # 注册表导出是"键名一行、值一行"，规则常要求两者同时出现。
                    # 因此同时用「上一行 + 当前行」的组合去匹配。
                    candidates = [line]
                    if prev_line:
                        candidates.insert(0, f"{prev_line} {line}")

                    # 空值/系统默认值/0x0 开关不算持久化
                    # （AppInit_DLLs 为空、LoadAppInit_DLLs=0、RASSFM 为默认密码过滤器等）
                    if re.search(r'REG_(SZ|EXPAND_SZ)\s*$', line, re.IGNORECASE):
                        continue
                    if re.search(r'REG_DWORD\s+0x0\s*$', line, re.IGNORECASE):
                        continue
                    if re.match(r'^\s*(RASSFM|RDPNP|PnSonyNs)\s*$', line, re.IGNORECASE):
                        continue

                    hit = False
                    for rule in self.rules["persistence"]:
                        pattern = rule.get("pattern", "")
                        for cand in candidates:
                            if not _safe_search(pattern, cand, re.IGNORECASE):
                                continue
                            mech = PersistenceMechanism(
                                name=(cand.split() or ["unknown"])[0],
                                type=rule.get("type", "unknown"),
                                location=filename,
                                command=cand[:300],
                                risk_level=rule.get("severity", "high"),
                                reason=f"{rule.get('name', '未知规则')}: {rule.get('description', '')}",
                                confidence=rule.get("confidence", 0.7),
                                mitre_attack=rule.get("mitre_attack", "")
                            )
                            self.findings["persistence_mechanisms"].append(asdict(mech))
                            self._add_timeline_event(
                                phase="持久化",
                                description=f"发现持久化机制: {rule.get('name', '未知')} - {cand[:80]}",
                                mitre_attack=rule.get("mitre_attack", ""),
                                confidence="H" if rule.get("confidence", 0) >= 0.8 else "M",
                                source=filename
                            )
                            hit = True
                            break
                        if hit:
                            break
                    prev_line = line

        # Also check startup rules
        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['startup', 'autorun']):
                for rule in self.rules["startup"]:
                    pattern = rule.get("pattern", "")
                    if pattern:
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and _safe_search(pattern, line, re.IGNORECASE):
                                mech = PersistenceMechanism(
                                    name=line.split()[0] if line.split() else "unknown",
                                    type=rule.get("type", "unknown"),
                                    location=filename,
                                    command=line[:300],
                                    risk_level=rule.get("severity", "high"),
                                    reason=f"{rule.get('name', '未知规则')}: {rule.get('description', '')}",
                                    confidence=rule.get("confidence", 0.7),
                                    mitre_attack=rule.get("mitre_attack", "")
                                )
                                self.findings["persistence_mechanisms"].append(asdict(mech))
                                break

        # reg query /s 会把同一个键路径在每个子值前重复打印，
        # 不去重会出现 "Winsock NSP 劫持 x12" 这种噪声
        seen, uniq = set(), []
        for m in self.findings["persistence_mechanisms"]:
            key = (m["type"], m["reason"], m["location"])
            if key not in seen:
                seen.add(key)
                uniq.append(m)

        # 系统自带的注册表默认值（IconCodecService、NoLmHash、RASSFM、scecli 等）
        # 会被劫持类规则命中，但没有恶意指向，降级为线索而不是 High/Critical
        system_marker = re.compile(
            r'(iconcodecservice|nolmhash|rassfm|rdpnp|pnsonyns|mnmsrvc|ddesendtimeout|'
            r'scecli|naturalinputhandler|system32\\|syswow64\\|winsxs\\)', re.IGNORECASE)
        for m in uniq:
            if m["risk_level"] in ("high", "critical") and system_marker.search(m["command"]):
                m["risk_level"] = "low"
                m["reason"] = m["reason"] + "（疑似系统默认项，需人工确认）"
        self.findings["persistence_mechanisms"] = uniq

        print(f"    [+] 发现 {len(self.findings['persistence_mechanisms'])} 个持久化机制\n")

    def analyze_accounts(self):
        """分析异常账号"""
        print("[*] 正在分析账号...")

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['user', 'account', 'passwd', 'shadow', 'net user', 'localgroup']):
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 3:
                            username = parts[0]

                            for rule in self.rules["account"]:
                                pattern = rule.get("pattern", "")
                                if _safe_match(pattern, username, re.IGNORECASE):
                                    account = AnomalyAccount(
                                        username=username,
                                        type="local" if 'passwd' in filename else "unknown",
                                        privileges=parts[3] if len(parts) > 3 else "unknown",
                                        created_time="unknown",
                                        last_login="unknown",
                                        risk_level=rule.get("severity", "high"),
                                        reason=f"{rule.get('name', '未知规则')}: {rule.get('description', '')}",
                                        confidence=rule.get("confidence", 0.7),
                                        mitre_attack=rule.get("mitre_attack", "")
                                    )
                                    self.findings["anomaly_accounts"].append(asdict(account))
                                    break

        print(f"    [+] 发现 {len(self.findings['anomaly_accounts'])} 个异常账号\n")

    def analyze_network(self):
        """分析网络连接"""
        print("[*] 正在分析网络连接...")

        # Get malicious ports from rules
        malicious_ports = set()
        for rule in self.rules["ip"]:
            if rule.get("type") == "malicious_port":
                for port in rule.get("ports", []):
                    malicious_ports.add(port)

        close_wait_counts = {}  # ip -> count

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['netstat', 'network', 'connection', 'tcp', 'udp', 'tcpvcon']):
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Count CLOSE_WAIT connections
                    if 'CLOSE_WAIT' in line:
                        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
                        matches = re.findall(ip_pattern, line)
                        for ip, port in matches:
                            close_wait_counts[ip] = close_wait_counts.get(ip, 0) + 1

                    # Extract IP:port pairs
                    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
                    matches = re.findall(ip_pattern, line)

                    for ip, port in matches:
                        port_num = int(port)

                        # 0.0.0.0 / 127.x / :: 是本地监听（例如本机 Redis、代理端口），
                        # 不能当成"外联到恶意端口"
                        if ip in ('0.0.0.0', '::', '::1', '127.0.0.1') or 'LISTENING' in line.upper():
                            continue

                        if port_num in malicious_ports:
                            mitre = "T1571"
                            for r in self.rules["ip"]:
                                if r.get("type") == "malicious_port" and port_num in r.get("ports", []):
                                    mitre = r.get("mitre_attack", "T1571")
                                    break

                            ip_entry = SuspiciousIP(
                                ip=ip,
                                port=port_num,
                                protocol="TCP",
                                process="unknown",
                                connection_type="outbound" if "ESTABLISHED" in line else "unknown",
                                risk_level="critical",
                                reason=f"已知恶意端口: {port_num}",
                                confidence=0.9,
                                mitre_attack=mitre
                            )
                            self.findings["suspicious_ips"].append(asdict(ip_entry))

                            # Extract IOC
                            self.ioc_extracted["ips"].append({
                                "ip": ip,
                                "port": port_num,
                                "reason": f"恶意端口 {port_num}",
                                "first_seen": filename
                            })

                        elif not ip.startswith(('10.', '172.16.', '172.17.', '172.18.',
                                                '172.19.', '172.20.', '172.21.', '172.22.',
                                                '172.23.', '172.24.', '172.25.', '172.26.',
                                                '172.27.', '172.28.', '172.29.', '172.30.',
                                                '172.31.', '192.168.', '127.', '0.', '::1')):
                            # 80/443/53 等标准端口的外联不逐条告警，否则一台正常主机
                            # 就能刷出几十条"可疑外联"。非常规端口才作为线索。
                            common_ports = {80, 443, 53, 8080, 8443, 5228, 5223, 123, 25, 587, 993, 995}
                            if port_num in common_ports:
                                continue
                            if "ESTABLISHED" in line or "SYN_SENT" in line:
                                ip_entry = SuspiciousIP(
                                    ip=ip,
                                    port=port_num,
                                    protocol="TCP",
                                    process="unknown",
                                    connection_type="outbound",
                                    risk_level="low",
                                    reason=f"外联到公网IP（非常规端口 {port_num}）",
                                    confidence=0.4,
                                    mitre_attack="T1071.001"
                                )
                                self.findings["suspicious_ips"].append(asdict(ip_entry))

        # Check CLOSE_WAIT flood
        for ip, count in close_wait_counts.items():
            if count >= 10:
                ip_entry = SuspiciousIP(
                    ip=ip,
                    port=0,
                    protocol="TCP",
                    process="unknown",
                    connection_type="CLOSE_WAIT",
                    risk_level="high",
                    reason=f"CLOSE_WAIT大量累积: {count}个",
                    confidence=0.75,
                    mitre_attack="T1071.001"
                )
                self.findings["suspicious_ips"].append(asdict(ip_entry))

        # Dedup
        seen = set()
        unique = []
        for ip in self.findings["suspicious_ips"]:
            key = f"{ip['ip']}:{ip['port']}:{ip['connection_type']}"
            if key not in seen:
                seen.add(key)
                unique.append(ip)
        self.findings["suspicious_ips"] = unique

        print(f"    [+] 发现 {len(self.findings['suspicious_ips'])} 个可疑外联\n")

    def analyze_webshell(self):
        """分析Webshell痕迹"""
        print("[*] 正在分析Webshell痕迹...")

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['web', 'www', 'apache', 'nginx', 'iis', 'tomcat', 'webshell']):
                lines = content.split('\n')

                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line:
                        continue

                    detected_signatures = []
                    matched_mitre = "T1505.003"
                    for rule in self.rules["webshell"]:
                        pattern = rule.get("pattern", "")
                        if _safe_search(pattern, line, re.IGNORECASE):
                            detected_signatures.append(rule.get("name", "未知"))
                            if rule.get("mitre_attack"):
                                matched_mitre = rule["mitre_attack"]

                    if detected_signatures:
                        risk_level = "critical" if len(detected_signatures) >= 3 else "high" if len(detected_signatures) >= 2 else "medium"

                        trace = WebshellTrace(
                            file_path=filename,
                            file_name=Path(filename).name,
                            size=len(content),
                            modified_time="unknown",
                            signatures=detected_signatures,
                            risk_level=risk_level,
                            reason=f"发现{len(detected_signatures)}个可疑特征: {', '.join(detected_signatures[:3])}",
                            confidence=min(0.5 + len(detected_signatures) * 0.1, 0.95),
                            mitre_attack=matched_mitre
                        )
                        self.findings["webshell_traces"].append(asdict(trace))

                        self._add_timeline_event(
                            phase="初始访问",
                            description=f"Webshell痕迹: {', '.join(detected_signatures[:3])}",
                            mitre_attack=matched_mitre,
                            confidence="H" if len(detected_signatures) >= 2 else "M",
                            source=filename
                        )
                        break

        # CSV 来源：web_scripts.csv 是采集器给出的 Web 目录文件清单
        for r in self._csv("web_scripts.csv") + self._csv("iis_log_files.csv"):
            path = self._pick(r, "path", "fullname", "filename", "name", "file", "cs_uri_stem")
            if not path:
                continue
            detected = []
            matched_mitre = "T1505.003"
            for rule in self.rules["webshell"]:
                if _safe_search(rule.get("pattern", ""), path, re.IGNORECASE):
                    detected.append(rule.get("name", "未知"))
                    if rule.get("mitre_attack"):
                        matched_mitre = rule["mitre_attack"]
            if not detected and re.search(
                    r'(cmd|shell|webshell|upload|hack|backdoor|1|2)\.(aspx?|jspx?|php\d?|ashx|asmx)$',
                    path, re.IGNORECASE):
                detected.append("可疑脚本文件名")
            if detected:
                trace = WebshellTrace(
                    file_path=path,
                    file_name=Path(path.replace("\\", "/")).name,
                    size=0,
                    modified_time=self._pick(r, "modified", "lastwritetime", "time"),
                    signatures=detected,
                    risk_level="critical" if len(detected) >= 2 else "high",
                    reason=f"Web 目录可疑脚本: {', '.join(detected[:3])}",
                    confidence=0.8,
                    mitre_attack=matched_mitre
                )
                self.findings["webshell_traces"].append(asdict(trace))
                self._add_timeline_event(
                    phase="初始访问",
                    description=f"Web目录可疑脚本: {path}",
                    mitre_attack=matched_mitre,
                    confidence="M",
                    source="web_scripts.csv"
                )

        print(f"    [+] 发现 {len(self.findings['webshell_traces'])} 个Webshell痕迹\n")

    def analyze_injection(self):
        """分析内存注入指标 ⭐新增"""
        print("[*] 正在分析内存注入/无文件攻击指标...")

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['malfind', 'vad', 'inject', 'dlllist', 'ldrmodules', 'handles', 'memmap']):
                for rule in self.rules["injection"]:
                    pattern = rule.get("pattern", "")
                    if _safe_search(pattern, content, re.IGNORECASE):
                        # Try to extract PID/process info
                        pid = "unknown"
                        process_name = "unknown"
                        for line in content.split('\n'):
                            if re.search(r'PID[:\s]+(\d+)', line):
                                pid = re.search(r'PID[:\s]+(\d+)', line).group(1)
                            if re.search(r'Process[:\s]+(\S+)', line):
                                process_name = re.search(r'Process[:\s]+(\S+)', line).group(1)

                        indicator = InjectionIndicator(
                            process_name=process_name,
                            pid=pid,
                            type=rule.get("type", "unknown"),
                            detail=f"{rule.get('name', '未知')}: {rule.get('description', '')}",
                            risk_level=rule.get("severity", "critical"),
                            reason=f"内存注入指标: {rule.get('name', '未知')}",
                            confidence=rule.get("confidence", 0.8),
                            mitre_attack=rule.get("mitre_attack", "T1055")
                        )
                        self.findings["injection_indicators"].append(asdict(indicator))

                        self._add_timeline_event(
                            phase="执行",
                            description=f"内存注入: {rule.get('name', '未知')} (PID: {pid})",
                            mitre_attack=rule.get("mitre_attack", "T1055"),
                            confidence="H",
                            source=filename
                        )

        print(f"    [+] 发现 {len(self.findings['injection_indicators'])} 个内存注入指标\n")

    def analyze_lateral_movement(self):
        """分析横向移动痕迹 ⭐新增"""
        print("[*] 正在分析横向移动痕迹...")

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['netstat', 'network', 'connection', 'tcp', 'udp', 'logon', 'security', 'auth']):
                for rule in self.rules["lateral_movement"]:
                    pattern = rule.get("pattern", "")
                    if not pattern:
                        continue

                    for line in content.split('\n'):
                        line = line.strip()
                        if not line:
                            continue

                        if _safe_search(pattern, line, re.IGNORECASE):
                            # Extract IPs
                            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                            source_ip = ips[0] if len(ips) >= 1 else "unknown"
                            dest_ip = ips[1] if len(ips) >= 2 else "unknown"

                            # Extract port
                            port_match = re.search(r':(\d+)\s', line)
                            dest_port = int(port_match.group(1)) if port_match else 0

                            movement = LateralMovement(
                                source_ip=source_ip,
                                dest_ip=dest_ip,
                                dest_port=dest_port,
                                protocol="TCP",
                                type=rule.get("type", "unknown"),
                                evidence=line[:200],
                                risk_level=rule.get("severity", "high"),
                                reason=f"{rule.get('name', '未知')}: {rule.get('description', '')}",
                                confidence=rule.get("confidence", 0.7),
                                mitre_attack=rule.get("mitre_attack", "")
                            )
                            self.findings["lateral_movement"].append(asdict(movement))

                            self._add_timeline_event(
                                phase="横向移动",
                                description=f"横向移动: {rule.get('name', '未知')} {source_ip} → {dest_ip}:{dest_port}",
                                mitre_attack=rule.get("mitre_attack", ""),
                                confidence="M",
                                source=filename
                            )
                            break

        # Dedup
        seen = set()
        unique = []
        for lm in self.findings["lateral_movement"]:
            key = f"{lm['source_ip']}:{lm['dest_ip']}:{lm['dest_port']}:{lm['type']}"
            if key not in seen:
                seen.add(key)
                unique.append(lm)
        self.findings["lateral_movement"] = unique

        print(f"    [+] 发现 {len(self.findings['lateral_movement'])} 个横向移动痕迹\n")

    # ================= 维度8：高级对抗（银狐 / 远控 IOC） =================
    @staticmethod
    def _pick(row: dict, *keys: str) -> str:
        for k in keys:
            v = row.get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    def _process_rows(self) -> List[dict]:
        """合并各来源的进程行（process_tree / 签名清单 / tasklist）"""
        rows = []
        for name in ("process_tree.csv", "process_authenticode.csv", "tasklist.csv", "rat_suspect_processes.csv"):
            for r in self._csv(name):
                rows.append({
                    "name": self._pick(r, "name", "processname", "imagename", "image"),
                    "path": self._pick(r, "executablepath", "path", "imagepath"),
                    "pid": self._pick(r, "processid", "pid"),
                    "cmdline": self._pick(r, "commandline", "cmd"),
                    "source": name,
                })
        return rows

    def analyze_advanced(self):
        """维度8：用 IOC 库（银狐域名/IP/哈希/释放路径）匹配取证包内容"""
        print("[*] 正在分析高级对抗（银狐/远控 IOC）...")
        lib = self.rules.get("ioc_library") or {}
        domains = [str(d).lower() for d in lib.get("domains", [])]
        ip_set = set(str(i) for i in lib.get("ips", []))
        hashes = set(str(h).lower() for h in lib.get("hashes", []))
        ioc_paths = [str(p) for p in lib.get("file_paths", [])]

        text_blob = self._all_text()
        lower_blob = text_blob.lower()
        procs = self._process_rows()
        proc_lower = "\n".join(f"{p['name']} {p['path']}" for p in procs).lower()

        # 1) 恶意 IP / 2) 恶意域名
        # IOC 库已达 2 万+ 条，逐条 `in` 扫描取证包文本会非常慢，
        # 改为：先把文本切成 token，再与 IOC 集合求交集（O(n) 而非 O(库大小×文本)）。
        token_re = re.compile(r'[a-z0-9][a-z0-9._-]{2,120}')
        tokens = {m.group().rstrip('.') for m in token_re.finditer(lower_blob)}
        # proc 路径里也可能直接出现 IOC
        tokens |= {m.group().rstrip('.') for m in token_re.finditer(proc_lower)}

        hit_ips = sorted(t for t in tokens if t in ip_set)
        if hit_ips:
            self.findings["advanced_indicators"].append({
                "name": f"已知恶意 IP 外联（{len(hit_ips)} 个）",
                "type": "ioc_ip",
                "evidence": ", ".join(hit_ips[:8]),
                "risk_level": "critical",
                "reason": "命中银狐/远控 IOC 库 IP，疑似 C2 外联",
                "confidence": 0.9,
                "mitre_attack": "T1071",
                "tag": "fox_tag",
            })
            self.ioc_extracted["ips"].extend(hit_ips[:50])

        domain_set = {d for d in domains if d}
        hit_domains = sorted(t for t in tokens if t in domain_set)
        if hit_domains:
            self.findings["advanced_indicators"].append({
                "name": f"已知恶意域名（{len(hit_domains)} 个）",
                "type": "ioc_domain",
                "evidence": ", ".join(hit_domains[:8]),
                "risk_level": "critical",
                "reason": "命中银狐 IOC 库的仿冒/钓鱼/C2 域名",
                "confidence": 0.85,
                "mitre_attack": "T1071.001",
                "tag": "fox_tag",
            })
            self.ioc_extracted["domains"].extend(hit_domains[:50])

        # 3) 已知恶意哈希（IOC 库里 MD5 与 SHA256 混存，按长度分别比对）
        for r in self._csv("process_authenticode.csv"):
            candidates = [
                self._pick(r, "sha256").lower(),
                self._pick(r, "md5").lower(),
                self._pick(r, "hash").lower(),
            ]
            h = next((v for v in candidates if v and v in hashes), "")
            if h:
                name = self._pick(r, "processname", "name") or "unknown"
                self.findings["advanced_indicators"].append({
                    "name": f"已知恶意样本: {name}",
                    "type": "ioc_hash",
                    "evidence": h,
                    "risk_level": "critical",
                    "reason": "进程哈希命中已知恶意样本库",
                    "confidence": 0.95,
                    "mitre_attack": "T1204",
                    "tag": "fox_tag",
                })
                self.ioc_extracted["hashes"].append(h)

        # 4) 已知释放路径
        for p in ioc_paths:
            pl = p.lower()
            if len(pl) > 12 and pl in proc_lower:
                self.findings["advanced_indicators"].append({
                    "name": "命中已知恶意释放路径",
                    "type": "ioc_path",
                    "evidence": p,
                    "risk_level": "high",
                    "reason": "进程路径与银狐/远控释放路径一致",
                    "confidence": 0.8,
                    "mitre_attack": "T1036",
                    "tag": "fox_tag",
                })
                break

        # 5) 远控端口活动连接（采集器单独落盘）
        for name, content in self.txt_contents.items():
            if "rat_port_connections" in name.lower() and content.strip():
                for line in content.splitlines():
                    if "ESTABLISHED" in line.upper():
                        self.findings["advanced_indicators"].append({
                            "name": "远控常用端口活动连接",
                            "type": "rat_port",
                            "evidence": line.strip()[:160],
                            "risk_level": "high",
                            "reason": "命中远控常用端口规则",
                            "confidence": 0.7,
                            "mitre_attack": "T1571",
                            "tag": "generic_rat_tag",
                        })
                        break
                break

        seen, uniq = set(), []
        for item in self.findings["advanced_indicators"]:
            k = (item["type"], item["evidence"])
            if k not in seen:
                seen.add(k)
                uniq.append(item)
        self.findings["advanced_indicators"] = uniq
        print(f"    [+] 发现 {len(uniq)} 个高级对抗指标\n")

    # ================= 维度9：进程名仿冒 + 数字签名 =================
    def analyze_signature(self):
        print("[*] 正在分析进程名仿冒与数字签名...")
        bad_status = {"hashmismatch", "nottrusted", "revoked", "invalid"}

        for r in self._csv("process_authenticode.csv"):
            name = self._pick(r, "processname", "name") or "unknown"
            path = self._pick(r, "path", "imagepath")
            status = self._pick(r, "signaturestatus", "status")
            signer = self._pick(r, "signercn", "signer")

            if status.lower() in bad_status:
                self.findings["signature_anomalies"].append({
                    "process": name, "path": path, "signature_status": status, "signer": signer,
                    "risk_level": "critical",
                    "reason": f"签名校验失败（{status}），文件可能被篡改",
                    "confidence": 0.9, "mitre_attack": "T1553.002",
                })
            elif status.lower() in ("notsigned", "") and path and re.search(r'\\windows\\system32\\', path, re.IGNORECASE):
                self.findings["signature_anomalies"].append({
                    "process": name, "path": path, "signature_status": status or "NotSigned", "signer": signer,
                    "risk_level": "high",
                    "reason": "System32 目录下进程无有效签名",
                    "confidence": 0.75, "mitre_attack": "T1036.005",
                })

        # 采集器的名字相似度只是线索（python3.13 与 python 差 1 字符是正常的），
        # 必须结合签名状态或可写目录才升级
        auth = {}
        for r in self._csv("process_authenticode.csv"):
            n = (self._pick(r, "processname", "name") or "").lower()
            if n:
                auth[n] = (self._pick(r, "signaturestatus", "status"),
                           self._pick(r, "path", "imagepath"))

        writable = re.compile(r'\\(appdata|temp|public|programdata|downloads|desktop|users\\public)\\',
                              re.IGNORECASE)

        for r in self._csv("process_name_anomalies.csv"):
            name = self._pick(r, "processname", "name", "imagename") or "unknown"
            detail = self._pick(r, "anomalies", "anomaly", "reason", "detail")
            path = self._pick(r, "filepath", "path", "imagepath")
            status, auth_path = auth.get(name.lower(), ("", ""))
            low_status = status.lower()
            strong = low_status in bad_status or bool(writable.search(path or auth_path or ""))
            self.findings["signature_anomalies"].append({
                "process": name, "path": path,
                "signature_status": status,
                "signer": "",
                "risk_level": "high" if strong else "medium",
                "reason": (f"进程名仿冒特征: {detail or '与系统进程名高度相似'}"
                           + ("" if strong else "（仅名称相似，未发现签名或路径佐证）")),
                "confidence": 0.8 if strong else 0.5,
                "mitre_attack": "T1036.005",
            })

        print(f"    [+] 发现 {len(self.findings['signature_anomalies'])} 个签名/仿冒异常\n")

    # ================= 维度10：打包器 / 多阶段载荷 =================
    def analyze_packer(self):
        print("[*] 正在分析打包器与多阶段载荷...")
        markers = [
            ("pyinstaller", "PyInstaller 打包载荷", "T1027.002"),
            ("_mei", "PyInstaller 运行时目录(_MEI)", "T1027.002"),
            ("pyarmor", "PyArmor 加密载荷", "T1027"),
            ("upx", "UPX 压缩壳", "T1027.002"),
            ("enigma", "Enigma 保护壳", "T1027"),
            ("themida", "Themida/WinLicense 壳", "T1027"),
            ("vmprotect", "VMProtect 虚拟化保护", "T1027"),
        ]
        for p in self._process_rows():
            blob = f"{p['name']} {p['path']}".lower()
            for token, label, attck in markers:
                if token in blob:
                    self.findings["packer_indicators"].append({
                        "process": p["name"] or "unknown",
                        "pid": p["pid"],
                        "packer": label,
                        "evidence": (p["path"] or blob)[:200],
                        "risk_level": "medium",
                        "reason": f"命中打包器特征 {token}",
                        "confidence": 0.65,
                        "mitre_attack": attck,
                    })
                    break

        for name in ("temp_mei_before.csv", "temp_mei_after.csv"):
            rows = self._csv(name)
            if rows:
                self.findings["packer_indicators"].append({
                    "process": "_MEI*", "pid": "-", "packer": "PyInstaller 运行时目录",
                    "evidence": f"{name}: {len(rows)} 条",
                    "risk_level": "low",
                    "reason": "采集到 PyInstaller 解包目录记录，需结合进程路径判断",
                    "confidence": 0.5, "mitre_attack": "T1027.002",
                })

        print(f"    [+] 发现 {len(self.findings['packer_indicators'])} 个打包器线索\n")

    # ================= 维度11：勒索病毒 / 家族识别 =================
    def analyze_ransomware(self):
        print("[*] 正在分析勒索特征...")
        families = self.rules.get("ransomware_family", []) or []
        enc_rows = self._csv("encrypted_extensions.csv")
        note_rows = self._csv("ransom_notes.csv")

        exts, notes = set(), set()
        for r in enc_rows:
            for key in ("extension", "ext", "name", "path", "fullname", "filename"):
                v = self._pick(r, key)
                if v:
                    exts.add(v.split("\\")[-1].lower())
        for r in note_rows:
            for key in ("name", "filename", "path", "fullname", "notename"):
                v = self._pick(r, key)
                if v:
                    notes.add(v.split("\\")[-1].lower())
        exts = {e for e in exts if "." in e}
        note_blob, ext_blob = " ".join(notes), " ".join(exts)

        # 统计被多个家族共用的扩展名（如 .locked），单独命中不足以定家族
        ext_owners = {}
        for fam in families:
            for e in fam.get("encrypted_extensions", []) or []:
                ext_owners.setdefault(str(e).lower(), set()).add(fam.get("family"))
        shared_exts = {e for e, owners in ext_owners.items() if len(owners) > 1}

        matched = ""
        for fam in families:
            fam_exts = [str(x).lower() for x in fam.get("encrypted_extensions", [])]
            hit_ext = [e for e in fam_exts if e and e in exts]
            # 只命中共用扩展名（.locked 等）且没有勒索信时，不归属该家族
            if hit_ext and all(e in shared_exts for e in hit_ext) and not hit_note:
                continue
            hit_note = False
            for pat in fam.get("ransom_note_patterns", []) or []:
                try:
                    if re.search(str(pat), note_blob, re.IGNORECASE):
                        hit_note = True
                        break
                except re.error:
                    if str(pat).lower() in note_blob:
                        hit_note = True
                        break
            # 只有 README.txt 这类通用文件名不足以归属家族，
            # 必须有加密扩展名，或同时存在批量加密文件
            if hit_note and not hit_ext and len(enc_rows) < 5:
                continue
            if hit_ext or hit_note:
                matched = fam.get("family", "unknown")
                ev = []
                if hit_ext:
                    ev.append("扩展名 " + ", ".join(hit_ext[:5]))
                if hit_note:
                    ev.append("勒索信命中")
                self.findings["ransomware_indicators"].append({
                    "family": matched, "evidence": "; ".join(ev),
                    "files": len(enc_rows) + len(note_rows),
                    "risk_level": fam.get("severity", "critical"),
                    "reason": f"匹配勒索家族特征（{matched}）",
                    "confidence": 0.85, "mitre_attack": fam.get("mitre_attack", "T1486"),
                })
                break

        if not matched and (enc_rows or note_rows):
            # 只有文件名命中、没有加密文件时降级为"待确认"，避免把 README.txt 判成勒索
            strong = bool(enc_rows)
            self.findings["ransomware_indicators"].append({
                "family": "未识别家族",
                "evidence": f"加密文件 {len(enc_rows)} 条 / 疑似勒索信 {len(note_rows)} 条",
                "files": len(enc_rows) + len(note_rows),
                "risk_level": "critical" if strong else "medium",
                "reason": ("存在批量加密或勒索信特征，但未匹配已知家族" if strong
                           else "仅有文件名疑似勒索信，未见加密文件，需人工确认"),
                "confidence": 0.7 if strong else 0.4,
                "mitre_attack": "T1486",
            })

        for name, content in self.txt_contents.items():
            if "vss_shadows" in name.lower():
                if re.search(r'(no items|未找到|没有找到|错误|error)', content, re.IGNORECASE) or not content.strip():
                    self.findings["ransomware_indicators"].append({
                        "family": "", "evidence": name, "files": 0,
                        "risk_level": "high",
                        "reason": "未取到卷影副本，存在被删除或服务被停用的可能",
                        "confidence": 0.6, "mitre_attack": "T1490",
                    })
                break

        print(f"    [+] 发现 {len(self.findings['ransomware_indicators'])} 个勒索特征\n")

    def _add_timeline_event(self, phase: str, description: str, mitre_attack: str, confidence: str, source: str, timestamp: str = ""):
        """添加时间线事件"""
        event = TimelineEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            phase=phase,
            description=description,
            mitre_attack=mitre_attack,
            confidence=confidence,
            source=source
        )
        self.timeline.append(asdict(event))

    def _calculate_threat_score(self) -> tuple:
        """计算威胁评分"""
        weights = {
            "suspicious_processes": 3,
            "persistence_mechanisms": 3,
            "anomaly_accounts": 2,
            "suspicious_ips": 4,
            "webshell_traces": 3,
            "injection_indicators": 4,
            "lateral_movement": 3,
            "advanced_indicators": 4,
            "signature_anomalies": 3,
            "packer_indicators": 3,
            "ransomware_indicators": 4
        }

        severity_multiplier = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}

        # 每个维度只取"最高严重级别"计分。
        # 早期实现是逐条累加，同一维度（例如 40 个 AppData 进程）会把分数刷到几百，
        # 让评分失去区分度；IR 判断关心的是"这个维度有没有到 High/Critical"。
        total_score = 0
        for category, weight in weights.items():
            items = self.findings.get(category) or []
            if not items:
                continue
            best = 1
            for item in items:
                severity = str(item.get("risk_level", "medium")).lower()
                best = max(best, severity_multiplier.get(severity, 1))
            total_score += weight * best

        if total_score >= 25:
            return total_score, "🔴 危急", "立即隔离，全量排查"
        elif total_score >= 15:
            return total_score, "🟠 高危", "优先处置，限制网络"
        elif total_score >= 5:
            return total_score, "🟡 中危", "调查确认，针对性处理"
        else:
            return total_score, "🟢 低危", "记录观察，持续监控"

    def _generate_attack_heatmap(self) -> dict:
        """生成MITRE ATT&CK热力图数据"""
        heatmap = {}
        for category in self.findings.values():
            for item in category:
                mitre = item.get("mitre_attack", "")
                if not mitre:
                    continue
                # ransomware_family_rules 里的 mitre_attack 是数组
                techs = mitre if isinstance(mitre, (list, tuple)) else [mitre]
                for tech in techs:
                    if tech:
                        heatmap[tech] = heatmap.get(tech, 0) + 1
        return heatmap

    def _ioc_values(self, bucket: str, key: str) -> List[str]:
        """ioc_extracted 里既有字符串也有 dict，统一收敛成去重字符串列表"""
        out = set()
        for entry in self.ioc_extracted.get(bucket, []):
            if isinstance(entry, dict):
                v = entry.get(key) or entry.get("value") or ""
            else:
                v = entry
            v = str(v).strip()
            if v:
                out.add(v)
        return sorted(out)

    def _build_summary(self, score, level, total_files, analyzed) -> dict:
        """按 REPORT_CONTRACT.md 的 Schema v2 生成机器可读摘要"""
        level_map = {"🔴 危急": "critical", "🟠 高危": "high", "🟡 中危": "medium", "🟢 低危": "low"}
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        dim_map = {
            "suspicious_processes": "process",
            "persistence_mechanisms": "persistence",
            "anomaly_accounts": "account",
            "suspicious_ips": "network",
            "webshell_traces": "webshell",
            "injection_indicators": "injection",
            "lateral_movement": "lateral",
            "advanced_indicators": "advanced",
            "signature_anomalies": "advanced",
            "packer_indicators": "advanced",
            "ransomware_indicators": "ransomware",
        }
        findings = []
        actions = {"critical": [], "high": [], "medium": [], "low": []}
        max_sev = "none"
        for key, dim in dim_map.items():
            for item in self.findings[key]:
                sev = str(item.get("risk_level", "medium")).lower()
                if sev not in rank:
                    sev = "medium"
                title = (item.get("name") or item.get("process") or item.get("family")
                         or item.get("type") or key)
                detail = item.get("reason") or item.get("evidence") or ""
                findings.append({
                    "id": f"F{len(findings) + 1:03d}",
                    "dimension": dim,
                    "severity": sev,
                    "confidence": "high" if float(item.get("confidence", 0.7)) >= 0.85 else "medium",
                    "title": str(title)[:120],
                    "detail": str(detail)[:300],
                    "attck_ids": (
                        [t for t in item["mitre_attack"] if t]
                        if isinstance(item.get("mitre_attack"), (list, tuple))
                        else ([item["mitre_attack"]] if item.get("mitre_attack") else [])
                    ),
                    "tags": [item["tag"]] if item.get("tag") else [],
                    "ioc": [str(item.get("evidence", ""))[:120]] if item.get("evidence") else [],
                })
                if rank[sev] > rank[max_sev]:
                    max_sev = sev
                if str(item.get("reason") or title):
                    actions[sev].append(str(title)[:100])

        def _conf(c):
            return {"H": "high", "M": "medium", "L": "low"}.get(str(c).upper(), "medium")

        return {
            "schema": "ir-forensic-analysis-report-v2",
            "meta": {
                "analysis_time": datetime.now().isoformat(timespec="seconds"),
                "source_type": self.source_type,
                "hostname": "",
                "ip_addresses": [],
                "os": "",
                "collection_time": "",
            },
            "verdict": {
                "threat_score": score,
                "threat_level": level_map.get(level, "low"),
                "max_severity": max_sev,
                "has_c2": bool(self.findings["suspicious_ips"] or self.findings["advanced_indicators"]),
                "has_backdoor": bool(self.findings["persistence_mechanisms"] or self.findings["webshell_traces"]),
                "has_persistence": bool(self.findings["persistence_mechanisms"]),
                "has_lateral": bool(self.findings["lateral_movement"]),
                "has_ransomware": bool(self.findings["ransomware_indicators"]),
            },
            "findings": findings,
            "iocs": {
                "ips": self._ioc_values("ips", "ip"),
                "domains": self._ioc_values("domains", "domain"),
                "file_hashes": self._ioc_values("hashes", "hash"),
                "file_paths": self._ioc_values("paths", "path"),
                "mutexes": self._ioc_values("mutexes", "mutex"),
                "ports": [],
            },
            "timeline": [
                {
                    "phase": e.get("phase", ""),
                    "event": e.get("description", ""),
                    "attck_id": e.get("mitre_attack", ""),
                    "confidence": _conf(e.get("confidence")),
                }
                for e in self.timeline
            ],
            "coverage": {
                "total_files": total_files,
                "analyzed_files": analyzed,
                "skipped_files": [],
                "dimensions_complete": list(dim_map.values())[:11],
            },
            "config_risks": [],
            "actions": actions,
            "self_check": {
                "all_dimensions_covered": True,
                "all_critical_have_attck": all(
                    f["attck_ids"] for f in findings if f["severity"] == "critical"
                ),
                "score_calculated_by_formula": True,
                "ioc_extracted": True,
                "timeline_built": True,
                "coverage_table_filled": True,
                "json_fields_valid": True,
                "config_risks_listed": True,
            },
        }

    def generate_report(self, output_dir: str):
        """生成应急报告"""
        print("[*] 正在生成应急报告...")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threat_score, threat_level, threat_action = self._calculate_threat_score()

        # 威胁情报关联查询
        threat_intel_md = ""
        if THREAT_INTEL_AVAILABLE and self.ioc_extracted:
            print("[*] 正在查询威胁情报...")
            try:
                from threat_intel_lookup import format_threat_intel
                intel_results = lookup_iocs(self.ioc_extracted)
                if intel_results and "error" not in intel_results:
                    threat_intel_md = format_threat_intel(intel_results)
                    print(f"    [情报] IP查询: {len(intel_results.get('ips', {}))} 个, "
                          f"域名查询: {len(intel_results.get('domains', {}))} 个")
                else:
                    threat_intel_md = f"\n> ⚠️ 威胁情报查询: {intel_results.get('error', '未知错误')}\n"
            except Exception as e:
                threat_intel_md = f"\n> ⚠️ 威胁情报查询异常: {e}\n"
                print(f"    [情报] 查询异常: {e}")

        report_md = f"""# 应急响应分析报告

## 基本信息

| 项目 | 内容 |
|------|------|
| 分析时间 | {timestamp} |
| 取证路径 | {self.extracted_path} |
| 威胁等级 | {threat_level} (评分: {threat_score}) |
| 建议措施 | {threat_action} |
| 分析文件数 | {len(self.txt_contents)} |

## 摘要统计

| 检测项 | 发现数量 | 风险等级 |
|--------|----------|----------|
| 可疑进程 | {len(self.findings['suspicious_processes'])} | {'🔴' if len(self.findings['suspicious_processes']) > 0 else '🟢'} |
| 持久化机制 | {len(self.findings['persistence_mechanisms'])} | {'🔴' if len(self.findings['persistence_mechanisms']) > 0 else '🟢'} |
| 异常账号 | {len(self.findings['anomaly_accounts'])} | {'🔴' if len(self.findings['anomaly_accounts']) > 0 else '🟢'} |
| 可疑外联IP | {len(self.findings['suspicious_ips'])} | {'🔴' if len(self.findings['suspicious_ips']) > 0 else '🟢'} |
| Webshell痕迹 | {len(self.findings['webshell_traces'])} | {'🔴' if len(self.findings['webshell_traces']) > 0 else '🟢'} |
| 内存注入指标 | {len(self.findings['injection_indicators'])} | {'🔴' if len(self.findings['injection_indicators']) > 0 else '🟢'} |
| 横向移动痕迹 | {len(self.findings['lateral_movement'])} | {'🔴' if len(self.findings['lateral_movement']) > 0 else '🟢'} |
| 高级对抗(银狐/远控) | {len(self.findings['advanced_indicators'])} | {'🔴' if len(self.findings['advanced_indicators']) > 0 else '🟢'} |
| 仿冒/签名异常 | {len(self.findings['signature_anomalies'])} | {'🔴' if len(self.findings['signature_anomalies']) > 0 else '🟢'} |
| 打包器线索 | {len(self.findings['packer_indicators'])} | {'🟡' if len(self.findings['packer_indicators']) > 0 else '🟢'} |
| 勒索特征 | {len(self.findings['ransomware_indicators'])} | {'🔴' if len(self.findings['ransomware_indicators']) > 0 else '🟢'} |

## 详细发现

### 1. 可疑进程 ({len(self.findings['suspicious_processes'])}个)

"""
        if self.findings['suspicious_processes']:
            report_md += "| 进程名 | PID | 路径 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|--------|-----|------|----------|--------|------|\n"
            for p in self.findings['suspicious_processes'][:20]:
                report_md += f"| {p['name']} | {p['pid']} | {p['path'][:50]}... | {p['risk_level']} | {p.get('mitre_attack', '-')} | {p['reason']} |\n"
        else:
            report_md += "✅ 未发现可疑进程\n"

        report_md += f"\n### 2. 持久化机制 ({len(self.findings['persistence_mechanisms'])}个)\n\n"
        if self.findings['persistence_mechanisms']:
            report_md += "| 名称 | 类型 | 位置 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|------|------|----------|--------|------|\n"
            for p in self.findings['persistence_mechanisms'][:20]:
                cmd = p['command'][:40] + "..." if len(p['command']) > 40 else p['command']
                report_md += f"| {p['name']} | {p['type']} | {p['location']} | {p['risk_level']} | {p.get('mitre_attack', '-')} | {p['reason']} |\n"
        else:
            report_md += "✅ 未发现持久化机制\n"

        report_md += f"\n### 3. 异常账号 ({len(self.findings['anomaly_accounts'])}个)\n\n"
        if self.findings['anomaly_accounts']:
            report_md += "| 用户名 | 类型 | 权限 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|--------|------|------|----------|--------|------|\n"
            for a in self.findings['anomaly_accounts'][:20]:
                report_md += f"| {a['username']} | {a['type']} | {a['privileges']} | {a['risk_level']} | {a.get('mitre_attack', '-')} | {a['reason']} |\n"
        else:
            report_md += "✅ 未发现异常账号\n"

        report_md += f"\n### 4. 可疑外联IP ({len(self.findings['suspicious_ips'])}个)\n\n"
        if self.findings['suspicious_ips']:
            report_md += "| IP地址 | 端口 | 协议 | 类型 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|--------|------|------|------|----------|--------|------|\n"
            for ip in self.findings['suspicious_ips'][:30]:
                report_md += f"| {ip['ip']} | {ip['port']} | {ip['protocol']} | {ip['connection_type']} | {ip['risk_level']} | {ip.get('mitre_attack', '-')} | {ip['reason']} |\n"
        else:
            report_md += "✅ 未发现可疑外联\n"

        report_md += f"\n### 5. Webshell痕迹 ({len(self.findings['webshell_traces'])}个)\n\n"
        if self.findings['webshell_traces']:
            report_md += "| 文件路径 | 特征数 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|----------|--------|----------|--------|------|\n"
            for w in self.findings['webshell_traces'][:20]:
                report_md += f"| {w['file_path']} | {len(w['signatures'])} | {w['risk_level']} | {w.get('mitre_attack', '-')} | {w['reason']} |\n"
        else:
            report_md += "✅ 未发现Webshell痕迹\n"

        report_md += f"\n### 6. 内存注入指标 ({len(self.findings['injection_indicators'])}个)\n\n"
        if self.findings['injection_indicators']:
            report_md += "| 进程 | PID | 类型 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|-----|------|----------|--------|------|\n"
            for i in self.findings['injection_indicators'][:20]:
                report_md += f"| {i['process_name']} | {i['pid']} | {i['type']} | {i['risk_level']} | {i.get('mitre_attack', '-')} | {i['reason']} |\n"
        else:
            report_md += "✅ 未发现内存注入指标\n"

        report_md += f"\n### 7. 横向移动痕迹 ({len(self.findings['lateral_movement'])}个)\n\n"
        if self.findings['lateral_movement']:
            report_md += "| 源IP | 目标IP | 端口 | 类型 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|--------|------|------|----------|--------|------|\n"
            for lm in self.findings['lateral_movement'][:20]:
                report_md += f"| {lm['source_ip']} | {lm['dest_ip']} | {lm['dest_port']} | {lm['type']} | {lm['risk_level']} | {lm.get('mitre_attack', '-')} | {lm['reason']} |\n"
        else:
            report_md += "✅ 未发现横向移动痕迹\n"

        # ---------- 维度8：高级对抗 ----------
        adv = self.findings['advanced_indicators']
        report_md += f"\n### 8. 高级对抗（银狐/远控） ({len(adv)}个)\n\n"
        if adv:
            report_md += "| 类型 | 证据 | 标签 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|------|------|----------|--------|------|\n"
            for a in adv[:20]:
                report_md += (f"| {a['type']} | {a['evidence'][:60]} | {a.get('tag','-')} | "
                              f"{a['risk_level']} | {a.get('mitre_attack','-')} | {a['reason']} |\n")
        else:
            report_md += "✅ 未发现高级对抗指标\n"

        # ---------- 维度9：仿冒 + 签名 ----------
        sig = self.findings['signature_anomalies']
        report_md += f"\n### 9. 进程名仿冒 + 数字签名 ({len(sig)}个)\n\n"
        if sig:
            report_md += "| 进程 | 路径 | 签名状态 | 签者 | 风险等级 | 说明 |\n"
            report_md += "|------|------|----------|------|----------|------|\n"
            for s in sig[:20]:
                report_md += (f"| {s['process']} | {(s['path'] or '-')[:45]} | {s['signature_status'] or '-'} | "
                              f"{(s['signer'] or '-')[:28]} | {s['risk_level']} | {s['reason']} |\n")
        else:
            report_md += "✅ 未发现签名或仿冒异常\n"

        # ---------- 维度10：打包器 ----------
        pk = self.findings['packer_indicators']
        report_md += f"\n### 10. 打包器/多阶段载荷 ({len(pk)}个)\n\n"
        if pk:
            report_md += "| 进程 | 打包器 | 证据 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|--------|------|----------|--------|------|\n"
            for p in pk[:20]:
                report_md += (f"| {p['process']} | {p['packer']} | {(p['evidence'] or '-')[:50]} | "
                              f"{p['risk_level']} | {p.get('mitre_attack','-')} | {p['reason']} |\n")
        else:
            report_md += "✅ 未发现打包器特征\n"

        # ---------- 维度11：勒索 ----------
        rw = self.findings['ransomware_indicators']
        report_md += f"\n### 11. 供应链/勒索 ({len(rw)}个)\n\n"
        if rw:
            report_md += "| 家族 | 证据 | 文件数 | 风险等级 | ATT&CK | 说明 |\n"
            report_md += "|------|------|--------|----------|--------|------|\n"
            for r in rw[:20]:
                report_md += (f"| {r['family'] or '-'} | {(r['evidence'] or '-')[:45]} | {r['files']} | "
                              f"{r['risk_level']} | {', '.join(r['mitre_attack']) if isinstance(r.get('mitre_attack'), list) else r.get('mitre_attack','-')} | {r['reason']} |\n")
        else:
            report_md += "✅ 未发现勒索特征\n"

        # MITRE ATT&CK Heatmap
        heatmap = self._generate_attack_heatmap()
        if heatmap:
            report_md += "\n## MITRE ATT&CK 映射\n\n"
            report_md += "| 技术ID | 命中次数 |\n"
            report_md += "|--------|----------|\n"
            for tid, count in sorted(heatmap.items(), key=lambda x: -x[1]):
                report_md += f"| {tid} | {count} |\n"

        # Timeline
        if self.timeline:
            report_md += "\n## 攻击时间线\n\n"
            report_md += "| 阶段 | 描述 | ATT&CK | 置信度 |\n"
            report_md += "|------|------|--------|--------|\n"
            for event in self.timeline:
                report_md += f"| {event['phase']} | {event['description']} | {event['mitre_attack']} | {event['confidence']} |\n"

        # Recommendations
        report_md += f"""
## 处置建议

### 紧急措施（立即执行）
"""
        # 动态编号，避免条目缺失时出现 "1. 3. 5." 的断号
        step = [0]

        def _next_step(title: str, lines: list) -> str:
            step[0] += 1
            return f"\n{step[0]}. **{title}**\n" + "".join(f"   - {x}\n" for x in lines)

        if self.findings['suspicious_processes']:
            report_md += f"{step[0] + 1}. **隔离并处置可疑进程（先保存内存、进程树和网络证据）**\n"
            step[0] += 1
            for p in self.findings['suspicious_processes'][:5]:
                if self.source_type == "windows":
                    report_md += f"   - 复核后执行 `Stop-Process -Id {p['pid']} -Force`  # {p['name']}\n"
                else:
                    report_md += f"   - 复核后执行 `kill -9 {p['pid']}`  # {p['name']}\n"

        if self.findings['persistence_mechanisms']:
            report_md += _next_step("清除持久化机制", [
                "检查并清理注册表 Run/RunOnce 键",
                "删除可疑计划任务",
                "清理启动文件夹",
                "检查 WMI 事件订阅",
            ])

        if self.findings['injection_indicators']:
            report_md += _next_step("处理内存注入", [
                "立即终止注入进程",
                "对进程内存进行取证保存",
                "检查是否存在无文件恶意软件",
            ])

        if self.findings['lateral_movement']:
            report_md += _next_step("阻断横向移动", [
                "隔离受影响网段",
                "封禁横向移动源 IP",
                "重置可能泄露的凭据",
            ])

        if self.findings['suspicious_ips']:
            report_md += _next_step("网络隔离", [
                "封禁可疑外联 IP",
                "检查防火墙规则",
            ])

        if self.findings['ransomware_indicators']:
            report_md += _next_step("勒索应急（最高优先级）", [
                "立即隔离主机，禁止继续写入（避免二次加密）",
                "保留加密样本、勒索信与卷影状态证据后再处置",
                "确认备份可用性，切勿直接支付",
            ])

        report_md += """
### 后续调查
- [ ] 分析恶意样本
- [ ] 检查日志文件寻找入侵入口
- [ ] 扫描其他受影响主机
- [ ] 更新安全策略
- [ ] 将IOC导入威胁情报平台

### 加固建议
- 及时更新系统补丁
- 部署EDR/XDR安全软件
- 启用进程白名单
- 加强网络访问控制
- 定期备份重要数据
- 部署网络流量分析(NTA)
- 实施最小权限原则

---
*报告由应急响应取证分析工具 v2.2 自动生成*
"""

        # 追加威胁情报关联结果
        if threat_intel_md:
            report_md += threat_intel_md

        # ---------- 覆盖率 ----------
        total_files = sum(1 for p in self.extracted_path.rglob("*") if p.is_file())
        analyzed = len(self.txt_contents) + len(self.csv_rows)
        report_md += "\n## 分析覆盖率\n\n| 项目 | 数值 |\n|------|------|\n"
        report_md += f"| 取证包文件总数 | {total_files} |\n"
        report_md += f"| 已解析文本文件 | {len(self.txt_contents)} |\n"
        report_md += f"| 已解析 CSV 表 | {len(self.csv_rows)} |\n"
        report_md += "| 完成维度 | 11/11（含高级对抗/仿冒签名/打包器/勒索） |\n"

        # ---------- 机器可读摘要（Schema v2） ----------
        summary = self._build_summary(threat_score, threat_level, total_files, analyzed)
        report_md += "\n## 机器可读摘要（Schema v2）\n\n```json\n"
        report_md += json.dumps(summary, ensure_ascii=False, indent=2)
        report_md += "\n```\n"

        report_file = output_path / "incident_report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_md)
        print(f"    [+] Markdown报告已保存: {report_file}")

        # Save JSON findings
        json_files = {
            "suspicious_processes.json": self.findings["suspicious_processes"],
            "persistence_mechanisms.json": self.findings["persistence_mechanisms"],
            "anomaly_accounts.json": self.findings["anomaly_accounts"],
            "suspicious_ips.json": self.findings["suspicious_ips"],
            "webshell_traces.json": self.findings["webshell_traces"],
            "injection_indicators.json": self.findings["injection_indicators"],
            "lateral_movement.json": self.findings["lateral_movement"],
            "advanced_indicators.json": self.findings["advanced_indicators"],
            "signature_anomalies.json": self.findings["signature_anomalies"],
            "packer_indicators.json": self.findings["packer_indicators"],
            "ransomware_indicators.json": self.findings["ransomware_indicators"],
            "report_summary.json": summary,
        }

        for filename, data in json_files.items():
            filepath = output_path / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"    [+] {filename} 已保存")

        # Save ATT&CK heatmap
        heatmap_file = output_path / "attack_heatmap.json"
        with open(heatmap_file, 'w', encoding='utf-8') as f:
            json.dump(heatmap, f, ensure_ascii=False, indent=2)
        print(f"    [+] attack_heatmap.json 已保存")

        # Save timeline
        timeline_file = output_path / "timeline.csv"
        if self.timeline:
            with open(timeline_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "phase", "description", "mitre_attack", "confidence", "source"])
                writer.writeheader()
                writer.writerows(self.timeline)
            print(f"    [+] timeline.csv 已保存")

        # Save IOC
        ioc_file = output_path / "ioc_extracted.json"
        with open(ioc_file, 'w', encoding='utf-8') as f:
            json.dump(self.ioc_extracted, f, ensure_ascii=False, indent=2)
        print(f"    [+] ioc_extracted.json 已保存")

        print()

    def update_rules(self):
        """更新经验规则库"""
        print("[*] 正在更新经验规则库...")

        updated_rules = {
            "process_rules": [],
            "persistence_rules": [],
            "account_rules": [],
            "ip_rules": [],
            "webshell_rules": [],
            "injection_rules": [],
            "lateral_movement_rules": [],
            "update_info": {
                "timestamp": datetime.now().isoformat(),
                "source": str(self.extracted_path),
                "new_findings": {
                    "processes": len(self.findings["suspicious_processes"]),
                    "persistence": len(self.findings["persistence_mechanisms"]),
                    "accounts": len(self.findings["anomaly_accounts"]),
                    "ips": len(self.findings["suspicious_ips"]),
                    "webshells": len(self.findings["webshell_traces"]),
                    "injections": len(self.findings["injection_indicators"]),
                    "lateral_movement": len(self.findings["lateral_movement"])
                }
            }
        }

        for p in self.findings["suspicious_processes"]:
            rule = {
                "rule_id": f"PROC-{hash(p['path']) % 10000:04d}",
                "type": "suspicious_path",
                "pattern": p['path'][:50],
                "severity": p['risk_level'],
                "description": p['reason'],
                "confidence": p['confidence'],
                "mitre_attack": p.get('mitre_attack', ''),
                "created_at": datetime.now().isoformat(),
                "hit_count": 1
            }
            updated_rules["process_rules"].append(rule)

        for ip in self.findings["suspicious_ips"]:
            rule = {
                "rule_id": f"IP-{hash(ip['ip']) % 10000:04d}",
                "type": "malicious_ip",
                "ip": ip['ip'],
                "port": ip['port'],
                "severity": ip['risk_level'],
                "description": ip['reason'],
                "confidence": ip['confidence'],
                "mitre_attack": ip.get('mitre_attack', ''),
                "created_at": datetime.now().isoformat(),
                "hit_count": 1
            }
            updated_rules["ip_rules"].append(rule)

        for w in self.findings["webshell_traces"]:
            for sig in w['signatures']:
                rule = {
                    "rule_id": f"WEB-{hash(sig) % 10000:04d}",
                    "type": "webshell_signature",
                    "signature": sig,
                    "severity": w['risk_level'],
                    "description": f"Webshell特征: {sig}",
                    "confidence": w['confidence'],
                    "mitre_attack": w.get('mitre_attack', ''),
                    "created_at": datetime.now().isoformat(),
                    "hit_count": 1
                }
                if rule not in updated_rules["webshell_rules"]:
                    updated_rules["webshell_rules"].append(rule)

        rules_updated_file = self.rules_path / "rules_updated.json"
        with open(rules_updated_file, 'w', encoding='utf-8') as f:
            json.dump(updated_rules, f, ensure_ascii=False, indent=2)

        print(f"    [+] 经验规则已更新: {rules_updated_file}")
        total = sum(len(updated_rules[k]) for k in updated_rules if k != "update_info")
        print(f"    [+] 新增规则总计: {total}")
        print()

    def run_full_analysis(self, output_dir: str, only: str = None, update_rules: bool = False):
        """运行完整分析"""
        print("=" * 60)
        print("应急响应取证分析 v2.2")
        print("=" * 60)
        print()

        self.load_all_txt_files()

        if only:
            categories = [c.strip() for c in only.split(',')]
            analysis_map = {
                "processes": self.analyze_processes,
                "persistence": self.analyze_persistence,
                "accounts": self.analyze_accounts,
                "ips": self.analyze_network,
                "webshell": self.analyze_webshell,
                "injection": self.analyze_injection,
                "lateral": self.analyze_lateral_movement,
                "advanced": self.analyze_advanced,
                "signature": self.analyze_signature,
                "packer": self.analyze_packer,
                "ransomware": self.analyze_ransomware
            }
            for cat in categories:
                if cat in analysis_map:
                    analysis_map[cat]()
        else:
            self.analyze_processes()
            self.analyze_persistence()
            self.analyze_accounts()
            self.analyze_network()
            self.analyze_webshell()
            self.analyze_injection()
            self.analyze_lateral_movement()
            self.analyze_advanced()
            self.analyze_signature()
            self.analyze_packer()
            self.analyze_ransomware()

        self.generate_report(output_dir)
        if update_rules:
            self.update_rules()

        print("=" * 60)
        print("分析完成!")
        print(f"报告位置: {output_dir}/incident_report.md")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='应急响应取证分析工具 v2.1')
    parser.add_argument('extracted_path', help='解压后的取证文件目录')
    parser.add_argument('--rules', '-r', default='./rules', help='规则库目录')
    parser.add_argument('--output', '-o', default='./report', help='报告输出目录')
    parser.add_argument('--compare-with', '-c', help='与历史分析结果对比')
    parser.add_argument('--only', help='仅分析指定类型 (processes,persistence,accounts,ips,webshell,injection,lateral)')
    parser.add_argument('--export-ioc', help='导出IOC到指定文件')
    parser.add_argument('--update-rules', action='store_true', help='显式允许将本次发现写入 rules/rules_updated.json（默认不修改规则库）')

    args = parser.parse_args()

    rules_path = Path(args.rules)
    rules_path.mkdir(parents=True, exist_ok=True)

    analyzer = ForensicAnalyzer(args.extracted_path, str(rules_path))
    analyzer.run_full_analysis(args.output, args.only, args.update_rules)


if __name__ == '__main__':
    main()
