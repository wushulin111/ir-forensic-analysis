#!/usr/bin/env python3
"""
应急响应取证分析主脚本 v2.0
自动分析Linux和Windows取证文件，覆盖7大检测维度，生成含ATT&CK映射的应急报告
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
    """取证分析器 v2.0"""

    def __init__(self, extracted_path: str, rules_path: str):
        self.extracted_path = Path(extracted_path)
        self.rules_path = Path(rules_path)
        self.txt_contents = {}
        self.findings = {
            "suspicious_processes": [],
            "persistence_mechanisms": [],
            "anomaly_accounts": [],
            "suspicious_ips": [],
            "webshell_traces": [],
            "injection_indicators": [],
            "lateral_movement": []
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
            "lateral_movement": "lateral_movement_rules.json"
        }

        for rule_type, filename in rule_files.items():
            rule_file = self.rules_path / filename
            if rule_file.exists():
                try:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rules[rule_type] = json.load(f)
                except Exception as e:
                    print(f"[!] 加载规则文件失败 {filename}: {e}")

        return rules

    def load_all_txt_files(self):
        """加载所有txt文件内容"""
        print("[*] 正在加载取证文件...")

        for txt_file in self.extracted_path.rglob("*.txt"):
            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    relative_path = str(txt_file.relative_to(self.extracted_path))
                    self.txt_contents[relative_path] = content
                    print(f"    [+] 已加载: {relative_path}")
            except Exception as e:
                print(f"    [-] 加载失败 {txt_file}: {e}")

        # Also load .log files
        for log_file in self.extracted_path.rglob("*.log"):
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    relative_path = str(log_file.relative_to(self.extracted_path))
                    self.txt_contents[relative_path] = content
                    print(f"    [+] 已加载: {relative_path}")
            except Exception as e:
                print(f"    [-] 加载失败 {log_file}: {e}")

        print(f"[*] 共加载 {len(self.txt_contents)} 个文件\n")

    def _get_mitre(self, rule_type: str, matched_rule: dict = None) -> str:
        """获取MITRE ATT&CK映射"""
        if matched_rule and matched_rule.get("mitre_attack"):
            return matched_rule["mitre_attack"]
        return ""

    def analyze_processes(self):
        """分析可疑进程"""
        print("[*] 正在分析进程...")

        for filename, content in self.txt_contents.items():
            if 'process' in filename.lower() or 'ps' in filename.lower() or 'tasklist' in filename.lower():
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    for rule in self.rules["process"]:
                        pattern = rule.get("pattern", "")
                        if pattern and re.search(pattern, line, re.IGNORECASE):
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

        persistence_keywords = [
            'startup', 'autorun', 'scheduled_task', 'registry_run', 'service',
            'crontab', 'systemd', 'wmi', 'persistence', 'autorun', 'boot',
            'run_key', 'task_scheduler'
        ]

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in persistence_keywords):
                lines = content.split('\n')

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    for rule in self.rules["persistence"]:
                        pattern = rule.get("pattern", "")
                        if pattern and re.search(pattern, line, re.IGNORECASE):
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
                            self._add_timeline_event(
                                phase="持久化",
                                description=f"发现持久化机制: {rule.get('name', '未知')} - {line[:80]}",
                                mitre_attack=rule.get("mitre_attack", ""),
                                confidence="H" if rule.get("confidence", 0) >= 0.8 else "M",
                                source=filename
                            )
                            break

        # Also check startup rules
        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['startup', 'autorun']):
                for rule in self.rules["startup"]:
                    pattern = rule.get("pattern", "")
                    if pattern:
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and re.search(pattern, line, re.IGNORECASE):
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
                                if pattern and re.match(pattern, username, re.IGNORECASE):
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
                            if "ESTABLISHED" in line or "SYN_SENT" in line:
                                ip_entry = SuspiciousIP(
                                    ip=ip,
                                    port=port_num,
                                    protocol="TCP",
                                    process="unknown",
                                    connection_type="outbound",
                                    risk_level="medium",
                                    reason="外联到公网IP",
                                    confidence=0.5,
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
                        if pattern and re.search(pattern, line, re.IGNORECASE):
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

        print(f"    [+] 发现 {len(self.findings['webshell_traces'])} 个Webshell痕迹\n")

    def analyze_injection(self):
        """分析内存注入指标 ⭐新增"""
        print("[*] 正在分析内存注入/无文件攻击指标...")

        for filename, content in self.txt_contents.items():
            if any(keyword in filename.lower() for keyword in ['malfind', 'vad', 'inject', 'dlllist', 'ldrmodules', 'handles', 'memmap']):
                for rule in self.rules["injection"]:
                    pattern = rule.get("pattern", "")
                    if pattern and re.search(pattern, content, re.IGNORECASE):
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

                        if re.search(pattern, line, re.IGNORECASE):
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

    def _add_timeline_event(self, phase: str, description: str, mitre_attack: str, confidence: str, source: str):
        """添加时间线事件"""
        event = TimelineEvent(
            timestamp=datetime.now().isoformat(),  # Will be refined if actual timestamp available
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
            "lateral_movement": 3
        }

        severity_multiplier = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}

        total_score = 0
        for category, weight in weights.items():
            for item in self.findings[category]:
                severity = item.get("risk_level", "medium")
                multiplier = severity_multiplier.get(severity, 1)
                total_score += weight * multiplier

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
                if mitre:
                    heatmap[mitre] = heatmap.get(mitre, 0) + 1
        return heatmap

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
        if self.findings['suspicious_processes']:
            report_md += "1. **终止可疑进程**\n"
            for p in self.findings['suspicious_processes'][:5]:
                report_md += f"   - `kill -9 {p['pid']}`  # {p['name']}\n"

        if self.findings['persistence_mechanisms']:
            report_md += "\n2. **清除持久化机制**\n"
            report_md += "   - 检查并清理注册表 Run/RunOnce 键\n"
            report_md += "   - 删除可疑计划任务\n"
            report_md += "   - 清理启动文件夹\n"
            report_md += "   - 检查WMI事件订阅\n"

        if self.findings['injection_indicators']:
            report_md += "\n3. **处理内存注入**\n"
            report_md += "   - 立即终止注入进程\n"
            report_md += "   - 对进程内存进行取证保存\n"
            report_md += "   - 检查是否存在无文件恶意软件\n"

        if self.findings['lateral_movement']:
            report_md += "\n4. **阻断横向移动**\n"
            report_md += "   - 隔离受影响网段\n"
            report_md += "   - 封禁横向移动源IP\n"
            report_md += "   - 重置可能泄露的凭据\n"

        if self.findings['suspicious_ips']:
            report_md += "\n5. **网络隔离**\n"
            report_md += "   - 封禁可疑外联IP\n"
            report_md += "   - 检查防火墙规则\n"

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
*报告由应急响应取证分析Skill v2.0自动生成*
"""

        # 追加威胁情报关联结果
        if threat_intel_md:
            report_md += threat_intel_md

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

    def run_full_analysis(self, output_dir: str, only: str = None):
        """运行完整分析"""
        print("=" * 60)
        print("应急响应取证分析 v2.0")
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
                "lateral": self.analyze_lateral_movement
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

        self.generate_report(output_dir)
        self.update_rules()

        print("=" * 60)
        print("分析完成!")
        print(f"报告位置: {output_dir}/incident_report.md")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='应急响应取证分析工具 v2.0')
    parser.add_argument('extracted_path', help='解压后的取证文件目录')
    parser.add_argument('--rules', '-r', default='./rules', help='规则库目录')
    parser.add_argument('--output', '-o', default='./report', help='报告输出目录')
    parser.add_argument('--compare-with', '-c', help='与历史分析结果对比')
    parser.add_argument('--only', help='仅分析指定类型 (processes,persistence,accounts,ips,webshell,injection,lateral)')
    parser.add_argument('--export-ioc', help='导出IOC到指定文件')

    args = parser.parse_args()

    rules_path = Path(args.rules)
    rules_path.mkdir(parents=True, exist_ok=True)

    analyzer = ForensicAnalyzer(args.extracted_path, str(rules_path))
    analyzer.run_full_analysis(args.output, args.only)


if __name__ == '__main__':
    main()
