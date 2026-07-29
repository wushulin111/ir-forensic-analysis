#!/usr/bin/env python3
"""
经验规则库管理脚本
用于管理、更新、合并和查询经验规则
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class RuleManager:
    """规则管理器"""
    
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化规则文件
        self.rule_files = {
            "process": self.rules_dir / "process_rules.json",
            "startup": self.rules_dir / "startup_rules.json",
            "account": self.rules_dir / "account_rules.json",
            "ip": self.rules_dir / "ip_rules.json",
            "webshell": self.rules_dir / "webshell_rules.json",
            "historical": self.rules_dir / "historical_findings.json"
        }
        
        self._init_default_rules()
        
    def _init_default_rules(self):
        """初始化默认规则"""
        
        # 进程检测规则
        if not self.rule_files["process"].exists():
            default_process_rules = [
                {
                    "rule_id": "PROC-0001",
                    "type": "suspicious_path",
                    "name": "临时目录执行",
                    "description": "进程在/tmp或/var/tmp目录执行",
                    "pattern": "^/(tmp|var/tmp|dev/shm|run)/",
                    "severity": "high",
                    "confidence": 0.8,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "PROC-0002",
                    "type": "hidden_directory",
                    "name": "隐藏目录执行",
                    "description": "进程在隐藏目录中执行",
                    "pattern": "/\\.[^/]+/",
                    "severity": "medium",
                    "confidence": 0.6,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "PROC-0003",
                    "type": "windows_temp",
                    "name": "Windows临时目录执行",
                    "description": "进程在Windows临时目录执行",
                    "pattern": "(Temp|tmp)\\.*\\.exe",
                    "severity": "high",
                    "confidence": 0.85,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "PROC-0004",
                    "type": "known_malware",
                    "name": "已知恶意进程名",
                    "description": "匹配已知恶意软件进程名",
                    "pattern": "(xmrig|minerd|kworkerds|ddgs|systemten|sysguard|watchdogs)",
                    "severity": "critical",
                    "confidence": 0.95,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                }
            ]
            self._save_rules("process", default_process_rules)
            
        # 启动项检测规则
        if not self.rule_files["startup"].exists():
            default_startup_rules = [
                {
                    "rule_id": "START-0001",
                    "type": "encoded_command",
                    "name": "编码命令执行",
                    "description": "PowerShell/Base64编码命令",
                    "pattern": "(powershell|cmd).*(-enc|base64|FromBase64String)",
                    "severity": "critical",
                    "confidence": 0.9,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "START-0002",
                    "type": "rundll32_abuse",
                    "name": "Rundll32滥用",
                    "description": "使用rundll32执行恶意代码",
                    "pattern": "rundll32\\.exe.*,",
                    "severity": "high",
                    "confidence": 0.8,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "START-0003",
                    "type": "wmi_persistence",
                    "name": "WMI持久化",
                    "description": "WMI事件订阅持久化",
                    "pattern": "(wmic|powershell).*(__EventFilter|CommandLineEventConsumer)",
                    "severity": "high",
                    "confidence": 0.85,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                }
            ]
            self._save_rules("startup", default_startup_rules)
            
        # 账号检测规则
        if not self.rule_files["account"].exists():
            default_account_rules = [
                {
                    "rule_id": "ACCT-0001",
                    "type": "spoofed_system",
                    "name": "仿冒系统账号",
                    "description": "用户名仿冒系统账号",
                    "pattern": "^(administrator|root|system|guest)\\d+$",
                    "severity": "high",
                    "confidence": 0.85,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "ACCT-0002",
                    "type": "hidden_account",
                    "name": "隐藏账号",
                    "description": "用户名以点开头（隐藏账号）",
                    "pattern": "^\\.",
                    "severity": "critical",
                    "confidence": 0.9,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "ACCT-0003",
                    "type": "suspicious_name",
                    "name": "可疑命名账号",
                    "description": "账号名包含可疑关键词",
                    "pattern": "(hack|shell|backdoor|test|temp|support_\\d+)",
                    "severity": "medium",
                    "confidence": 0.7,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                }
            ]
            self._save_rules("account", default_account_rules)
            
        # IP威胁情报规则
        if not self.rule_files["ip"].exists():
            default_ip_rules = [
                {
                    "rule_id": "IP-0001",
                    "type": "malicious_port",
                    "name": "已知恶意端口",
                    "description": "连接到已知恶意端口",
                    "ports": [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337, 44445, 55554],
                    "severity": "critical",
                    "confidence": 0.9,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "IP-0002",
                    "type": "tor_exit",
                    "name": "Tor出口节点",
                    "description": "连接到Tor网络",
                    "pattern": "tor_exit",
                    "severity": "medium",
                    "confidence": 0.7,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                }
            ]
            self._save_rules("ip", default_ip_rules)
            
        # Webshell检测规则
        if not self.rule_files["webshell"].exists():
            default_webshell_rules = [
                {
                    "rule_id": "WEB-0001",
                    "type": "eval_function",
                    "name": "PHP eval函数",
                    "description": "使用eval执行代码",
                    "pattern": "eval\\s*\\(",
                    "severity": "high",
                    "confidence": 0.8,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "WEB-0002",
                    "type": "system_exec",
                    "name": "系统命令执行",
                    "description": "使用system/exec等函数",
                    "pattern": "(system|exec|shell_exec|passthru|proc_open|popen)\\s*\\(",
                    "severity": "high",
                    "confidence": 0.85,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "WEB-0003",
                    "type": "base64_decode",
                    "name": "Base64解码",
                    "description": "使用base64_decode解码",
                    "pattern": "base64_decode\\s*\\(",
                    "severity": "medium",
                    "confidence": 0.6,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "WEB-0004",
                    "type": "file_operation",
                    "name": "可疑文件操作",
                    "description": "文件上传/写入操作",
                    "pattern": "(file_put_contents|fwrite|move_uploaded_file)\\s*\\(",
                    "severity": "medium",
                    "confidence": 0.65,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                },
                {
                    "rule_id": "WEB-0005",
                    "type": "common_name",
                    "name": "常见Webshell文件名",
                    "description": "文件名匹配常见Webshell",
                    "pattern": "(shell|cmd|exec|hack|backdoor|ice|lanker)\\.(php|jsp|asp|aspx)",
                    "severity": "high",
                    "confidence": 0.75,
                    "created_at": "2024-01-01",
                    "hit_count": 0
                }
            ]
            self._save_rules("webshell", default_webshell_rules)
            
    def _save_rules(self, rule_type: str, rules: list):
        """保存规则到文件"""
        rule_file = self.rule_files[rule_type]
        with open(rule_file, 'w', encoding='utf-8') as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
            
    def _load_rules(self, rule_type: str) -> list:
        """从文件加载规则"""
        rule_file = self.rule_files[rule_type]
        if rule_file.exists():
            with open(rule_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
        
    def list_rules(self, rule_type: Optional[str] = None):
        """列出所有规则"""
        if rule_type:
            if rule_type not in self.rule_files:
                print(f"[-] 未知规则类型: {rule_type}")
                return
            types_to_list = [rule_type]
        else:
            types_to_list = list(self.rule_files.keys())
            
        for rt in types_to_list:
            rules = self._load_rules(rt)
            print(f"\n[{rt.upper()}] 规则数: {len(rules)}")
            for rule in rules[:5]:  # 只显示前5条
                print(f"  - {rule.get('rule_id', 'N/A')}: {rule.get('name', 'N/A')} (置信度: {rule.get('confidence', 0)})")
            if len(rules) > 5:
                print(f"  ... 还有 {len(rules) - 5} 条规则")
                
    def add_rule(self, rule_type: str, rule: dict):
        """添加新规则"""
        if rule_type not in self.rule_files:
            print(f"[-] 未知规则类型: {rule_type}")
            return
            
        rules = self._load_rules(rule_type)
        
        # 生成规则ID
        max_id = 0
        for r in rules:
            rid = r.get('rule_id', '')
            if '-' in rid:
                try:
                    num = int(rid.split('-')[1])
                    max_id = max(max_id, num)
                except:
                    pass
                    
        rule['rule_id'] = f"{rule_type.upper()[:4]}-{max_id + 1:04d}"
        rule['created_at'] = datetime.now().isoformat()
        rule['hit_count'] = 0
        
        rules.append(rule)
        self._save_rules(rule_type, rules)
        
        print(f"[+] 规则已添加: {rule['rule_id']}")
        
    def delete_rule(self, rule_type: str, rule_id: str):
        """删除规则"""
        if rule_type not in self.rule_files:
            print(f"[-] 未知规则类型: {rule_type}")
            return
            
        rules = self._load_rules(rule_type)
        original_count = len(rules)
        rules = [r for r in rules if r.get('rule_id') != rule_id]
        
        if len(rules) < original_count:
            self._save_rules(rule_type, rules)
            print(f"[+] 规则已删除: {rule_id}")
        else:
            print(f"[-] 未找到规则: {rule_id}")
            
    def merge_rules(self, source_file: str, target_type: str):
        """合并外部规则文件"""
        if target_type not in self.rule_files:
            print(f"[-] 未知规则类型: {target_type}")
            return
            
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                new_rules = json.load(f)
                
            existing_rules = self._load_rules(target_type)
            
            # 合并并去重
            existing_patterns = {r.get('pattern', ''): r for r in existing_rules}
            merged_count = 0
            
            for rule in new_rules:
                pattern = rule.get('pattern', '')
                if pattern and pattern not in existing_patterns:
                    # 生成新ID
                    max_id = max([int(r.get('rule_id', 'X-0').split('-')[1]) 
                                 for r in existing_rules if '-' in r.get('rule_id', '')] or [0])
                    rule['rule_id'] = f"{target_type.upper()[:4]}-{max_id + 1:04d}"
                    rule['created_at'] = datetime.now().isoformat()
                    rule['hit_count'] = 0
                    existing_rules.append(rule)
                    merged_count += 1
                    
            self._save_rules(target_type, existing_rules)
            print(f"[+] 成功合并 {merged_count} 条新规则")
            
        except Exception as e:
            print(f"[-] 合并失败: {e}")
            
    def export_rules(self, output_file: str, rule_type: Optional[str] = None):
        """导出规则"""
        export_data = {}
        
        if rule_type:
            if rule_type not in self.rule_files:
                print(f"[-] 未知规则类型: {rule_type}")
                return
            types_to_export = [rule_type]
        else:
            types_to_export = list(self.rule_files.keys())
            
        for rt in types_to_export:
            export_data[rt] = self._load_rules(rt)
            
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
            
        print(f"[+] 规则已导出: {output_file}")
        
    def compare_with_historical(self, current_findings_file: str):
        """与历史发现对比"""
        historical_file = self.rule_files["historical"]
        
        # 加载当前发现
        with open(current_findings_file, 'r', encoding='utf-8') as f:
            current = json.load(f)
            
        # 加载历史发现
        if historical_file.exists():
            with open(historical_file, 'r', encoding='utf-8') as f:
                historical = json.load(f)
        else:
            historical = {"findings": [], "ioc_library": {}}
            
        print("\n[*] 历史对比分析")
        print("-" * 40)
        
        # 对比进程
        current_procs = {(p.get('name', ''), p.get('path', '')) 
                        for p in current.get('suspicious_processes', [])}
        historical_procs = {(p.get('name', ''), p.get('path', '')) 
                           for p in historical.get('findings', [{}])[0].get('suspicious_processes', []) 
                           if historical.get('findings')}
        
        new_procs = current_procs - historical_procs
        if new_procs:
            print(f"[+] 新发现的可疑进程: {len(new_procs)}个")
            for name, path in list(new_procs)[:5]:
                print(f"    - {name}: {path[:50]}")
                
        # 对比IP
        current_ips = {p.get('ip', '') for p in current.get('suspicious_ips', [])}
        historical_ips = {p.get('ip', '') 
                         for p in historical.get('findings', [{}])[0].get('suspicious_ips', []) 
                         if historical.get('findings')}
        
        new_ips = current_ips - historical_ips
        if new_ips:
            print(f"[+] 新发现的可疑IP: {len(new_ips)}个")
            for ip in list(new_ips)[:5]:
                print(f"    - {ip}")
                
        # 更新历史记录
        if "findings" not in historical:
            historical["findings"] = []
        historical["findings"].insert(0, current)
        historical["findings"] = historical["findings"][:10]  # 保留最近10次
        
        # 更新IOC库
        if "ioc_library" not in historical:
            historical["ioc_library"] = {"ips": [], "paths": [], "hashes": []}
            
        for ip in current_ips:
            if ip not in historical["ioc_library"]["ips"]:
                historical["ioc_library"]["ips"].append(ip)
                
        for name, path in current_procs:
            if path and path not in historical["ioc_library"]["paths"]:
                historical["ioc_library"]["paths"].append(path)
                
        with open(historical_file, 'w', encoding='utf-8') as f:
            json.dump(historical, f, ensure_ascii=False, indent=2)
            
        print(f"\n[+] 历史记录已更新")
        
    def reset_rules(self):
        """重置为默认规则"""
        confirm = input("确定要重置所有规则吗? 此操作不可恢复 (yes/no): ")
        if confirm.lower() == 'yes':
            # 删除现有规则文件
            for rule_file in self.rule_files.values():
                if rule_file.exists():
                    rule_file.unlink()
            # 重新初始化
            self._init_default_rules()
            print("[+] 规则已重置为默认值")
        else:
            print("[*] 操作已取消")


def main():
    parser = argparse.ArgumentParser(description='经验规则库管理工具')
    parser.add_argument('--rules-dir', '-d', default='./rules', help='规则库目录')
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出规则')
    list_parser.add_argument('--type', '-t', help='规则类型 (process/startup/account/ip/webshell)')
    
    # add 命令
    add_parser = subparsers.add_parser('add', help='添加规则')
    add_parser.add_argument('type', help='规则类型')
    add_parser.add_argument('--name', required=True, help='规则名称')
    add_parser.add_argument('--pattern', required=True, help='匹配模式')
    add_parser.add_argument('--severity', default='medium', help='风险等级')
    add_parser.add_argument('--confidence', type=float, default=0.7, help='置信度')
    add_parser.add_argument('--description', default='', help='规则描述')
    
    # delete 命令
    del_parser = subparsers.add_parser('delete', help='删除规则')
    del_parser.add_argument('type', help='规则类型')
    del_parser.add_argument('rule_id', help='规则ID')
    
    # merge 命令
    merge_parser = subparsers.add_parser('merge', help='合并规则文件')
    merge_parser.add_argument('source', help='源规则文件')
    merge_parser.add_argument('target_type', help='目标规则类型')
    
    # export 命令
    export_parser = subparsers.add_parser('export', help='导出规则')
    export_parser.add_argument('output', help='输出文件')
    export_parser.add_argument('--type', '-t', help='规则类型')
    
    # compare 命令
    compare_parser = subparsers.add_parser('compare', help='与历史对比')
    compare_parser.add_argument('findings', help='当前发现文件')
    
    # reset 命令
    reset_parser = subparsers.add_parser('reset', help='重置规则')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    manager = RuleManager(args.rules_dir)
    
    if args.command == 'list':
        manager.list_rules(args.type)
    elif args.command == 'add':
        rule = {
            'name': args.name,
            'pattern': args.pattern,
            'severity': args.severity,
            'confidence': args.confidence,
            'description': args.description
        }
        manager.add_rule(args.type, rule)
    elif args.command == 'delete':
        manager.delete_rule(args.type, args.rule_id)
    elif args.command == 'merge':
        manager.merge_rules(args.source, args.target_type)
    elif args.command == 'export':
        manager.export_rules(args.output, args.type)
    elif args.command == 'compare':
        manager.compare_with_historical(args.findings)
    elif args.command == 'reset':
        manager.reset_rules()


if __name__ == '__main__':
    main()
