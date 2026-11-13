#!/usr/bin/env python3
"""安全配置与劫持面解析：hosts / DNS 缓存 / 防火墙 / Defender 排除 / BITS /
AppInit_DLLs / 管理员组 / 环境变量。

这些产物在采集包里都是 txt，通用加载器会读进字符串池，但没有任何维度专门判断。
本模块把它们结构化成 findings，交给 analyze_forensics 归入对应维度。

用法：
    python analyze_config.py <解压后的取证目录> [--out <输出目录>]

输出（默认写到 <取证目录>/_derived/config/）：
    hosts_entries.csv / defender_exclusions.csv / bits_jobs.csv / admin_members.csv
    security_config_summary.json（含 findings）
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

DEFAULT_HOSTS = {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost",
                 "ip6-loopback", "local", "wpad"}
WRITABLE_HINTS = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\",
                  "\\downloads\\", "\\recycle")
AV_DOMAINS = ("defender", "microsoft.com", "windowsupdate", "kaspersky", "360.cn", "huorong",
              "qianxin", "sangfor", "trendmicro", "symantec", "mcafee", "eset")


def _read(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", "replace")


def _find(extracted: Path, *names) -> Path | None:
    lowered = {n.lower() for n in names}
    for path in extracted.rglob("*"):
        if path.is_file() and path.name.lower() in lowered:
            return path
    return None


def _load_iocs() -> tuple[set, set]:
    for candidate in (Path(__file__).resolve().parents[1] / "rules" / "ioc_library.json",):
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8-sig"))
                iocs = data.get("iocs", {})
                return ({str(d).lower() for d in iocs.get("domains", [])},
                        {str(i) for i in iocs.get("ips", [])})
            except (OSError, ValueError):
                pass
    return set(), set()


# ---------------- hosts ----------------
def parse_hosts(path: Path) -> list[dict]:
    rows = []
    for line in _read(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        ip, hosts = parts[0], parts[1:]
        for host in hosts:
            default = host.lower() in DEFAULT_HOSTS or ip in ("127.0.0.1", "::1", "0.0.0.0")
            rows.append({"ip": ip, "host": host, "default": default})
    return rows


# ---------------- DNS 缓存 ----------------
def parse_dns(path: Path) -> list[dict]:
    text = _read(path)
    rows = []
    blocks = re.split(r"\n\s*\n", text)
    for block in blocks:
        name = re.search(r"记录名称[^\w]*?[:：]\s*(\S+)", block)
        if not name:
            name = re.search(r"Record Name[^\w]*?[:：]\s*(\S+)", block)
        if not name:
            continue
        ips = re.findall(r"(?:A \(主机\) 记录|A \(Host\) Record)[^\n]*\n\s*(\d+\.\d+\.\d+\.\d+)", block)
        if not ips:
            ips = re.findall(r"^\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$", block, re.M)
        rows.append({"host": name.group(1), "ips": ips})
    return rows


# ---------------- Defender 排除项 ----------------
def parse_defender(path: Path) -> dict:
    text = _read(path)
    out = {"paths": [], "processes": [], "extensions": [], "error": "", "unavailable": False}
    wanted = {"paths", "processes", "extensions"}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[WARN]") or stripped.startswith("[ERROR]"):
            out["error"] = stripped[:160]
            out["unavailable"] = True
            continue
        match = re.match(r"^---\s*([\w\- ]+?)\s*---$", stripped)
        if match:
            key = match.group(1).strip().lower()
            current = key if key in wanted else None
            continue
        if not stripped or current is None:
            continue
        if "(missing" in stripped or "access denied" in stripped.lower():
            out["unavailable"] = True
            continue
        out[current].append(stripped)
    return out


# ---------------- BITS ----------------
def parse_bits(path: Path) -> list[dict]:
    text = _read(path)
    jobs = {}
    for line in text.splitlines():
        match = re.match(r"\{([0-9A-Fa-f\-]{36})\}\s+'([^']*)'\s+(\w+)", line)
        if match:
            jobs[match.group(1)] = {"guid": match.group(1), "name": match.group(2),
                                    "state": match.group(3), "urls": []}
            continue
        for url in re.findall(r"https?://\S+", line):
            if jobs:
                jobs[list(jobs)[-1]]["urls"].append(url)
    return list(jobs.values())


# ---------------- AppInit / AppCert DLL ----------------
def parse_dll_config(path: Path) -> dict:
    text = _read(path)
    out = {"appinit": "", "appcert": "", "load_appinit": "", "source": path.name}
    for name, pattern in (("appinit", r"^\s*AppInit_DLLs[ \t]+REG_\w+[ \t]*(.*)$"),
                          ("appcert", r"^\s*AppCertDlls[ \t]+REG_\w+[ \t]*(.*)$"),
                          ("load_appinit", r"^\s*LoadAppInit_DLLs[ \t]+REG_\w+[ \t]*(.*)$")):
        match = re.search(pattern, text, re.I | re.M)
        if match:
            out[name] = match.group(1).strip()
    return out


# ---------------- 管理员组 ----------------
def parse_admin(path: Path) -> list[str]:
    text = _read(path)
    members, collecting = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^成员$|^Members$", stripped) or stripped.startswith("====") or \
                stripped.startswith("----"):
            collecting = True
            continue
        if collecting:
            if not stripped or stripped.startswith(("命令成功", "The command completed", "别名", "Alias")):
                if members:
                    break
                continue
            members.append(stripped)
    return members


# ---------------- 环境变量（PATH） ----------------
def parse_environment(path: Path) -> dict:
    text = _read(path)
    out = {"path_entries": [], "suspicious_path": []}
    for line in text.splitlines():
        if re.match(r"^\s*(Path|PATH)\s*=", line):
            value = line.split("=", 1)[1]
            entries = [x.strip() for x in value.split(";") if x.strip()]
            out["path_entries"] = entries
            out["suspicious_path"] = [e for e in entries
                                      if any(h in (e + "\\").lower() for h in WRITABLE_HINTS)]
    return out


# ---------------- 防火墙 ----------------
def parse_firewall(path: Path) -> dict:
    text = _read(path)
    out = {"state": "", "policy": "", "disabled": False}
    match = re.search(r"(状态|State)\s*(启用|禁用|On|Off)", text)
    if match:
        out["state"] = match.group(2)
        out["disabled"] = match.group(2) in ("禁用", "Off")
    match = re.search(r"(防火墙策略|Firewall Policy)\s*(.+)", text)
    if match:
        out["policy"] = match.group(2).strip()
    return out


SYSTEM_DLL_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                   "\\program files\\", "\\program files (x86)\\")
COM_HIJACK_DIRS = ("\\temp\\", "\\tmp\\", "\\users\\public\\",
                   "\\programdata\\", "\\downloads\\", "\\recycle")
RISKY_DL_EXT = (".exe", ".scr", ".ps1", ".js", ".vbs", ".hta", ".msi", ".bat", ".cmd",
                ".docm", ".xlsm", ".lnk", ".iso")
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_com_hijack(path: Path) -> list[dict]:
    """解析 reg query 导出：找 InprocServer32 的默认值。"""
    text = _read(path)
    rows, section, take_next = [], "", False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("HKEY"):
            section = stripped
            take_next = "inprocserver32" in section.lower()
            continue
        if not take_next or not stripped:
            continue
        match = re.match(r"^\(默认\)\s+REG_\w+\s+(.*)$", stripped) or \
                re.match(r"^InprocServer32\s+REG_\w+\s+(.*)$", stripped)
        if match:
            dll = match.group(1).strip()
            if dll:
                rows.append({"section": section, "dll": dll})
            take_next = False
    return rows


def parse_downloads(path: Path) -> list[dict]:
    rows = []
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                full = (row.get("FullName") or row.get("Path") or "").strip()
                if not full:
                    continue
                rows.append({"path": full, "size": row.get("Length") or "",
                             "time": (row.get("LastWriteTime") or "").strip()})
    except OSError:
        pass
    return rows


def parse_bam(path: Path) -> list[dict]:
    """BAM：每条 REG_BINARY 前 8 字节是 FILETIME（小端）。"""
    text = _read(path)
    rows = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\\Device\\\S+)\s+REG_BINARY\s+([0-9A-Fa-f]+)", line)
        if not match:
            continue
        raw = match.group(2)
        stamp = ""
        if len(raw) >= 16:
            try:
                value = int.from_bytes(bytes.fromhex(raw[:16]), "little")
                moment = FILETIME_EPOCH + timedelta(microseconds=value // 10)
                if 2000 <= moment.year <= 2035:
                    stamp = moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OverflowError):
                stamp = ""
        rows.append({"path": match.group(1), "time": stamp})
    rows.sort(key=lambda r: r["time"], reverse=True)
    return rows


def _rel(path: Path, root: Path) -> str:
    """相对路径；如果解压后多了一层 sha256 目录，去掉它。"""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return str(path)
    parts = list(rel.parts)
    if len(parts) > 1 and re.fullmatch(r"[0-9a-f]{32,64}", parts[0]):
        parts = parts[1:]
    return "/".join(parts)


def analyze_config(extracted_dir, out_dir=None) -> dict:
    extracted = Path(extracted_dir)
    out = Path(out_dir) if out_dir else extracted / "_derived" / "config"
    out.mkdir(parents=True, exist_ok=True)

    ioc_domains, ioc_ips = _load_iocs()
    findings, data = [], {}
    gaps = []

    # hosts
    hosts_path = _find(extracted, "hosts.txt", "hosts")
    if hosts_path:
        rows = parse_hosts(hosts_path)
        custom = [r for r in rows if not r["default"]]
        data["hosts"] = rows
        if custom:
            av = [r for r in custom if any(d in r["host"].lower() for d in AV_DOMAINS)]
            findings.append({
                "dimension": "network", "type": "hosts_hijack",
                "name": f"hosts 文件存在 {len(custom)} 条自定义映射",
                "evidence": "；".join(f"{r['ip']} → {r['host']}" for r in custom[:4]),
                "risk_level": "high" if av else "medium",
                "reason": ("其中包含屏蔽安全厂商域名" if av else "自定义映射可能用于劫持或屏蔽"),
                "confidence": 0.75, "mitre_attack": "T1565.001",
            })

    # DNS 缓存
    dns_path = _find(extracted, "dns_cache.txt")
    if dns_path:
        rows = parse_dns(dns_path)
        data["dns"] = rows
        hits = [r for r in rows if r["host"].lower() in ioc_domains
                or any(ip in ioc_ips for ip in r["ips"])]
        if hits:
            findings.append({
                "dimension": "network", "type": "dns_ioc",
                "name": f"DNS 缓存命中威胁情报 {len(hits)} 条",
                "evidence": "；".join(f"{r['host']} → {','.join(r['ips'][:2])}" for r in hits[:4]),
                "risk_level": "high", "reason": "本机曾解析过 IOC 域名",
                "confidence": 0.85, "mitre_attack": "T1071.004",
            })

    # Defender 排除项
    def_path = _find(extracted, "defender_exclusions.txt")
    if def_path:
        info = parse_defender(def_path)
        data["defender"] = info
        total = len(info["paths"]) + len(info["processes"]) + len(info["extensions"])
        if total and not info.get("unavailable"):
            findings.append({
                "dimension": "advanced", "type": "defender_exclusions",
                "name": f"Defender 排除项 {total} 条",
                "evidence": "；".join((info["paths"] + info["processes"] + info["extensions"])[:4]),
                "risk_level": "high",
                "reason": "攻击者常通过添加排除项让恶意文件不被扫描",
                "confidence": 0.8, "mitre_attack": "T1562.001",
            })

    # BITS 任务
    bits_path = _find(extracted, "bits_jobs.txt")
    if bits_path:
        jobs = parse_bits(bits_path)
        data["bits"] = jobs
        risky = [j for j in jobs if j["urls"] or j["state"].upper() in ("TRANSFERRING", "SUSPENDED")]
        if risky:
            findings.append({
                "dimension": "persistence", "type": "bits_job",
                "name": f"BITS 传输任务 {len(risky)} 个（含远程 URL 或进行中）",
                "evidence": "；".join(f"{j['name'][:40]} [{j['state']}] {j['urls'][:1]}" for j in risky[:3]),
                "risk_level": "medium",
                "reason": "BITS 常被用于持久化下载与静默外传",
                "confidence": 0.6, "mitre_attack": "T1197",
            })

    # AppInit / AppCert DLL
    for name, label in (("appinit_dlls.txt", "AppInit_DLLs"), ("appcert_dlls.txt", "AppCertDlls")):
        path = _find(extracted, name)
        if not path:
            continue
        info = parse_dll_config(path)
        data[label] = info
        value = info.get("appinit" if "init" in name else "appcert", "").strip()
        looks_like_key = bool(re.match(r"^[A-Za-z_][\w]*\s+REG_", value))
        if value and not looks_like_key and "access denied" not in value.lower():
            findings.append({
                "dimension": "persistence", "type": "dll_injection_config",
                "name": f"{label} 被设置",
                "evidence": value[:200],
                "risk_level": "high",
                "reason": "该键会让指定 DLL 注入到每个加载 user32 的进程",
                "confidence": 0.85, "mitre_attack": "T1546.010",
            })

    # 管理员组
    admin_path = _find(extracted, "admin_group.txt")
    if admin_path:
        members = parse_admin(admin_path)
        data["admin_members"] = members
        unusual = [m for m in members if m.lower() not in
                   ("administrator", "admin", "domain admins", "enterprise admins")]
        if unusual:
            findings.append({
                "dimension": "account", "type": "admin_group",
                "name": f"本地管理员组成员 {len(members)} 个",
                "evidence": "、".join(members[:6]),
                "risk_level": "info",
                "reason": "需人工确认非默认成员是否为业务账号",
                "confidence": 0.6, "mitre_attack": "T1078.003",
            })

    # PATH 劫持
    env_path = _find(extracted, "Environment.txt", "environment.csv")
    if env_path:
        info = parse_environment(env_path)
        data["environment"] = info
        if info["suspicious_path"]:
            findings.append({
                "dimension": "persistence", "type": "path_hijack",
                "name": f"PATH 含可写目录 {len(info['suspicious_path'])} 条",
                "evidence": "；".join(info["suspicious_path"][:4]),
                "risk_level": "medium",
                "reason": "可写目录在 PATH 中可被用于 DLL/可执行文件劫持",
                "confidence": 0.65, "mitre_attack": "T1574.007",
            })

    # 防火墙
    fw_path = _find(extracted, "firewall.txt")
    if fw_path:
        info = parse_firewall(fw_path)
        data["firewall"] = info
        if info["disabled"]:
            findings.append({
                "dimension": "advanced", "type": "firewall_disabled",
                "name": "防火墙被关闭",
                "evidence": f"状态={info['state']}",
                "risk_level": "high",
                "reason": "关闭防火墙是常见的驻留前置动作",
                "confidence": 0.8, "mitre_attack": "T1562.004",
            })

    # COM 劫持
    com_dir = None
    for candidate in extracted.rglob("com_hijack"):
        if candidate.is_dir():
            com_dir = candidate
            break
    if com_dir:
        rows = []
        for path in com_dir.glob("*.txt"):
            rows.extend(parse_com_hijack(path))
        data["com_hijack"] = rows
        # 只把"落在可写目录"的 InprocServer32 判为可疑：
        # 系统目录、Program Files、%systemroot% 以及第三方软件目录都属正常。
        def _is_suspicious(dll: str) -> bool:
            low = (dll or "").lower()
            if not low:
                return False
            if any(d in low for d in SYSTEM_DLL_DIRS):
                return False
            if low.startswith("%systemroot%") or low.startswith("%windir%") or ":\\windows" in low:
                return False
            return any(h in low for h in COM_HIJACK_DIRS)

        suspicious = [r for r in rows if _is_suspicious(r["dll"])]
        if suspicious:
            findings.append({
                "dimension": "persistence", "type": "com_hijack",
                "name": f"COM 劫持可疑项 {len(suspicious)} 条",
                "evidence": "；".join(f"{r['dll'][:60]}" for r in suspicious[:3]),
                "risk_level": "high",
                "reason": "InprocServer32 指向非系统目录，可用于劫持进程内 COM 调用",
                "confidence": 0.75, "mitre_attack": "T1546.015",
            })

    # 下载目录
    dl_path = _find(extracted, "downloads.csv")
    if dl_path:
        rows = parse_downloads(dl_path)
        data["downloads"] = rows[:500]
        risky = [r for r in rows if r["path"].lower().endswith(RISKY_DL_EXT)]
        if risky:
            findings.append({
                "dimension": "advanced", "type": "downloads_dir",
                "name": f"下载目录存在可执行/脚本文件 {len(risky)} 个",
                "evidence": "；".join(r["path"][:60] for r in risky[:3]),
                "risk_level": "medium",
                "reason": "可执行文件下载落盘，需核对来源与签名",
                "confidence": 0.6, "mitre_attack": "T1105",
            })

    # BAM 执行痕迹
    bam_path = _find(extracted, "bam.txt")
    if bam_path:
        rows = parse_bam(bam_path)
        data["bam"] = rows[:300]
        if rows:
            newest = [r for r in rows if r["time"]][:3]
            findings.append({
                "dimension": "advanced", "type": "bam_execution",
                "name": f"BAM 记录程序执行 {len(rows)} 条",
                "evidence": "；".join(f"{Path(r['path']).name} {r['time']}" for r in newest),
                "risk_level": "info",
                "reason": "BAM 提供程序最近执行时间，可与 Prefetch 交叉验证",
                "confidence": 0.9, "mitre_attack": "T1204",
            })

    # ---- 采集清单完整性（collection_manifest.json） ----
    manifest_path = _find(extracted, "collection_manifest.json")
    if manifest_path:
        try:
            manifest = json.loads(_read(manifest_path))
        except ValueError:
            manifest = {}
        modules = manifest.get("modules") or []
        bad = [m for m in modules if str(m.get("status", "")).lower() not in ("ok", "")]
        data["manifest"] = {"modules": len(modules), "bad": len(bad),
                            "failed": manifest.get("modules_failed"),
                            "errors": manifest.get("errors") or []}
        if bad:
            findings.append({
                "dimension": "advanced", "type": "collection_incomplete",
                "name": f"采集模块有 {len(bad)} 个未完成（partial/failed）",
                "evidence": "；".join(f"{m.get('name')}({m.get('status')})" for m in bad[:5]),
                "risk_level": "medium",
                "reason": "对应维度的结论可能因数据缺失而不完整，需结合采集日志判断",
                "confidence": 0.9, "mitre_attack": "",
            })
            for module in bad:
                gaps.append({"file": f"module:{module.get('name')}",
                             "reason": f"{module.get('status')}: {str(module.get('error') or '')[:80]}"})

    # ---- IIS 站点（iis_sites.txt） ----
    iis_path = _find(extracted, "iis_sites.txt")
    if iis_path:
        text = _read(iis_path)
        failed = any(marker in text for marker in
                     ("不是内部或外部命令", "Cannot find", "appcmd", "not recognized"))
        if failed:
            gaps.append({"file": "7_web/iis_sites.txt", "reason": "IIS 采集失败（appcmd 不可用）"})
            data["iis"] = {"available": False}
        else:
            sites = [l.strip() for l in text.splitlines() if l.strip() and "site" in l.lower()]
            data["iis"] = {"available": True, "sites": sites[:100]}
            writable_sites = [s for s in sites
                              if any(h in s.lower() for h in WRITABLE_HINTS)]
            if writable_sites:
                findings.append({
                    "dimension": "webshell", "type": "iis_writable_root",
                    "name": f"IIS 站点目录位于可写路径 {len(writable_sites)} 个",
                    "evidence": "；".join(s[:80] for s in writable_sites[:3]),
                    "risk_level": "medium",
                    "reason": "站点根目录可写时 webshell 落地风险更高",
                    "confidence": 0.6, "mitre_attack": "T1505.003",
                })

    # ---- 证据缺口自检（采集失败/权限不足/被跳过） ----
    for path in extracted.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        if name.upper().endswith(".FAILED.TXT") or name.lower() in ("hives_skipped.txt",):
            gaps.append({"file": _rel(path, extracted), "reason": "采集失败或被跳过"})
            continue
        if path.suffix.lower() in (".txt", ".csv") and path.stat().st_size < 400:
            try:
                head = path.read_text(encoding="utf-8", errors="ignore")[:400].lower()
            except OSError:
                continue
            if "access denied" in head or "拒绝访问" in head or "(missing" in head:
                gaps.append({"file": _rel(path, extracted), "reason": "权限不足或内容缺失"})
    data["gaps"] = gaps
    if gaps:
        findings.append({
            "dimension": "advanced", "type": "evidence_gap",
            "name": f"证据缺口 {len(gaps)} 处（相关维度结论需保守）",
            "evidence": "；".join(f"{g['file']}" for g in gaps[:5]),
            "risk_level": "info",
            "reason": "采集失败/权限不足时对应维度会显示无发现，但这不等于没有问题",
            "confidence": 1.0, "mitre_attack": "",
        })

    # ---- 写 CSV ----
    def write_csv(name, rows, fields):
        with open(out / name, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    write_csv("hosts_entries.csv", data.get("hosts", []), ["ip", "host", "default"])
    write_csv("bam_entries.csv", data.get("bam", []), ["path", "time"])
    write_csv("evidence_gaps.csv", data.get("gaps", []), ["file", "reason"])
    write_csv("com_hijack.csv", data.get("com_hijack", []), ["section", "dll"])
    write_csv("bits_jobs.csv", data.get("bits", []), ["guid", "name", "state", "urls"])
    write_csv("admin_members.csv", [{"member": m} for m in data.get("admin_members", [])],
              ["member"])
    defender = data.get("defender") or {}
    write_csv("defender_exclusions.csv",
              [{"kind": k, "value": v} for k in ("paths", "processes", "extensions")
               for v in defender.get(k, [])], ["kind", "value"])

    summary = {
        "available": bool(findings),
        "gaps": (data.get("gaps") or [])[:50],
        "findings": findings,
        "counts": {
            "hosts_custom": sum(1 for r in data.get("hosts", []) if not r["default"]),
            "dns_entries": len(data.get("dns", [])),
            "defender_exclusions": sum(len(defender.get(k, []))
                                       for k in ("paths", "processes", "extensions")),
            "bits_jobs": len(data.get("bits", [])),
            "admin_members": len(data.get("admin_members", [])),
            "bam_entries": len(data.get("bam", [])),
            "com_hijack": len(data.get("com_hijack", [])),
            "evidence_gaps": len(data.get("gaps", [])),
            "manifest_bad_modules": (data.get("manifest") or {}).get("bad", 0),
            "downloads_risky": sum(1 for r in data.get("downloads", [])
                                   if r["path"].lower().endswith(RISKY_DL_EXT)),
        },
    }
    (out / "security_config_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# 安全配置与劫持面", ""]
    for key, value in summary["counts"].items():
        lines.append(f"- {key}: {value}")
    if findings:
        lines += ["", "## 发现", "", "| 维度 | 等级 | 内容 |", "|---|---|---|"]
        lines += [f"| {f['dimension']} | {f['risk_level']} | {f['name']} |" for f in findings]
    (out / "config_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extracted_dir")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    target = Path(args.extracted_dir)
    if not target.is_dir():
        print(f"[错误] 目录不存在：{target}", file=sys.stderr)
        sys.exit(2)
    summary = analyze_config(target, Path(args.out) if args.out else None)
    print(f"安全配置：{len(summary['findings'])} 项发现，计数 {summary['counts']}")


if __name__ == "__main__":
    main()
