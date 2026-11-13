#!/usr/bin/env python3
"""注册表导出结构化：Run / RunOnce / IFEO / Winlogon / Services（reg query 文本）。

采集器用 `reg query` 把关键自启动位置导成 txt，通用加载器只做字符串扫描，
这里把它们解析成结构化条目并按路径/命令行分级。

用法：
    python analyze_persistence_exports.py <解压后的取证目录> [--out <输出目录>]
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# 只解析这几个高风险位置；其它导出（如 IFEO 的 MitigationOptions）不算持久化
SECTION_RULES = [
    (r"\\currentversion\\run$", "Run", "persistence"),
    (r"\\currentversion\\runonce$", "RunOnce", "persistence"),
    (r"\\currentversion\\runservices", "RunServices", "persistence"),
    (r"image file execution options", "IFEO", "hijack"),
    (r"\\winlogon$", "Winlogon", "hijack"),
    (r"\\services\\[^\\]+$", "Service", "persistence"),
]

HIGH_HINTS = ("\\temp\\", "\\tmp\\", "\\users\\public\\", "-enc", "-encodedcommand",
              "frombase64", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
              "wscript", "cscript", "cmd /c")
SCRIPT_EXT = (".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta", ".scr")


def _read(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "utf-16"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", "replace")


def classify(section: str) -> tuple[str, str]:
    low = section.lower()
    for pattern, kind, group in SECTION_RULES:
        if re.search(pattern, low):
            return kind, group
    return "", ""


def parse_reg_dump(path: Path) -> list[dict]:
    rows, section = [], ""
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("HKEY"):
            section = stripped
            continue
        match = re.match(r"^(\S.*?)\s+REG_(?:SZ|EXPAND_SZ|DWORD|QWORD|MULTI_SZ|BINARY)\s+(.*)$",
                         stripped)
        if not match or not section:
            continue
        name, value = match.group(1).strip(), match.group(2).strip()
        kind, group = classify(section)
        if not kind:
            continue
        rows.append({"file": path.name, "section": section, "name": name,
                     "value": value, "kind": kind, "group": group})
    return rows


def risk_of(row: dict) -> tuple[str, str]:
    value = (row["value"] or "").lower()
    name = (row["name"] or "").lower()
    kind = row["kind"]

    if kind == "IFEO":
        # 只有 Debugger 才是劫持；MitigationOptions 之类是系统缓解配置
        if name == "debugger":
            return "high", "IFEO Debugger 被设置（映像劫持）"
        return "", ""
    if kind == "Winlogon":
        if name in ("shell", "userinit") and ("explorer.exe" not in value
                                              and "userinit.exe" not in value):
            return "high", f"Winlogon {row['name']} 被改写"
        return "", ""
    if kind == "Service" and name == "imagepath":
        if any(h in value for h in ("\\temp\\", "\\users\\public", "\\programdata", "\\appdata")):
            return "high", "服务 ImagePath 指向可写目录"
        return "", ""

    # Run / RunOnce / RunServices
    reasons = []
    level = "low"
    for hint in HIGH_HINTS:
        if hint in value:
            reasons.append(f"命令行包含 {hint.strip()}")
            level = "high"
            break
    if any(value.endswith(ext) or ext in value for ext in SCRIPT_EXT):
        reasons.append("调用脚本文件")
        level = "high" if level == "low" else level
    if any(h in value for h in ("\\appdata\\", "\\programdata\\")):
        reasons.append("位于用户可写目录")
        level = "medium" if level == "low" else level
    return level, "；".join(reasons)


def analyze_persistence_exports(extracted_dir, out_dir=None) -> dict:
    extracted = Path(extracted_dir)
    out = Path(out_dir) if out_dir else extracted / "_derived" / "persistence_exports"
    out.mkdir(parents=True, exist_ok=True)

    # 只挑可能的 reg query 导出，避免把普通 txt 当注册表
    candidates = [p for p in extracted.rglob("*.txt")
                  if p.stat().st_size < 5 * 1024 * 1024 and "HKEY" in _read(p)[:4000]]

    rows, errors = [], []
    for path in candidates:
        try:
            rows.extend(parse_reg_dump(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: {exc}")

    for row in rows:
        row["risk"], row["risk_reason"] = risk_of(row)
    kept = [r for r in rows if r["risk"]]

    findings = []
    high = [r for r in kept if r["risk"] == "high"]
    medium = [r for r in kept if r["risk"] == "medium"]
    if high:
        findings.append({
            "dimension": "persistence", "type": "registry_autostart",
            "name": f"注册表自启动存在高危项 {len(high)} 条",
            "evidence": "；".join(f"{r['name']} → {r['value'][:60]}" for r in high[:4]),
            "risk_level": "high",
            "reason": "自启动项指向临时/可写目录或使用脚本/LOLBin 执行",
            "confidence": 0.8, "mitre_attack": "T1547.001",
        })
    elif medium:
        findings.append({
            "dimension": "persistence", "type": "registry_autostart",
            "name": f"注册表自启动位于用户可写目录 {len(medium)} 条",
            "evidence": "；".join(f"{r['name']} → {r['value'][:60]}" for r in medium[:4]),
            "risk_level": "medium",
            "reason": "需核对是否为正常软件按用户安装",
            "confidence": 0.55, "mitre_attack": "T1547.001",
        })

    autostart = [r for r in rows if r["kind"] in ("Run", "RunOnce", "RunServices")]
    if autostart:
        findings.append({
            "dimension": "persistence", "type": "registry_autostart_inventory",
            "name": f"自启动项清单 {len(autostart)} 条（Run/RunOnce）",
            "evidence": "；".join(r["name"] for r in autostart[:6]),
            "risk_level": "info",
            "reason": "结构化清单，供人工核对新增项",
            "confidence": 1.0, "mitre_attack": "T1547.001",
        })

    with open(out / "registry_exports.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["kind", "name", "value", "risk",
                                                "risk_reason", "section", "file"],
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    kinds = {}
    for row in rows:
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1

    summary = {
        "available": bool(rows),
        "findings": findings,
        "counts": {"entries": len(rows), "suspicious": len(kept),
                   "high": len(high), "types": kinds},
        "errors": errors[:10],
    }
    (out / "persistence_exports_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
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
    s = analyze_persistence_exports(target, Path(args.out) if args.out else None)
    c = s["counts"]
    print(f"注册表导出：{c['entries']} 条（高危 {c['high']}），类型 {c['types']}")


if __name__ == "__main__":
    main()
