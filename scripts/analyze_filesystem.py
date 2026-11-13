#!/usr/bin/env python3
"""文件系统时间线：interesting_files / recent_files / recycle_bin。

关注：可疑落盘位置、双扩展名、时间戳异常（Creation > LastWrite）。

用法：
    python analyze_filesystem.py <解压后的取证目录> [--out <输出目录>]
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

RISKY_EXT = (".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
             ".msi", ".lnk", ".docm", ".xlsm")
# 落在这些目录的可执行文件才是强线索；下载目录/AppData 很多是正常安装，降为中危
HIGH_DIRS = ("\\temp\\", "\\tmp\\", "\\users\\public\\", "\\recycle")
MEDIUM_DIRS = ("\\downloads\\", "\\appdata\\", "\\programdata\\")
DOUBLE_EXT = (".pdf.exe", ".doc.exe", ".jpg.exe", ".txt.exe", ".pdf.scr", ".doc.scr",
              ".jpg.scr", ".zip.exe", ".rar.exe")


def _read(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "utf-16"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", "replace")


def _parse_time(value: str):
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value[:19], fmt)
        except ValueError:
            continue
    return None


def parse_csv(path: Path) -> list[dict]:
    rows = []
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                full = (row.get("FullName") or row.get("Path") or "").strip()
                if not full:
                    continue
                rows.append({
                    "path": full,
                    "size": row.get("Length") or "",
                    "modified": (row.get("LastWriteTime") or "").strip(),
                    "created": (row.get("CreationTime") or "").strip(),
                    "ext": (row.get("Extension") or Path(full).suffix).strip(),
                })
    except OSError:
        pass
    return rows


def risk_of(row: dict) -> tuple[str, str]:
    low = row["path"].lower()
    reasons, level = [], "low"
    if any(low.endswith(ext) or ext in low for ext in DOUBLE_EXT):
        reasons.append("双扩展名伪装")
        level = "high"
    if row["ext"].lower() in RISKY_EXT:
        if any(h in low for h in HIGH_DIRS):
            reasons.append(f"临时/公共目录中的 {row['ext']}")
            level = "high"
        elif any(h in low for h in MEDIUM_DIRS):
            reasons.append(f"下载/用户目录中的 {row['ext']}")
            level = "medium" if level == "low" else level
    created, modified = _parse_time(row["created"]), _parse_time(row["modified"])
    if created and modified and created > modified:
        reasons.append("创建时间晚于修改时间（疑似时间戳篡改）")
        level = "medium" if level == "low" else level
    return level, "；".join(reasons)


def analyze_filesystem(extracted_dir, out_dir=None, max_rows=5000) -> dict:
    extracted = Path(extracted_dir)
    out = Path(out_dir) if out_dir else extracted / "_derived" / "filesystem"
    out.mkdir(parents=True, exist_ok=True)

    sources = []
    for name in ("interesting_files.csv", "recent_files.csv"):
        path = next((p for p in extracted.rglob(name)), None)
        if path:
            rows = parse_csv(path)
            if rows:
                sources.append((name, rows))

    rows_all = []
    for name, rows in sources:
        for row in rows:
            row["source"] = name
            row["risk"], row["risk_reason"] = risk_of(row)
            rows_all.append(row)

    findings = []
    risky = [r for r in rows_all if r["risk"] in ("high", "medium")]
    high = [r for r in risky if r["risk"] == "high"]
    if high:
        findings.append({
            "dimension": "artifact", "type": "suspicious_dropped_file",
            "name": f"可疑落盘文件 {len(high)} 个（双扩展名/可写目录可执行）",
            "evidence": "；".join(r["path"][:70] for r in high[:4]),
            "risk_level": "high",
            "reason": "可执行文件落在临时/用户目录，或使用双扩展名伪装",
            "confidence": 0.65, "mitre_attack": "T1204",
        })
    if rows_all:
        findings.append({
            "dimension": "artifact", "type": "filesystem_inventory",
            "name": f"文件系统清单 {len(rows_all)} 条（可疑 {len(risky)}）",
            "evidence": f"来源：{', '.join(n for n, _ in sources)}",
            "risk_level": "info",
            "reason": "按时间排序可用于还原投递与落地过程",
            "confidence": 1.0, "mitre_attack": "",
        })

    with open(out / "filesystem_timeline.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "size", "modified", "created", "ext",
                                                "source", "risk", "risk_reason"],
                                extrasaction="ignore")
        writer.writeheader()
        for row in sorted(rows_all, key=lambda r: r["modified"], reverse=True)[:max_rows]:
            writer.writerow(row)

    summary = {
        "available": bool(rows_all),
        "findings": findings,
        "counts": {
            "files": len(rows_all),
            "suspicious": len(risky),
            "high": len(high),
            "sources": [n for n, _ in sources],
        },
    }
    (out / "filesystem_summary.json").write_text(
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
    s = analyze_filesystem(target, Path(args.out) if args.out else None)
    if not s.get("available"):
        print("文件系统：无可用清单")
        return
    c = s["counts"]
    print(f"文件系统：{c['files']} 条（可疑 {c['suspicious']}，高危 {c['high']}）")


if __name__ == "__main__":
    main()
