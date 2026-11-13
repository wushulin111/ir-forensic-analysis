#!/usr/bin/env python3
"""Amcache.hve 解析：已安装程序 / 执行过的文件 / 内核驱动。

Windows 10/11 的结构：
  Root\\InventoryApplication        程序（Name / Version / Publisher / InstallDate / RootDirPath）
  Root\\InventoryApplicationFile    文件（ProgramId / FileId=SHA1）
  Root\\InventoryDriverBinary       驱动（DriverName / DriverCompany / DriverSigned / DriverInFile）
  Root\\File                        Win7 旧结构（可选）

用法：
    python analyze_amcache.py <解压后的取证目录> [--out <输出目录>]

输出：amcache.csv / amcache_summary.json / amcache_report.md
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

SUSPICIOUS_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\",
                   "\\programdata\\", "\\downloads\\", "\\recycle")


def _values(subkey) -> dict:
    try:
        return {str(v.name): v.value for v in subkey.iter_values(as_json=False)}
    except Exception:  # noqa: BLE001
        return {}


def _pick(values: dict, *names, default=""):
    for name in names:
        for key, value in values.items():
            if key.lower() == name.lower() and value not in (None, ""):
                return value
    return default


def _fmt_time(value) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return text[:32]


def _risk(kind: str, path: str, signed=None, company="") -> tuple[str, str]:
    blob = (path or "").lower()
    reasons = []
    level = "low"
    hit = next((h for h in SUSPICIOUS_DIRS if h in blob), None)
    if hit:
        reasons.append(f"路径包含 {hit}")
        level = "medium"
    if kind == "driver":
        if signed is False:
            reasons.append("内核驱动未签名（BYOVD 关注点）")
            level = "high"
        elif not company:
            reasons.append("驱动无厂商信息")
            level = "medium" if level == "low" else level
    return level, "；".join(reasons)


def parse_amcache(extracted_dir: Path, out_dir: Path | None = None,
                  max_entries: int = 20000) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "amcache"
    out_dir.mkdir(parents=True, exist_ok=True)

    hives = sorted(extracted_dir.rglob("Amcache.hve")) + sorted(extracted_dir.rglob("amcache.hve"))
    if not hives:
        return {"available": False, "reason": "未找到 Amcache.hve", "entries": []}

    try:
        from regipy.registry import RegistryHive
    except ImportError:
        return {"available": False, "reason": "缺少 regipy（pip install regipy）", "entries": []}

    entries, errors, counts = [], [], {"application": 0, "file": 0, "driver": 0}
    hive_path = hives[0]
    try:
        reg = RegistryHive(str(hive_path))
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "hive": hive_path.name, "total": 0, "suspicious": 0,
                "with_sha1": 0, "errors": [f"{hive_path.name}: {exc}"], "entries": []}

    def add(entry):
        if len(entries) < max_entries:
            entries.append(entry)

    # ---- 应用程序 ----
    try:
        key = reg.get_key("\\Root\\InventoryApplication")
        for sub in key.iter_subkeys():
            values = _values(sub)
            name = _pick(values, "Name")
            path = _pick(values, "RootDirPath")
            level, reason = _risk("application", str(path))
            add({
                "kind": "application",
                "name": str(name or sub.name)[:160],
                "version": str(_pick(values, "Version"))[:40],
                "publisher": str(_pick(values, "Publisher"))[:80],
                "path": str(path)[:260],
                "sha1": "",
                "time": _fmt_time(_pick(values, "InstallDate")),
                "signed": "",
                "risk": level, "risk_reason": reason,
            })
            counts["application"] += 1
    except Exception as exc:  # noqa: BLE001
        errors.append(f"InventoryApplication: {exc}")

    # ---- 文件（ProgramId + FileId=SHA1） ----
    try:
        key = reg.get_key("\\Root\\InventoryApplicationFile")
        for sub in key.iter_subkeys():
            values = _values(sub)
            file_id = str(_pick(values, "FileId"))
            name = sub.name.split("|")[0]
            add({
                "kind": "file",
                "name": name[:160],
                "version": "",
                "publisher": "",
                "path": "",
                "sha1": file_id[:40],
                "time": "",
                "signed": "",
                "risk": "low", "risk_reason": "",
            })
            counts["file"] += 1
    except Exception as exc:  # noqa: BLE001
        errors.append(f"InventoryApplicationFile: {exc}")

    # ---- 内核驱动 ----
    try:
        key = reg.get_key("\\Root\\InventoryDriverBinary")
        for sub in key.iter_subkeys():
            values = _values(sub)
            driver = _pick(values, "DriverName")
            company = _pick(values, "DriverCompany")
            signed_raw = _pick(values, "DriverSigned")
            signed = bool(signed_raw) if signed_raw not in ("", None) else None
            path = _pick(values, "DriverInFile", "Inf")
            level, reason = _risk("driver", str(path), signed, str(company))
            add({
                "kind": "driver",
                "name": str(driver or sub.name)[:160],
                "version": str(_pick(values, "DriverVersion"))[:40],
                "publisher": str(company)[:80],
                "path": str(path)[:260],
                "sha1": "",
                "time": "",
                "signed": "" if signed is None else ("是" if signed else "否"),
                "risk": level, "risk_reason": reason,
            })
            counts["driver"] += 1
    except Exception as exc:  # noqa: BLE001
        errors.append(f"InventoryDriverBinary: {exc}")

    suspicious = [e for e in entries if e["risk"] in ("medium", "high")]
    unsigned_drivers = [e for e in entries if e["kind"] == "driver" and e["signed"] == "否"]
    summary = {
        "available": True,
        "hive": hive_path.name,
        "total": len(entries),
        "counts": counts,
        "suspicious": len(suspicious),
        "unsigned_drivers": len(unsigned_drivers),
        "with_sha1": sum(1 for e in entries if e["sha1"]),
        "errors": errors,
        "entries": entries,
    }

    with open(out_dir / "amcache.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["kind", "name", "version", "publisher", "path",
                                                "sha1", "time", "signed", "risk", "risk_reason"])
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry)
    (out_dir / "amcache_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Amcache（程序 / 文件 / 驱动）", "",
             f"- hive：{hive_path.name}",
             f"- 程序 {counts['application']} 条 · 文件 {counts['file']} 条 · 驱动 {counts['driver']} 条",
             f"- 可疑 {len(suspicious)} 条 · 未签名驱动 {len(unsigned_drivers)} 个", ""]
    if unsigned_drivers:
        lines += ["## 未签名内核驱动", "", "| 驱动 | 厂商 | 路径 |", "|---|---|---|"]
        lines += [f"| {e['name'][:50]} | {e['publisher'][:30] or '-'} | {e['path'][:70]} |"
                  for e in unsigned_drivers[:20]]
        lines.append("")
    if suspicious:
        lines += ["## 可疑条目", "", "| 类型 | 名称 | 原因 |", "|---|---|---|"]
        lines += [f"| {e['kind']} | {e['name'][:50]} | {e['risk_reason'][:60]} |"
                  for e in suspicious[:20]]
        lines.append("")
    apps = [e for e in entries if e["kind"] == "application"][:20]
    if apps:
        lines += ["## 程序样例", "", "| 程序 | 版本 | 安装时间 |", "|---|---|---|"]
        lines += [f"| {e['name'][:40]} | {e['version'][:20]} | {e['time']} |" for e in apps]
    (out_dir / "amcache_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    s = parse_amcache(target, Path(args.out) if args.out else None)
    if not s.get("available"):
        print("Amcache 不可用：", s.get("reason"))
        return
    c = s.get("counts", {})
    print(f"Amcache：程序 {c.get('application', 0)} / 文件 {c.get('file', 0)} / "
          f"驱动 {c.get('driver', 0)}，可疑 {s.get('suspicious', 0)}，"
          f"未签名驱动 {s.get('unsigned_drivers', 0)}")


if __name__ == "__main__":
    main()
