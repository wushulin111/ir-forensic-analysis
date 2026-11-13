#!/usr/bin/env python3
"""Prefetch 解析：MAM/XPRESS 解压 → 可执行名、运行次数、最近运行时间、引用文件。

用法：
    python analyze_prefetch.py <解压后的取证目录> [--out <输出目录>]

输出：prefetch.csv / prefetch_summary.json / prefetch_report.md
"""

import argparse
import csv
import json
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# 已知偏移：v23/v26 与 v30/v31 不同
COUNT_OFFSET = {17: 0x90, 23: 0x90, 26: 0x98, 30: 0x98, 31: 0xD0}
TIME_OFFSET = {17: 0x78, 23: 0x78, 26: 0x80, 30: 0x80, 31: 0x80}
SUSPICIOUS_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\",
                   "\\programdata\\", "\\downloads\\", "\\recycle")


def decompress(raw: bytes) -> bytes | None:
    """MAM\x04 + 4 字节长度 + XPRESS Huffman；老系统为未压缩的 SCCA。"""
    if raw[:3] == b"SCCA":
        return raw
    if raw[:3] != b"MAM":
        return None
    try:
        from dissect.util.compression import lzxpress_huffman
    except ImportError:
        return None
    try:
        size = struct.unpack("<I", raw[4:8])[0]
        out = lzxpress_huffman.decompress(raw[8:])
        return out[:size] if size and len(out) >= size else out
    except Exception:  # noqa: BLE001
        return None


def utf16_strings(data: bytes, min_len: int = 4) -> list[str]:
    out, cur = [], []
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo <= 126:
            cur.append(chr(lo))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def parse_pf(path: Path) -> dict | None:
    raw = path.read_bytes()
    data = decompress(raw)
    if not data or len(data) < 84:
        return None
    version = struct.unpack("<I", data[0:4])[0]
    exe = data[0x10:0x10 + 60].decode("utf-16-le", "ignore").rstrip("\x00")

    run_count = None
    offset = COUNT_OFFSET.get(version)
    if offset:
        try:
            value = struct.unpack("<I", data[offset:offset + 4])[0]
            run_count = value if 0 < value < 1_000_000 else None
        except struct.error:
            pass

    last_runs = []
    base = TIME_OFFSET.get(version)
    if base:
        for index in range(8):
            try:
                ft = struct.unpack("<Q", data[base + index * 8: base + index * 8 + 8])[0]
            except struct.error:
                break
            if not ft:
                continue
            try:
                moment = FILETIME_EPOCH + timedelta(microseconds=ft // 10)
            except OverflowError:
                continue
            if 1990 <= moment.year <= 2035:
                last_runs.append(moment.astimezone().strftime("%Y-%m-%d %H:%M:%S"))

    strings = utf16_strings(data, 4)
    paths = [s for s in strings if ("\\" in s or ":/" in s) and len(s) >= 6][:200]

    return {
        "file": path.name,
        "version": version,
        "executable": exe,
        "run_count": run_count,
        "last_run": last_runs[0] if last_runs else "",
        "last_runs": ";".join(last_runs[:8]),
        "referenced_count": len(paths),
        "referenced_sample": " | ".join(paths[:10]),
        "risk": "low",
        "risk_reason": "",
    }


def risk_of(entry: dict) -> tuple[str, str]:
    blob = (entry["file"] + " " + entry["referenced_sample"]).lower()
    reasons = []
    level = "low"
    for hint in SUSPICIOUS_DIRS:
        if hint in blob:
            reasons.append(f"路径包含 {hint}")
            level = "medium"
            break
    name = entry["executable"].lower()
    if any(name.startswith(prefix) for prefix in ("cmd.exe", "powershell.exe", "wscript.exe",
                                                 "cscript.exe", "mshta.exe", "rundll32.exe",
                                                 "regsvr32.exe")):
        reasons.append("由脚本解释器/系统代理进程执行")
        level = "medium" if level == "low" else level
    if entry["run_count"] and entry["run_count"] >= 50 and level == "medium":
        reasons.append(f"执行次数较多（{entry['run_count']}）")
    return level, "；".join(reasons)


def parse_prefetch(extracted_dir: Path, out_dir: Path | None = None) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "prefetch"
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(extracted_dir.rglob("*.pf"))
    entries, errors = [], []
    for path in files:
        try:
            entry = parse_pf(path)
            if not entry:
                errors.append(f"{path.name}: 解压或解析失败")
                continue
            entry["risk"], entry["risk_reason"] = risk_of(entry)
            entries.append(entry)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: {exc}")

    suspicious = [e for e in entries if e["risk"] in ("medium", "high")]
    summary = {
        "available": bool(files), "files": len(files), "parsed": len(entries),
        "suspicious": len(suspicious), "errors": errors[:20],
        "top_run": sorted([e for e in entries if e["run_count"]],
                          key=lambda x: -(x["run_count"] or 0))[:20],
        "entries": entries,
    }

    with open(out_dir / "prefetch.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", "version", "executable", "run_count",
                                                "last_run", "referenced_count", "risk",
                                                "risk_reason", "referenced_sample"],
                                extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry)
    (out_dir / "prefetch_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Prefetch 执行痕迹", "",
             f"- 文件：{len(files)} 个，解析成功 {len(entries)} 个，可疑 {len(suspicious)} 个", ""]
    if summary["top_run"]:
        lines += ["## 执行次数 Top", "", "| 程序 | 次数 | 最近运行 |", "|---|---|---|"]
        lines += [f"| {e['executable']} | {e['run_count']} | {e['last_run']} |"
                  for e in summary["top_run"][:15]]
        lines.append("")
    if suspicious:
        lines += ["## 可疑执行痕迹", "", "| 程序 | 原因 | 引用路径 |", "|---|---|---|"]
        lines += [f"| {e['executable']} | {e['risk_reason']} | "
                  f"{(e['referenced_sample'] or '')[:100]} |" for e in suspicious[:20]]
    (out_dir / "prefetch_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    s = parse_prefetch(target, Path(args.out) if args.out else None)
    print(f"Prefetch：{s['files']} 个文件，解析 {s['parsed']} 个，可疑 {s['suspicious']} 个")


if __name__ == "__main__":
    main()
