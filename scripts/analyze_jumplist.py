#!/usr/bin/env python3
"""Jump List 解析：OLE 复合文档里的 DestList + LNK 流，提取最近访问的文件路径。

用法：
    python analyze_jumplist.py <解压后的取证目录> [--out <输出目录>]

输出：jumplist.csv / jumplist_summary.json / jumplist_report.md
"""

import argparse
import csv
import json
import struct
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

SUSPICIOUS_HINTS = ("\\temp\\", "\\appdata\\", "\\users\\public\\", "\\downloads\\", "\\recycle")


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


def path_like(values: list[str]) -> list[str]:
    result = []
    for value in values:
        text = value.strip()
        if len(text) < 5:
            continue
        if "\\" in text or ":/" in text or text.lower().startswith(("http://", "https://")):
            if text not in result:
                result.append(text)
    return result


def parse_destlist(blob: bytes) -> dict:
    """DestList 头部：version(uint32) + entry_count(uint32)。"""
    info = {"version": None, "count": None}
    if len(blob) < 8:
        return info
    try:
        version, count = struct.unpack("<II", blob[:8])
        info["version"] = version
        info["count"] = count if count < 100000 else None
    except struct.error:
        pass
    return info


def parse_jumplist(extracted_dir: Path, out_dir: Path | None = None) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "jumplist"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        import olefile
    except ImportError:
        return {"available": False, "reason": "缺少 olefile", "entries": []}

    files = sorted(extracted_dir.rglob("*.automaticdestinations-ms"))
    entries, errors = [], []
    for path in files:
        try:
            ole = olefile.OleFileIO(str(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: {exc}")
            continue
        try:
            streams = ["/".join(s) for s in ole.listdir()]
            info = {"version": None, "count": None}
            if "DestList" in streams:
                info = parse_destlist(ole.openstream("DestList").read())

            paths = []
            for name in streams:
                if name == "DestList":
                    continue
                try:
                    blob = ole.openstream(name).read()
                except Exception:  # noqa: BLE001
                    continue
                paths.extend(path_like(utf16_strings(blob, 4)))
            # DestList 里的字符串（最近访问的完整路径）
            if "DestList" in streams:
                try:
                    paths.extend(path_like(utf16_strings(ole.openstream("DestList").read(), 4)))
                except Exception:  # noqa: BLE001
                    pass
            ole.close()

            unique = []
            for value in paths:
                if value not in unique:
                    unique.append(value)

            entries.append({
                "file": path.name,
                "app_id": path.stem.split(".")[0][-16:],
                "streams": len(streams),
                "destlist_count": info.get("count"),
                "paths": unique[:50],
                "path_count": len(unique),
            })
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: {exc}")
            try:
                ole.close()
            except Exception:  # noqa: BLE001
                pass

    # 汇总所有路径，标记可疑位置
    all_paths = []
    for entry in entries:
        for value in entry["paths"]:
            all_paths.append({"file": entry["file"], "path": value})

    suspicious = [p for p in all_paths
                  if any(h in p["path"].lower() for h in SUSPICIOUS_HINTS)]

    summary = {
        "available": bool(files),
        "files": len(files),
        "parsed": len(entries),
        "total_paths": len(all_paths),
        "suspicious": len(suspicious),
        "errors": errors[:20],
        "entries": entries,
        "top_paths": all_paths[:200],
    }

    with open(out_dir / "jumplist.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", "path"])
        writer.writeheader()
        for item in all_paths:
            writer.writerow(item)
    (out_dir / "jumplist_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Jump List（最近访问文件）", "",
             f"- 文件：{len(files)} 个，解析 {len(entries)} 个，条目路径 {len(all_paths)} 条", ""]
    if suspicious:
        lines += ["## 可疑位置（临时/下载/公共目录）", "", "| 文件 | 路径 |", "|---|---|"]
        lines += [f"| {p['file'][:40]} | {p['path'][:110]} |" for p in suspicious[:20]]
        lines.append("")
    if all_paths:
        lines += ["## 最近路径样例", "", "| 路径 |", "|---|"]
        lines += [f"| {p['path'][:120]} |" for p in all_paths[:30]]
    (out_dir / "jumplist_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    s = parse_jumplist(target, Path(args.out) if args.out else None)
    if not s.get("available"):
        print("JumpList 不可用：", s.get("reason"))
        return
    print(f"JumpList：{s['files']} 个文件，解析 {s['parsed']} 个，路径 {s['total_paths']} 条"
          f"（可疑 {s['suspicious']}）")


if __name__ == "__main__":
    main()
