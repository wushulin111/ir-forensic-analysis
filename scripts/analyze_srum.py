#!/usr/bin/env python3
"""SRUM（SRUDB.dat）解析：程序级网络使用量，用于发现异常外传。

依赖 dissect.esedb（可选）。缺失时降级为字符串提取，并在结论里注明"未完整解析"。

用法：
    python analyze_srum.py <解压后的取证目录> [--out <输出目录>]
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

NETWORK_TABLE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
WRITABLE_HINTS = ("\\temp\\", "\\tmp\\", "\\users\\public\\", "\\appdata\\", "\\programdata\\")
BIG_UPLOAD = 100 * 1024 * 1024  # 100 MB


def _fmt_filetime(value) -> str:
    try:
        moment = FILETIME_EPOCH + timedelta(microseconds=int(value) // 10)
    except (ValueError, OverflowError, TypeError):
        return ""
    if not (1990 <= moment.year <= 2035):
        return ""
    return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _decode_id(value) -> str:
    if isinstance(value, bytes):
        for enc in ("utf-16-le", "utf-8"):
            try:
                text = value.decode(enc).strip("\x00").strip()
                if text and text.isprintable():
                    return text
            except UnicodeDecodeError:
                continue
    return str(value or "")


def parse_with_esedb(path: Path) -> dict | None:
    try:
        from dissect.esedb import EseDB
    except ImportError:
        return None
    fh = None
    try:
        fh = open(path, "rb")
        db = EseDB(fh)
        idmap = {}
        try:
            for rec in db.table("SruDbIdMapTable").records():
                index = rec.get("IdIndex")
                if index is not None:
                    idmap[index] = _decode_id(rec.get("IdBlob"))
        except Exception:  # noqa: BLE001
            pass

        agg = {}
        rows = 0
        for rec in db.table(NETWORK_TABLE).records():
            rows += 1
            app_id = rec.get("AppId")
            name = idmap.get(app_id) or f"AppId:{app_id}"
            item = agg.setdefault(name, {"sent": 0, "recv": 0, "count": 0,
                                         "first": "", "last": ""})
            item["sent"] += int(rec.get("BytesSent") or 0)
            item["recv"] += int(rec.get("BytesRecvd") or 0)
            item["count"] += 1
            stamp = _fmt_filetime(rec.get("TimeStamp"))
            if stamp:
                if not item["first"] or stamp < item["first"]:
                    item["first"] = stamp
                if not item["last"] or stamp > item["last"]:
                    item["last"] = stamp
        return {"rows": rows, "apps": agg, "mode": "esedb"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:200]}
    finally:
        if fh:
            fh.close()


def parse_with_strings(path: Path) -> dict:
    """降级：从二进制里扫 UTF-16/ASCII 路径，只能给出"出现过哪些程序"。"""
    data = path.read_bytes()
    found = set()
    for enc, width in (("ascii", 1), ("utf-16-le", 2)):
        text = data.decode(enc, "ignore")
        for match in __import__("re").findall(
                r"[A-Za-z]:\\\\?[^\x00-\x1f\"<>|]{4,150}\.(?:exe|dll|sys)", text):
            found.add(match)
    return {"rows": len(found), "apps": {f: {"sent": 0, "recv": 0, "count": 0,
                                             "first": "", "last": ""} for f in found},
            "mode": "strings"}


def analyze_srum(extracted_dir, out_dir=None, max_apps=500) -> dict:
    extracted = Path(extracted_dir)
    out = Path(out_dir) if out_dir else extracted / "_derived" / "srum"
    out.mkdir(parents=True, exist_ok=True)

    hives = list(extracted.rglob("SRUDB.dat"))
    if not hives:
        return {"available": False, "reason": "未找到 SRUDB.dat", "findings": []}

    parsed = parse_with_esedb(hives[0]) or parse_with_strings(hives[0])
    if parsed.get("error"):
        parsed = parse_with_strings(hives[0])

    apps = parsed.get("apps") or {}
    ranked = sorted(apps.items(), key=lambda kv: kv[1]["sent"] + kv[1]["recv"], reverse=True)

    with open(out / "srum_network.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["app", "bytes_sent", "bytes_recv", "records", "first_seen", "last_seen"])
        for name, info in ranked[:max_apps]:
            writer.writerow([name, info["sent"], info["recv"], info["count"],
                             info["first"], info["last"]])

    findings = []
    if parsed["mode"] == "esedb":
        top = ranked[:5]
        if top:
            findings.append({
                "dimension": "network", "type": "srum_network",
                "name": f"SRUM 记录 {parsed['rows']} 条网络使用，涉及 {len(apps)} 个程序",
                "evidence": "；".join(f"{n.split(chr(92))[-1][:32]} 发送 "
                                      f"{i['sent'] // 1024 // 1024}MB" for n, i in top),
                "risk_level": "info",
                "reason": "按程序统计的流量，可用于发现异常外传",
                "confidence": 0.9, "mitre_attack": "T1041",
            })
        # 只对"解析出真实程序名"的条目告警：AppId:123 这类未映射项噪声太大
        named = [(n, i) for n, i in ranked if ".exe" in n.lower() or "\\" in n]
        big = [(n, i) for n, i in named if i["sent"] >= BIG_UPLOAD]
        if big:
            def _huge(item):
                name, info = item
                return (info["sent"] >= 1024 * 1024 * 1024
                        and "\\windows\\system32" not in name.lower())

            severity = "high" if any(_huge(x) for x in big) else "medium"
            findings.append({
                "dimension": "network", "type": "srum_big_upload",
                "name": f"存在大流量外传程序 {len(big)} 个（≥100MB）",
                "evidence": "；".join(f"{n.split(chr(92))[-1][:36]} 发送 "
                                      f"{i['sent'] // 1024 // 1024}MB" for n, i in big[:4]),
                "risk_level": severity,
                "reason": "单程序累计发送量偏大，需确认是否为正常同步/更新（≥1GB 且非系统程序判高危）",
                "confidence": 0.6, "mitre_attack": "T1041",
            })
        writable = [(n, i) for n, i in named
                    if any(h in n.lower() for h in WRITABLE_HINTS) and i["sent"] + i["recv"] > 0]
        if writable:
            findings.append({
                "dimension": "network", "type": "srum_writable_app",
                "name": f"可写目录中的程序存在网络活动 {len(writable)} 个",
                "evidence": "；".join(n[:60] for n, _ in writable[:3]),
                "risk_level": "medium",
                "reason": "临时/用户目录程序联网，常见于投放器与远控",
                "confidence": 0.65, "mitre_attack": "T1105",
            })
    else:
        findings.append({
            "dimension": "network", "type": "srum_partial",
            "name": f"SRUM 未完整解析（缺 dissect.esedb），已提取 {len(apps)} 个程序路径",
            "evidence": "；".join(list(apps)[:3])[:200],
            "risk_level": "info",
            "reason": "安装 dissect.esedb 后可获得按程序的收发字节数",
            "confidence": 0.4, "mitre_attack": "",
        })

    summary = {
        "available": True, "mode": parsed["mode"], "rows": parsed.get("rows", 0),
        "apps": len(apps), "findings": findings,
        "counts": {"apps": len(apps), "rows": parsed.get("rows", 0),
                   "big_upload": sum(1 for _, i in ranked if i["sent"] >= BIG_UPLOAD)},
    }
    (out / "srum_summary.json").write_text(
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
    s = analyze_srum(target, Path(args.out) if args.out else None)
    if not s.get("available"):
        print("SRUM 不可用：", s.get("reason"))
        return
    print(f"SRUM：{s['mode']} 模式，{s['counts']['rows']} 条记录、"
          f"{s['counts']['apps']} 个程序，大流量外传 {s['counts']['big_upload']} 个")


if __name__ == "__main__":
    main()
