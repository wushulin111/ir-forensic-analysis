#!/usr/bin/env python3
"""EVTX 事件日志解析：登录、进程创建、服务安装、账号变更、日志清除、PowerShell。

用法：
    python analyze_evtx.py <解压后的取证目录> [--out <输出目录>] [--max-records 300000]

输出：
    evtx_events.csv    关键事件（时间/通道/EventID/用户/IP/进程/命令行）
    evtx_summary.json  统计与检测结论
    evtx_report.md     人读报告
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

KEY_EVENTS = {
    4624: "登录成功", 4625: "登录失败", 4634: "注销", 4647: "用户主动注销",
    4648: "显式凭据登录", 4672: "特权登录",
    4688: "进程创建", 4689: "进程退出",
    4720: "创建用户", 4722: "启用用户", 4724: "重置密码", 4726: "删除用户",
    4728: "加入全局组", 4732: "加入本地组", 4756: "加入通用组",
    1102: "日志被清除", 104: "日志被清除",
    7045: "服务安装", 7036: "服务状态变更", 7040: "服务启动类型变更",
    4698: "计划任务创建", 4699: "计划任务删除", 4702: "计划任务更新",
    4104: "PowerShell 脚本块", 4103: "PowerShell 模块日志",
    1116: "Defender 检测", 1117: "Defender 处置",
    5156: "网络连接", 5157: "网络阻断",
}

SUSPICIOUS_CMD = (
    "-enc", "-encodedcommand", "frombase64", "downloadstring", "invoke-expression",
    "iex(", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic process call",
    "\\temp\\", "\\users\\public\\", "\\appdata\\local\\temp",
)
SUSPICIOUS_SERVICE_PATH = ("\\temp\\", "\\users\\public\\", "\\appdata\\", "\\programdata\\")


SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon",
                   "dwm-1", "umfd-0", "umfd-1", "defaultaccount"}


def _parse_ts(value: str):
    """把 EVTX 的 ISO 时间转成 datetime（失败返回 None）。"""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:32], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _is_system_account(user: str) -> bool:
    name = (user or "").strip().lower()
    return (not name) or name.endswith("$") or name in SYSTEM_ACCOUNTS


def _text(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return str(value.get("#text") or value.get("text") or value)
    if isinstance(value, list):
        return "; ".join(_text(v) for v in value)
    return str(value)


def _item_text(item: dict) -> str:
    return _text(item.get("#text") if item.get("#text") is not None else item.get("text"))


def _event_data(event: dict) -> dict:
    """把 EventData / UserData 展平成 {名字: 值}。

    pyevtx-rs 的 JSON 有三种形态：
      EventData: {"Data": [{"@Name": "X", "#text": "v"}]}
      EventData: {"Data": {"@Name": "X", "#text": "v"}}
      EventData: {"X": "v", "Y": "v"}          （部分通道直接平铺）
    """
    out = {}
    data = event.get("EventData") or {}
    if isinstance(data, dict):
        raw = data.get("Data")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    name = item.get("@Name") or (item.get("#attributes") or {}).get("Name") or ""
                    out[str(name)] = _item_text(item)
                else:
                    out.setdefault("_data", []).append(_text(item))
        elif isinstance(raw, dict):
            name = raw.get("@Name") or (raw.get("#attributes") or {}).get("Name") or "_data"
            out[str(name)] = _item_text(raw)
        else:
            for key, value in data.items():
                if key.startswith("#") or key == "Data":
                    continue
                if isinstance(value, dict):
                    out[key] = _item_text(value)
                elif isinstance(value, list):
                    out[key] = "; ".join(_item_text(v) if isinstance(v, dict) else _text(v)
                                         for v in value)
                else:
                    out[key] = _text(value)
    user_data = event.get("UserData") or {}
    if isinstance(user_data, dict):
        for key, value in user_data.items():
            if key.startswith("#"):
                continue
            out.setdefault(key, _text(value))
    return out


def _system_time(system: dict) -> str:
    tc = system.get("TimeCreated")
    if isinstance(tc, dict):
        attrs = tc.get("#attributes") or {}
        return str(attrs.get("SystemTime") or tc.get("@SystemTime") or "")
    return str(tc or "")


def _channel_of(path: Path) -> str:
    name = path.stem
    mapping = {
        "security": "Security", "system": "System", "application": "Application",
        "microsoft-windows-powershell": "PowerShell",
        "microsoft-windows-sysmon": "Sysmon",
        "microsoft-windows-taskscheduler": "TaskScheduler",
        "microsoft-windows-terminalservices": "RDP",
    }
    low = name.lower()
    for key, value in mapping.items():
        if low.startswith(key):
            return value
    return name[:40]


def parse_evtx(extracted_dir: Path, out_dir: Path | None = None,
               max_records: int = 300000) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "evtx"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        import evtx
    except ImportError:
        return {"available": False, "reason": "缺少 evtx 库（pip install evtx）",
                "events": [], "files": [], "detections": []}

    files = sorted(extracted_dir.rglob("*.evtx"))
    summary = {
        "available": bool(files), "files": [], "events": [], "total_records": 0,
        "event_ids": {}, "detections": [], "errors": [],
        "time_range": {"start": "", "end": ""},
    }
    events = []
    id_counter = Counter()
    timestamps = []
    failed_logins = defaultdict(int)
    failed_events = defaultdict(list)      # (user, ip) -> [datetime]
    failed_ip_examples = {}
    success_after_fail = []

    for path in files:
        channel = _channel_of(path)
        count = 0
        try:
            parser = evtx.PyEvtxParser(str(path))
            for record in parser.records_json():
                if count >= max_records:
                    break
                count += 1
                try:
                    payload = json.loads(record["data"])
                except (ValueError, KeyError):
                    continue
                event = payload.get("Event") or {}
                system = event.get("System") or {}
                event_id = system.get("EventID")
                try:
                    event_id = int(_text(event_id).strip() or 0)
                except ValueError:
                    event_id = 0
                if event_id not in KEY_EVENTS:
                    continue

                data = _event_data(event)
                ts = _system_time(system)
                channel = _text(system.get("Channel")) or channel
                if ts:
                    timestamps.append(ts)

                user = (data.get("TargetUserName") or data.get("SubjectUserName")
                        or data.get("AccountName") or "")
                ip = data.get("IpAddress") or data.get("SourceIpAddress") or ""
                process = data.get("NewProcessName") or data.get("Image") or ""
                command = data.get("CommandLine") or data.get("ScriptBlockText") or ""
                service = data.get("ServiceName") or data.get("TaskName") or ""
                image_path = data.get("ImagePath") or ""

                row = {
                    "timestamp": ts, "channel": channel, "event_id": event_id,
                    "event": KEY_EVENTS.get(event_id, str(event_id)),
                    "user": user, "ip": "" if ip in ("-", "::1", "127.0.0.1") else ip,
                    "process": process, "command": command[:500],
                    "service": service, "image_path": image_path[:300],
                }
                events.append(row)
                id_counter[event_id] += 1

                if event_id == 4625 and not _is_system_account(user):
                    key = row["ip"] or user
                    if key:
                        failed_logins[key] += 1
                        failed_ip_examples.setdefault(key, ts)
                        moment = _parse_ts(ts)
                        if moment:
                            failed_events[(user, row["ip"])].append(moment)
                elif event_id == 4624 and not _is_system_account(user):
                    moment = _parse_ts(ts)
                    history = failed_events.get((user, row["ip"])) or []
                    if moment and history:
                        recent = [m for m in history if abs((moment - m).total_seconds()) <= 3600]
                        if len(recent) >= 5:
                            success_after_fail.append(row)
                if len(events) >= 20000:
                    break
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"{path.name}: {exc}")
        summary["files"].append({"file": path.name, "channel": channel, "records": count})
        summary["total_records"] += count
        if len(events) >= 20000:
            break

    # ---------- 检测 ----------
    detections = summary["detections"]

    for key, count in failed_logins.items():
        if count >= 5 and key not in ("unknown", "-"):
            detections.append({
                "id": "brute_force", "severity": "high" if count < 50 else "critical",
                "title": f"登录失败集中（{key} 失败 {count} 次）",
                "count": count,
                "evidence": f"首次记录时间 {failed_ip_examples.get(key, '-')}",
            })
            break

    if success_after_fail:
        detections.append({
            "id": "success_after_fail", "severity": "critical",
            "title": f"失败后成功登录（{len(success_after_fail)} 次，疑似爆破成功）",
            "count": len(success_after_fail),
            "evidence": "；".join(f"{r['user']}@{r['ip']} {r['timestamp']}"
                                  for r in success_after_fail[:3]),
        })

    cleared = [e for e in events if e["event_id"] in (1102, 104)]
    if cleared:
        detections.append({
            "id": "log_cleared", "severity": "critical",
            "title": f"日志被清除（{len(cleared)} 次）",
            "count": len(cleared),
            "evidence": "；".join(f"{e['user']} {e['timestamp']}" for e in cleared[:3]),
        })

    services = [e for e in events if e["event_id"] == 7045]
    risky_services = [e for e in services
                      if any(h in (e["image_path"] or "").lower() for h in SUSPICIOUS_SERVICE_PATH)]
    if risky_services:
        detections.append({
            "id": "service_install_suspicious", "severity": "high",
            "title": f"可疑服务安装（{len(risky_services)} 个，指向可写目录）",
            "count": len(risky_services),
            "evidence": "；".join(f"{e['service']} → {e['image_path'][:60]}"
                                  for e in risky_services[:3]),
        })
    elif services:
        detections.append({
            "id": "service_install", "severity": "low",
            "title": f"服务安装事件 {len(services)} 次（需核对来源）",
            "count": len(services),
            "evidence": "；".join(f"{e['service']} → {e['image_path'][:50]}" for e in services[:3]),
        })

    accounts_created = [e for e in events if e["event_id"] == 4720]
    if accounts_created:
        detections.append({
            "id": "account_created", "severity": "high",
            "title": f"创建本地账号 {len(accounts_created)} 次",
            "count": len(accounts_created),
            "evidence": "；".join(f"{e['user']} {e['timestamp']}" for e in accounts_created[:3]),
        })

    admin_add = [e for e in events if e["event_id"] in (4732, 4728, 4756)
                 and "admin" in (str(e.get("service", "")) + str(e.get("command", ""))).lower()]
    if admin_add:
        detections.append({
            "id": "admin_group_add", "severity": "high",
            "title": f"账号被加入管理员组 {len(admin_add)} 次",
            "count": len(admin_add),
            "evidence": "；".join(f"{e['user']} {e['timestamp']}" for e in admin_add[:3]),
        })

    suspicious_proc = [e for e in events if e["event_id"] == 4688
                       and any(h in (e["command"] or "").lower() for h in SUSPICIOUS_CMD)]
    if suspicious_proc:
        detections.append({
            "id": "suspicious_process", "severity": "high",
            "title": f"可疑命令行执行（{len(suspicious_proc)} 次）",
            "count": len(suspicious_proc),
            "evidence": "；".join(f"{(e['process'] or '')[:40]} | {(e['command'] or '')[:60]}"
                                  for e in suspicious_proc[:3]),
        })

    ps_blocks = [e for e in events if e["event_id"] == 4104
                 and any(h in (e["command"] or "").lower() for h in ("-enc", "frombase64", "iex"))]
    if ps_blocks:
        detections.append({
            "id": "powershell_encoded", "severity": "medium",
            "title": f"PowerShell 编码/反射执行脚本块（{len(ps_blocks)} 条）",
            "count": len(ps_blocks),
            "evidence": "；".join((e["command"] or "")[:60] for e in ps_blocks[:2]),
        })

    defender = [e for e in events if e["event_id"] in (1116, 1117)]
    if defender:
        detections.append({
            "id": "defender_alert", "severity": "high",
            "title": f"Defender 检测/处置事件 {len(defender)} 条",
            "count": len(defender),
            "evidence": "；".join(f"{e['timestamp']}" for e in defender[:3]),
        })

    # ---------- 输出 ----------
    summary.update({
        "events": events[:5000],
        "event_ids": dict(id_counter.most_common(20)),
        "time_range": {
            "start": min(timestamps) if timestamps else "",
            "end": max(timestamps) if timestamps else "",
        },
        "failed_login_top": sorted(failed_logins.items(), key=lambda x: -x[1])[:10],
        "counts": {
            "events_kept": len(events),
            "files": len(files),
            "detections": len(detections),
        },
    })

    with open(out_dir / "evtx_events.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["timestamp", "channel", "event_id", "event",
                                                "user", "ip", "process", "command",
                                                "service", "image_path"])
        writer.writeheader()
        for row in events[:20000]:
            writer.writerow(row)
    (out_dir / "evtx_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Windows 事件日志分析", ""]
    lines += [f"- 文件：{len(files)} 个，记录：{summary['total_records']} 条，关键事件：{len(events)} 条",
              f"- 时间范围：{summary['time_range']['start'] or '-'} ~ {summary['time_range']['end'] or '-'}",
              ""]
    if detections:
        lines += ["## 检测结论", "", "| 等级 | 结论 | 次数 |", "|---|---|---|"]
        lines += [f"| {d['severity']} | {d['title']} | {d['count']} |" for d in detections]
        lines.append("")
    if summary["failed_login_top"]:
        lines += ["## 登录失败 Top", "", "| 来源 | 次数 |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in summary["failed_login_top"]]
    (out_dir / "evtx_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extracted_dir")
    parser.add_argument("--out", default=None)
    parser.add_argument("--max-records", type=int, default=300000)
    args = parser.parse_args()
    target = Path(args.extracted_dir)
    if not target.is_dir():
        print(f"[错误] 目录不存在：{target}", file=sys.stderr)
        sys.exit(2)
    s = parse_evtx(target, Path(args.out) if args.out else None, args.max_records)
    if not s.get("available"):
        print("EVTX 不可用：", s.get("reason"))
        return
    print(f"EVTX：{s['counts']['files']} 个文件、{s['total_records']} 条记录、"
          f"关键事件 {s['counts']['events_kept']}、检测 {s['counts']['detections']} 项")


if __name__ == "__main__":
    main()
