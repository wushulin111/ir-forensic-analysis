#!/usr/bin/env python3
"""补充取证解析器：计划任务 XML / 注册表导出 / 浏览器书签。

采集包里这些产物没有标准扩展名或不是 txt/csv，通用加载器读不到，所以单独解析：

- `3_persistence/tasks_xml/*`       plan 任务 XML（UTF-16，无扩展名）
- `*.reg`                           注册表导出（UTF-16）
- `browser_artifacts/**/Bookmarks`  Chromium 书签（JSON，无扩展名）

输出（默认写到 <取证目录>/_artifacts）：
    scheduled_tasks.csv / registry_keys.csv / browser_bookmarks_extra.csv
    artifacts_summary.json / artifacts_report.md
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# 高危：临时/公共目录、编码执行、LOLBin 转发、脚本解释器
HIGH_HINTS = (
    "\\temp\\", "\\tmp\\", "\\users\\public\\",
    "-enc", "-encodedcommand", "frombase64", "mshta", "rundll32", "regsvr32",
    "certutil", "bitsadmin", "wscript", "cscript",
)
# 中危：通用解释器、用户可写目录（很多正常软件也这样，不能直接判危）
MEDIUM_HINTS = (
    "powershell", "cmd /c", "cmd.exe /c", "\\\\appdata\\\\", "\\appdata\\",
    "\\programdata\\", "\\downloads\\",
)
SUSPICIOUS_EXT = (".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta", ".scr")


def _read_text_auto(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-16", "utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", "replace")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_task_xml(path: Path) -> dict:
    text = _read_text_auto(path)
    info = {"file": path.name, "uri": "", "command": "", "arguments": "",
            "user_id": "", "trigger": "", "enabled": "", "run_level": ""}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # XML 损坏时退回正则兜底
        import re
        for key, pattern in (("command", r"<Command>(.*?)</Command>"),
                             ("arguments", r"<Arguments>(.*?)</Arguments>"),
                             ("user_id", r"<UserId>(.*?)</UserId>")):
            m = re.search(pattern, text, re.S)
            if m:
                info[key] = m.group(1).strip()
        return info

    for node in root.iter():
        name = _local(node.tag)
        if name == "URI" and not info["uri"]:
            info["uri"] = (node.text or "").strip()
        elif name == "Command" and not info["command"]:
            info["command"] = (node.text or "").strip()
        elif name == "Arguments" and not info["arguments"]:
            info["arguments"] = (node.text or "").strip()
        elif name == "UserId" and not info["user_id"]:
            info["user_id"] = (node.text or "").strip()
        elif name == "RunLevel" and not info["run_level"]:
            info["run_level"] = (node.text or "").strip()
        elif name in ("StartBoundary", "Delay") and not info["trigger"]:
            info["trigger"] = f"{name}={node.text}"
        elif name == "Enabled" and info["enabled"] == "":
            info["enabled"] = (node.text or "").strip()
    return info


def risk_of_task(task: dict) -> tuple[str, str]:
    blob = f"{task.get('command', '')} {task.get('arguments', '')}".lower()
    reasons = []
    level = "low"
    for hint in HIGH_HINTS:
        if hint in blob:
            reasons.append(f"命令行包含 {hint.strip()}")
            level = "high"
            break
    if any(ext in blob for ext in SUSPICIOUS_EXT):
        reasons.append("调用脚本文件")
        level = "medium" if level == "low" else level
    if level == "low":
        for hint in MEDIUM_HINTS:
            if hint in blob:
                reasons.append(f"命令行包含 {hint.strip()}")
                level = "medium"
                break
    if not task.get("command"):
        reasons.append("没有取到执行命令（可能被隐藏或解析失败）")
        level = "medium" if level == "low" else level
    return level, "；".join(reasons)


def parse_reg(path: Path) -> list[dict]:
    text = _read_text_auto(path)
    entries, section = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line or not section:
            continue
        name, _, value = line.partition("=")
        name = name.strip().strip('"')
        value = value.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        entries.append({"section": section, "name": name, "value": value, "file": path.name})
    return entries


def risk_of_reg(entry: dict) -> tuple[str, str]:
    section = entry["section"].lower()
    value = str(entry.get("value", "")).lower()
    reasons = []
    level = "low"
    if "\\currentversion\\run" in section or "\\currentversion\\runonce" in section:
        level = "medium"
        reasons.append("自启动 Run/RunOnce 键")
        if any(h in value for h in ("\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\")):
            level = "high"
            reasons.append("指向临时/用户可写目录")
        if value.endswith(SUSPICIOUS_EXT):
            level = "high"
            reasons.append("启动脚本文件")
    elif "image file execution options" in section:
        level = "high"
        reasons.append("IFEO 劫持位置")
    elif "\\winlogon" in section and entry["name"].lower() in ("shell", "userinit"):
        level = "high"
        reasons.append("Winlogon 启动项被改写")
    elif "\\services\\" in section and entry["name"].lower() == "imagepath":
        if any(h in value for h in ("\\temp\\", "\\users\\public\\", "\\programdata\\", "\\appdata\\")):
            level = "high"
            reasons.append("服务 ImagePath 指向可写目录")
    return level, "；".join(reasons)


def parse_chromium_bookmarks(path: Path, browser: str) -> list[dict]:
    out = []
    try:
        data = json.loads(_read_text_auto(path))
    except (ValueError, OSError):
        return out
    roots = data.get("roots") or {}

    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("type") == "url" and node.get("url"):
            out.append({"browser": browser, "name": node.get("name", ""),
                        "url": node["url"], "date_added": node.get("date_added", "")})
        for child in node.get("children") or []:
            walk(child)

    for key in ("bookmark_bar", "other", "synced"):
        walk(roots.get(key))
    return out


def parse_artifacts(extracted_dir: Path, out_dir: Path | None = None) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {"tasks": [], "registry": [], "bookmarks": [], "errors": [],
               "counts": {}, "risky": {"tasks": 0, "registry": 0}}

    # 1) 计划任务
    for folder in extracted_dir.rglob("tasks_xml"):
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            if not path.is_file():
                continue
            try:
                task = parse_task_xml(path)
                level, reason = risk_of_task(task)
                task["risk"] = level
                task["risk_reason"] = reason
                summary["tasks"].append(task)
            except Exception as exc:  # noqa: BLE001
                summary["errors"].append(f"task {path.name}: {exc}")

    # 2) 注册表导出
    for path in extracted_dir.rglob("*.reg"):
        try:
            for entry in parse_reg(path):
                level, reason = risk_of_reg(entry)
                entry["risk"] = level
                entry["risk_reason"] = reason
                summary["registry"].append(entry)
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"reg {path.name}: {exc}")

    # 3) Chromium 书签（无扩展名 JSON）
    for path in extracted_dir.rglob("Bookmarks"):
        if not path.is_file():
            continue
        browser = path.parent.name.split("_")[1] if "_" in path.parent.name else "Chromium"
        summary["bookmarks"].extend(parse_chromium_bookmarks(path, browser))

    # 只保留有意义的注册表项（Run/服务/IFEO/Winlogon），其余不入 CSV 避免噪声
    interesting = [e for e in summary["registry"] if e["risk"] != "low"]
    summary["risky"]["tasks"] = sum(1 for t in summary["tasks"] if t["risk"] in ("high", "critical"))
    summary["risky"]["registry"] = sum(1 for e in interesting if e["risk"] in ("high", "critical"))
    summary["counts"] = {
        "tasks": len(summary["tasks"]),
        "registry_entries": len(summary["registry"]),
        "registry_interesting": len(interesting),
        "bookmarks": len(summary["bookmarks"]),
    }

    def write_csv(name, rows, fields):
        with open(out_dir / name, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    write_csv("scheduled_tasks.csv", summary["tasks"],
              ["uri", "command", "arguments", "user_id", "trigger", "enabled",
               "run_level", "risk", "risk_reason"])
    write_csv("registry_keys.csv", interesting,
              ["section", "name", "value", "risk", "risk_reason", "file"])
    write_csv("browser_bookmarks_extra.csv", summary["bookmarks"],
              ["browser", "name", "url", "date_added"])

    (out_dir / "artifacts_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # Markdown
    lines = ["# 补充取证（计划任务 / 注册表 / 书签）", ""]
    c = summary["counts"]
    lines += [f"- 计划任务：{c['tasks']} 个（高危 {summary['risky']['tasks']}）",
              f"- 注册表项：{c['registry_entries']} 条（关注 {c['registry_interesting']} 条，"
              f"高危 {summary['risky']['registry']}）",
              f"- 书签：{c['bookmarks']} 条", ""]
    risky_tasks = [t for t in summary["tasks"] if t["risk"] in ("high", "critical")]
    if risky_tasks:
        lines += ["## 可疑计划任务", "", "| 任务 | 命令 | 原因 |", "|---|---|---|"]
        lines += [f"| {t['uri'] or t['file']} | {(t['command'] or '')[:70]} | {t['risk_reason']} |"
                  for t in risky_tasks[:20]]
        lines.append("")
    risky_reg = [e for e in interesting if e["risk"] in ("high", "critical")]
    if risky_reg:
        lines += ["## 高风险注册表项", "", "| 位置 | 名称 | 值 | 原因 |", "|---|---|---|---|"]
        lines += [f"| {e['section'][:60]} | {e['name']} | {str(e['value'])[:50]} | {e['risk_reason']} |"
                  for e in risky_reg[:20]]
        lines.append("")
    (out_dir / "artifacts_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

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
    summary = parse_artifacts(target, Path(args.out) if args.out else None)
    c = summary["counts"]
    print(f"计划任务 {c['tasks']}（高危 {summary['risky']['tasks']}）/ "
          f"注册表关注 {c['registry_interesting']}（高危 {summary['risky']['registry']}）/ "
          f"书签 {c['bookmarks']}")


if __name__ == "__main__":
    main()
