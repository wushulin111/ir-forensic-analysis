#!/usr/bin/env python3
"""账号交叉验证：local_users.csv / hidden_accounts.txt / 交叉表 / 管理员组。

要点：
- 交叉表若把"所有账号"都标成 WMI 独有 → 判定为对比失败，而不是真有隐藏账号
- 管理员组成员不在账号表里 → 高危（隐藏管理员）
- 启用但从未登录/从未设密码的账号 → 需人工确认

用法：
    python analyze_accounts.py <解压后的取证目录> [--out <输出目录>]
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

BUILTIN = {"administrator", "guest", "defaultaccount", "wdagutilityaccount",
           "system", "local service", "network service"}


def _read(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "utf-16"):
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


def parse_local_users(path: Path) -> list[dict]:
    rows = []
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                name = (row.get("Name") or "").strip()
                if not name:
                    continue
                rows.append({
                    "name": name,
                    "enabled": str(row.get("Enabled", "")).strip(),
                    "password_last_set": (row.get("PasswordLastSet") or "").strip(),
                    "last_logon": (row.get("LastLogon") or "").strip(),
                })
    except OSError:
        pass
    return rows


def parse_hidden(path: Path) -> list[str]:
    text = _read(path)
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def parse_crosscheck(path: Path) -> dict:
    """解析交叉表：返回 {wmi_only: [...], net_only: [...], anomaly: bool}。"""
    out = {"wmi_only": [], "net_only": [], "notes": [], "anomaly": False}
    for line in _read(path).splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"\[WMI独有高危\]\s*(\S+)", line)
        if match:
            out["wmi_only"].append(match.group(1))
            continue
        match = re.match(r"\[net独有\]\s*(.+)", line)
        if match:
            out["net_only"].append(match.group(1).strip())
            continue
        if line.startswith("["):
            out["notes"].append(line[:160])
    return out


def parse_admin_members(path: Path) -> list[str]:
    text = _read(path)
    members, collecting = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^成员$|^Members$", stripped):
            collecting = True
            continue
        if collecting:
            if stripped.startswith("命令成功") or stripped.startswith("The command completed"):
                break
            if stripped and not stripped.startswith(("-", "=")):
                members.append(stripped)
    return members


def analyze_accounts(extracted_dir, out_dir=None) -> dict:
    extracted = Path(extracted_dir)
    out = Path(out_dir) if out_dir else extracted / "_derived" / "accounts"
    out.mkdir(parents=True, exist_ok=True)

    findings, data = [], {}

    users_path = _find(extracted, "local_users.csv")
    users = parse_local_users(users_path) if users_path else []
    data["users"] = users
    names = {u["name"].lower() for u in users}

    # 启用但从未登录 / 从未设密码
    idle = [u for u in users
            if u["enabled"].lower() == "true" and not u["last_logon"]
            and u["name"].lower() not in BUILTIN]
    if idle:
        findings.append({
            "dimension": "account", "type": "idle_enabled_account",
            "name": f"启用但从未登录的账号 {len(idle)} 个",
            "evidence": "、".join(u["name"] for u in idle[:6]),
            "risk_level": "low",
            "reason": "可能是新建后门账号，也可能是服务/沙箱账号，需核对用途",
            "confidence": 0.5, "mitre_attack": "T1136.001",
        })

    # 交叉表
    cross_path = _find(extracted, "hidden_account_crosscheck.txt")
    if cross_path:
        cross = parse_crosscheck(cross_path)
        data["crosscheck"] = cross
        total_enabled = sum(1 for u in users if u["enabled"].lower() == "true")
        # 把所有已知账号都标成 WMI 独有 = 对比逻辑失败（不是真隐藏）
        if cross["wmi_only"] and total_enabled and len(cross["wmi_only"]) >= total_enabled:
            cross["anomaly"] = True
            findings.append({
                "dimension": "account", "type": "crosscheck_failed",
                "name": "账号交叉验证失败（对比结果不可信）",
                "evidence": f"{len(cross['wmi_only'])} 个账号被判为 WMI 独有，"
                            f"覆盖了全部 {total_enabled} 个启用账号",
                "risk_level": "info",
                "reason": "net 与 WMI 账号枚举结果同时被列为差异，说明采集或对比环节出错，"
                          "不能据此判定存在隐藏账号",
                "confidence": 0.9, "mitre_attack": "",
            })
        elif cross["wmi_only"]:
            findings.append({
                "dimension": "account", "type": "hidden_account_wmi",
                "name": f"仅 WMI 可见的账号 {len(cross['wmi_only'])} 个",
                "evidence": "、".join(cross["wmi_only"][:6]),
                "risk_level": "high",
                "reason": "net user 枚举被 Hook 时会出现该现象，常用于隐藏后门账号",
                "confidence": 0.7, "mitre_attack": "T1136.001",
            })

    # 管理员组成员 vs 账号表
    admin_path = _find(extracted, "admin_group.txt")
    if admin_path:
        members = parse_admin_members(admin_path)
        data["admin_members"] = members
        phantom = [m for m in members if m.lower() not in names]
        if phantom and names:
            findings.append({
                "dimension": "account", "type": "phantom_admin",
                "name": f"管理员组存在账号表中不存在的成员 {len(phantom)} 个",
                "evidence": "、".join(phantom[:6]),
                "risk_level": "high",
                "reason": "成员在本地账号表里查不到，可能是隐藏账号或被篡改的组成员关系",
                "confidence": 0.75, "mitre_attack": "T1098",
            })

    # hidden_accounts.txt
    hidden_path = _find(extracted, "hidden_accounts.txt")
    if hidden_path:
        hidden = parse_hidden(hidden_path)
        data["hidden_accounts"] = hidden
        if hidden:
            findings.append({
                "dimension": "account", "type": "hidden_accounts",
                "name": f"隐藏账号检测命中 {len(hidden)} 条",
                "evidence": "；".join(hidden[:5]),
                "risk_level": "high",
                "reason": "采集脚本的隐藏账号检查有输出",
                "confidence": 0.7, "mitre_attack": "T1136.001",
            })

    with open(out / "accounts.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["name", "enabled", "password_last_set",
                                                "last_logon"])
        writer.writeheader()
        for user in users:
            writer.writerow(user)

    summary = {
        "available": bool(users),
        "findings": findings,
        "counts": {
            "users": len(users),
            "enabled": sum(1 for u in users if u["enabled"].lower() == "true"),
            "admin_members": len(data.get("admin_members", [])),
            "wmi_only": len((data.get("crosscheck") or {}).get("wmi_only", [])),
        },
    }
    (out / "accounts_summary.json").write_text(
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
    s = analyze_accounts(target, Path(args.out) if args.out else None)
    print(f"账号：{s['counts']['users']} 个（启用 {s['counts']['enabled']}），"
          f"{len(s['findings'])} 项发现")


if __name__ == "__main__":
    main()
