#!/usr/bin/env python3
"""派生解析器注册表：统一管理 6 类非文本产物的解析、依赖检查与产物目录。

目录约定（v5.9 起）：
    <取证目录>/_derived/<name>/{summary.json, *.csv, report.md}
兼容旧布局：`_browser/` `_artifacts/` `_evtx/` `_prefetch/` `_jumplist/` `_amcache/`

用法：
    python parsers_registry.py <取证目录> [--only evtx,prefetch] [--force] [--list]
"""

import argparse
import importlib
import json
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

DERIVED_ROOT = "_derived"

PARSERS = [
    {
        "name": "browser", "label": "浏览器取证", "module": "analyze_browser",
        "func": "parse_browser_artifacts", "marker": "browser_summary.json",
        "deps": [], "detect": {"dirs": ["browser_artifacts"]},
        "desc": "History / places.sqlite / Bookmarks / Favicons / Top Sites",
    },
    {
        "name": "artifacts", "label": "计划任务与注册表", "module": "analyze_artifacts",
        "func": "parse_artifacts", "marker": "artifacts_summary.json",
        "deps": [], "detect": {"dirs": ["tasks_xml"], "globs": ["*.reg"]},
        "desc": "tasks_xml（UTF-16 无扩展名）/ .reg / Chromium Bookmarks",
    },
    {
        "name": "config", "label": "安全配置与劫持面", "module": "analyze_config",
        "func": "analyze_config", "marker": "security_config_summary.json",
        "deps": [], "detect": {"globs": ["hosts.txt", "dns_cache.txt", "firewall.txt",
                                         "defender_exclusions.txt", "bits_jobs.txt",
                                         "appinit_dlls.txt", "admin_group.txt"]},
        "desc": "hosts / DNS 缓存 / 防火墙 / Defender 排除 / BITS / AppInit_DLLs",
    },
    {
        "name": "accounts", "label": "账号交叉验证", "module": "analyze_accounts",
        "func": "analyze_accounts", "marker": "accounts_summary.json",
        "deps": [], "detect": {"globs": ["local_users.csv", "hidden_accounts.txt",
                                         "hidden_account_crosscheck.txt"]},
        "desc": "账号表 / 隐藏账号 / net-WMI 交叉 / 管理员组",
    },
    {
        "name": "persistence_exports", "label": "注册表导出", "module": "analyze_persistence_exports",
        "func": "analyze_persistence_exports", "marker": "persistence_exports_summary.json",
        "deps": [], "detect": {"globs": ["Run.txt", "RunOnce.txt",
                                         "Image File Execution Options.txt"]},
        "desc": "Run / RunOnce / IFEO / Winlogon / Services 结构化",
    },
    {
        "name": "filesystem", "label": "文件系统时间线", "module": "analyze_filesystem",
        "func": "analyze_filesystem", "marker": "filesystem_summary.json",
        "deps": [], "detect": {"globs": ["interesting_files.csv", "recent_files.csv"]},
        "desc": "可疑落盘 / 双扩展名 / 时间戳异常",
    },
    {
        "name": "srum", "label": "SRUM 网络使用", "module": "analyze_srum",
        "func": "analyze_srum", "marker": "srum_summary.json",
        "deps": [], "optional_deps": ["dissect.esedb"], "detect": {"globs": ["SRUDB.dat"]},
        "desc": "按程序的收发字节数（异常外传）",
    },
    {
        "name": "evtx", "label": "事件日志", "module": "analyze_evtx",
        "func": "parse_evtx", "marker": "evtx_summary.json",
        "deps": ["evtx"], "detect": {"globs": ["*.evtx"]},
        "desc": "登录 / 进程创建 / 服务安装 / 日志清除 / PowerShell",
    },
    {
        "name": "prefetch", "label": "Prefetch", "module": "analyze_prefetch",
        "func": "parse_prefetch", "marker": "prefetch_summary.json",
        "deps": ["dissect.util"], "detect": {"globs": ["*.pf"]},
        "desc": "执行次数 / 最近运行时间 / 引用文件",
    },
    {
        "name": "jumplist", "label": "JumpList", "module": "analyze_jumplist",
        "func": "parse_jumplist", "marker": "jumplist_summary.json",
        "deps": ["olefile"], "detect": {"globs": ["*.automaticdestinations-ms"]},
        "desc": "最近打开的文件路径",
    },
    {
        "name": "amcache", "label": "Amcache", "module": "analyze_amcache",
        "func": "parse_amcache", "marker": "amcache_summary.json",
        "deps": ["regipy"], "detect": {"globs": ["Amcache.hve"]},
        "desc": "程序 / 文件（SHA1）/ 驱动（签名状态）",
    },
]

LEGACY_DIRS = {
    "browser": "_browser", "artifacts": "_artifacts", "evtx": "_evtx",
    "prefetch": "_prefetch", "jumplist": "_jumplist", "amcache": "_amcache",
}


def get(name: str) -> dict | None:
    return next((p for p in PARSERS if p["name"] == name), None)


def derived_dir(extracted: Path, name: str) -> Path:
    return Path(extracted) / DERIVED_ROOT / name


def resolve_dir(extracted: Path, name: str) -> Path:
    """优先新布局 _derived/<name>，回退旧布局 _<name>。"""
    new = derived_dir(extracted, name)
    if new.is_dir():
        return new
    legacy = Path(extracted) / LEGACY_DIRS.get(name, f"_{name}")
    return legacy if legacy.is_dir() else new


def deps_ok(parser: dict) -> tuple[bool, list[str]]:
    missing = []
    for dep in parser["deps"]:
        try:
            importlib.import_module(dep)
        except ImportError:
            missing.append(dep)
    return (not missing), missing


def has_input(extracted: Path, parser: dict) -> bool:
    detect = parser.get("detect") or {}
    for d in detect.get("dirs") or []:
        if any(p.is_dir() and p.name.lower() == d.lower() for p in Path(extracted).rglob("*")):
            return True
    for pattern in detect.get("globs") or []:
        if next(Path(extracted).rglob(pattern), None):
            return True
    return False


def summary_of(parser: dict, result: dict) -> str:
    name = parser["name"]
    if name == "evtx":
        return (f"{result.get('counts', {}).get('files', 0)} 个文件、"
                f"{result.get('total_records', 0)} 条记录、"
                f"{result.get('counts', {}).get('detections', 0)} 项检测")
    if name == "prefetch":
        return f"{result.get('parsed', 0)} 个（可疑 {result.get('suspicious', 0)}）"
    if name == "jumplist":
        return f"{result.get('parsed', 0)} 个（路径 {result.get('total_paths', 0)} 条）"
    if name == "amcache":
        c = result.get("counts", {})
        return (f"程序 {c.get('application', 0)} / 文件 {c.get('file', 0)} / "
                f"驱动 {c.get('driver', 0)}，可疑 {result.get('suspicious', 0)}")
    if name == "accounts":
        c = result.get("counts", {})
        return f"账号 {c.get('users', 0)} 个（启用 {c.get('enabled', 0)}）"
    if name == "persistence_exports":
        c = result.get("counts", {})
        return f"注册表项 {c.get('entries', 0)} 条（高危 {c.get('high', 0)}）"
    if name == "filesystem":
        c = result.get("counts", {})
        return f"文件 {c.get('files', 0)} 条（可疑 {c.get('suspicious', 0)}）"
    if name == "srum":
        c = result.get("counts", {})
        return f"{result.get('mode', '?')} 模式、{c.get('apps', 0)} 个程序"
    if name == "browser":
        return (f"{len(result.get('databases', []))} 个库、历史 {result.get('history', 0)}、"
                f"下载 {result.get('downloads', 0)}、站点缓存 "
                f"{result.get('site_cache_count', 0)}")
    if name == "artifacts":
        c = result.get("counts", {})
        return (f"计划任务 {c.get('tasks', 0)}、注册表 {c.get('registry_entries', 0)}、"
                f"书签 {c.get('bookmarks', 0)}")
    return ""


def ensure(extracted, only=None, force=False, quiet=False) -> dict:
    """按需解析所有检测到的产物，返回 manifest。"""
    extracted = Path(extracted)
    root = extracted / DERIVED_ROOT
    root.mkdir(parents=True, exist_ok=True)
    manifest = {"extracted": str(extracted), "generated_at":
                time.strftime("%Y-%m-%dT%H:%M:%S"), "parsers": {}, "log": []}

    targets = [p for p in PARSERS if (not only or p["name"] in only)]
    for parser in targets:
        name = parser["name"]
        out = derived_dir(extracted, name)
        marker = out / parser["marker"]
        entry = {"label": parser["label"], "dir": str(out), "status": "", "elapsed": 0.0}

        if marker.is_file() and not force:
            entry["status"] = "cached"
            manifest["parsers"][name] = entry
            continue
        if not has_input(extracted, parser):
            entry["status"] = "no_input"
            manifest["parsers"][name] = entry
            continue
        ok, missing = deps_ok(parser)
        if not ok:
            entry["status"] = "missing_dep"
            entry["missing"] = missing
            manifest["parsers"][name] = entry
            manifest["log"].append(f"    [-] {parser['label']} 跳过：缺少 {', '.join(missing)}")
            continue

        started = time.time()
        try:
            module = importlib.import_module(parser["module"])
            func = getattr(module, parser["func"])
            result = func(extracted, out) or {}
            entry.update({"status": "ok", "elapsed": round(time.time() - started, 1),
                          "summary_path": str(marker), "detail": summary_of(parser, result)})
            manifest["log"].append(f"[+] {parser['label']}：{entry['detail']}"
                                   f"（{entry['elapsed']}s）")
        except Exception as exc:  # noqa: BLE001
            entry.update({"status": "error", "error": str(exc)[:300],
                          "elapsed": round(time.time() - started, 1)})
            manifest["log"].append(f"    [-] {parser['label']} 解析失败：{exc}")
        manifest["parsers"][name] = entry

    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    if not quiet:
        for line in manifest["log"]:
            print(line)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extracted_dir", nargs="?", help="解压后的取证目录")
    parser.add_argument("--only", default="", help="只跑指定解析器（逗号分隔）")
    parser.add_argument("--force", action="store_true", help="已有产物也重跑")
    parser.add_argument("--list", action="store_true", help="列出所有解析器")
    args = parser.parse_args()

    if args.list:
        for p in PARSERS:
            ok, missing = deps_ok(p)
            mark = "OK" if ok else f"缺 {','.join(missing)}"
            print(f"{p['name']:10} {p['label']:10} 依赖:{mark:22} {p['desc']}")
        return

    target = Path(args.extracted_dir or "")
    if not target.is_dir():
        print(f"[错误] 目录不存在：{target}", file=sys.stderr)
        sys.exit(2)
    only = [x.strip() for x in args.only.split(",") if x.strip()] or None
    manifest = ensure(target, only=only, force=args.force)
    ok = sum(1 for v in manifest["parsers"].values() if v["status"] == "ok")
    print(f"完成：{ok} 个解析成功，产物在 {target / DERIVED_ROOT}")


if __name__ == "__main__":
    main()
