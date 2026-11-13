#!/usr/bin/env python3
"""浏览器取证解析器：把采集包 browser_artifacts/ 里的 SQLite 库解析成 CSV / JSON / Markdown。

支持：
- Chromium 系（Chrome / Edge / Brave / Opera / 360SE / QQBrowser / Chromium / Vivaldi）
  History：urls / visits / downloads / keyword_search_terms
- Firefox：places.sqlite（moz_places / moz_historyvisits / moz_bookmarks）
- 可选：Cookies / Web Data / Login Data（若采集器一并拷贝）

用法：
    python analyze_browser.py <解压后的取证目录> [--out <输出目录>]

输出（写到 --out，默认写到取证目录）：
    browser_history.csv     时间, 浏览器, 配置, URL, 标题, 访问次数
    browser_downloads.csv   时间, 浏览器, 目标路径, 来源URL, 大小, 状态, 风险
    browser_bookmarks.csv   浏览器, 标题, URL, 添加时间
    browser_summary.json    统计摘要（供分析器/平台读取）
    browser_report.md       人读报告
"""

import argparse
import csv
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Chromium: 1601-01-01 起的微秒；Firefox: 1970-01-01 起的微秒
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# 下载风险分级：可执行文件高、安装包/宏文档中、压缩包低
HIGH_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse",
            ".vbs", ".vbe", ".ps1", ".hta", ".lnk"}
MEDIUM_EXT = {".msi", ".jar", ".iso", ".img", ".vhd", ".vhdx", ".docm", ".xlsm", ".pptm"}
LOW_EXT = {".zip", ".rar", ".7z", ".gz", ".tar"}
RISKY_EXT = HIGH_EXT | MEDIUM_EXT | LOW_EXT
# 只有“临时目录/公共目录”才算可疑落盘位置；“下载目录”本身就是下载目标，不升级风险
RISKY_HINT = ("\\temp\\", "/tmp/", "\\appdata\\", "\\users\\public\\", "\\windows\\temp\\")

DB_HINTS = ("history", "places", "cookies", "web data", "login data", "bookmarks", "favicons")


def _to_dt(chromium_us=None, firefox_us=None):
    try:
        if chromium_us:
            value = int(chromium_us)
            if value <= 0:
                return None
            return CHROMIUM_EPOCH + timedelta(microseconds=value)
        if firefox_us:
            value = int(firefox_us)
            if value <= 0:
                return None
            return UNIX_EPOCH + timedelta(microseconds=value)
    except (ValueError, OverflowError, TypeError):
        return None
    return None


def _fmt(dt):
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _open(db_path: Path):
    """尽量只读打开；被占用时先复制到临时目录。"""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3)
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        return conn
    except sqlite3.Error:
        pass
    tmp_dir = Path(tempfile.mkdtemp(prefix="browser_dbfix_"))
    target = tmp_dir / db_path.name
    shutil.copy2(db_path, target)
    # 顺带复制 WAL/SHM，提升一致性
    for suffix in ("-wal", "-shm"):
        side = Path(str(db_path) + suffix)
        if side.is_file():
            shutil.copy2(side, Path(str(target) + suffix))
    conn = sqlite3.connect(str(target), timeout=3)
    return conn


def _has_table(conn, name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        return bool(row)
    except sqlite3.Error:
        return False


def _guess_browser(db_path: Path) -> tuple[str, str]:
    """从文件名推断浏览器与 profile：<user>_<Browser>_<profile>_history.db"""
    stem = db_path.stem
    parts = stem.split("_")
    browser = "Unknown"
    profile = ""
    known = ["Chrome", "Edge", "Firefox", "Opera", "Brave", "360SE", "QQBrowser",
             "Chromium", "Vivaldi", "Sogou", "UC"]
    for name in known:
        if name.lower() in stem.lower():
            browser = name
            idx = next((i for i, p in enumerate(parts) if name.lower() in p.lower()), None)
            if idx is not None and idx + 1 < len(parts):
                profile = parts[idx + 1]
            break
    if not profile:
        for marker in ("Default", "Profile"):
            if marker.lower() in stem.lower():
                idx = next((i for i, p in enumerate(parts) if marker.lower() in p.lower()), None)
                profile = parts[idx] if idx is not None else marker
                break
    return browser, profile


def parse_chromium(conn, browser, profile) -> dict:
    out = {"history": [], "downloads": [], "searches": []}

    if _has_table(conn, "urls"):
        rows = conn.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls "
            "WHERE url IS NOT NULL ORDER BY last_visit_time DESC LIMIT 20000").fetchall()
        for url, title, visits, last in rows:
            out["history"].append({
                "timestamp": _fmt(_to_dt(chromium_us=last)),
                "browser": browser, "profile": profile,
                "url": url or "", "title": title or "", "visit_count": visits or 0,
            })

    if _has_table(conn, "downloads"):
        rows = conn.execute(
            "SELECT target_path, tab_url, total_bytes, state, danger_type, start_time "
            "FROM downloads ORDER BY start_time DESC LIMIT 5000").fetchall()
        for target, tab_url, size, state, danger, start in rows:
            out["downloads"].append({
                "timestamp": _fmt(_to_dt(chromium_us=start)),
                "browser": browser,
                "target_path": target or "",
                "source_url": tab_url or "",
                "size": size or 0,
                "state": state if state is not None else "",
                "danger_type": danger if danger is not None else "",
            })

    if _has_table(conn, "keyword_search_terms") and _has_table(conn, "urls"):
        try:
            rows = conn.execute(
                "SELECT k.term, u.url FROM keyword_search_terms k "
                "JOIN urls u ON u.id = k.url_id LIMIT 5000").fetchall()
            out["searches"] = [{"term": t or "", "url": u or ""} for t, u in rows]
        except sqlite3.Error:
            pass
    return out


def parse_firefox(conn, browser, profile) -> dict:
    out = {"history": [], "downloads": [], "searches": [], "bookmarks": []}

    if _has_table(conn, "moz_places"):
        rows = conn.execute(
            "SELECT url, title, visit_count, last_visit_date FROM moz_places "
            "WHERE url IS NOT NULL ORDER BY last_visit_date DESC LIMIT 20000").fetchall()
        for url, title, visits, last in rows:
            out["history"].append({
                "timestamp": _fmt(_to_dt(firefox_us=last)),
                "browser": browser, "profile": profile,
                "url": url or "", "title": title or "", "visit_count": visits or 0,
            })

    if _has_table(conn, "moz_bookmarks") and _has_table(conn, "moz_places"):
        try:
            rows = conn.execute(
                "SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b "
                "JOIN moz_places p ON p.id = b.fk WHERE p.url IS NOT NULL LIMIT 5000").fetchall()
            out["bookmarks"] = [{
                "browser": browser, "title": t or "", "url": u or "",
                "timestamp": _fmt(_to_dt(firefox_us=d)),
            } for t, u, d in rows]
        except sqlite3.Error:
            pass
    return out


def parse_site_cache(db_path: Path, browser: str) -> dict:
    """解析 Favicons（图标缓存里的访问站点）与 Top Sites（常访问站点）。"""
    out = {"sites": []}
    name = db_path.name.lower()
    try:
        conn = _open(db_path)
        conn.row_factory = sqlite3.Row
    except Exception:  # noqa: BLE001
        return out
    try:
        if "favicon" in name and _has_table(conn, "icon_mapping"):
            rows = conn.execute(
                "SELECT DISTINCT page_url FROM icon_mapping WHERE page_url IS NOT NULL LIMIT 5000"
            ).fetchall()
            for row in rows:
                url = row["page_url"]
                if url:
                    out["sites"].append({"browser": browser, "url": url,
                                         "source": "favicon", "rank": ""})
        elif "top sites" in name and _has_table(conn, "top_sites"):
            rows = conn.execute(
                "SELECT url, title, url_rank FROM top_sites WHERE url IS NOT NULL "
                "ORDER BY url_rank LIMIT 5000").fetchall()
            for row in rows:
                out["sites"].append({"browser": browser, "url": row["url"],
                                     "title": row["title"] or "",
                                     "source": "top_sites", "rank": row["url_rank"]})
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return out


def parse_generic(conn, browser) -> dict:
    """Cookies / Web Data / Login Data 等（若被采集）。"""
    out = {"cookies": [], "logins": []}
    if _has_table(conn, "cookies"):
        try:
            rows = conn.execute(
                "SELECT host_key, name, expires_utc FROM cookies LIMIT 5000").fetchall()
            out["cookies"] = [{"browser": browser, "host": h or "", "name": n or "",
                               "expires": _fmt(_to_dt(chromium_us=e))} for h, n, e in rows]
        except sqlite3.Error:
            pass
    if _has_table(conn, "moz_cookies"):
        try:
            rows = conn.execute(
                "SELECT host, name, expiry FROM moz_cookies LIMIT 5000").fetchall()
            existing = {(c["host"], c["name"]) for c in out["cookies"]}
            for host, name, expiry in rows:
                if (host, name) in existing:
                    continue
                moment = None
                if expiry:
                    try:
                        moment = datetime.fromtimestamp(int(expiry), tz=timezone.utc)
                    except (ValueError, OSError, OverflowError):
                        moment = None
                out["cookies"].append({"browser": browser, "host": host or "",
                                       "name": name or "", "expires": _fmt(moment)})
        except sqlite3.Error:
            pass
    if _has_table(conn, "moz_formhistory"):
        try:
            rows = conn.execute(
                "SELECT fieldname, value FROM moz_formhistory LIMIT 2000").fetchall()
            for field, value in rows:
                out.setdefault("formhistory", []).append(
                    {"browser": browser, "field": field or "", "value": (value or "")[:120]})
        except sqlite3.Error:
            pass
    if _has_table(conn, "logins"):
        try:
            rows = conn.execute(
                "SELECT origin_url, username_value FROM logins LIMIT 2000").fetchall()
            out["logins"] = [{"browser": browser, "origin": o or "", "username": u or ""}
                             for o, u in rows]
        except sqlite3.Error:
            pass
    return out


def _risk_of_download(item: dict) -> tuple[str, str]:
    path = (item.get("target_path") or "").lower()
    url = (item.get("source_url") or "").lower()
    ext = os.path.splitext(path)[1]
    reasons = []
    level = "low"
    if ext in HIGH_EXT:
        reasons.append(f"可执行/脚本扩展名 {ext}")
        level = "high"
    elif ext in MEDIUM_EXT:
        reasons.append(f"安装包/宏文档 {ext}")
        level = "medium"
    elif ext in LOW_EXT:
        reasons.append(f"压缩包 {ext}")
        level = "low"

    if any(hint in path for hint in RISKY_HINT):
        reasons.append("落盘在临时/公共目录")
        level = "high" if level in ("low", "medium") else level

    # Chromium danger_type：1/2/3/7/8 是真实危险；6=用户强制放行；4/5/13 只是"可能"
    try:
        danger = int(item.get("danger_type") or 0)
    except (TypeError, ValueError):
        danger = 0
    if danger in (1, 2, 3, 7, 8, 10):
        reasons.append(f"浏览器判定危险（danger_type={danger}）")
        level = "high"
    elif danger == 6:
        reasons.append("用户强制放行了安全警告（danger_type=6）")
        level = "high" if level == "low" else level
    elif danger in (4, 5, 13):
        reasons.append(f"浏览器提示可能危险（danger_type={danger}）")
        level = "medium" if level == "low" else level

    if url.startswith("http://") and ext in HIGH_EXT:
        reasons.append("明文 HTTP 下载可执行文件")
        level = "high"

    return level, "；".join(reasons)


def load_ioc_domains(limit=40000):
    """从规则库加载 IOC 域名（可选）。"""
    candidates = [
        Path(__file__).resolve().parents[1] / "rules" / "ioc_library.json",
        Path(os.getenv("IR_IOC_LIBRARY", "")) if os.getenv("IR_IOC_LIBRARY") else None,
    ]
    for path in candidates:
        if path and path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                domains = {str(d).lower() for d in (data.get("iocs", {}).get("domains") or [])}
                ips = {str(i) for i in (data.get("iocs", {}).get("ips") or [])}
                return domains, ips
            except (OSError, ValueError):
                continue
    return set(), set()


def parse_browser_artifacts(extracted_dir: Path, out_dir: Path | None = None) -> dict:
    extracted_dir = Path(extracted_dir)
    out_dir = Path(out_dir) if out_dir else extracted_dir / "_derived" / "browser"
    out_dir.mkdir(parents=True, exist_ok=True)

    browser_dirs = [p for p in extracted_dir.rglob("*")
                    if p.is_dir() and p.name.lower() == "browser_artifacts"]
    db_files = []
    for folder in browser_dirs:
        # 递归：deep/ 子目录里还有 cookies.sqlite / formhistory.sqlite
        db_files.extend([p for p in folder.rglob("*")
                         if p.is_file() and p.suffix.lower() in (".db", ".sqlite", ".sqlite3")])

    summary = {
        "available": bool(db_files),
        "databases": [], "history": 0, "downloads": 0, "bookmarks": 0,
        "cookies": 0, "logins": 0, "searches": 0,
        "browsers": {}, "time_range": {"start": "", "end": ""},
        "top_domains": [], "risky_downloads": [], "errors": [],
    }
    history, downloads, bookmarks, cookies, logins, forms = [], [], [], [], [], []
    sites = []

    ioc_domains, ioc_ips = load_ioc_domains()

    # 浏览器目录里还有无扩展名的 SQLite（Favicons / Top Sites），单独扫
    site_cache_files = []
    for folder in browser_dirs:
        for path in folder.rglob("*"):
            if path.is_file() and path.suffix == "" and path.name.lower() in ("favicons", "top sites"):
                site_cache_files.append(path)

    for db_path in db_files:
        browser, profile = _guess_browser(db_path)
        summary["databases"].append({"file": db_path.name, "browser": browser,
                                     "profile": profile, "size": db_path.stat().st_size})
        try:
            conn = _open(db_path)
            conn.row_factory = sqlite3.Row
            if _has_table(conn, "urls") or _has_table(conn, "downloads"):
                data = parse_chromium(conn, browser, profile)
            elif _has_table(conn, "moz_places"):
                data = parse_firefox(conn, browser, profile)
            else:
                data = {"history": [], "downloads": [], "bookmarks": []}
            generic = parse_generic(conn, browser)
            conn.close()
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"{db_path.name}: {exc}")
            continue

        history.extend(data.get("history", []))
        downloads.extend(data.get("downloads", []))
        bookmarks.extend(data.get("bookmarks", []))
        cookies.extend(generic.get("cookies", []))
        logins.extend(generic.get("logins", []))
        forms.extend(generic.get("formhistory", []))
        summary["searches"] += len(data.get("searches", []))

    # 站点缓存（Favicons / Top Sites）
    for cache_path in site_cache_files:
        browser = cache_path.parent.name.split("_")[1] if "_" in cache_path.parent.name else "Chromium"
        try:
            cache = parse_site_cache(cache_path, browser)
            summary["databases"].append({"file": str(cache_path.relative_to(extracted_dir)),
                                         "browser": browser, "profile": "",
                                         "size": cache_path.stat().st_size, "kind": "site_cache"})
            sites.extend(cache.get("sites", []))
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"{cache_path.name}: {exc}")

    # 风险标注 + IOC 命中
    risky = []
    for item in downloads:
        level, reason = _risk_of_download(item)
        item["risk"] = level
        item["risk_reason"] = reason
        host = urlparse(item.get("source_url") or "").hostname or ""
        if host and (host.lower() in ioc_domains or host in ioc_ips):
            item["risk"] = "critical"
            item["risk_reason"] = (reason + "；" if reason else "") + f"命中威胁情报域名 {host}"
        if level in ("high", "critical") or item["risk"] in ("high", "critical"):
            risky.append(item)

    history_hits = []
    for item in history:
        host = urlparse(item.get("url") or "").hostname or ""
        if host and (host.lower() in ioc_domains or host in ioc_ips):
            history_hits.append(item)

    # 写 CSV
    def write_csv(name, rows, fields):
        path = out_dir / name
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path

    write_csv("browser_history.csv", history,
              ["timestamp", "browser", "profile", "url", "title", "visit_count"])
    write_csv("browser_downloads.csv", downloads,
              ["timestamp", "browser", "target_path", "source_url", "size", "state",
               "risk", "risk_reason"])
    write_csv("browser_bookmarks.csv", bookmarks, ["timestamp", "browser", "title", "url"])
    if cookies:
        write_csv("browser_cookies.csv", cookies, ["browser", "host", "name", "expires"])
    if logins:
        write_csv("browser_logins.csv", logins, ["browser", "origin", "username"])
    if sites:
        write_csv("browser_sites.csv", sites, ["browser", "source", "url", "title", "rank"])
    if forms:
        write_csv("browser_formhistory.csv", forms, ["browser", "field", "value"])

    # 统计
    stamps = [h["timestamp"] for h in history if h["timestamp"]]
    summary.update({
        "history": len(history),
        "downloads": len(downloads),
        "bookmarks": len(bookmarks),
        "cookies": len(cookies),
        "formhistory": len(forms),
        "logins": len(logins),
        "time_range": {
            "start": min(stamps) if stamps else "",
            "end": max(stamps) if stamps else "",
        },
        "browsers": dict(Counter(h["browser"] for h in history)),
        "top_domains": Counter(
            urlparse(h["url"]).hostname or "" for h in history
        ).most_common(15),
        "risky_downloads": risky[:50],
        "ioc_hits": history_hits[:50],
        "risky_count": len(risky),
        "ioc_hit_count": len(history_hits),
        "site_cache_count": len(sites),
        "site_cache_note": "来源：Favicons 图标缓存 + Top Sites 常访问站点，可在历史被清空时提供线索",
    })
    summary["top_domains"] = [[d, c] for d, c in summary["top_domains"] if d]

    (out_dir / "browser_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    # Markdown 报告
    lines = ["# 浏览器取证", ""]
    if not db_files:
        lines.append("未发现浏览器数据库。")
    else:
        lines += [
            f"- 数据库：{len(db_files)} 个",
            f"- 历史记录：{summary['history']} 条",
            f"- 下载记录：{summary['downloads']} 条（高风险 {summary['risky_count']} 条）",
            f"- 书签：{summary['bookmarks']} 条；Cookie：{summary['cookies']}；登录记录：{summary['logins']}",
            f"- 时间范围：{summary['time_range']['start'] or '-'} ~ {summary['time_range']['end'] or '-'}",
            "",
        ]
        if summary["top_domains"]:
            lines += ["## 访问最多的域名", "", "| 域名 | 次数 |", "|---|---|"]
            lines += [f"| {d} | {c} |" for d, c in summary["top_domains"][:15]]
            lines.append("")
        if risky:
            lines += ["## 高风险下载", "", "| 时间 | 浏览器 | 目标路径 | 来源 | 原因 |",
                      "|---|---|---|---|---|"]
            for item in risky[:20]:
                lines.append(f"| {item['timestamp']} | {item['browser']} | "
                             f"{item['target_path'][:60]} | {item['source_url'][:60]} | "
                             f"{item['risk_reason']} |")
            lines.append("")
        if sites:
            lines += ["## 站点缓存（Favicons / Top Sites）", "",
                      f"共 {len(sites)} 条（历史为空时可作为替代线索）", "",
                      "| 来源 | 浏览器 | URL |", "|---|---|---|"]
            lines += [f"| {s['source']} | {s.get('browser', '')} | {str(s['url'])[:100]} |"
                      for s in sites[:20]]
            lines.append("")
        if history_hits:
            lines += ["## 访问了威胁情报域名", "", "| 时间 | 浏览器 | URL |", "|---|---|---|"]
            for item in history_hits[:20]:
                lines.append(f"| {item['timestamp']} | {item['browser']} | {item['url'][:90]} |")
    (out_dir / "browser_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extracted_dir", help="解压后的取证目录")
    parser.add_argument("--out", default=None, help="输出目录（默认写到取证目录）")
    args = parser.parse_args()

    target = Path(args.extracted_dir)
    if not target.is_dir():
        print(f"[错误] 目录不存在：{target}", file=sys.stderr)
        sys.exit(2)

    summary = parse_browser_artifacts(target, Path(args.out) if args.out else None)
    print(f"浏览器数据库：{len(summary['databases'])} 个")
    print(f"历史 {summary['history']} 条 / 下载 {summary['downloads']} 条"
          f"（高风险 {summary['risky_count']}）/ 书签 {summary['bookmarks']}")
    if summary["errors"]:
        for err in summary["errors"]:
            print(f"  [警告] {err}", file=sys.stderr)
    print(f"输出：{Path(args.out) if args.out else target}")


if __name__ == "__main__":
    main()
