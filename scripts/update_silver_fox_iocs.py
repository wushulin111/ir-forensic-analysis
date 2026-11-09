#!/usr/bin/env python3
"""
银狐 IOC 库更新脚本

从文本 / JSON / CSV 中提取域名、IPv4、MD5/SHA256，规范化去重后合并进
rules/ioc_library.json，并记录来源与日期（provenance），保持向后兼容。

用法：
  # 预览（不写文件）
  python scripts/update_silver_fox_iocs.py --from-file new_iocs.txt --source CCTGA --date 2026-11-02 --dry-run

  # 实际写入
  python scripts/update_silver_fox_iocs.py --from-file new_iocs.txt --source CCTGA --date 2026-11-02

  # 直接从 URL 抓取（页面需为服务端渲染）
  python scripts/update_silver_fox_iocs.py --url https://example.com/report.html --source VendorBlog

文件既可以是纯文本（正则抽取），也可以是 JSON（{"domains":[],"ips":[],"hashes":[]}）。
"""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
IOC_FILE = ROOT / "rules" / "ioc_library.json"

DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'(?:com|net|cn|org|top|xyz|club|info|biz|vip|cc|io|me|site|online|shop|live|work|'
    r'link|icu|cyou|ml|ga|tk|pw|ws|su|ru|de|jp|hk|tw|app|dev|cloud|pro|store|fit|buzz|'
    r'my|monster|quest|sbs|cam|rest|fun|space|website|tech|life|world|today|digital)\b',
    re.I)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
MD5_RE = re.compile(r'\b[a-f0-9]{32}\b', re.I)
SHA256_RE = re.compile(r'\b[a-f0-9]{64}\b', re.I)

# 明显不是 IOC 的域名（平台自身、公共基础设施、示例域）
DOMAIN_BLOCKLIST = {
    "microsoft.com", "windows.com", "msftncsi.com", "msedge.net", "live.com", "office.com",
    "google.com", "gstatic.com", "googleapis.com", "youtube.com", "bing.com",
    "apple.com", "icloud.com", "amazon.com", "cloudflare.com", "akamai.net",
    "threatbook.com", "qianxin.com", "huorong.cn", "rising.com.cn", "360.cn", "tencent.com",
    "freebuf.com", "secrss.com", "cn-sec.com", "github.com", "githubusercontent.com",
    "weixin.qq.com", "qq.com", "example.com", "cert.org.cn", "cverc.org.cn",
    "abuse.ch", "virustotal.com", "malpedia.caad.fkie.fraunhofer.de",
}
DOMAIN_BLOCK_SUFFIX = (".gov.cn", ".edu.cn", ".org.cn")


def is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_reserved or a.is_loopback or a.is_multicast or a.is_unspecified


def normalize_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    # 还原 [.] / [.131] 这类防混淆写法
    d = d.replace("[.]", ".").replace("[", "").replace("]", "")
    return d


def extract(text: str) -> dict:
    domains, ips, hashes = set(), set(), set()
    for m in DOMAIN_RE.findall(text):
        d = normalize_domain(m)
        if any(d == b or d.endswith("." + b) for b in DOMAIN_BLOCKLIST):
            continue
        if any(d.endswith(s) for s in DOMAIN_BLOCK_SUFFIX):
            continue
        if re.fullmatch(IP_RE, d):
            continue
        domains.add(d)
    for m in IP_RE.findall(text):
        if not is_private_ip(m):
            ips.add(m)
    for m in SHA256_RE.findall(text):
        hashes.add(m.lower())
    for m in MD5_RE.findall(text):
        hashes.add(m.lower())
    return {"domains": sorted(domains), "ips": sorted(ips), "hashes": sorted(hashes)}


def load_library() -> dict:
    return json.load(open(IOC_FILE, encoding="utf-8-sig"))


def merge(lib: dict, new: dict, source: str, day: str) -> dict:
    iocs = lib.setdefault("iocs", {})
    prov = lib.setdefault("provenance", {})
    added = {"domains": [], "ips": [], "hashes": [], "file_paths": []}
    for kind in ("domains", "ips", "hashes", "file_paths"):
        bucket = iocs.setdefault(kind, [])
        existing = set(str(x).lower() for x in bucket)
        for item in new.get(kind, []):
            key = str(item).lower()
            if key in existing:
                continue
            bucket.append(item)
            existing.add(key)
            added[kind].append(item)
            prov.setdefault(str(item), {"source": source, "date": day})
    stats = lib.setdefault("stats", {})
    stats.update({
        "domains": len(iocs.get("domains", [])),
        "ips": len(iocs.get("ips", [])),
        "hashes": len(iocs.get("hashes", [])),
        "file_paths": len(iocs.get("file_paths", [])),
        "hashes_md5": sum(1 for h in iocs.get("hashes", []) if len(str(h)) == 32),
        "hashes_sha256": sum(1 for h in iocs.get("hashes", []) if len(str(h)) == 64),
    })
    lib["last_updated"] = day
    return added


def main():
    ap = argparse.ArgumentParser(description="银狐 IOC 库更新")
    ap.add_argument("--from-file", help="本地文本/JSON 文件")
    ap.add_argument("--url", help="服务端渲染的页面 URL")
    ap.add_argument("--source", required=True, help="来源标签，如 CCTGA / ThreatFox / 微步")
    ap.add_argument("--date", default=date.today().isoformat())
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.from_file and not args.url:
        ap.error("需要 --from-file 或 --url")

    if args.url:
        import urllib.request
        req = urllib.request.Request(args.url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore")
    else:
        text = Path(args.from_file).read_text(encoding="utf-8-sig", errors="ignore")

    try:
        data = json.loads(text)
        new = {k: list(map(str, data.get(k, []))) for k in ("domains", "ips", "hashes", "file_paths")}
    except Exception:
        new = extract(text)

    lib = load_library()
    before = dict(lib.get("stats", {}))
    added = merge(lib, new, args.source, args.date)

    print(f"来源: {args.source}  日期: {args.date}")
    print(f"本次提取: 域名 {len(new.get('domains', []))} / IP {len(new.get('ips', []))} / 哈希 {len(new.get('hashes', []))}")
    print(f"新增入账: 域名 {len(added['domains'])} / IP {len(added['ips'])} / 哈希 {len(added['hashes'])}")
    for k in ("domains", "ips", "hashes"):
        if added[k]:
            print(f"  {k}: {added[k][:10]}")
    print(f"库存变化: {before} -> {lib['stats']}")

    if args.dry_run:
        print("[dry-run] 不写入文件")
        return
    with open(IOC_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(lib, f, ensure_ascii=False, indent=2)
    print(f"已写入 {IOC_FILE}")


if __name__ == "__main__":
    main()
