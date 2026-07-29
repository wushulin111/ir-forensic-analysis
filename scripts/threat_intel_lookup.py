#!/usr/bin/env python3
"""
威胁情报查询模块 v2.0 - 配合 ir-forensic-analysis 使用
多源情报查询：微步在线(VT/ThreatBook) + VirusTotal + CVERC + AbuseIPDB
自动降级：主源失败后自动切换到备用源
"""

import json
import os
import sys
import io
import requests
from typing import List, Dict, Optional
from pathlib import Path

# [Windows] 编码修复
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def load_config() -> dict:
    config_path = Path(__file__).parent.parent / "config" / "threat_intel.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def query_threatbook_ip(ip: str, api_key: str) -> dict:
    """微步 IP 信誉查询"""
    try:
        r = requests.post(
            "https://api.threatbook.cn/v3/scene/ip_reputation",
            data={"apikey": api_key, "resource": ip},
            timeout=10
        )
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", {}).get(ip, {})
        return {"error": f"微步返回: {data.get('verbose_msg', 'unknown')}"}
    except Exception as e:
        return {"error": f"微步查询异常: {str(e)}"}


def query_threatbook_domain(domain: str, api_key: str) -> dict:
    """微步域名信誉查询"""
    try:
        r = requests.post(
            "https://api.threatbook.cn/v3/scene/domain_context",
            data={"apikey": api_key, "resource": domain},
            timeout=10
        )
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", {}).get(domain, {})
        return {"error": data.get('verbose_msg', 'unknown')}
    except Exception as e:
        return {"error": f"微步域名查询异常: {str(e)}"}


def query_threatbook_hash(file_hash: str, api_key: str) -> dict:
    """微步文件Hash查询"""
    try:
        r = requests.post(
            "https://api.threatbook.cn/v3/file/report",
            data={"apikey": api_key, "resource": file_hash},
            timeout=15
        )
        data = r.json()
        if data.get("response_code") == 0:
            return data.get("data", {})
        return {"error": data.get('verbose_msg', 'unknown')}
    except Exception as e:
        return {"error": f"微步Hash查询异常: {str(e)}"}


def query_vt_hash(file_hash: str, api_key: str) -> dict:
    """VirusTotal Hash查询"""
    if not api_key:
        return {"error": "VT API Key 未配置"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=15
        )
        # 134字节 = 未收录
        if len(r.content) < 200:
            return {"not_found": True, "error": "VT未收录该样本"}
        data = r.json()
        if "data" in data:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            malicious_engines = []
            for eng, res in results.items():
                if res.get("category") == "malicious":
                    malicious_engines.append(f"{eng}: {res.get('result', 'malicious')}")
            return {
                "source": "VirusTotal",
                "stats": stats,
                "malicious_count": stats.get("malicious", 0),
                "total_engines": sum(stats.values()),
                "malicious_engines": malicious_engines[:10],
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_submission_date"),
                "type": attrs.get("type_description", ""),
                "names": attrs.get("names", [])[:5],
                "meaningful_name": attrs.get("meaningful_name", "")
            }
        return {"error": "VT返回数据异常"}
    except Exception as e:
        return {"error": f"VT查询异常: {str(e)}"}


def query_vt_ip(ip: str, api_key: str) -> dict:
    """VirusTotal IP查询"""
    if not api_key:
        return {"error": "VT API Key 未配置"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=15
        )
        data = r.json()
        if "data" in data:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "stats": stats,
                "malicious_count": stats.get("malicious", 0),
                "country": attrs.get("country", ""),
                "asn": attrs.get("asn", ""),
                "as_owner": attrs.get("as_owner", "")
            }
        return {"error": "VT未收录该IP"}
    except Exception as e:
        return {"error": f"VT IP查询异常: {str(e)}"}



def query_otx_ip(ip: str, api_key: str = "") -> dict:
    """AlienVault OTX IP信誉查询"""
    try:
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        malware_families = set()
        tags = set()
        for pulse in pulses:
            for mf in pulse.get("malware_families", []):
                malware_families.add(mf)
            for tag in pulse.get("tags", []):
                tags.add(tag)
        return {
            "source": "AlienVault OTX",
            "pulse_count": pulse_info.get("count", 0),
            "malware_families": sorted(malware_families)[:10],
            "malware_str": ", ".join(sorted(malware_families)[:5]),
            "tags": sorted(tags)[:10],
            "reputation": data.get("reputation", 0),
            "country": data.get("country_name", ""),
            "city": data.get("city", "")
        }
    except Exception as e:
        return {"error": f"OTX查询异常: {str(e)}"}


def query_otx_domain(domain: str, api_key: str = "") -> dict:
    """AlienVault OTX 域名信誉查询"""
    try:
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        malware_families = set()
        tags = set()
        for pulse in pulses:
            for mf in pulse.get("malware_families", []):
                malware_families.add(mf)
            for tag in pulse.get("tags", []):
                tags.add(tag)
        return {
            "source": "AlienVault OTX",
            "pulse_count": pulse_info.get("count", 0),
            "malware_families": sorted(malware_families)[:10],
            "malware_str": ", ".join(sorted(malware_families)[:5]),
            "tags": sorted(tags)[:10],
            "alexa_rank": data.get("alexa", ""),
            "whois": data.get("whois", "")
        }
    except Exception as e:
        return {"error": f"OTX域名查询异常: {str(e)}"}


def query_otx_hash(file_hash: str, api_key: str = "") -> dict:
    """AlienVault OTX 文件Hash信誉查询"""
    try:
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        malware_families = set()
        tags = set()
        for pulse in pulses:
            for mf in pulse.get("malware_families", []):
                malware_families.add(mf)
            for tag in pulse.get("tags", []):
                tags.add(tag)
        return {
            "source": "AlienVault OTX",
            "pulse_count": pulse_info.get("count", 0),
            "malware_families": sorted(malware_families)[:10],
            "malware_str": ", ".join(sorted(malware_families)[:5]),
            "tags": sorted(tags)[:10],
            "md5": data.get("md5", ""),
            "sha1": data.get("sha1", ""),
            "sha256": data.get("sha256", "")
        }
    except Exception as e:
        return {"error": f"OTX Hash查询异常: {str(e)}"}


def query_urlhaus_host(host: str) -> dict:
    """URLhaus 查询某IP/域名历史上分发过的恶意URL"""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            timeout=10
        )
        data = r.json()
        if data.get("query_status") != "ok":
            return {"error": data.get("query_status", "unknown")}
        urls = data.get("urls", [])
        threats = set()
        tags = set()
        for url_info in urls:
            threat = url_info.get("threat", "")
            if threat:
                threats.add(threat)
            for tag in url_info.get("tags", []):
                tags.add(tag)
        return {
            "source": "URLhaus",
            "url_count": data.get("url_count", 0),
            "threat_types": sorted(threats),
            "threat_str": ", ".join(sorted(threats)[:3]),
            "tags": sorted(tags)[:10],
            "first_seen": urls[0].get("date_added", "") if urls else "",
            "recent_samples": len(urls)
        }
    except Exception as e:
        return {"error": f"URLhaus查询异常: {str(e)}"}

def query_cverc_hash(file_hash: str, api_key: str) -> dict:
    """CVERC 文件Hash查询"""
    if not api_key:
        return {"not_configured": True, "error": "CVERC API Key 未配置"}
    try:
        r = requests.post(
            "https://api.cverc.org.cn/api/v1/file/check",
            data={"hash": file_hash},
            headers={"apikey": api_key},
            timeout=15
        )
        data = r.json()
        if data.get("code") == 0 or data.get("code") == 200:
            return {
                "source": "CVERC",
                "verdict": data.get("data", {}).get("verdict", "unknown"),
                "malware_type": data.get("data", {}).get("malware_type", ""),
                "name": data.get("data", {}).get("name", ""),
                "score": data.get("data", {}).get("score", 0)
            }
        return {"error": f"CVERC返回: {data.get('message', 'unknown')}"}
    except Exception as e:
        return {"error": f"CVERC查询异常: {str(e)}"}


def query_abuseipdb(ip: str, api_key: str) -> dict:
    """AbuseIPDB IP信誉查询"""
    if not api_key:
        return {"not_configured": True, "error": "AbuseIPDB API Key 未配置"}
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10
        )
        data = r.json()
        if "data" in data:
            d = data["data"]
            return {
                "source": "AbuseIPDB",
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "usage_type": d.get("usageType", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
                "last_reported": d.get("lastReportedAt", "")
            }
        return {"error": "AbuseIPDB未收录"}
    except Exception as e:
        return {"error": f"AbuseIPDB查询异常: {str(e)}"}


def query_ipinfo(ip: str) -> dict:
    """IPinfo.io 基础信息查询（免费，无需Key）"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        data = r.json()
        return {
            "source": "IPinfo",
            "ip": data.get("ip", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "org": data.get("org", ""),
            "asn": data.get("asn", {}).get("asn", "") if isinstance(data.get("asn"), dict) else "",
            "hostname": data.get("hostname", "")
        }
    except Exception as e:
        return {"error": f"IPinfo查询异常: {str(e)}"}


def multi_source_query_ip(ip: str, config: dict) -> dict:
    """多源IP查询 — 微步→OTX→URLhaus→VT→AbuseIPDB→IPinfo"""
    results = {}
    order = config.get("query_order", ["微步在线X情报社区", "AlienVault OTX", "URLhaus"])

    for source_name in order:
        source = None
        for s in config.get("sources", []):
            if s.get("name") == source_name and s.get("enabled"):
                source = s
                break
        if not source:
            continue

        api_key = source.get("api_key", "")
        if source_name == "微步在线X情报社区":
            r = query_threatbook_ip(ip, api_key)
            if "error" not in r:
                results["微步"] = r
            else:
                results["微步_error"] = r.get("error", "")
        elif source_name == "AlienVault OTX":
            r = query_otx_ip(ip, api_key)
            if "error" not in r:
                results["OTX"] = r
        elif source_name == "URLhaus":
            r = query_urlhaus_host(ip)
            if "error" not in r:
                results["URLhaus"] = r
        elif source_name == "VirusTotal":
            if not api_key:
                results["VT_error"] = "未配置Key"
                continue
            r = query_vt_ip(ip, api_key)
            if "error" not in r:
                results["VirusTotal"] = r
        elif source_name == "AbuseIPDB":
            if not api_key:
                results["AbuseIPDB_error"] = "未配置Key"
                continue
            r = query_abuseipdb(ip, api_key)
            if "error" not in r:
                results["AbuseIPDB"] = r

    # 补充IPinfo基础信息（最后补充，不阻断）
    results["IPinfo"] = query_ipinfo(ip)
    return results


def multi_source_query_hash(file_hash: str, config: dict) -> dict:
    """多源Hash查询"""
    results = {}
    order = config.get("query_order", [])
    
    for source_name in order:
        source = None
        for s in config.get("sources", []):
            if s.get("name") == source_name and s.get("enabled"):
                source = s
                break
        if not source:
            continue
        
        api_key = source.get("api_key", "")
        if source_name == "微步在线X情报社区":
            r = query_threatbook_hash(file_hash, api_key)
            if "error" not in r:
                results["微步"] = r
        elif source_name == "AlienVault OTX":
            r = query_otx_hash(file_hash, api_key)
            if "error" not in r:
                results["OTX"] = r
        elif source_name == "VirusTotal":
            r = query_vt_hash(file_hash, api_key)
            if "error" not in r:
                results["VirusTotal"] = r
                if r.get("not_found"):
                    continue
        elif source_name == "CVERC国家计算机病毒协同分析平台":
            if not api_key:
                results["CVERC_error"] = "未配置Key"
                continue
            r = query_cverc_hash(file_hash, api_key)
            if "error" not in r:
                results["CVERC"] = r
    
    return results


def lookup_iocs(iocs: dict, config: dict = None) -> dict:
    """对IOC列表做多源情报查询"""
    if config is None:
        config = load_config()
    
    results = {"ips": {}, "domains": {}, "hashes": {}, "query_summary": []}
    
    # 查IP
    seen_ips = set()
    ip_entries = iocs.get("ips", [])
    if isinstance(ip_entries, list):
        for entry in ip_entries:
            ip = entry.get("ip", "") if isinstance(entry, dict) else entry
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                results["ips"][ip] = multi_source_query_ip(ip, config)
    
    # 查域名（微步 + OTX）
    seen_domains = set()
    tb_key = ""
    otx_key = ""
    for s in config.get("sources", []):
        if s.get("name") == "微步在线X情报社区":
            tb_key = s.get("api_key", "")
        elif s.get("name") == "AlienVault OTX":
            otx_key = s.get("api_key", "")
    for entry in iocs.get("domains", []):
        domain = entry.get("domain", "") if isinstance(entry, dict) else entry
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            domain_result = {"微步": query_threatbook_domain(domain, tb_key)}
            domain_result["OTX"] = query_otx_domain(domain, otx_key)
            results["domains"][domain] = domain_result
    
    # 查Hash
    seen_hashes = set()
    for entry in iocs.get("hashes", []):
        h = entry.get("hash", "") if isinstance(entry, dict) else entry
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            results["hashes"][h] = multi_source_query_hash(h, config)
    
    return results


def format_threat_intel(results: dict) -> str:
    """格式化情报结果为Markdown"""
    md = "\n## 威胁情报关联分析\n\n"
    
    # IP查询结果
    ip_results = results.get("ips", {})
    if ip_results:
        md += "### IP情报\n\n| IP | 微步 | OTX | URLhaus | VT | AbuseIPDB | IPinfo |\n"
        md += "|------|------|-----|---------|----|----------|--------|\n"
        for ip, info in ip_results.items():
            tb = info.get("微步", {})
            tb_sev = tb.get("severity", "-") if not tb.get("error") else "err"
            vt = info.get("VirusTotal", {})
            vt_cnt = vt.get("malicious_count", "-") if not vt.get("error") else "-"
            otx = info.get("OTX", {})
            otx_str = f"P{otx.get('pulse_count',0)}/{otx.get('malware_str','-')}" if not otx.get("error") else "-"
            uh = info.get("URLhaus", {})
            uh_str = f"{uh.get('url_count',0)}url/{uh.get('threat_str','-')}" if not uh.get("error") else "-"
            ab = info.get("AbuseIPDB", {})
            ab_score = f"{ab.get('abuse_score','?')}/100" if not ab.get("error") else "-"
            ipi = info.get("IPinfo", {})
            loc = f"{ipi.get('city','?')},{ipi.get('country','?')}" if not ipi.get("error") else "-"
            md += f"| {ip} | {tb_sev} | {otx_str} | {uh_str} | {vt_cnt}/{vt.get('total_engines','?')} | {ab_score} | {loc} |\n"
    else:
        md += "✅ 无非可信IP需要查询\n\n"
    
    # Hash查询结果
    hash_results = results.get("hashes", {})
    if hash_results:
        md += "\n### 文件Hash情报\n\n| Hash | 微步 | OTX | VT检测 | CVERC |\n"
        md += "|------|------|-----|--------|------|\n"
        for h, info in hash_results.items():
            vt = info.get("VirusTotal", {})
            vt_str = f"{vt.get('malicious_count','?')}/{vt.get('total_engines','?')}" if not vt.get("error") else vt.get("error", "-")
            tb = info.get("微步", {})
            tb_str = tb.get("severity", "-") if not tb.get("error") else "-"
            otx_h = info.get("OTX", {})
            otx_h_str = f"P{otx_h.get('pulse_count',0)}/{otx_h.get('malware_str','-')}" if not otx_h.get("error") else "-"
            cv = info.get("CVERC", {})
            cv_str = cv.get("verdict", "-") if not cv.get("error") else "-"
            md += f"| `{h[:16]}...` | {tb_str} | {otx_h_str} | {vt_str} | {cv_str} |\n"
        md += "✅ 无非可信Hash需要查询\n\n"
    
    return md


if __name__ == "__main__":
    # 测试
    test_iocs = {
        "ips": [
            {"ip": "8.8.8.8", "port": 443},
            {"ip": "45.33.32.156", "port": 6666}
        ],
        "domains": ["google.com"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
    }
    result = lookup_iocs(test_iocs)
    print(format_threat_intel(result))
    print("\n--- RAW ---")
    print(json.dumps(result, indent=2, ensure_ascii=False)[:3000])
