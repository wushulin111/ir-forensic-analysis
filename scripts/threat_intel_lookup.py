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
        config = json.load(f)
    # API Key 优先从环境变量补充，避免明文写死在配置里
    for source in config.get("sources", []):
        env_key = source.get("env_key", "")
        if env_key:
            env_value = os.environ.get(env_key, "")
            if env_value:
                source["api_key"] = env_value
    return config


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


def query_kaspersky(value: str, api_key: str, ioc_type: str) -> dict:
    """卡巴斯基 OpenTIP 查询 hash/ip/domain，需注册 API Token"""
    if not api_key:
        return {"not_configured": True, "error": "Kaspersky OpenTIP API Key 未配置"}
    try:
        r = requests.get(
            f"https://opentip.kaspersky.com/api/v1/search/{ioc_type}",
            params={"request": value},
            headers={"x-api-key": api_key},
            timeout=15
        )
        data = r.json()
        if not isinstance(data, dict):
            return {"error": "Kaspersky返回格式异常"}
        if "error" in data:
            return {"error": data.get("error", "Kaspersky查询失败")}
        return {
            "source": "Kaspersky OpenTIP",
            "zone": data.get("Zone", ""),
            "reputation": data.get("Reputation", ""),
            "detection": data.get("Detection", ""),
            "threat_score": data.get("ThreatScore", ""),
            "is_blacklisted": data.get("IsBlackListed", ""),
            "first_seen": data.get("FirstSeen", ""),
            "last_seen": data.get("LastSeen", ""),
            "ioc": data.get("Ioc", ""),
            "type": data.get("Type", "")
        }
    except Exception as e:
        return {"error": f"Kaspersky查询异常: {str(e)}"}


def query_threatfox(value: str, api_key: str = "") -> dict:
    """ThreatFox 查询 IP/域名/Hash 历史恶意记录，需要免费注册 Auth-Key"""
    try:
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": value},
            headers=headers,
            timeout=15
        )
        data = r.json()
        if data.get("query_status") != "ok":
            return {"error": data.get("query_status", "unknown")}
        iocs = data.get("data", [])
        families = set()
        threat_types = set()
        tags = set()
        for item in iocs:
            fam = item.get("malware", "") or item.get("malware_printable", "")
            if fam:
                families.add(fam)
            tt = item.get("threat_type", "")
            if tt:
                threat_types.add(tt)
            for t in (item.get("tags", []) or []):
                tags.add(t)
        return {
            "source": "ThreatFox",
            "ioc_count": data.get("num_iocs", 0),
            "malware_families": sorted(families)[:10],
            "malware_str": ", ".join(sorted(families)[:5]),
            "threat_types": sorted(threat_types)[:10],
            "threat_str": ", ".join(sorted(threat_types)[:3]),
            "tags": sorted(tags)[:10],
            "first_seen": iocs[0].get("first_seen", "") if iocs else ""
        }
    except Exception as e:
        return {"error": f"ThreatFox查询异常: {str(e)}"}


def query_malwarebazaar_hash(file_hash: str, api_key: str = "") -> dict:
    """MalwareBazaar 查询恶意样本Hash元数据，需要免费注册 Auth-Key"""
    try:
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers=headers,
            timeout=15
        )
        data = r.json()
        if data.get("query_status") != "ok":
            return {"error": data.get("query_status", "unknown")}
        rows = data.get("data", [])
        if not rows:
            return {"not_found": True, "error": "MalwareBazaar未收录"}
        row = rows[0]
        return {
            "source": "MalwareBazaar",
            "signature": row.get("signature", ""),
            "signature_str": row.get("signature", "未知"),
            "tags": (row.get("tags") or [])[:10],
            "file_type": row.get("file_type", ""),
            "first_seen": row.get("first_seen", ""),
            "last_seen": row.get("last_seen", ""),
            "sha256": row.get("sha256_hash", ""),
            "delivery_method": row.get("delivery_method", ""),
            "reporter": row.get("reporter", "")
        }
    except Exception as e:
        return {"error": f"MalwareBazaar查询异常: {str(e)}"}


def query_pulsedive(value: str, api_key: str = "") -> dict:
    """Pulsedive 查询 IP/域名/Hash 风险评分，无Key也能用但限流更严"""
    try:
        params = {"indicator": value, "pretty": 1}
        if api_key:
            params["key"] = api_key
        r = requests.get("https://pulsedive.com/api/indicator.php", params=params, timeout=8)
        data = r.json()
        if isinstance(data, dict) and data.get("error"):
            return {"error": data.get("error")}
        if not isinstance(data, dict):
            return {"error": "Pulsedive返回格式异常"}
        return {
            "source": "Pulsedive",
            "risk": data.get("risk", ""),
            "threat": data.get("threat", ""),
            "threat_str": data.get("threat", ""),
            "type": data.get("type", ""),
            "stamp": data.get("stamp", ""),
            "triaged": data.get("triaged", False),
            "properties": data.get("properties", {}) if isinstance(data.get("properties"), dict) else {}
        }
    except Exception as e:
        return {"error": f"Pulsedive查询异常: {str(e)}"}


def query_greynoise_ip(ip: str, api_key: str) -> dict:
    """GreyNoise Community API 查询IP噪声/威胁分类，需免费Key"""
    if not api_key:
        return {"not_configured": True, "error": "GreyNoise API Key 未配置"}
    try:
        headers = {"key": api_key, "accept": "application/json"}
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=10)
        data = r.json()
        if isinstance(data, dict) and data.get("message"):
            return {"error": data.get("message")}
        if not isinstance(data, dict):
            return {"error": "GreyNoise返回格式异常"}
        return {
            "source": "GreyNoise",
            "ip": data.get("ip", ""),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", ""),
            "name": data.get("name", ""),
            "last_seen": data.get("last_seen", "")
        }
    except Exception as e:
        return {"error": f"GreyNoise查询异常: {str(e)}"}


def query_hybrid_hash(file_hash: str, api_key: str) -> dict:
    """Hybrid Analysis (Falcon Sandbox) 查询样本情报，需免费Key"""
    if not api_key:
        return {"not_configured": True, "error": "Hybrid Analysis API Key 未配置"}
    try:
        r = requests.get(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            params={"hash": file_hash},
            headers={"api-key": api_key, "user-agent": "ir-forensic-analysis/1.0"},
            timeout=20
        )
        data = r.json()
        if isinstance(data, list) and data:
            row = data[0]
            return {
                "source": "Hybrid Analysis",
                "verdict": row.get("verdict", ""),
                "threat_score": row.get("threat_score", ""),
                "threat_level": row.get("threat_level", ""),
                "sha256": row.get("sha256", ""),
                "submit_name": row.get("submit_name", ""),
                "av_detect": row.get("av_detect", ""),
                "vx_family": row.get("vx_family", "")
            }
        if isinstance(data, dict) and data.get("error"):
            return {"error": data.get("error")}
        return {"not_found": True, "error": "Hybrid Analysis未收录"}
    except Exception as e:
        return {"error": f"Hybrid Analysis查询异常: {str(e)}"}


def query_urlscan_domain(domain: str, api_key: str = "") -> dict:
    """URLScan.io 查询域名历史扫描记录，无需Key可查公开结果"""
    try:
        headers = {"accept": "application/json"}
        if api_key:
            headers["API-Key"] = api_key
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 20},
            headers=headers,
            timeout=15
        )
        data = r.json()
        if isinstance(data, dict) and data.get("message"):
            return {"error": data.get("message")}
        if not isinstance(data, dict):
            return {"error": "URLScan返回格式异常"}
        results = data.get("results", [])
        malicious = 0
        for item in results:
            verdict = (item.get("page", {}) or {}).get("verdicts", {}) or {}
            if (verdict.get("overall", {}) or {}).get("malicious", False):
                malicious += 1
        return {
            "source": "URLScan.io",
            "result_count": data.get("total", len(results)),
            "malicious_count": malicious,
            "first_scan": results[-1].get("task", {}).get("time", "") if results else "",
            "last_scan": results[0].get("task", {}).get("time", "") if results else ""
        }
    except Exception as e:
        return {"error": f"URLScan查询异常: {str(e)}"}


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


def _get_enabled_source(source_name: str, config: dict) -> Optional[dict]:
    for s in config.get("sources", []):
        if s.get("name") == source_name and s.get("enabled"):
            return s
    return None


def multi_source_query_ip(ip: str, config: dict) -> dict:
    """多源IP查询：微步/OTX/URLhaus/VT/AbuseIPDB/GreyNoise/Pulsedive/Kaspersky/ThreatFox"""
    results = {}
    order = config.get("ip_query_order", config.get("query_order", ["微步在线X情报社区", "AlienVault OTX", "URLhaus"]))
    for source_name in order:
        source = _get_enabled_source(source_name, config)
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
        elif source_name == "GreyNoise":
            r = query_greynoise_ip(ip, api_key)
            if "error" not in r:
                results["GreyNoise"] = r
            else:
                results["GreyNoise_error"] = r.get("error", "")
        elif source_name == "Pulsedive":
            r = query_pulsedive(ip, api_key)
            if "error" not in r:
                results["Pulsedive"] = r
        elif source_name == "Kaspersky OpenTIP":
            r = query_kaspersky(ip, api_key, "ip")
            if "error" not in r:
                results["Kaspersky"] = r
            else:
                results["Kaspersky_error"] = r.get("error", "")
        elif source_name == "ThreatFox":
            r = query_threatfox(ip, api_key)
            if "error" not in r:
                results["ThreatFox"] = r
    # 补充IPinfo基础信息（最后补充，不阻断）
    results["IPinfo"] = query_ipinfo(ip)
    return results


def multi_source_query_domain(domain: str, config: dict) -> dict:
    """多源域名查询：微步/OTX/URLhaus/URLScan/Pulsedive/Kaspersky/ThreatFox"""
    results = {}
    order = config.get("domain_query_order", config.get("query_order", ["微步在线X情报社区", "AlienVault OTX", "URLhaus"]))
    for source_name in order:
        source = _get_enabled_source(source_name, config)
        if not source:
            continue
        api_key = source.get("api_key", "")
        if source_name == "微步在线X情报社区":
            r = query_threatbook_domain(domain, api_key)
            if "error" not in r:
                results["微步"] = r
            else:
                results["微步_error"] = r.get("error", "")
        elif source_name == "AlienVault OTX":
            r = query_otx_domain(domain, api_key)
            if "error" not in r:
                results["OTX"] = r
        elif source_name == "URLhaus":
            r = query_urlhaus_host(domain)
            if "error" not in r:
                results["URLhaus"] = r
        elif source_name == "URLScan.io":
            r = query_urlscan_domain(domain, api_key)
            if "error" not in r:
                results["URLScan.io"] = r
        elif source_name == "Pulsedive":
            r = query_pulsedive(domain, api_key)
            if "error" not in r:
                results["Pulsedive"] = r
        elif source_name == "Kaspersky OpenTIP":
            r = query_kaspersky(domain, api_key, "domain")
            if "error" not in r:
                results["Kaspersky"] = r
            else:
                results["Kaspersky_error"] = r.get("error", "")
        elif source_name == "ThreatFox":
            r = query_threatfox(domain, api_key)
            if "error" not in r:
                results["ThreatFox"] = r
    return results


def multi_source_query_hash(file_hash: str, config: dict) -> dict:
    """多源Hash查询：微步/OTX/VT/CVERC/MalwareBazaar/ThreatFox/Kaspersky/Pulsedive/Hybrid"""
    results = {}
    order = config.get("hash_query_order", config.get("query_order", []))
    for source_name in order:
        source = _get_enabled_source(source_name, config)
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
        elif source_name == "MalwareBazaar":
            r = query_malwarebazaar_hash(file_hash, api_key)
            if "error" not in r:
                results["MalwareBazaar"] = r
        elif source_name == "ThreatFox":
            r = query_threatfox(file_hash, api_key)
            if "error" not in r:
                results["ThreatFox"] = r
        elif source_name == "Kaspersky OpenTIP":
            r = query_kaspersky(file_hash, api_key, "hash")
            if "error" not in r:
                results["Kaspersky"] = r
            else:
                results["Kaspersky_error"] = r.get("error", "")
        elif source_name == "Pulsedive":
            r = query_pulsedive(file_hash, api_key)
            if "error" not in r:
                results["Pulsedive"] = r
        elif source_name == "Hybrid Analysis":
            r = query_hybrid_hash(file_hash, api_key)
            if "error" not in r:
                results["Hybrid Analysis"] = r
            else:
                results["Hybrid_error"] = r.get("error", "")
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
    
    # 查域名（按 domain_query_order 多源查询）
    seen_domains = set()
    for entry in iocs.get("domains", []):
        domain = entry.get("domain", "") if isinstance(entry, dict) else entry
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            results["domains"][domain] = multi_source_query_domain(domain, config)
    
    # 查Hash
    seen_hashes = set()
    for entry in iocs.get("hashes", []):
        h = entry.get("hash", "") if isinstance(entry, dict) else entry
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            results["hashes"][h] = multi_source_query_hash(h, config)
    
    return results


def _cell(result: dict, value_key: str, fmt=None) -> str:
    """把单个情报源结果格式化为表格单元格"""
    if not result:
        return "-"
    if result.get("not_found"):
        return "未收录"
    if result.get("error"):
        return "err"
    value = result.get(value_key, "-")
    if value in (None, "", "-"):
        return "-"
    if fmt:
        try:
            return fmt(value, result)
        except Exception:
            return str(value)
    return str(value)


def _threatbook_level(result: dict) -> str:
    """兼容微步 IP(severity) 与 Hash(summary.threat_level) 的威胁等级取值"""
    if not result:
        return "-"
    if result.get("error"):
        return "err"
    severity = result.get("severity")
    if severity:
        return str(severity)
    summary = result.get("summary") or {}
    level = summary.get("threat_level", "")
    return str(level) if level else "-"


def _cross_analysis_summary(results: dict, config: dict) -> str:
    """生成情报交叉分析说明，标注各平台参与状态与 Key 配置要求"""
    lines = [
        "### 情报交叉分析说明",
        "",
        "本次分析已对以下平台进行自动交叉比对，结果以各平台返回数据为准：",
        "",
        "| 平台 | 覆盖类型 | 需要Key | 本次状态 |",
        "|------|----------|--------|----------|",
    ]
    ioc_types = ["ips", "domains", "hashes"]
    for source in config.get("sources", []):
        if source.get("type") != "api" or not source.get("enabled"):
            continue
        name = source.get("name", "")
        result_key = source.get("result_key", name)
        ioc_types_str = "/".join(source.get("ioc_types") or [])
        key_required = bool(source.get("key_required", False))
        key_need = "是" if key_required else "否"
        has_key = bool(source.get("api_key", ""))
        found = False
        for ioc_type in ioc_types:
            for item in results.get(ioc_type, {}).values():
                if result_key in item:
                    found = True
                    break
            if found:
                break
        if found:
            status = "已自动比对"
        elif key_required and not has_key:
            status = "未配置Key，已跳过"
        else:
            status = "已查询，无匹配记录"
        lines.append(f"| {name} | {ioc_types_str or '-'} | {key_need} | {status} |")
    lines.append("")
    lines.append("> 需要 Key 的平台请通过环境变量或 config/threat_intel.json 配置，配置后自动参与下次分析。")
    return "\n".join(lines) + "\n"


def format_threat_intel(results: dict, config: dict = None) -> str:
    """格式化情报结果为Markdown"""
    if config is None:
        config = load_config()
    md = "\n## 威胁情报关联分析\n\n"

    # IP查询结果
    ip_results = results.get("ips", {})
    if ip_results:
        md += "### IP情报\n\n| IP | 微步 | OTX | URLhaus | VT | AbuseIPDB | GreyNoise | Pulsedive | Kaspersky | ThreatFox | IPinfo |\n"
        md += "|------|------|-----|---------|----|----------|-----------|-----------|-----------|-----------|--------|\n"
        for ip, info in ip_results.items():
            tb_sev = _threatbook_level(info.get("微步"))
            vt = info.get("VirusTotal", {})
            vt_cnt = _cell(vt, "malicious_count", lambda v, r: f"{v}/{r.get('total_engines','?')}")
            otx = info.get("OTX", {})
            otx_str = _cell(otx, "malware_str", lambda v, r: f"P{r.get('pulse_count',0)}/{v}")
            uh = info.get("URLhaus", {})
            uh_str = _cell(uh, "threat_str", lambda v, r: f"{r.get('url_count',0)}url/{v}")
            ab = info.get("AbuseIPDB", {})
            ab_score = _cell(ab, "abuse_score", lambda v, r: f"{v}/100")
            gn_str = _cell(info.get("GreyNoise"), "classification")
            pd_str = _cell(info.get("Pulsedive"), "risk", lambda v, r: f"{v}/{r.get('threat_str','-')}")
            kasp_str = _cell(info.get("Kaspersky"), "zone", lambda v, r: f"{v}/{r.get('threat_score','-')}")
            tf_str = _cell(info.get("ThreatFox"), "malware_str", lambda v, r: f"{r.get('ioc_count',0)}ioc/{v}")
            ipi = info.get("IPinfo", {})
            loc = _cell(ipi, "city", lambda v, r: f"{v},{r.get('country','?')}")
            md += f"| {ip} | {tb_sev} | {otx_str} | {uh_str} | {vt_cnt} | {ab_score} | {gn_str} | {pd_str} | {kasp_str} | {tf_str} | {loc} |\n"
    else:
        md += "未发现需要查询的IP\n\n"

    # 域名查询结果
    domain_results = results.get("domains", {})
    if domain_results:
        md += "\n### 域名情报\n\n| 域名 | 微步 | OTX | URLhaus | URLScan | Pulsedive | Kaspersky | ThreatFox |\n"
        md += "|------|------|-----|---------|---------|-----------|-----------|-----------|\n"
        for domain, info in domain_results.items():
            tb_sev = _threatbook_level(info.get("微步"))
            otx = info.get("OTX", {})
            otx_str = _cell(otx, "malware_str", lambda v, r: f"P{r.get('pulse_count',0)}/{v}")
            uh = info.get("URLhaus", {})
            uh_str = _cell(uh, "threat_str", lambda v, r: f"{r.get('url_count',0)}url/{v}")
            us = info.get("URLScan.io", {})
            us_str = _cell(us, "result_count", lambda v, r: f"{v}scan/{r.get('malicious_count',0)}mal")
            pd_str = _cell(info.get("Pulsedive"), "risk", lambda v, r: f"{v}/{r.get('threat_str','-')}")
            kasp_str = _cell(info.get("Kaspersky"), "zone", lambda v, r: f"{v}/{r.get('threat_score','-')}")
            tf_str = _cell(info.get("ThreatFox"), "malware_str", lambda v, r: f"{r.get('ioc_count',0)}ioc/{v}")
            md += f"| `{domain}` | {tb_sev} | {otx_str} | {uh_str} | {us_str} | {pd_str} | {kasp_str} | {tf_str} |\n"

    # Hash查询结果
    hash_results = results.get("hashes", {})
    if hash_results:
        md += "\n### 文件Hash情报\n\n| Hash | 微步 | OTX | VT检测 | CVERC | MalwareBazaar | Kaspersky | Pulsedive | ThreatFox | Hybrid |\n"
        md += "|------|------|-----|--------|------|---------------|-----------|-----------|-----------|--------|\n"
        for h, info in hash_results.items():
            vt = info.get("VirusTotal", {})
            vt_str = _cell(vt, "malicious_count", lambda v, r: f"{v}/{r.get('total_engines','?')}")
            tb_str = _threatbook_level(info.get("微步"))
            otx_h = info.get("OTX", {})
            otx_h_str = _cell(otx_h, "malware_str", lambda v, r: f"P{r.get('pulse_count',0)}/{v}")
            cv_str = _cell(info.get("CVERC"), "verdict")
            mb_str = _cell(info.get("MalwareBazaar"), "signature")
            kasp_str = _cell(info.get("Kaspersky"), "zone", lambda v, r: f"{v}/{r.get('detection','-')}")
            pd_str = _cell(info.get("Pulsedive"), "risk", lambda v, r: f"{v}/{r.get('threat_str','-')}")
            tf_str = _cell(info.get("ThreatFox"), "malware_str", lambda v, r: f"{r.get('ioc_count',0)}ioc/{v}")
            hy_str = _cell(info.get("Hybrid Analysis"), "verdict", lambda v, r: f"{v}/{r.get('threat_score','-')}")
            md += f"| `{h[:16]}...` | {tb_str} | {otx_h_str} | {vt_str} | {cv_str} | {mb_str} | {kasp_str} | {pd_str} | {tf_str} | {hy_str} |\n"

    md += "\n" + _cross_analysis_summary(results, config)

    return md


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="多源威胁情报查询工具")
    parser.add_argument("--ip", help="查询IP")
    parser.add_argument("--domain", help="查询域名")
    parser.add_argument("--hash", help="查询文件Hash")
    parser.add_argument("--raw", action="store_true", help="同时输出原始JSON")
    args = parser.parse_args()

    if not (args.ip or args.domain or args.hash):
        parser.print_help()
        sys.exit(0)

    iocs = {"ips": [], "domains": [], "hashes": []}
    if args.ip:
        iocs["ips"].append(args.ip)
    if args.domain:
        iocs["domains"].append(args.domain)
    if args.hash:
        iocs["hashes"].append(args.hash)

    result = lookup_iocs(iocs)
    print(format_threat_intel(result))
    if args.raw:
        print("\n--- RAW ---")
        print(json.dumps(result, indent=2, ensure_ascii=False))
