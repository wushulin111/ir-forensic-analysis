# 威胁情报平台接入说明

本文档说明 `ir-forensic-analysis` 已接入、可接入以及需要配置 Key 的威胁情报平台，以及如何把新平台加到 skill 中。

## 当前脚本已接入的平台

`scripts/threat_intel_lookup.py` 已支持以下平台，配置位于 `config/threat_intel.json`：

| 平台 | 查询类型 | 是否需要 Key | 默认状态 |
|------|----------|--------------|----------|
| 微步在线 X 情报社区 | IP/域名/Hash | 需要 | 已启用（配置中内置 Key） |
| AlienVault OTX | IP/域名/Hash | 可选 | 已启用 |
| URLhaus (abuse.ch) | IP/域名 | 不需要 | 已启用 |
| VirusTotal | IP/Hash | 需要 | 已启用，未配置 Key |
| CVERC 国家计算机病毒协同分析平台 | Hash | 需要 | 已启用，未配置 Key |
| AbuseIPDB | IP | 需要 | 已启用，未配置 Key |
| IPinfo.io | IP 归属 | 不需要 | 已启用 |
| ThreatFox (abuse.ch) | IP/域名/Hash | 需要免费 Auth-Key | 默认关闭，配置后启用 |
| MalwareBazaar (abuse.ch) | Hash | 需要免费 Auth-Key | 默认关闭，配置后启用 |
| Pulsedive | IP/域名/Hash | 可选（无 Key 限流更严） | 已启用 |
| URLScan.io | 域名历史扫描 | 可选 | 已启用 |
| Kaspersky OpenTIP | IP/域名/Hash | 需要 | 本地已启用，Token 到期由 `kaspersky_token_manager.py` 自动续期；发布版需自行配置 |
| GreyNoise Community | IP | 需要免费 Key | 默认关闭，配置 Key 后启用 |
| Hybrid Analysis (Falcon Sandbox) | Hash | 需要免费 Key | 默认关闭，配置 Key 后启用 |
| 奇安信失陷检测情报 | IP/域名 | 需要 | 默认关闭，配置 Key 后启用 |

## 全球常用威胁情报平台清单

### 国内平台

| 平台 | 入口 | API 情况 | 建议 |
|------|------|----------|------|
| 微步在线 X 情报社区 | https://x.threatbook.com/ | 有公开 API | 已接入 |
| 奇安信威胁情报中心 | https://ti.qianxin.com/ | REST API（失陷检测等）+ QTI-MCP | 已接入失陷检测接口，配置 Key 后自动参与比对；MCP 适合在 DeepChat/Cherry Studio 等客户端中使用 |
| 启明星辰 VenusEye | https://www.venuseye.com.cn/ | 企业级 API | 配置企业API后自动接入 |
| 绿盟威胁情报 NTI | https://ti.nsfocus.com/ | 企业级 API | 配置企业API后自动接入 |
| 360 威胁情报中心 | https://ti.360.net/ | 无公开免费 API | 配置企业API后自动接入 |
| 腾讯威胁情报 TIX | https://tix.qq.com/ | 企业级 API | 配置企业API后自动接入 |
| 安恒威胁情报中心 | https://ti.dbappsecurity.com.cn/ | 企业级 API | 配置企业API后自动接入 |
| 深信服威胁情报 | https://ti.sangfor.com/ | 企业级 API | 配置企业API后自动接入 |
| 安天威胁情报中心 | https://www.antiycloud.com/ | 无公开免费 API | 配置企业API后自动接入 |
| 国家互联网应急中心 CNCERT | https://www.cert.org.cn/ | 行业协作 | 通报/协作渠道 |
| CVERC 国家计算机病毒协同分析平台 | 已接入 API | 有 API | 已接入 |

### 国际平台

| 平台 | 入口 | API 情况 | 建议 |
|------|------|----------|------|
| VirusTotal | https://www.virustotal.com/ | 有 API，免费版限速 | 已接入 |
| AlienVault OTX | https://otx.alienvault.com/ | 有公开 API | 已接入 |
| AbuseIPDB | https://www.abuseipdb.com/ | 有 API，免费版限次 | 已接入 |
| URLhaus | https://urlhaus.abuse.ch/ | 有公开 API | 已接入 |
| MalwareBazaar | https://bazaar.abuse.ch/ | 有 API，需免费 Auth-Key | 已接入，待配置 |
| ThreatFox | https://threatfox.abuse.ch/ | 有 API，需免费 Auth-Key | 已接入，待配置 |
| Pulsedive | https://pulsedive.com/ | 有 API，免费 Key | 已接入 |
| URLScan.io | https://urlscan.io/ | 有 API，免费 Key 可选 | 已接入 |
| Kaspersky OpenTIP | https://opentip.kaspersky.com/ | 有 API，免费注册 Token | 已接入；本地已配置并支持自动续期 |
| GreyNoise | https://viz.greynoise.io/ | Community API 免费 Key | 已接入，待配置 Key |
| Hybrid Analysis | https://www.hybrid-analysis.com/ | 有 API，免费 Key | 已接入，待配置 Key |
| IBM X-Force Exchange | https://exchange.xforce.ibmcloud.com/ | 有 API，免费 Key | 可扩展 |
| Microsoft Defender Threat Intelligence | https://ti.defender.microsoft.com/ | 企业 API | 可扩展 |
| Cisco Talos Reputation Center | https://talosintelligence.com/reputation_center/ | 无公开免费 API | 未自动接入，可扩展 |
| Recorded Future | https://www.recordedfuture.com/ | 企业 API | 可扩展 |
| Mandiant / Google Threat Intelligence | https://www.mandiant.com/ | 企业 API | 可扩展 |
| CrowdStrike Falcon Intelligence | https://falcon.crowdstrike.com/ | 企业 API | 可扩展 |
| Fortinet FortiGuard | https://www.fortiguard.com/ | 企业 API | 可扩展 |
| Check Point ThreatCloud | https://threatcloud.checkpoint.com/ | 企业 API | 可扩展 |
| ESET Threat Intelligence | https://www.eset.com/ | 企业 API | 可扩展 |
| SophosLabs Intelix | https://www.sophos.com/en-us/labs | 有 API，免费试用 | 可扩展 |
| URLScan / URLVoid / ScamAdviser 等 OSINT | 各官网 | 网页/API 混合 | 辅助查询 |

> 说明：国内厂商的威胁情报多数面向企业客户，公开免费 API 较少。若你们单位已有企业 API，把接口和 Key 加入 `config/threat_intel.json` 后即可自动参与交叉分析。国际平台中有公开免费 API 的已直接接入，需要 Key 的通过环境变量配置后自动启用。

## 报告如何呈现

- 分析时脚本会对配置中已启用的 API 平台自动查询，不需要人工打开网页复核。
- 报告“威胁情报关联分析”章节会展示 IP/域名/Hash 的交叉比对结果，并在“情报交叉分析说明”中列出本次使用了哪些平台、是否需要 Key、本次是否成功参与比对。
- 未配置 Key 的平台会被明确标注“未配置Key，已跳过”，不会误判为“无情报”。

## 如何配置平台

1. 本地使用复制 `config/threat_intel.json.example` 为 `config/threat_intel.json` 后编辑；GitHub 发布版不提交真实配置，只保留 `.example`。
2. 把对应平台的 `enabled` 改为 `true`。
3. 填入 `api_key`，或设置环境变量（推荐）：
   - `TI_THREATBOOK_API_KEY`
   - `TI_VIRUSTOTAL_API_KEY`
   - `TI_OTX_API_KEY`
   - `TI_ABUSEIPDB_API_KEY`
   - `TI_CVERC_API_KEY`
   - `TI_PULSEDIVE_API_KEY`
   - `TI_KASPERSKY_OPENTIP_API_KEY`
   - `TI_QIANXIN_API_KEY`
   - `TI_KASPERSKY_ACCOUNT_EMAIL`（自动续期用，可选）
   - `TI_KASPERSKY_ACCOUNT_PASSWORD`（自动续期用，可选）
   - `TI_GREYNOISE_API_KEY`
   - `TI_HYBRID_ANALYSIS_API_KEY`
   - `TI_URLSCAN_API_KEY`
   - `TI_THREATFOX_AUTH_KEY`
   - `TI_MALWAREBAZAAR_AUTH_KEY`
4. 如需调整查询顺序，修改 `ip_query_order`、`domain_query_order`、`hash_query_order`。

环境变量优先级高于配置文件，脚本加载配置时会用环境变量覆盖同名字段。

> 卡巴斯基 Token 最长一年有效期。`scripts/kaspersky_token_manager.py` 会在 Token 剩余 30 天以内时，使用配置中的 `account_email` / `account_password` 自动登录 OpenTIP 并生成新 Token，写回 `config/threat_intel.json`。手动执行：`python scripts/kaspersky_token_manager.py --refresh`。

> 奇安信接入说明：REST API 直接使用 `apikey` 查询 `https://ti.qianxin.com/api/v2/compromise`，适合 skill 的自动交叉分析；QTI-MCP（`https://mcp.ti.qianxin.com/ti-stream-mcp` 或 `/ti-mcp/sse`）提供 16 个会话式查询函数，更适合 MCP 客户端。两种方式都需要向 `ti_support@qianxin.com` 申请 API Key。

## 命令行使用

```bash
python scripts/threat_intel_lookup.py --hash <sha256>
python scripts/threat_intel_lookup.py --ip <ip>
python scripts/threat_intel_lookup.py --domain <domain>
python scripts/threat_intel_lookup.py --hash <sha256> --raw
```

`analyze_forensics.py` 在完成 IOC 提取后会自动调用 `lookup_iocs()`，把结果以 Markdown 追加到 `incident_report.md`。

## 新增一个平台的步骤

1. 在 `threat_intel_lookup.py` 中新增查询函数，返回统一的 dict，错误时返回 `{"error": "..."}`，未收录时返回 `{"not_found": True, "error": "..."}`。
2. 在 `config/threat_intel.json` 的 `sources` 中新增条目，设置 `enabled`、`api_key`、`env_key`、`note`，并加入对应类型的 `*_query_order`。
3. 在 `multi_source_query_ip`、`multi_source_query_domain`、`multi_source_query_hash` 中加入对应分支。
4. 在 `format_threat_intel` 中补充表格列或详情。
5. 运行 `python scripts/threat_intel_lookup.py --hash <测试hash> --raw` 验证。

## 安全提示

- 不要把 API Key 提交到公开仓库；建议统一使用环境变量。
- 当前 `config/threat_intel.json` 中仍写有微步 API Key，属于敏感内容，建议迁移到环境变量后移除明文。
- 在线查询会向第三方平台提交 IOC，若样本涉及客户敏感环境，请先确认授权与数据合规。
