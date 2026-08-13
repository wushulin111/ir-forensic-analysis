# 银狐（SilverFox / ValleyRAT / UTG-Q-1000）2026 情报速览

> 更新日期：2026-08-13
> 用途：供 `ir-forensic-analysis` skill 在应急响应时快速定位银狐最新变种、IOC 与检测要点。完整 IOC 已并入 `rules/silver_fox_rules.json` 和 `rules/ioc_library.json`（当前 43 条规则 / 1918 域名 / 414 IP / 45 哈希 / 207 释放路径）。

## 一、2026 年重要时间线

| 时间 | 事件 | 关键点 |
|------|------|--------|
| 2026-01~02 | 海外税务钓鱼（印度/俄罗斯等） | 1600+ 钓鱼邮件，PDF 诱饵→压缩包→RustSL 加载器→ValleyRAT/ABCDoor |
| 2026-05-21 | CVERC 官方预警 | 人事主题诱饵（违纪名单/裁员补偿），落点 `C:\Program Files\Internet Explorer\log.dll`，回连 `:8880/getinstall64` |
| 2026-05-22 | CNCERT/公安部风险提示 | 仿冒 Chrome/WPS/Clash/VPN，SEO+AI 批量钓鱼站，注入系统进程，C2 443/22 |
| 2026-06 起 | 奇安信 UTG-Q-1000 Zinst 系列 | `zinst.*` 批量命名，MSI/EXE，仿冒腾讯/阿里 Agent DLL，`TCLService` 服务，hosts 篡改 |
| 2026-07-05 | Foresiet 税务钓鱼 Part II | 白文件侧加载 30MB `teamspeak_control.dll`，内存解密 .bin，CLR 执行 ValleyRAT |
| 2026-07-16 | 瑞星 DoH 变种分析 | 伪装雷电模拟器，DoH 经 223.5.5.5/8.8.8.8 解析 C2，窃取 Telegram 会话 |
| 2026-07-20 | 公安部跨国抓捕 | 首犯潘某君从越南押解回国，银狐黑产上游被打击 |
| 2026-07-28~31 | Cato CTRL / HackerNews / SecurityAffairs | 日本制造业 ValleyRAT：新 DLL 侧加载宿主 + 三驱动 BYOVD + 双恢复机制 |
| 2026-07-29 | CNCERT 公开征集银狐威胁线索 | 国家层面收集样本/情报，安全厂商协同 |
| 2026-07-31 | CN-SEC IOC 分享 | 30 个已解码 C2/投递域名 |
| 2026-08-04 | 火绒趋势分析 | 每日境内肉鸡 IP 峰值超 1.7 万，AI 批量造毒，攻击向境外扩展 |

## 二、核心情报源（建议订阅）

| 情报源 | 地址 | 更新频率 | 用途 |
|--------|------|----------|------|
| CVERC 国家计算机病毒协同分析平台 | https://www.cverc.org.cn/ | 预警实时 | 官方样本/预警 |
| CNCERT 通报 | https://www.cert.org.cn/ | 预警实时 | 官方风险提示 |
| 奇安信威胁情报中心 | https://ti.qianxin.com/ | 按周 | UTG-Q-1000 变种分析 |
| 微步在线 | https://s.threatbook.com/ | 按周/月 | 攻击事件与月度报告 |
| 火绒安全 | https://www.huorong.cn/ | 按周/月 | 银狐趋势、样本分析 |
| 瑞星威胁情报 | https://rayblog.rising.com.cn/ | 按事件 | 深度逆向（DoH/壳） |
| 绿盟/启明星辰/360/腾讯安全 | 各官网威胁情报栏目 | 按月 | 国内补充 |
| ThreatFox SilverFox 标签 | https://threatfox.abuse.ch/browse/tag/SilverFox/ | 每日 | 最新恶意样本/IOC 标签 |
| MalwareBazaar ValleyRAT 签名 | https://bazaar.abuse.ch/browse/signature/ValleyRAT/ | 每日 | ValleyRAT 样本哈希 |
| Cato CTRL | https://www.catonetworks.com/blog/ | 按事件 | 海外攻击链/新驱动 |
| Foresiet | https://foresiet.com/blog/ | 按事件 | 税务钓鱼基础设施 |
| Mallory | https://mallory.ai/stories/ | 按事件 | 攻击事件关联 |
| CN-SEC | https://cn-sec.com/ | 每日 | 国内安全社区 IOC 分享 |
| Nextron（THOR） | https://www.nextron-systems.com/ | 按事件 | YARA 规则与 C2 |
| 腾讯文档【开源恶意域名情报库】 | https://docs.qq.com/sheet/DSFNqd2JTZG5sa1ZV?tab=BB08J2 | 实时 | 社区共享挖矿/勒索/银狐恶意域名库，本次已同步 1390 个域名 |

## 三、2026 新增关键 IOC

### 域名（节选，完整见 `rules/ioc_library.json`）

- CNCERT 2026-05：`www.ozz79u.com`、`www.danpengit.com`、`www.vpconn.fit`、`ychsq.icu`、`womsz.com`、`tmm.magentaias.com`、`ltan7942.top`、`dd.kmsccedn.com`、`www.w1pf9.com`、`www.amdyjl5.com`、`feiji22.vip`、`woyfc.com`、`vaeth.cn`、`www.hongyun4.com`、`www.chishuikaisuo.com`、`www.xr95633.com`、`rtjthgjnwetghf39.top`
- CN-SEC 2026-07-31：`ddosdns.cc`、`dvhgtdsn.cn`、`fyuuk.bing.hk.cn`、`gbwsdukz.cn`、`lotevkk.cn`、`lpomnhcf.cn`、`romnklj.cn`、`tbhjklosw.cn`、`uukk.wec512.com`、`yminsgdb.cn`、`tomnhuds.cn`、`888.xasf03.com`、`uonmgb.cn`、`fadkjnkmip.cn`、`pdxx.p9l12.com`、`zhyyds.star1ine.com`、`yyds.ydssiss.icu`、`555888.cyou`、`qaqbba.com`、`laomsjdun.cn`、`xiuyiu.net`、`dgj.ex4ax2ox3.com`、`iceiiskeng.com`、`jjbbaa12.cc`、`jqn.jhwtwue.com`、`www.tuiguang168.top`、`xwa.aisiss.icu`、`yk.ggdy.com`、`zhong.2j3j.xyz`、`116.bei9.xyz`
- 投递/CDN/白云：`file.wx2.qq.com`、`hrefbfdhfhgre-1422102728.cos.ap-hongkong.myqcloud.com`、`jun616.oss-cn-beijing.aliyuncs.com`、`q706nw.oss-cn-beijing.aliyuncs.com`、`z6ywy4.oss-cn-beijing.aliyuncs.com`、`new629.oss-cn-beijing.aliyuncs.com`、`f6h6ue.oss-cn-beijing.aliyuncs.com`
- 海外钓鱼集群：`adreses.vip`、`membese.vip`、`dusdt.vip`、`aethercode.vip`、`coinok.vip`、`prmgv.vip`、`xxgzbts.cn`、`yygzbts.cn`、`nwphotoblog.com`、`blueoceancode.com`、`foeo.cn`、`bpsalpe.cn`、`jobfreeeco.it.com`
- 其它：`oidng2.duoshit.com`（DoH C2）、`keepmasterr.com`（Nextron C2）

### IP

- CNCERT 2026-05：`103.73.220.57`、`104.143.33.78`、`185.203.39.134`、`103.12.148.80`、`137.220.158.22`、`182.16.88.242`、`192.238.128.30`、`27.124.2.150`、`47.76.195.75`、`103.156.25.99`、`122.248.198.240`、`203.91.74.8`、`154.23.183.157`、`47.76.255.167`、`54.254.148.22`、`154.23.184.120`、`192.252.176.79`、`47.130.236.119`、`137.220.153.134`
- 厂商报告：`43.128.26.132`（Cato C2）、`8.210.32.229:28290` / `47.243.224.111:7090`（奇安信 C2）、`47.242.39.192`（Foresiet 钓鱼集群）、`161.248.15.144:9000`（Nextron C2）

### 样本哈希（节选）

- CVERC 2026-05：`2f8cf966b3fc87ba1a8151428a36652e78f2d57005621eecd514629a902e88b5`
- 瑞星 2026-07：`8c4fc902905459a53f686372a1a85526`（雷电模拟器安装包）、`319c718edc390a304acb0bc8886e0da5`（wjcapture.dll）、`a63b2d1aeab6322fda74d20e0a54c4b7`（内嵌银狐 DLL）
- 奇安信 Zinst 系列 25 个 MD5：见 `rules/silver_fox_rules.json` 的 SFOX-0035

## 四、2026 检测要点

### 行为链

1. 诱饵：人事/税务/发票/违纪名单/裁员补偿/仿冒软件下载站
2. 投递：微信/QQ/邮件/SEO/AI 钓鱼站，压缩包内白加黑套件
3. 加载：`log.dll`、`PDFCORE8.dll`、`wjcapture.dll`、`teamspeak_control.dll` 等 DLL 侧加载
4. 对抗：`ntdll` Unhooking、`ZwTraceEvent` hook、三驱动 BYOVD（`BootRepair.sys`/`EnPortv.sys`/`wsftprm.sys`）、`kabuto.sys`、TrueSightKiller
5. 注入：`svchost.exe`/`ctfmon.exe`/`sihost.exe`/`elevation_service.exe` 线程上下文劫持、PoolParty
6. 隐蔽通信：`:8880`、`:443`、`:22`，DoH（223.5.5.5/223.6.6.6/8.8.8.8），HTTPS/自定义 TCP
7. 持久化：注册表 Run、计划任务（含 `AppClient`）、伪服务（`UserDataSvc_`/`netcssv`/`TCLService`）、启动目录 `.lnk`
8. 恢复机制：loader 与注入 payload 互相守护，30 秒 batch 看门狗
9. 获利：远程控制、键盘记录、Telegram/微信/QQ 会话窃取、账号劫持、内网传播、挖矿

### 现场排查建议

- 优先查：`netstat` 外联 `:8880/:443/:22/:28290/:7090/:9000`、进程模块中的上述 DLL、内核驱动服务、`FaCai2024` 字符串、`HKCU\Console\0` / `HKLM\SOFTWARE\IpDates_sun` 注册表项
- 重点看浏览器下载记录与临时目录（`%TEMP%` 下的白文件侧加载组合）
- 若发现 `svchost.exe` 等系统进程异常，对比进程树、父进程、命令行与签名

## 五、如何保持更新

1. 每日：检查 ThreatFox `SilverFox` 标签、MalwareBazaar `ValleyRAT` 签名，拉取新增样本哈希与 C2 域名
2. 每周：查看微步/奇安信/火绒/瑞星/绿盟等国内厂商报告，提取新行为特征
3. 每月：核对 CVERC/CNCERT 官方预警，把新增 IOC 合并进 `rules/ioc_library.json` 并更新 `silver_fox_rules.json`
4. 更新后：同步 `references/DETECTION_RULES.md` 的速查表与 `CHANGELOG.md`，再发布到 GitHub
5. 腾讯文档情报库按需同步：先读取全表，把新增域名去重后并入 `rules/ioc_library.json` 的 `iocs.domains`，再更新 `last_updated` 与 `stats`
