# 日志路径推断参考

> 用于入口推断阶段：根据采集到的进程/端口/服务信息，确定应在采集数据中查找哪些日志文件。
> 覆盖 Windows + Linux，按服务类型分组。

---

## Web 服务

### Nginx

| | Windows | Linux |
|--|---------|-------|
| 默认安装 | `C:\nginx\` 或 `D:\nginx\` | `/usr/local/nginx/` |
| access log | `[安装目录]\logs\access.log` | `/var/log/nginx/access.log` |
| error log | `[安装目录]\logs\error.log` | `/var/log/nginx/error.log` |
| 推断线索 | 进程中有 `nginx.exe`，或监听 80/443 端口 | 进程中有 `nginx`，或监听 80/443 |
| 分析点 | 401/403/404 爆破、异常 User-Agent、webshell 写入后访问时间、POST 大请求体 |

### Apache HTTP Server

| | Windows | Linux |
|--|---------|-------|
| 默认安装 | `C:\Apache24\` 或 `C:\Program Files\Apache Group\Apache2\` | `/etc/httpd/` (RPM) 或 `/etc/apache2/` (Deb) |
| access log | `[安装目录]\logs\access.log` | `/var/log/httpd/access_log` 或 `/var/log/apache2/access.log` |
| error log | `[安装目录]\logs\error.log` | `/var/log/httpd/error_log` 或 `/var/log/apache2/error.log` |
| ssl log | `[安装目录]\logs\ssl_access.log` | `/var/log/httpd/ssl_access_log` |
| 推断线索 | 进程中有 `httpd.exe`，或 80/443 端口 | `httpd` 进程 |
| 分析点 | 同 Nginx，额外关注 `.htaccess` 篡改、mod_cgi 滥用 |

### IIS

| | Windows |
|--|---------|
| access log | `C:\Windows\System32\LogFiles\W3SVC[N]/u_ex[YYMMDD].log` (W3C 格式) |
| ftp log | `C:\Windows\System32\LogFiles\MSFTPSVC[N]\*.log` |
| 推断线索 | `w3wp.exe` 进程，或 80/443 端口、`IR-Run "iis-sites"` 有输出 |
| 分析点 | IIS 日志格式为 W3C 扩展日志，字段含 cs-uri-stem、sc-status、cs(User-Agent)。关注 404 扫描、PUT 上传、WebDAV 利用 |

---

## 中间件

### Tomcat

| | Windows | Linux |
|--|---------|-------|
| 默认安装 | `C:\Program Files\Apache Tomcat\` 或 `C:\Users\<用户>\.tomcat\` | `/usr/local/tomcat/` |
| 运行日志 | `[安装目录]\logs\catalina.out` | `$CATALINA_HOME/logs/catalina.out` |
| 访问日志 | `[安装目录]\logs\localhost_access_log.*.txt` | `$CATALINA_HOME/logs/localhost_access_log.*.txt` |
| 管理日志 | `[安装目录]\logs\manager.log`、`host-manager.log` | 同左 |
| 推断线索 | `java.exe` + 8080/8443 端口 + 进程命令行含 `tomcat` (注意：不一定有 `tomcat` 字样，Spring Boot 也跑在 8080) |
| 分析点 | 关注 `catalina.out` 中的异常堆栈（反序列化 RCE）、`localhost_access_log` 中的 `/manager/`、`/host-manager/` 路径访问、404/500 异常 |

### JBoss / WildFly

| | Windows | Linux |
|--|---------|-------|
| 默认安装 | `C:\wildfly\` 或 `D:\jboss\` | `/opt/wildfly/` |
| 运行日志 | `[安装目录]\standalone\log\server.log` | `$JBOSS_HOME/standalone/log/server.log` |
| 访问日志 | `[安装目录]\standalone\log\access.log` | 同左 |
| 推断线索 | `java.exe` + 8080/9990 端口 + 大 `-Xmx` 参数 |
| 分析点 | JMX 控制台访问、deploy 目录非授权写入、`server.log` 中的认证失败 |

### 东方通 TongWeb

| | Windows | Linux |
|--|---------|-------|
| 默认安装 | `D:\tongweb\` | `/opt/tongweb/` |
| 核心日志 | `[安装目录]\logs\tongweb.log` | 同左 |
| 访问日志 | `[安装目录]\logs\access.log` | 同左 |
| 推断线索 | `java.exe` + 端口 + `tongweb` 在进程命令行中 |
| 分析点 | 国产中间件，常见于政府/央企环境 |

---

## 数据库

### MySQL / MariaDB

| | Windows | Linux |
|--|---------|-------|
| 错误日志 | `C:\ProgramData\MySQL\MySQL Server X.X\Data\*.err` 或 `[安装目录]\data\*.log` | `/var/log/mysqld.log` 或 `/var/lib/mysql/*.err` |
| 慢查询 | 同一目录 `*-slow.log` | 同一目录 |
| 二进制日志 | `[安装目录]\data\mysql-bin.******` | 同左 |
| 推断线索 | `mysqld.exe` 或 3306 端口 |
| 分析点 | `mysqld.log` 中关注 `Access denied`（爆破）、`Got error`（漏洞利用后遗症）；slow query 中关注超长 SQL 注入 payload；binlog 可用于入侵后的数据恢复确认 |

### PostgreSQL

| | Windows | Linux |
|--|---------|-------|
| 核心日志 | `C:\Program Files\PostgreSQL\*\data\pg_log\postgresql-*.log` | `/var/log/postgresql/postgresql-*-main.log` |
| WAL 日志 | `[数据目录]\pg_wal\` | 同左 |
| 推断线索 | `postgres.exe` 或 5432 端口 |
| 分析点 | `postgresql-*.log` 中关注 `FATAL`、`could not connect`、认证失败记录 |

### Redis

| | Windows | Linux |
|--|---------|-------|
| 服务日志 | `[安装目录]\logs\redis-server.log` | `/var/log/redis/redis-server.log` |
| 推断线索 | `redis-server.exe` 或 6379 端口 |
| 分析点 | Redis 未授权访问 (6379 无密码), AOF/RDB 持久化文件路径, `redis-cli FLUSHALL` (勒索后清空) |

### MongoDB

| | Windows | Linux |
|--|---------|-------|
| 运行日志 | `C:\ProgramData\MongoDB\log\mongod.log` | `/var/log/mongodb/mongod.log` |
| 推断线索 | `mongod.exe` 或 27017 端口 |
| 分析点 | 未授权访问、审计日志(如果有) |

---

## 国产数据库

| 数据库 | 默认路径 | 核心日志文件 | 端口 | 推断线索 |
|--------|---------|------------|------|---------|
| 达梦 DM8 | `D:\dm8\log\`、Linux: `/dm8/log/` | `dm_service_*.log`, `dm_alert.log` | 5236 | 进程含 `dmserver` 或端口 |
| 人大金仓 KingbaseES | `C:\Kingbase\ES\V8\log\`、Linux: `/opt/kingbase/log/` | `kingbase.log`, `kingbase-err.log` | 54321 | 进程含 `kingbase` |
| 南大通用 GBase | `C:\Program Files\GBase\log\`、Linux: `/opt/gbase/log/` | `gbase.log`, `gbase_error.log` | 待确认 | 进程含 `gbase` |
| PolarDB(阿里云) | `[安装目录]\log\`、Linux: `/opt/polardb/log/` | `polardb.log`, `slow_query.log` | 兼容 MySQL | 进程含 `polar` |

---

## SSH / 远程访问

| | Windows | Linux |
|--|---------|-------|
| SSH 日志 | 内建于 Security.evtx (EID 4624/4625，登录类型 3/10) | `/var/log/auth.log` 或 `/var/log/secure` |
| SSH 爆破 | Security.evtx 中短时间大量 4625 | `auth.log` 中 `Failed password`、`lastb` |
| RDP 日志 | Security.evtx (EID 4624/4625 类型 10) + RDP 专用日志 | N/A (Linux 不用 RDP) |
| 推断线索 | 22 端口 (SSH) / 3389 端口 (RDP) |
| 分析点 | 爆破成功点 (4625 群中穿插 4624)、来源 IP 分布、是否从内网 IP 连接 (横向移动) |

---

## 消息队列 / 网关

| 服务 | Windows 默认日志 | Linux 默认日志 | 端口 | 推断线索 |
|------|----------------|---------------|------|---------|
| RocketMQ | `D:\rocketmq\logs\namesrv.log`, `broker.log` | `/opt/rocketmq/logs/` 同文件名 | 9876/10911 | `java` + 端口 |
| Kafka | `C:\tmp\kafka-logs\server.log` | `/var/log/kafka/server.log` | 9092 | `java` + 端口 |
| RabbitMQ | `C:\Users\<用户>\AppData\Roaming\RabbitMQ\logs\` | `/var/log/rabbitmq/` | 5672/15672 | `rabbit` 进程或端口 |

---

## 纯 EVTX 分析（Windows 事件日志）

当没有采集到 5_filesystem/service_versions.txt（或空白）时，通过已知进程名回查 EVTX 中的关键事件 ID：

| 信号 | 回查 EVTX | 事件 ID |
|------|-----------|---------|
| 发现可疑进程 | Security.evtx + System.evtx → 进程创建时间 | 4688 (ProcessCreate) |
| 发现服务更改 | System.evtx → 服务安装/启动 | 7045 (New Service), 7036 (Service State) |
| 发现计划任务 | Security.evtx → 任务创建 | 4698 (Scheduled Task Created) |
| 发现登录行为 | Security.evtx → 登录/注销 | 4624 (Logon), 4625 (Fail), 4634 (Logoff), 4648 (Explicit) |
| 发现 RDP 连接 | Security.evtx + RDP 专用 EVTX | 4624 (Type 10) + RDP EVTX 21-25 |
| 发现日志清除 | Security.evtx + System.evtx | 1102 (Security Log Cleared), 104 (System Log Cleared) |
| 发现 PowerShell | PowerShell EVTX → script block | 4104 (Scriptblock), 4103 (Module) |

---

## Sysmon 辅助检测表

如果 `service_versions.txt` 显示 `Sysmon: 已安装`，则 Sysmon_Operational.evtx 可用，以下事件 ID 直接增强各维度的检测粒度：

| Sysmon EID | 增强的检测维度 | 分析要点 |
|-----------|--------------|---------|
| 1 | 进程 | ProcessGUID 关联全生命周期、CommandLine 比 tasklist 更完整、Hashes 字段 |
| 2 | 文件 | 进程篡改文件创建时间——隐藏后门的常见手法 |
| 3 | 网络 | 真正的 TCP/UDP 外部连接（含非 ESTABLISHED 的状态）、Initiated 标记区分主动出站和被接入站 |
| 7 | 注入 | 模块加载到进程中的意外 DLL——横向对比 process_modules.csv |
| 8 | 注入、横向 | **关键**：远程线程创建——直接检测注入行为 |
| 10 | 凭据 | LSASS 进程被异常打开——哈希传递 |
| 11 | 文件 | PE 文件落地——临时目录、启动目录 |
| 13 | 持久化 | 注册表 Run 键值写入——完整 Details 字段 |
| 15 | 文件、钓鱼 | Zone.Identifier 流——浏览器下载文件的来源标记 |
| 17/18 | 横向 | 命名管道——PsExec、Cobalt Strike 的管道特征 |
| 19-21 | 持久化 | WMI 事件订阅——完整的 Filter → Consumer → Binding 链 |
| 22 | C2 | DNS 查询——C2 域名、DGA 域名 |
| 25 | 注入 | 进程空心化检测——ProcessTampering |
| 29 | 文件 | PE 创建——替代 EID 11 用于可执行文件落地监控 |
| 23/26 | 文件 | 文件删除——后门自我清理的痕迹 |

---

## 使用原则

1. **先读 `service_versions.txt`**：如果服务已识别，直接推断日志类型和路径
2. **无 `service_versions.txt` 时**：根据端口 → 进程名 → 默认安装路径的线索链回推
3. **日志缺失的标注**：如果对应服务的日志不存在于采集数据中，在报告的 Gaps/Unknowns 节标注「XXX 日志未采集，YYY 路径的追溯受限」
4. **Sysmon 状态决定置信度**：有 Sysmon 则事件日志维度的置信度可提升一级；无 Sysmon 时必须在报告中标注「未部署 Sysmon，进程/网络/注入检测粒度受限」

