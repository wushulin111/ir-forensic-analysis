# 取证包目录结构映射 v2.5

> 详细描述 Windows 和 Linux 取证包的目录结构及 LLM 分析时的文件定位映射。
> 主 SKILL.md 保留快速评估路径表，完整目录结构见本文档。

---

## 取证包来源识别

解压后查看顶层目录名：

- `IR_HOSTNAME_TIMESTAMP/` 内含 `1_volatile/`, `2_accounts/` 等7个子目录 → **Windows v2.1+ 格式**
- `IR_HOSTNAME_TIMESTAMP/` 内含 `systeminfo.txt`, `tasklist.csv` 等平铺文件 → **Windows v1 格式**（旧版）
- `IR_HOSTNAME_YYYYMMDD_HHMMSS/` 内含 `system_info.txt`, `netstat_ano.txt` → **Linux who.sh v8.0+ 格式**

---

## Windows 取证包 (win_collect.ps1 v2.1+ / v3.0+)

```
IR_HOSTNAME_TIMESTAMP/
├── 1_volatile/                     # [易失性数据]
│   ├── netstat_ano.txt             → 网络连接（端口/状态/PID）
│   ├── netstat_anob.txt            → 网络连接+进程名关联
│   ├── route.txt / arp.txt         → 路由/ARP缓存
│   ├── ipconfig.txt                → 网卡/IP配置
│   ├── dns_cache.txt               → DNS缓存
│   ├── firewall_profiles.txt       → 防火墙配置
│   ├── firewall_rules_in.txt       → 入站规则
│   ├── hosts.txt                   → hosts文件
│   ├── tasklist.csv                → 进程列表（CSV）
│   ├── tasklist_svc.txt            → 进程+服务关联
│   ├── process_detail.txt          → 进程详情（路径/命令行/父PID）
│   ├── process_full.txt            → 进程全量信息
│   ├── process_tree.csv            → 进程树（父子关系）
│   ├── process_modules.csv         → 进程加载DLL（ntdll重映射检测）
│   ├── sessions.txt                → 终端会话
│   ├── net_sessions.txt            → 网络会话
│   └── net_use.txt / net_share.txt → 网络映射/共享
│
├── 2_accounts/                     # [账号信息]
│   ├── users.txt / admin_group.txt / all_groups.txt
│   ├── local_users.csv / group_members.csv
│   ├── sam_users.csv               → SAM注册表RID/F值（克隆账号检测, v3.0+）
│   └── hidden_accounts.txt         → 隐藏/$后缀账号（v3.0+）
│
├── 3_persistence/                  # [持久化机制] 重点排查
│   ├── run_hklm.txt / run_hkcu.txt / runonce_*.txt / run_wow64.txt
│   ├── winlogon.txt                → Winlogon/Userinit劫持
│   ├── ifeo.txt                    → 映像劫持
│   ├── winnt_windows.txt           → AppInit_DLLs
│   ├── lsa.txt / screensaver.txt / session_manager.txt / bho.txt
│   ├── amsi_providers.txt          → AMSI提供者
│   ├── logon_scripts.txt           → UserInitMprLogonScript后门 (v3.0+)
│   ├── group_policy_scripts.txt    → 组策略脚本 (v3.0+)
│   ├── safeboot_alternate.txt      → 安全模式劫持 (v3.0+)
│   ├── exclude_known_dlls.txt      → DLL排除项 (v3.0+)
│   ├── com_hijack.csv              → COM劫持 (v3.0+)
│   ├── appcompat_shim.txt          → AppCompatCache/Shim (v3.0+)
│   ├── known_dlls.txt              → KnownDLLs (v3.0+)
│   ├── service_dlls.csv            → 服务DLL路径 (v3.0+)
│   ├── services.txt / services_detail.csv
│   ├── unquoted_service_paths.csv  → 服务路径提权
│   ├── schtasks.csv / schtasks.xml / task_files.csv
│   ├── wmi_event_filters.txt / wmi_event_consumers.txt / wmi_bindings.txt
│   ├── startup_folder.csv / startup_*.txt
│   └── ps_profiles.txt             → PowerShell Profile
│
├── 4_system/                       # [系统信息]
│   ├── systeminfo.txt / whoami.txt / environment.txt / gpresult.txt
│   ├── hotfixes.txt / autorun_wmic.txt
│   ├── installed_software.csv / installed_software_wow64.csv
│   ├── prefetch.csv / srudb.dat / usn_journal.csv
│
├── 5_filesystem/                   # [文件系统]
│   ├── temp_executables.csv / recent_files.csv / downloads_suspicious.csv
│   ├── hidden_executables.csv / recent_modified_system.csv / ads_users.txt
│   ├── recycle_bin.csv (v3.0+) / browser_downloads.csv (v3.0+) / suspicious_downloads.csv (v3.0+)
│
├── 6_logs/                         # [日志]
│   ├── Security.evtx / System.evtx / Application.evtx
│   ├── ..._PowerShell_Operational.evtx / ..._Sysmon_Operational.evtx
│   ├── ..._LocalSessionManager.evtx / ..._RdpCoreTS.evtx
│   ├── powershell_scriptblock.txt / security_key_events.csv / rdp_sessions.txt
│
├── 7_web/                          # [Web/IIS]
│   ├── applicationHost.config / iis_log_files.csv
│   ├── url_acl.txt / http_service_state.txt (v3.0+)
│   ├── *.log / web_scripts.csv
│
├── IR_metadata.txt / file_hashes.csv / vss_shadows.txt / collection.log
```

---

## Linux 取证包 (who.sh v8.0+)

```
IR_HOSTNAME_TIMESTAMP/
├── 1_volatile/                     # [易失性数据]
│   ├── netstat_ano.txt / ss_tlnp.txt
│   ├── arp.txt / route.txt
│   ├── process_full.txt / process_tree.txt
│   ├── lsof.txt / top.txt
│   ├── w.txt / last.txt / lastb.txt
│
├── 2_accounts/                     # [账号信息]
│   ├── passwd.txt / shadow.txt / sudoers.txt / groups.txt
│   ├── empty_password.txt / uid0.txt
│
├── 3_persistence/                  # [持久化机制]
│   ├── crontab_all.txt / cron_dirs.txt / anacrontab.txt
│   ├── rc_local.txt / rc_d.txt
│   ├── systemd_units.txt / systemd_timer.txt / init_d.txt / xinetd.txt
│   ├── ld_so_preload.txt
│   ├── suid_sgid.txt / capabilities.txt (v8.0+)
│   ├── ssh_authorized_keys.txt / sshd_config.txt (v8.0+)
│   ├── bashrc_profile.txt          → ~/.bashrc/~/.profile/~/.zshrc劫持 (v8.1+)
│   ├── user_systemd.txt            → ~/.config/systemd/user/ (v8.1+)
│   ├── modules_load.txt            → /etc/modules-load.d/内核模块 (v8.1+)
│   ├── xdg_autostart.txt           → ~/.config/autostart/ (v8.1+)
│   └── pkg_hooks.txt               → apt/yum hook劫持 (v8.1+)
│
├── 4_backdoor/                     # [后门检测 v8.0+]
│   ├── ssh_softlink.txt / openssh_integrity.txt / pam_integrity.txt
│   ├── command_integrity.txt / gates_malware.txt / unhide.txt
│
├── 5_system/                       # [系统信息]
│   ├── system_info.txt / kernel_modules.txt / environment.txt
│   ├── service_list.txt / selinux.txt / iptables.txt / hosts.txt
│
├── 6_logs/                         # [日志]
│   ├── auth.log / secure / syslog.txt
│   ├── web_access_summary.txt / db_logs_check.txt (v8.0+)
│   ├── bash_history/
│
├── 7_filesystem/                   # [文件系统]
│   ├── tmp_executables.txt / dev_shm.txt
│   ├── recent_modified.txt / hidden_files.txt / world_writable.txt
│
├── IR_metadata.txt / file_hashes.sha256 / collection.log
```
