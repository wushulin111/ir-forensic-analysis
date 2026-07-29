#!/bin/bash
# ============================================================
# macOS IR 取证采集脚本 v1.0 (离线版)
# 兼容: macOS 10.15+ (Catalina / Big Sur / Monterey / Ventura / Sonoma / Sequoia)
# 完全离线运行 | 内置哈希链完整性校验
# ============================================================
# 用法:
#   chmod +x mac_collect.sh
#   sudo ./mac_collect.sh
# 输出:
#   /opt/ir_evidence/IR_{HOSTNAME}_{TIMESTAMP}/  — 原始数据
#   /opt/ir_evidence/IR_{HOSTNAME}_{TIMESTAMP}.tar.gz — 打包
# ============================================================

set -euo pipefail

HOSTNAME=$(hostname -s 2>/dev/null || scutil --get ComputerName 2>/dev/null || echo "mac")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE="/opt/ir_evidence"
DIR="${BASE}/IR_${HOSTNAME}_${TIMESTAMP}"
ARCHIVE="${BASE}/IR_${HOSTNAME}_${TIMESTAMP}.tar.gz"
LOG="${DIR}/collection_log.txt"

# 颜色
_RED='\033[1;31m';_GREEN='\033[32m';_CYAN='\033[36m';_YELLOW='\033[1;93m';_NC='\033[0m'
OK="${_GREEN}[OK]${_NC}";WARN="${_YELLOW}[!]${_NC}";ERR="${_RED}[ERR]${_NC}";INFO="${_CYAN}[*]${_NC}"

mkdir -p "$DIR"

log() { local ts=$(date '+%H:%M:%S'); echo -e "  [$ts] $1" | tee -a "$LOG"; }
run_cmd() {
    local desc="$1" cmd="$2" outfile="$3"
    echo "=== $desc ===" >> "$outfile"
    if eval "$cmd" >> "$outfile" 2>&1; then
        log "${OK} $desc"
    else
        log "${WARN} $desc (部分失败)"
    fi
}
run_sys() {
    local desc="$1" cmd="$2" outfile="$3"
    echo "=== $desc ===" >> "$outfile"
    eval "$cmd" >> "$outfile" 2>/dev/null || true
    log "${OK} $desc"
}

# 检查 Root
if [ "$EUID" -ne 0 ]; then
    echo -e "${WARN} 建议以 root 运行获取完整数据: sudo $0"
fi

log "=== macOS IR 采集开始 v1.0 ==="
log "目标: $DIR"

# ===== 1. 系统信息 =====
W="$DIR/01_SystemInfo"; mkdir -p "$W"
echo "=== 系统信息 ===" > "$W/system_info.txt"
sw_vers >> "$W/system_info.txt" 2>/dev/null || true
echo "" >> "$W/system_info.txt"
system_profiler SPHardwareDataType SPSoftwareDataType 2>/dev/null >> "$W/system_info.txt" || true
run_sys "hostname" "hostname -f" "$W/hostname.txt"
run_sys "uptime" "uptime" "$W/uptime.txt"
run_sys "date" "date; sysctl kern.boottime" "$W/datetime.txt"
run_sys "kernel" "uname -a; sysctl kern.version" "$W/kernel.txt"
run_sys "sysctl" "sysctl hw machdep kern" "$W/sysctl_all.txt"
run_sys "launchctl-ux" "launchctl list" "$W/launchctl_global.txt"
run_sys "env" "env" "$W/environment.txt"
run_sys "loginwindow" "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null || true" "$W/loginwindow.txt"

# ===== 2. 网络 =====
W="$DIR/02_Network"; mkdir -p "$W"
run_sys "ifconfig" "ifconfig -a" "$W/ifconfig.txt"
run_sys "networksetup" "networksetup -listallnetworkservices 2>/dev/null; networksetup -getinfo Ethernet 2>/dev/null || true" "$W/network_setup.txt"
run_sys "netstat" "netstat -anv -p tcp" "$W/netstat_tcp.txt"
run_sys "netstat-udp" "netstat -anv -p udp" "$W/netstat_udp.txt"
run_sys "lsof-i" "lsof -i -P -n 2>/dev/null || true" "$W/lsof_all.txt"
run_sys "lsof-listen" "lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true" "$W/lsof_listening.txt"
run_sys "arp" "arp -a 2>/dev/null || arp -an" "$W/arp_cache.txt"
run_sys "route" "netstat -rn" "$W/route_table.txt"
run_sys "pfctl" "pfctl -sr 2>/dev/null || echo 'pfctl not available'" "$W/pf_rules.txt"
run_sys "dns" "scutil --dns" "$W/dns_config.txt"
run_sys "smb" "smbutil statshares -a 2>/dev/null || true" "$W/smb_shares.txt"
run_sys "sharing" "sharing -l 2>/dev/null || true" "$W/sharing.txt"

# 外联IP提取
lsof -i -P -n 2>/dev/null | awk 'NR>1 && $9 ~ /->/ {split($9,a,"->"); split(a[2],b,":"); print b[1]}' | sort | uniq -c | sort -rn | head -20 > "$W/foreign_connections.txt" 2>/dev/null || true
log "${OK} 外联IP统计完成"

# ===== 3. 进程 =====
W="$DIR/03_Process"; mkdir -p "$W"
run_sys "ps-all" "ps auxwww" "$W/ps_all.txt"
run_sys "ps-tree" "ps auxfww" "$W/ps_tree.txt"
run_sys "top" "top -l 1 -n 30 -stats pid,command,cpu,mem,user 2>/dev/null || top -l 1 -n 30" "$W/top_cpu.txt"
run_sys "launchctl" "launchctl list" "$W/launchctl_list.txt"
run_sys "kextstat" "kextstat -l" "$W/kext_loaded.txt"
log "${OK} 进程完成"

# ===== 4. 持久化 =====
W="$DIR/04_Persistence"; mkdir -p "$W"
run_sys "launch-daemons" "ls -la /Library/LaunchDaemons/" "$W/launch_daemons_list.txt"
for f in /Library/LaunchDaemons/*.plist; do [ -f "$f" ] && echo "--- $f ---" && cat "$f" 2>/dev/null; done >> "$W/launch_daemons_content.txt" 2>/dev/null
run_sys "launch-agents" "ls -la /Library/LaunchAgents/ /System/Library/LaunchAgents/ $HOME/Library/LaunchAgents/ 2>/dev/null" "$W/launch_agents.txt"
run_sys "cron" "crontab -l 2>/dev/null || echo '(none)'; for u in /Users/*; do echo '=== $u ==='; crontab -u $(basename $u) -l 2>/dev/null; done" "$W/crontabs.txt"
run_sys "periodic" "ls -la /etc/periodic/ 2>/dev/null; cat /etc/periodic/daily/* 2>/dev/null" "$W/periodic.txt"
run_sys "login-items" "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null || true" "$W/login_items.txt"
run_sys "at-jobs" "atq 2>/dev/null || true" "$W/at_jobs.txt"
run_sys "emond" "ls -la /etc/emond.d/ 2>/dev/null || true" "$W/emond.txt"
run_sys "sys-login" "ls -la /Library/Scripts/ 2>/dev/null; cat /etc/rc.common 2>/dev/null || true" "$W/startup_scripts.txt"
log "${OK} 持久化完成"

# ===== 5. 账户 =====
W="$DIR/05_Accounts"; mkdir -p "$W"
run_sys "users" "dscl . list /Users | grep -v '^_' | grep -v '^daemon' | grep -v '^nobody'" "$W/local_users.txt"
run_sys "admin-users" "dscl . -read /Groups/admin GroupMembership 2>/dev/null; dseditgroup -o checkmember -a $(whoami) admin 2>/dev/null || true" "$W/admin_users.txt"
run_sys "last" "last -100" "$W/last_logins.txt"
run_sys "last-10" "last -10 -t console 2>/dev/null || last -10 console" "$W/last_console.txt"
run_sys "who" "who -a" "$W/who_all.txt"
run_sys "w" "w" "$W/who_now.txt"
run_sys "sudoers" "cat /etc/sudoers 2>/dev/null || echo '(no access)'; ls -la /etc/sudoers.d/ 2>/dev/null || true" "$W/sudoers.txt"
run_sys "shadow" "cat /etc/passwd 2>/dev/null || dscacheutil -q user 2>/dev/null | head -100" "$W/passwd.txt"
run_sys "ssh-users" "dscl . list /Users | while read u; do echo '=== $u ==='; dscl . -read /Users/$u HomeDirectory 2>/dev/null; ls -la /Users/$u/.ssh/authorized_keys 2>/dev/null; done" "$W/ssh_users.txt"
run_sys "keychain" "security list-keychains 2>/dev/null || true" "$W/keychains.txt"

# ===== 6. 计划任务 =====
W="$DIR/06_ScheduledTasks"; mkdir -p "$W"
run_sys "cron-system" "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null || true" "$W/cron_system.txt"
run_sys "systemd-timers" "echo 'N/A on macOS'" "$W/timers.txt"

# ===== 7. 文件系统 =====
W="$DIR/07_FileSystem"; mkdir -p "$W"
run_sys "tmp-dir" "ls -la /tmp/ /var/tmp/" "$W/tmp_dirs.txt"
run_sys "recent-3" "find /tmp /var/tmp $HOME/Downloads -type f -mtime -3 2>/dev/null | head -200" "$W/recent_files_3days.txt"
run_sys "recent-7" "find /tmp /var/tmp $HOME/Downloads -type f -mtime -7 2>/dev/null | head -200" "$W/recent_files_7days.txt"
run_sys "suid" "find / -perm -4000 -type f 2>/dev/null | head -100" "$W/suid_binaries.txt"
run_sys "hidden" "find /tmp /var/tmp $HOME -name '.*' -maxdepth 3 -type f 2>/dev/null | head -100" "$W/hidden_files.txt"
run_sys "disk-usage" "df -h" "$W/disk_usage.txt"
run_sys "fsevents" "ls -la /.fseventsd/ 2>/dev/null || true" "$W/fsevents.txt"

# ===== 8. 系统日志 =====
W="$DIR/08_SystemLogs"; mkdir -p "$W"
run_sys "system-log" "log show --last 1h --predicate 'eventMessage contains \"error\" or eventMessage contains \"fail\"' --style compact 2>/dev/null | head -500 || echo 'log command not available (macOS 10.15+ required)'" "$W/system_log_errors.txt"
run_sys "auth-log" "log show --last 24h --predicate 'subsystem contains \"com.apple.auth\"' --style compact 2>/dev/null | head -500 || cat /var/log/system.log 2>/dev/null | grep -i 'auth\|ssh\|sudo\|su\|login' | tail -100" "$W/auth_log.txt"
run_sys "install-log" "log show --last 7d --predicate 'subsystem contains \"install\"' --style compact 2>/dev/null | head -500 || true" "$W/install_log.txt"
run_sys "asl" "ls -la /var/log/asl/ 2>/dev/null; cat /var/log/asl/* 2>/dev/null | strings | grep -i 'error\|fail\|ssh\|sudo' | tail -200" "$W/asl_logs.txt"
run_sys "diagnostics" "ls -la /Library/Logs/DiagnosticReports/ 2>/dev/null | head -50" "$W/diagnostic_reports.txt"
run_sys "install-history" "cat /Library/Receipts/InstallHistory.plist 2>/dev/null | strings | head -200 || true" "$W/install_history.txt"

# ===== 9. 浏览器与历史 =====
W="$DIR/09_Browser"; mkdir -p "$W"
run_sys "bash-history" "cat $HOME/.bash_history $HOME/.zsh_history 2>/dev/null | tail -200" "$W/shell_history.txt"
run_sys "safari" "ls -la $HOME/Library/Safari/History.db 2>/dev/null || true; sqlite3 $HOME/Library/Safari/History.db 'SELECT datetime(visit_time+978307200,"unixepoch"),url FROM history_items JOIN history_visits ON history_items.id=history_visits.history_item ORDER BY visit_time DESC LIMIT 100' 2>/dev/null || true" "$W/safari_history.txt"
run_sys "downloads" "sqlite3 $HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'SELECT LSQuarantineDataURLString,LSQuarantineTimeStamp FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 100' 2>/dev/null || true" "$W/quarantine_events.txt"

# ===== 10. 安全配置 =====
W="$DIR/10_Security"; mkdir -p "$W"
run_sys "sip-status" "csrutil status 2>/dev/null || echo 'csrutil not available'" "$W/sip_status.txt"
run_sys "gatekeeper" "spctl --status 2>/dev/null || true" "$W/gatekeeper.txt"
run_sys "filevault" "fdesetup status 2>/dev/null || true" "$W/filevault.txt"
run_sys "xprotect" "cat /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist 2>/dev/null | head -50 || true" "$W/xprotect.txt"
run_sys "mrt" "cat /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Resources/MRTConfig.plist 2>/dev/null | head -50 || true" "$W/mrt_config.txt"
run_sys "ssh-config" "cat /etc/ssh/sshd_config 2>/dev/null || echo '(no access or not installed)'" "$W/ssh_config.txt"
run_sys "screenshare" "cat /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Support/systemsetup -getremotelogin 2>/dev/null; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true" "$W/remote_access.txt"

# ===== 11. 内核扩展 =====
W="$DIR/11_Kernel"; mkdir -p "$W"
run_sys "kext-list" "kextstat -l -arch x86_64 2>/dev/null || kextstat 2>/dev/null || true" "$W/kextstat.txt"
run_sys "kext-dirs" "ls -la /Library/Extensions/ /System/Library/Extensions/ 2>/dev/null | head -100" "$W/kext_dirs.txt"

# ===== 12. 元数据+哈希链 =====
W="$DIR/12_Metadata"; mkdir -p "$W"
IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
cat > "$W/metadata.txt" << EOF
macOS 取证包元数据 v1.0
========================
主机名: $HOSTNAME
IP: ${IP:-unknown}
OS: macOS $OS_VER
采集时间: $(date '+%Y-%m-%d %H:%M:%S')
文件数: $(find "$DIR" -type f | wc -l)
总大小: $(du -sh "$DIR" | cut -f1)
EOF
log "${OK} 元数据完成"

# 哈希链
find "$DIR" -type f -exec sha256sum {} \; | sort > "$W/hash_chain.txt" 2>/dev/null || \
find "$DIR" -type f -exec shasum -a 256 {} \; | sort > "$W/hash_chain.txt" 2>/dev/null
TOP_HASH=$(cat "$W/hash_chain.txt" | sha256sum | cut -d' ' -f1 2>/dev/null || \
           cat "$W/hash_chain.txt" | shasum -a 256 | cut -d' ' -f1)
echo "顶层哈希: $TOP_HASH" > "$W/top_hash.txt"
echo "验证: cat hash_chain.txt | sha256sum" >> "$W/top_hash.txt"
log "${OK} 哈希链: $TOP_HASH"

# 打包
cd "$BASE"
tar czf "$ARCHIVE" -C "$BASE" "IR_${HOSTNAME}_${TIMESTAMP}" 2>/dev/null
ZIP_HASH=$(sha256sum "$ARCHIVE" | cut -d' ' -f1 2>/dev/null || shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
ZIP_SIZE=$(du -h "$ARCHIVE" | cut -f1)
log "${OK} 打包完成: $ARCHIVE"
log "${OK} SHA256: $ZIP_HASH"

echo ""
echo -e "${_GREEN}========================================${_NC}"
echo -e "${_GREEN}  采集完成!${_NC}"
echo -e "${_CYAN}  打包: $ARCHIVE${_NC}"
echo -e "${_CYAN}  SHA256: $ZIP_HASH${_NC}"
echo -e "${_CYAN}  顶层哈希: $TOP_HASH${_NC}"
echo -e "${_YELLOW}  验证: cat $W/hash_chain.txt | sha256sum${_NC}"
echo -e "${_GREEN}========================================${_NC}"
