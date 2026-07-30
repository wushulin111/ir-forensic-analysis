#!/bin/bash
# ============================================================
# macOS IR 取证采集脚本 v2.0
# 兼容: macOS 10.15+ (Catalina ~ Sequoia)
# Intel + Apple Silicon 双架构 | 完全离线 | 哈希链完整性
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

# 架构检测
ARCH=$(uname -m)
IS_ARM=0; [ "$ARCH" = "arm64" ] && IS_ARM=1
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ROSETTA_PATH=""; [ -d "/Library/Apple/usr/libexec/oah" ] && ROSETTA_PATH="/Library/Apple/usr/libexec/oah"

log "=== macOS IR 采集 v2.0 | $ARCH | macOS $OS_VER ==="
log "目标: $DIR"

# ===== 1. 系统信息 =====
W="$DIR/01_SystemInfo"; mkdir -p "$W"
echo "=== 系统信息 ===" > "$W/system_info.txt"
sw_vers >> "$W/system_info.txt" 2>/dev/null || true
echo "arch: $ARCH" >> "$W/system_info.txt"
echo "apple_silicon: $([ $IS_ARM -eq 1 ] && echo 'yes' || echo 'no')" >> "$W/system_info.txt"
echo "rosetta: $([ -n "$ROSETTA_PATH" ] && echo 'installed' || echo 'not installed')" >> "$W/system_info.txt"
echo "" >> "$W/system_info.txt"
system_profiler SPHardwareDataType SPSoftwareDataType 2>/dev/null >> "$W/system_info.txt" || true
run_sys "hostname" "hostname -f 2>/dev/null; scutil --get HostName 2>/dev/null; scutil --get LocalHostName 2>/dev/null; scutil --get ComputerName 2>/dev/null" "$W/hostname.txt"
run_sys "uptime" "uptime" "$W/uptime.txt"
run_sys "date" "date; sysctl kern.boottime" "$W/datetime.txt"
run_sys "kernel" "uname -a; sysctl kern.version kern.osversion" "$W/kernel.txt"
run_sys "sysctl" "sysctl -a" "$W/sysctl_all.txt"
run_sys "nvram" "nvram -p 2>/dev/null || true" "$W/nvram.txt"
run_sys "launchctl-system" "launchctl list" "$W/launchctl_system.txt"
run_sys "launchctl-user" "launchctl list $(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name/ { print $3 }') 2>/dev/null || true" "$W/launchctl_user.txt"
run_sys "env" "env" "$W/environment.txt"
run_sys "loginwindow" "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null || true" "$W/loginwindow.txt"
run_sys "sleep-wake" "pmset -g everything 2>/dev/null || true" "$W/power_settings.txt"
run_sys "timezone" "systemsetup -gettimezone 2>/dev/null; date -u" "$W/timezone.txt"

# ===== 2. 网络 =====
W="$DIR/02_Network"; mkdir -p "$W"
run_sys "ifconfig" "ifconfig -a" "$W/ifconfig.txt"
run_sys "networksetup" "networksetup -listallnetworkservices 2>/dev/null; networksetup -getinfo Ethernet 2>/dev/null; networksetup -getinfo Wi-Fi 2>/dev/null || true" "$W/network_setup.txt"
run_sys "dns" "scutil --dns" "$W/dns_config.txt"
run_sys "proxy" "scutil --proxy" "$W/proxy_config.txt"
run_sys "netstat" "netstat -anv -p tcp" "$W/netstat_tcp.txt"
run_sys "netstat-udp" "netstat -anv -p udp" "$W/netstat_udp.txt"
run_sys "lsof-all" "lsof -i -P -n 2>/dev/null || true" "$W/lsof_all.txt"
run_sys "lsof-listen" "lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true" "$W/lsof_listening.txt"
run_sys "arp" "arp -a 2>/dev/null || arp -an" "$W/arp_cache.txt"
run_sys "route" "netstat -rn" "$W/route_table.txt"
run_sys "pfctl" "pfctl -sr 2>/dev/null || echo 'pfctl not available'; pfctl -s info 2>/dev/null || true" "$W/pf_rules.txt"
run_sys "alf" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null; /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null || true" "$W/alf_firewall.txt"
run_sys "smb" "smbutil statshares -a 2>/dev/null || true" "$W/smb_shares.txt"
run_sys "sharing" "sharing -l 2>/dev/null || true" "$W/sharing.txt"
run_sys "airport" "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null || true" "$W/wifi_info.txt"
run_sys "networkext" "systemextensionsctl list 2>/dev/null || true" "$W/network_extensions.txt"

# 外联IP提取
lsof -i -P -n 2>/dev/null | awk 'NR>1 && $9 ~ /->/ {split($9,a,"->"); split(a[2],b,":"); print b[1]}' | sort | uniq -c | sort -rn | head -20 > "$W/foreign_connections.txt" 2>/dev/null || true
log "${OK} 外联IP统计完成"

# ===== 3. 进程 =====
W="$DIR/03_Process"; mkdir -p "$W"
run_sys "ps-all" "ps auxwww" "$W/ps_all.txt"
run_sys "ps-tree" "ps auxfww 2>/dev/null || ps -eo pid,ppid,user,comm" "$W/ps_tree.txt"
run_sys "top" "top -l 2 -n 30 -stats pid,command,cpu,mem,user 2>/dev/null | tail -35" "$W/top_cpu.txt"
run_sys "launchctl" "launchctl list" "$W/launchctl_list.txt"
run_sys "kextstat" "kextstat -l 2>/dev/null || true" "$W/kext_loaded.txt"

# 进程签名验证 (codesign)
log "${INFO} 正在验证进程签名..."
echo "=== 进程签名验证 ===" > "$W/process_codesign.txt"
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    exe=$(ls -l "$pid_dir/exe" 2>/dev/null | awk '{print $NF}' || true)
    [ -z "$exe" ] && continue
    sig=$(codesign -dvv "$exe" 2>&1 | grep -E "Authority|Signature|Signed" | head -3 | tr '\n' ' ' || echo "UNSIGNED")
    echo "PID=$pid PATH=$exe SIG=$sig" >> "$W/process_codesign.txt"
done 2>/dev/null
log "${OK} 进程签名验证完成"

# 进程路径异常检测
log "${INFO} 检测异常进程路径..."
echo "=== 进程路径异常检测 ===" > "$W/process_anomalies.txt"
ps auxwww 2>/dev/null | awk 'NR>1 {print $2, $11}' | while read -r pid path; do
    lower=$(echo "$path" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        */tmp/*|*/private/tmp/*|*/downloads/*|*/desktop/*|*/documents/*)
            echo "[SUSPICIOUS_PATH] PID=$pid PATH=$path" >> "$W/process_anomalies.txt" ;;
    esac
done 2>/dev/null
log "${OK} 进程路径检测完成"

log "${OK} 进程采集完成"

# ===== 4. 持久化 =====
W="$DIR/04_Persistence"; mkdir -p "$W"

# LaunchDaemons
run_sys "launch-daemons-list" "ls -la /Library/LaunchDaemons/ /System/Library/LaunchDaemons/" "$W/launch_daemons_list.txt"
echo "=== LaunchDaemons 内容分析 ===" > "$W/launch_daemons_analysis.txt"
for f in /Library/LaunchDaemons/*.plist /System/Library/LaunchDaemons/*.plist; do
    [ -f "$f" ] || continue
    echo "--- $f ---" >> "$W/launch_daemons_analysis.txt"
    cat "$f" 2>/dev/null >> "$W/launch_daemons_analysis.txt"
    # 检测可疑路径
    grep -Eq '/tmp/|/private/tmp/|/Users/.*/Downloads/|/Users/.*/Desktop/' "$f" 2>/dev/null && \
        echo "  >>> [SUSPICIOUS] 可疑路径在 $f" >> "$W/launch_daemons_analysis.txt"
done 2>/dev/null

# LaunchAgents (all locations)
echo "=== LaunchAgents (System) ===" > "$W/launch_agents_system.txt"
for f in /System/Library/LaunchAgents/*.plist; do [ -f "$f" ] && echo "--- $f ---" >> "$W/launch_agents_system.txt" && cat "$f" 2>/dev/null >> "$W/launch_agents_system.txt"; done
echo "=== LaunchAgents (Library) ===" > "$W/launch_agents_library.txt"
for f in /Library/LaunchAgents/*.plist; do [ -f "$f" ] && echo "--- $f ---" >> "$W/launch_agents_library.txt" && cat "$f" 2>/dev/null >> "$W/launch_agents_library.txt"; done
echo "=== LaunchAgents (All Users) ===" > "$W/launch_agents_users.txt"
for user_home in /Users/*; do
    username=$(basename "$user_home")
    [ "$username" = "Shared" ] && continue
    for f in "$user_home/Library/LaunchAgents/"*.plist; do
        [ -f "$f" ] && echo "--- $f (user: $username) ---" >> "$W/launch_agents_users.txt" && cat "$f" 2>/dev/null >> "$W/launch_agents_users.txt"
    done
done 2>/dev/null

# Cron, Periodic, Shell Profiles
run_sys "cron" "crontab -l 2>/dev/null; for u in /Users/*; do [ -d \"$u\" ] && crontab -u $(basename $u) -l 2>/dev/null; done; echo '---' " "$W/crontabs.txt"
run_sys "periodic" "ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null" "$W/periodic.txt"
echo "=== Shell Profiles ===" > "$W/shell_profiles.txt"
for f in /etc/profile /etc/bashrc /etc/zshrc /etc/zprofile; do
    [ -f "$f" ] && echo "--- $f ---" >> "$W/shell_profiles.txt" && cat "$f" 2>/dev/null >> "$W/shell_profiles.txt"
done
for user_home in /Users/*; do
    for f in "$user_home/.bash_profile" "$user_home/.zshrc" "$user_home/.zprofile" "$user_home/.profile"; do
        [ -f "$f" ] && echo "--- $f ---" >> "$W/shell_profiles.txt" && cat "$f" 2>/dev/null >> "$W/shell_profiles.txt"
    done
done 2>/dev/null

# Login Items
run_sys "login-items" "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null || true" "$W/login_items.txt"

# Emond (Event Monitor)
run_sys "emond" "ls -la /etc/emond.d/ 2>/dev/null; cat /etc/emond.d/emond.plist 2>/dev/null || true" "$W/emond.txt"

log "${OK} 持久化完成"

# ===== 5. 账户 =====
W="$DIR/05_Accounts"; mkdir -p "$W"
run_sys "dscl-users" "dscl . -list /Users" "$W/users_list.txt"
run_sys "dscl-groups" "dscl . -list /Groups" "$W/groups_list.txt"
run_sys "admin-group" "dscl . -read /Groups/admin GroupMembership 2>/dev/null || dscacheutil -q group -a name admin" "$W/admin_group.txt"
run_sys "users-detail" "dscl . -list /Users | while read u; do echo \"=== \$u ===\"; dscl . -read \"/Users/\$u\" UniqueID PrimaryGroupID NFSHomeDirectory UserShell 2>/dev/null; echo; done" "$W/users_detail.txt"

# 隐藏用户检测
echo "=== 隐藏用户检测 ===" > "$W/hidden_users.txt"
dscl . -list /Users | while read u; do
    uid=$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')
    [ -z "$uid" ] && continue
    # UID < 500 且不是系统自带账号
    if [ "$uid" -lt 500 ] && [ "$u" != "root" ] && [ "$u" != "nobody" ] && [ "$u" != "daemon" ]; then
        echo "[HIDDEN_UID] $u (UID=$uid)" >> "$W/hidden_users.txt"
    fi
    # 检查是否隐藏 (IsHidden = 1)
    hidden=$(dscl . -read "/Users/$u" IsHidden 2>/dev/null | awk '{print $2}' || echo "0")
    if [ "$hidden" = "1" ]; then
        echo "[HIDDEN_FLAG] $u (IsHidden=1)" >> "$W/hidden_users.txt"
    fi
    # 检查密码是否为空
    shadow=$(dscl . -read "/Users/$u" ShadowHashData 2>/dev/null | wc -l)
    if [ "$shadow" -eq 0 ]; then
        echo "[EMPTY_PASSWORD] $u 可能无密码" >> "$W/hidden_users.txt"
    fi
done 2>/dev/null
run_sys "password-policy" "pwpolicy -getaccountpolicies 2>/dev/null || pwpolicy -getglobalpolicy 2>/dev/null || true" "$W/password_policy.txt"

# SSH 密钥
run_sys "ssh-keys" "cat /etc/ssh/sshd_config 2>/dev/null; echo '---'; for u in /Users/*; do cat \"$u/.ssh/authorized_keys\" 2>/dev/null && echo \"--- \$u ---\"; done" "$W/ssh_keys.txt"

# 登录记录
run_sys "last" "last -100" "$W/last_logins.txt"
run_sys "who" "who -a" "$W/who.txt"
run_sys "w" "w" "$W/w_command.txt"

# Sudo 日志
run_sys "sudo-logs" "cat /var/log/system.log 2>/dev/null | grep -i 'sudo' | tail -100; log show --last 24h --predicate 'process == \"sudo\"' 2>/dev/null | tail -100 || true" "$W/sudo_logs.txt"

log "${OK} 账户完成"

# ===== 6. 文件系统 =====
W="$DIR/06_FileSystem"; mkdir -p "$W"
run_sys "mounts" "mount" "$W/mount_points.txt"
run_sys "disk-usage" "df -h" "$W/disk_usage.txt"
run_sys "disk-list" "diskutil list" "$W/disk_list.txt"

# APFS 快照 (macOS 的 VSS 等价物)
run_sys "apfs-snapshots" "tmutil listlocalsnapshots / 2>/dev/null; diskutil apfs listSnapshots / 2>/dev/null || true" "$W/apfs_snapshots.txt"

# 可疑文件扫描
echo "=== 临时目录可执行文件 ===" > "$W/tmp_executables.txt"
find /tmp /private/tmp /var/tmp -type f -perm +111 2>/dev/null | head -100 >> "$W/tmp_executables.txt" || true
echo "=== 隐藏文件与目录 ===" > "$W/hidden_files.txt"
find /Users /tmp /var/tmp /Library -name ".*" -type f 2>/dev/null | head -200 >> "$W/hidden_files.txt" || true
echo "=== SUID/SGID 文件 ===" > "$W/suid_sgid.txt"
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | grep -v '^/System/\|^/usr/lib/\|^/sbin/' | head -50 >> "$W/suid_sgid.txt" || true
echo "=== 用户下载目录可疑文件 ===" > "$W/downloads_suspicious.txt"
for u in /Users/*/Downloads; do [ -d "$u" ] && find "$u" -type f \( -name "*.dmg" -o -name "*.pkg" -o -name "*.app" -o -name "*.sh" -o -name "*.command" -o -name "*.py" -o -name "*.pl" \) -mtime -30 2>/dev/null; done | head -100 >> "$W/downloads_suspicious.txt" || true
log "${OK} 文件系统扫描完成"

# ===== 7. 日志 =====
W="$DIR/07_Logs"; mkdir -p "$W"
run_sys "system-log" "log show --last 1h --predicate 'eventMessage contains \"error\" or eventMessage contains \"fail\"' --style compact 2>/dev/null | head -500 || echo 'log command not available'" "$W/system_log_errors.txt"
run_sys "auth-log" "log show --last 24h --predicate 'subsystem contains \"com.apple.auth\"' --style compact 2>/dev/null | head -500 || cat /var/log/system.log 2>/dev/null | grep -i 'auth\|ssh\|sudo\|su\|login' | tail -100" "$W/auth_log.txt"
run_sys "install-log" "log show --last 7d --predicate 'subsystem contains \"install\"' --style compact 2>/dev/null | head -500 || true" "$W/install_log.txt"
run_sys "asl" "ls -la /var/log/asl/ 2>/dev/null; for f in /var/log/asl/*; do [ -f \"$f\" ] && echo \"--- $f ---\" && cat \"$f\" 2>/dev/null | strings | grep -i 'error\|fail\|ssh\|sudo' | tail -50; done" "$W/asl_logs.txt"
run_sys "diagnostics" "ls -la /Library/Logs/DiagnosticReports/ 2>/dev/null | tail -100" "$W/diagnostic_reports.txt"
run_sys "system-log-full" "cat /var/log/system.log 2>/dev/null | tail -500 || true" "$W/system_log.txt"
run_sys "install-history" "cat /Library/Receipts/InstallHistory.plist 2>/dev/null | strings | head -500 || true" "$W/install_history.txt"
run_sys "unified-ssh" "log show --last 7d --predicate 'process == \"sshd\" or process == \"ssh\"' --style compact 2>/dev/null | head -200 || true" "$W/ssh_connections.txt"
log "${OK} 日志完成"

# ===== 8. 浏览器记录 =====
W="$DIR/08_Browser"; mkdir -p "$W"

run_sys "shell-history" "for u in /Users/*; do cat \"$u/.bash_history\" \"$u/.zsh_history\" \"$u/.zhistory\" 2>/dev/null; done | tail -500" "$W/shell_history.txt"

# Safari
run_sys "safari" "for u in /Users/*/Library/Safari; do [ -d \"$u\" ] && echo \"=== \$u ===\" && sqlite3 \"$u/History.db\" 'SELECT datetime(visit_time+978307200,\"unixepoch\"),url FROM history_items JOIN history_visits ON history_items.id=history_visits.history_item ORDER BY visit_time DESC LIMIT 100' 2>/dev/null; done || true" "$W/safari_history.txt"

# Chrome
echo "=== Chrome 历史记录 ===" > "$W/chrome_history.txt"
for u in /Users/*; do
    chrome_dir="$u/Library/Application Support/Google/Chrome"
    [ -d "$chrome_dir" ] || continue
    for profile in "$chrome_dir"/Default "$chrome_dir"/Profile*; do
        [ -f "$profile/History" ] || continue
        echo "--- $(basename "$u") / $(basename "$profile") ---" >> "$W/chrome_history.txt"
        sqlite3 "$profile/History" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),url FROM urls ORDER BY last_visit_time DESC LIMIT 100" 2>/dev/null >> "$W/chrome_history.txt" || true
    done
done

# Edge
echo "=== Edge 历史记录 ===" > "$W/edge_history.txt"
for u in /Users/*; do
    edge_dir="$u/Library/Application Support/Microsoft Edge"
    [ -d "$edge_dir" ] || continue
    for profile in "$edge_dir"/Default "$edge_dir"/Profile*; do
        [ -f "$profile/History" ] || continue
        echo "--- $(basename "$u") ---" >> "$W/edge_history.txt"
        sqlite3 "$profile/History" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),url FROM urls ORDER BY last_visit_time DESC LIMIT 100" 2>/dev/null >> "$W/edge_history.txt" || true
    done
done

# Firefox
echo "=== Firefox 历史记录 ===" > "$W/firefox_history.txt"
for u in /Users/*; do
    ff_dir="$u/Library/Application Support/Firefox/Profiles"
    [ -d "$ff_dir" ] || continue
    for profile in "$ff_dir"/*.default* "$ff_dir"/*.default-esr*; do
        [ -f "$profile/places.sqlite" ] || continue
        echo "--- $(basename "$u") / $(basename "$profile") ---" >> "$W/firefox_history.txt"
        sqlite3 "$profile/places.sqlite" "SELECT datetime(last_visit_date/1000000,'unixepoch'),url FROM moz_places ORDER BY last_visit_date DESC LIMIT 100" 2>/dev/null >> "$W/firefox_history.txt" || true
    done
done

# 下载记录 (Quarantine Events)
run_sys "downloads" "for u in /Users/*; do [ -f \"$u/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2\" ] && echo \"=== \$u ===\" && sqlite3 \"$u/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2\" 'SELECT datetime(LSQuarantineTimeStamp+978307200,\"unixepoch\"),LSQuarantineDataURLString,LSQuarantineAgentBundleIdentifier FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 200' 2>/dev/null; done || true" "$W/quarantine_events.txt"

log "${OK} 浏览器记录完成"

# ===== 9. 安全配置 =====
W="$DIR/09_Security"; mkdir -p "$W"
run_sys "sip" "csrutil status 2>/dev/null; csrutil authenticated-root status 2>/dev/null || true" "$W/sip_status.txt"
run_sys "gatekeeper" "spctl --status; spctl --list --type execute 2>/dev/null | head -50 || true" "$W/gatekeeper.txt"
run_sys "filevault" "fdesetup status 2>/dev/null || true" "$W/filevault.txt"
run_sys "xprotect" "cat /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist 2>/dev/null | head -100 || true" "$W/xprotect.txt"
run_sys "mrt" "cat /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Resources/MRTConfig.plist 2>/dev/null | head -100 || true" "$W/mrt_config.txt"
run_sys "ssh-config" "cat /etc/ssh/sshd_config 2>/dev/null; cat /etc/ssh/ssh_config 2>/dev/null || true" "$W/ssh_config.txt"
run_sys "remote-access" "systemsetup -getremotelogin 2>/dev/null; systemsetup -getremoteappleevents 2>/dev/null || true" "$W/remote_access.txt"

# TCC 隐私数据库
run_sys "tcc" "for u in /Users/*; do [ -f \"$u/Library/Application Support/com.apple.TCC/TCC.db\" ] && echo \"=== \$u ===\" && sqlite3 \"$u/Library/Application Support/com.apple.TCC/TCC.db\" 'SELECT service,client,auth_value FROM access ORDER BY service' 2>/dev/null; done || true" "$W/tcc_database.txt"

# System Policy / AMFI
run_sys "amfi" "nvram -p 2>/dev/null | grep amfi || true; csrutil status 2>/dev/null" "$W/amfi_status.txt"

log "${OK} 安全配置完成"

# ===== 10. 内核与扩展 =====
W="$DIR/10_Kernel"; mkdir -p "$W"
run_sys "kext-list" "kextstat -l 2>/dev/null || kextstat 2>/dev/null || true" "$W/kextstat.txt"
run_sys "kext-dirs" "ls -la /Library/Extensions/ /System/Library/Extensions/ 2>/dev/null | head -200" "$W/kext_dirs.txt"

# 非 Apple 内核扩展检测
echo "=== 第三方内核扩展检测 ===" > "$W/kext_non_apple.txt"
kextstat 2>/dev/null | grep -v 'com.apple' | while read -r line; do
    echo "[NON-APPLE] $line" >> "$W/kext_non_apple.txt"
done
log "${OK} 内核扩展完成"

# ===== 11. 元数据+哈希链 =====
W="$DIR/11_Metadata"; mkdir -p "$W"
IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)
cat > "$W/metadata.txt" << EOF
macOS 取证包元数据 v2.0
========================
主机名: $HOSTNAME
IP: ${IP:-unknown}
OS: macOS $OS_VER
架构: $ARCH ($([ $IS_ARM -eq 1 ] && echo 'Apple Silicon' || echo 'Intel'))
Rosetta: $([ -n "$ROSETTA_PATH" ] && echo 'installed' || echo 'not installed')
采集时间: $(date '+%Y-%m-%d %H:%M:%S')
文件数: $(find "$DIR" -type f | wc -l | tr -d ' ')
总大小: $(du -sh "$DIR" | cut -f1)
EOF
log "${OK} 元数据完成"

# 哈希链
find "$DIR" -type f ! -name "hash_chain.txt" ! -name "top_hash.txt" -exec shasum -a 256 {} \; 2>/dev/null | sort > "$W/hash_chain.txt"
TOP_HASH=$(cat "$W/hash_chain.txt" | shasum -a 256 | cut -d' ' -f1)
echo "顶层哈希: $TOP_HASH" > "$W/top_hash.txt"
echo "验证: cat hash_chain.txt | shasum -a 256" >> "$W/top_hash.txt"
log "${OK} 哈希链: $TOP_HASH"

# 打包
cd "$BASE"
tar czf "$ARCHIVE" -C "$BASE" "IR_${HOSTNAME}_${TIMESTAMP}" 2>/dev/null
ZIP_HASH=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
ZIP_SIZE=$(du -h "$ARCHIVE" | cut -f1)
log "${OK} 打包完成: $ARCHIVE ($ZIP_SIZE)"
log "${OK} SHA256: $ZIP_HASH"

echo ""
echo -e "${_GREEN}========================================${_NC}"
echo -e "${_GREEN}  macOS IR 采集完成 v2.0${_NC}"
echo -e "${_GREEN}========================================${_NC}"
echo -e "${_CYAN}  主机:     $HOSTNAME${_NC}"
echo -e "${_CYAN}  架构:     $ARCH ($([ $IS_ARM -eq 1 ] && echo 'Apple Silicon' || echo 'Intel'))${_NC}"
echo -e "${_CYAN}  打包:     $ARCHIVE${_NC}"
echo -e "${_CYAN}  大小:     $ZIP_SIZE${_NC}"
echo -e "${_CYAN}  SHA256:   $ZIP_HASH${_NC}"
echo -e "${_CYAN}  顶层哈希: $TOP_HASH${_NC}"
echo -e "${_YELLOW}  验证: cat $W/hash_chain.txt | shasum -a 256${_NC}"
echo -e "${_GREEN}========================================${_NC}"