#!/bin/bash
# ============================================================
# macOS IR 取证采集脚本 v2.1
# 兼容: macOS 10.15+ (Catalina ~ Sequoia)
# Intel + Apple Silicon 双架构 | 完全离线 | 包 SHA256 完整性
# 变更: 修复进程签名(/proc 死代码)、隐藏用户误报、SUID 命令、
#       Safari schema 兼容、IPv6 外联、错误可见性; 新增
#       sudoers/at/keychain/模块清单/包哈希旁车
# ============================================================
# 用法:
#   chmod +x mac_collect.sh
#   sudo ./mac_collect.sh
# 输出:
#   /opt/ir_evidence/IR_{HOSTNAME}_{TIMESTAMP}/  — 原始数据
#   /opt/ir_evidence/IR_{HOSTNAME}_{TIMESTAMP}.tar.gz — 打包
#   /opt/ir_evidence/IR_{HOSTNAME}_{TIMESTAMP}.tar.gz.sha256 — 包哈希
# ============================================================

set -euo pipefail

HOSTNAME=$(hostname -s 2>/dev/null || scutil --get ComputerName 2>/dev/null || echo "mac")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE="/opt/ir_evidence"
mkdir -p "$BASE"
DIR="${BASE}/IR_${HOSTNAME}_${TIMESTAMP}"
ARCHIVE="${BASE}/IR_${HOSTNAME}_${TIMESTAMP}.tar.gz"
LOG="${DIR}/collection_log.txt"

# 颜色
_RED='\033[1;31m';_GREEN='\033[32m';_CYAN='\033[36m';_YELLOW='\033[1;93m';_NC='\033[0m'
OK="${_GREEN}[OK]${_NC}";WARN="${_YELLOW}[!]${_NC}";ERR="${_RED}[ERR]${_NC}";INFO="${_CYAN}[*]${_NC}"

mkdir -p "$DIR"

log() { local ts=$(date '+%H:%M:%S'); echo -e "  [$ts] $1" | tee -a "$LOG"; }
# 记录模块完成状态到 manifest
manifest() {
    local module="$1" status="$2" detail="$3"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $module | $status | $detail" >> "$DIR/manifest.txt"
}
run_cmd() {
    local desc="$1" cmd="$2" outfile="$3"
    echo "=== $desc ===" >> "$outfile"
    if eval "$cmd" >> "$outfile" 2>&1; then
        log "${OK} $desc"
        manifest "$desc" "ok" "$outfile"
    else
        log "${WARN} $desc (部分失败)"
        manifest "$desc" "partial" "$outfile"
    fi
}
run_sys() {
    local desc="$1" cmd="$2" outfile="$3"
    local rc=0
    echo "=== $desc ===" >> "$outfile"
    if ! eval "$cmd" >> "$outfile" 2>&1; then
        rc=1
        echo "[STDERR/Failed] $desc: 命令执行失败或部分命令无权限" >> "$outfile"
        log "${WARN} $desc (执行失败/无权限)"
        manifest "$desc" "failed_or_partial" "$outfile"
    else
        log "${OK} $desc"
        manifest "$desc" "ok" "$outfile"
    fi
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

log "=== macOS IR 采集 v2.1 | $ARCH | macOS $OS_VER ==="
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
CONSOLE_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
if [ -n "$CONSOLE_USER" ]; then
    run_sys "launchctl-user" "launchctl print gui/$(id -u "$CONSOLE_USER" 2>/dev/null || echo 501) 2>/dev/null || launchctl list" "$W/launchctl_user.txt"
else
    run_sys "launchctl-user" "launchctl list" "$W/launchctl_user.txt"
fi
run_sys "env" "env" "$W/environment.txt"
run_sys "loginwindow" "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null || true" "$W/loginwindow.txt"
run_sys "sleep-wake" "pmset -g everything 2>/dev/null || true" "$W/power_settings.txt"
run_sys "timezone" "systemsetup -gettimezone 2>/dev/null; date -u" "$W/timezone.txt"

# ===== 2. 网络 =====
W="$DIR/02_Network"; mkdir -p "$W"
run_sys "ifconfig" "ifconfig -a" "$W/ifconfig.txt"
run_sys "networksetup" "networksetup -listallnetworkservices 2>/dev/null; networksetup -getinfo Ethernet 2>/dev/null; networksetup -getinfo Wi-Fi 2>/dev/null || true" "$W/network_setup.txt"
run_sys "wifi-known" "networksetup -listpreferredwirelessnetworks en0 2>/dev/null || true" "$W/wifi_known_networks.txt"
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

# 外联IP提取 (IPv4/IPv6 兼容)
lsof -i -P -n 2>/dev/null | awk 'NR>1 && $9 ~ /->/ {
    split($9,a,"->"); r=a[2];
    gsub(/^\[/,"",r); gsub(/\]/,"",r);
    n=split(r,b,":");
    if (n>1) { port=b[n]; delete b[n]; ip=join(b,":"); }
    else { ip=r; port=""; }
    print ip;
}
function join(arr,sep,  s,i){ s=""; for(i=1; i in arr; i++) s=(s==""?arr[i]:s sep arr[i]); return s }' | sort | uniq -c | sort -rn | head -20 > "$W/foreign_connections.txt" 2>/dev/null || true
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
ps -axo pid=,comm= 2>/dev/null | while read -r pid comm; do
    [ -z "$pid" ] && continue
    exe=$(lsof -p "$pid" 2>/dev/null | awk '$4=="txt" && $NF ~ /^\// {print $NF; exit}') || true
    if [ -z "$exe" ]; then
        exe=$(ps -o comm= -p "$pid" 2>/dev/null) || true
    fi
    [ -z "$exe" ] && continue
    if [ -x "$exe" ] && [ -f "$exe" ]; then
        sig=$(codesign -dvv "$exe" 2>&1 | grep -E "Authority|Signature|Signed" | head -3 | tr '\n' ' ') || sig="SIGNATURE_QUERY_FAILED"
        [ -z "$sig" ] && sig="UNSIGNED"
    else
        sig="PATH_NOT_FOUND"
    fi
    echo "PID=$pid PATH=$exe SIG=$sig" >> "$W/process_codesign.txt"
done 2>/dev/null || true
log "${OK} 进程签名验证完成"

# 进程路径异常检测
log "${INFO} 检测异常进程路径..."
echo "=== 进程路径异常检测 ===" > "$W/process_anomalies.txt"
ps -axo pid=,command= 2>/dev/null | while read -r pid rest; do
    path=$(echo "$rest" | awk '{print $1}')
    lower=$(echo "$path" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        */tmp/*|*/private/tmp/*|*/downloads/*|*/desktop/*|*/documents/*)
            echo "[SUSPICIOUS_PATH] PID=$pid PATH=$path" >> "$W/process_anomalies.txt" ;;
    esac
done 2>/dev/null || true
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
done 2>/dev/null || true

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
done 2>/dev/null || true

# Cron, Periodic, Shell Profiles
run_sys "cron" "crontab -l 2>/dev/null || true; for u in /Users/*; do [ -d \"\$u\" ] && crontab -u \$(basename \"\$u\") -l 2>/dev/null || true; done; echo '---' " "$W/crontabs.txt"
run_sys "periodic" "ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null" "$W/periodic.txt"
run_sys "at-jobs" "atq 2>/dev/null || true" "$W/at_jobs.txt"
echo "=== Shell Profiles ===" > "$W/shell_profiles.txt"
for f in /etc/profile /etc/bashrc /etc/zshrc /etc/zprofile; do
    [ -f "$f" ] && echo "--- $f ---" >> "$W/shell_profiles.txt" && cat "$f" 2>/dev/null >> "$W/shell_profiles.txt"
done
for user_home in /Users/*; do
    for f in "$user_home/.bash_profile" "$user_home/.zshrc" "$user_home/.zprofile" "$user_home/.profile"; do
        [ -f "$f" ] && echo "--- $f ---" >> "$W/shell_profiles.txt" && cat "$f" 2>/dev/null >> "$W/shell_profiles.txt"
    done
done 2>/dev/null || true

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

# 隐藏用户检测 (排除系统账号)
echo "=== 隐藏用户检测 ===" > "$W/hidden_users.txt"
SYSTEM_ACCOUNTS="root nobody daemon unknown www _amavisd _analyticsd _appleevents _applepay _appowner _appserverd _ard _assetcache _atsserver _avbdeviced _avatarsync _backupd _biome _caldav _captiveagent _clamav _cmiodalassistants _commerce _coreaudiod _coremediaiod _coreml _couchdb _cyrus _devdocs _deviceautomation _dialogd _displaypolicyd _distnoted _dovecot _dpaudio _driverkit _eppc _etcd _fpsd _ftp _gamecontrollerd _geod _git _hidd _icbaccount _installassistant _installcoordinationd _installer _jabber _kadmin_admin _kadmin_changepw _kcpasswordd _knowledgegraphd _krb_anonymous _krb_changepw _krb_kadmin _krb_kdc _krb_kdcd _krb_kerberos _krb_krbtgt _krb_services _krbfast _krbtgt _lda _locationd _logd _lp _mailman _mbsetupuser _mcxalr _mdnsresponder _mds _mds_stores _memberd _mobileasset _modelmanagerd _mysql _netbios _netstatistics _networkd _nsurlsessiond _nsurlstoraged _oahd _ondemand _openldap _opera _owner _paymentgateway _postfix _postgres _qtss _reportmemoryexception _reportpanic _rmd _rpc _sandbox _screensaver _scsd _securityagent _serialnumberd _setup _softwareupdate _spotlight _sshd _svn _systemadministrator _taskgated _teamsserver _timed _timezone _tokenhunter _trustevaluationagent _unknown _update _usbmuxd _userwindowd _usrshellswitcher _vpn _wallet _webproxy _webauthserver _windowserver _wwwproxy _xserverdocs _ypbind _appstore _firmwaresyncd _installer _networkd _sntpd _diagnosticd _logd _reportingd _desktopservicesd _submitd _appinstalld _applepayd _locationd _lskyboxd _appleeventsd _installcoordinationd _corespotlightd _csstatsd _diskimagesiod _displaypolicyd _familycircled _filecoordinationd _findmydevice _iconworksagent _identityservicesd _imagent _keyboardservicesagent _mdmclient _mocagent _nsurlsessiond _osprey _photolibraryd _pkd _preferences _siri _splboard _suggestd _tccd _thermaldispatcher _touchbaruser _unifiedassetd _watcherappd _xpcroleaccountd _kdebugd _metricd _cryptexd _audiomxd _bluebottled _feedbackd _gamed _mediaserverd _mobileactivated _sharedfilelistd _skserverd _syspolicy _usernoted _video_ _voice_ _wifi _wirelessproxyd _xsession _zoomus _mysql _proxy _mail _www _appserver _uucp _games _news _ingres _operator _lpadmin _ssh _systemstats _displaypl_agent _applepayd _biomed _mdsync _oahd _taskgated _usecoredump _procmod _fud _amfid _postgresql _applepayd _pmcalibrationd _sidecarrelay _datalore"
echo "system account list size: $(echo "$SYSTEM_ACCOUNTS" | wc -w | tr -d ' ')" > /dev/null
dscl . -list /Users 2>/dev/null | while read -r u; do
    uid=$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')
    [ -z "$uid" ] && continue
    # 排除系统内置账号：_ 开头、白名单、常见系统 UID
    if [[ "$u" == _* ]] || echo "$SYSTEM_ACCOUNTS" | grep -qw "$u" || [ "$uid" -lt 500 ]; then
        continue
    fi
    echo "[USER] $u (UID=$uid)" >> "$W/hidden_users.txt"
    # 检查是否隐藏 (IsHidden = 1)
    hidden=$(dscl . -read "/Users/$u" IsHidden 2>/dev/null | awk '{print $2}' || echo "0")
    if [ "$hidden" = "1" ]; then
        echo "  [HIDDEN_FLAG] $u (IsHidden=1)" >> "$W/hidden_users.txt"
    fi
    # 检查 ShadowHashData 是否为空 (空值行没有第二列)
    shadow=$(dscl . -read "/Users/$u" ShadowHashData 2>/dev/null | awk 'NF>1 {print $2}' | wc -l | tr -d ' ')
    if [ "$shadow" = "0" ]; then
        echo "  [NO_SHADOW_DATA] $u 可能无密码或无法读取" >> "$W/hidden_users.txt"
    fi
done 2>/dev/null || true
run_sys "password-policy" "pwpolicy -getaccountpolicies 2>/dev/null || pwpolicy -getglobalpolicy 2>/dev/null || true" "$W/password_policy.txt"

# SSH 密钥
run_sys "ssh-keys" "cat /etc/ssh/sshd_config 2>/dev/null; echo '---'; for u in /Users/*; do cat \"\$u/.ssh/authorized_keys\" 2>/dev/null && echo \"--- \$u ---\"; done" "$W/ssh_keys.txt"

# 登录记录
run_sys "last" "last -n 100" "$W/last_logins.txt"
run_sys "who" "who -a" "$W/who.txt"
run_sys "w" "w" "$W/w_command.txt"

# Sudo 日志
run_sys "sudo-logs" "cat /var/log/system.log 2>/dev/null | grep -i 'sudo' | tail -100; log show --last 24h --predicate 'process == \"sudo\"' 2>/dev/null | tail -100 || true" "$W/sudo_logs.txt"

# Sudoers (v2.1 补充)
run_sys "sudoers" "cat /etc/sudoers 2>/dev/null || echo '(无法读取 /etc/sudoers)'; ls -la /etc/sudoers.d/ 2>/dev/null || true; for f in /etc/sudoers.d/*; do [ -f \"\$f\" ] && echo \"--- \$f ---\" && cat \"\$f\" 2>/dev/null; done" "$W/sudoers.txt"

# Keychain 列表 (v2.1 补充)
run_sys "keychains" "security list-keychains 2>/dev/null || true; security default-keychain 2>/dev/null || true; security dump-keychain 2>/dev/null | head -50 || true" "$W/keychains.txt"

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
find /tmp /private/tmp /var/tmp -type f -perm -111 2>/dev/null | head -100 >> "$W/tmp_executables.txt" || true
echo "=== 隐藏文件与目录 ===" > "$W/hidden_files.txt"
find /Users /tmp /var/tmp /Library -name ".*" -type f 2>/dev/null | head -200 >> "$W/hidden_files.txt" || true
echo "=== SUID/SGID 文件 ===" > "$W/suid_sgid.txt"
find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | grep -v '^/System/\|^/usr/lib/\|^/sbin/\|^/Library/Apple/\|^/usr/bin/\|^/usr/sbin/' | head -50 >> "$W/suid_sgid.txt" || true
echo "=== 用户下载目录可疑文件 ===" > "$W/downloads_suspicious.txt"
for u in /Users/*/Downloads; do [ -d "$u" ] && find "$u" -type f \( -name "*.dmg" -o -name "*.pkg" -o -name "*.app" -o -name "*.sh" -o -name "*.command" -o -name "*.py" -o -name "*.pl" \) -mtime -30 2>/dev/null; done | head -100 >> "$W/downloads_suspicious.txt" || true
log "${OK} 文件系统扫描完成"

# ===== 7. 日志 =====
W="$DIR/07_Logs"; mkdir -p "$W"
run_sys "system-log" "log show --last 1h --predicate 'eventMessage contains \"error\" or eventMessage contains \"fail\"' --style compact 2>/dev/null | head -500 || echo 'log command not available'" "$W/system_log_errors.txt"
run_sys "auth-log" "log show --last 24h --predicate 'subsystem contains \"com.apple.auth\"' --style compact 2>/dev/null | head -500 || cat /var/log/system.log 2>/dev/null | grep -i 'auth\|ssh\|sudo\|su\|login' | tail -100" "$W/auth_log.txt"
run_sys "install-log" "log show --last 7d --predicate 'subsystem contains \"install\"' --style compact 2>/dev/null | head -500 || true" "$W/install_log.txt"
run_sys "asl" "ls -la /var/log/asl/ 2>/dev/null; for f in /var/log/asl/*; do [ -f \"\$f\" ] && echo \"--- \$f ---\" && cat \"\$f\" 2>/dev/null | strings | grep -i 'error\|fail\|ssh\|sudo' | tail -50; done" "$W/asl_logs.txt"
run_sys "diagnostics" "ls -la /Library/Logs/DiagnosticReports/ 2>/dev/null | tail -100" "$W/diagnostic_reports.txt"
run_sys "system-log-full" "cat /var/log/system.log 2>/dev/null | tail -500 || true" "$W/system_log.txt"
run_sys "install-history" "cat /Library/Receipts/InstallHistory.plist 2>/dev/null | strings | head -500 || true" "$W/install_history.txt"
run_sys "unified-ssh" "log show --last 7d --predicate 'process == \"sshd\" or process == \"ssh\"' --style compact 2>/dev/null | head -200 || true" "$W/ssh_connections.txt"
log "${OK} 日志完成"

# ===== 8. 浏览器记录 =====
W="$DIR/08_Browser"; mkdir -p "$W"

run_sys "shell-history" "for u in /Users/*; do cat \"\$u/.bash_history\" \"\$u/.zsh_history\" \"\$u/.zhistory\" 2>/dev/null; done | tail -500" "$W/shell_history.txt"

# Safari (schema 兼容: history_item / history_item_id)
run_sys "safari" "for u in /Users/*/Library/Safari; do [ -d \"\$u\" ] || continue; echo \"=== \$u ===\"; col=\$(sqlite3 \"\$u/History.db\" 'PRAGMA table_info(history_visits);' 2>/dev/null | grep -c history_item_id); if [ \"\$col\" -gt 0 ]; then sqlite3 \"\$u/History.db\" 'SELECT datetime(visit_time+978307200,\"unixepoch\"),url FROM history_items JOIN history_visits ON history_items.id=history_visits.history_item_id ORDER BY visit_time DESC LIMIT 100' 2>/dev/null; else sqlite3 \"\$u/History.db\" 'SELECT datetime(visit_time+978307200,\"unixepoch\"),url FROM history_items JOIN history_visits ON history_items.id=history_visits.history_item ORDER BY visit_time DESC LIMIT 100' 2>/dev/null; fi; done || true" "$W/safari_history.txt"

# Chrome
echo "=== Chrome 历史记录 ===" > "$W/chrome_history.txt"
for u in /Users/*; do
    chrome_dir="$u/Library/Application Support/Google/Chrome"
    [ -d "$chrome_dir" ] || continue
    for profile in "$chrome_dir"/Default "$chrome_dir"/Profile*; do
        [ -f "$profile/History" ] || continue
        echo "--- $(basename "$u") / $(basename "$profile") ---" >> "$W/chrome_history.txt"
        sqlite3 "$profile/History" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),url FROM urls ORDER BY last_visit_time DESC LIMIT 100" 2>&1 >> "$W/chrome_history.txt" || echo "  [WARN] Chrome 历史库可能被锁定或无权限" >> "$W/chrome_history.txt"
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
        sqlite3 "$profile/History" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),url FROM urls ORDER BY last_visit_time DESC LIMIT 100" 2>&1 >> "$W/edge_history.txt" || echo "  [WARN] Edge 历史库可能被锁定或无权限" >> "$W/edge_history.txt"
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
        sqlite3 "$profile/places.sqlite" "SELECT datetime(last_visit_date/1000000,'unixepoch'),url FROM moz_places ORDER BY last_visit_date DESC LIMIT 100" 2>&1 >> "$W/firefox_history.txt" || echo "  [WARN] Firefox 历史库可能被锁定或无权限" >> "$W/firefox_history.txt"
    done
done

# 下载记录 (Quarantine Events)
run_sys "downloads" "for u in /Users/*; do [ -f \"\$u/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2\" ] && echo \"=== \$u ===\" && sqlite3 \"\$u/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2\" 'SELECT datetime(LSQuarantineTimeStamp+978307200,\"unixepoch\"),LSQuarantineDataURLString,LSQuarantineAgentBundleIdentifier FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 200' 2>/dev/null; done || true" "$W/quarantine_events.txt"

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
run_sys "profiles" "profiles list 2>/dev/null; profiles show -type configuration 2>/dev/null || true" "$W/mdm_profiles.txt"

# TCC 隐私数据库
run_sys "tcc" "for u in /Users/*; do [ -f \"\$u/Library/Application Support/com.apple.TCC/TCC.db\" ] && echo \"=== \$u ===\" && sqlite3 \"\$u/Library/Application Support/com.apple.TCC/TCC.db\" 'SELECT service,client,auth_value FROM access ORDER BY service' 2>/dev/null; done || true" "$W/tcc_database.txt"

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
done || true
log "${OK} 内核扩展完成"

# ===== 11. 元数据+哈希链 =====
W="$DIR/11_Metadata"; mkdir -p "$W"
IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1) || true
cat > "$W/metadata.txt" << EOF
macOS 取证包元数据 v2.1
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

# 模块清单 (在哈希前追加统计)
echo "---" >> "$DIR/manifest.txt"
echo "模块总数: $(grep -c '|' "$DIR/manifest.txt" 2>/dev/null || echo 0)" >> "$DIR/manifest.txt"
log "${OK} 模块清单完成"

# 哈希链（只保留关键清单摘要，避免逐文件哈希拖慢现场采集）
TOP_HASH=$(shasum -a 256 "$DIR/manifest.txt" "$DIR/collection_log.txt" 2>/dev/null | shasum -a 256 | cut -d' ' -f1) || TOP_HASH="N/A"
echo "关键清单哈希: $TOP_HASH" > "$W/top_hash.txt"
echo "说明: 现场取证以打包 SHA256 为准，不逐文件哈希" >> "$W/top_hash.txt"
log "${OK} 关键清单哈希: $TOP_HASH"

# 打包
cd "$BASE"
tar czf "$ARCHIVE" -C "$BASE" "IR_${HOSTNAME}_${TIMESTAMP}" 2>/dev/null
ZIP_HASH=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
ZIP_SIZE=$(du -h "$ARCHIVE" | cut -f1)
echo "$ZIP_HASH  $ARCHIVE" > "${ARCHIVE}.sha256"
log "${OK} 打包完成: $ARCHIVE ($ZIP_SIZE)"
log "${OK} SHA256: $ZIP_HASH"
log "${OK} 包哈希已写入: ${ARCHIVE}.sha256"

echo ""
echo -e "${_GREEN}========================================${_NC}"
echo -e "${_GREEN}  macOS IR 采集完成 v2.1${_NC}"
echo -e "${_GREEN}========================================${_NC}"
echo -e "${_CYAN}  主机:     $HOSTNAME${_NC}"
echo -e "${_CYAN}  架构:     $ARCH ($([ $IS_ARM -eq 1 ] && echo 'Apple Silicon' || echo 'Intel'))${_NC}"
echo -e "${_CYAN}  打包:     $ARCHIVE${_NC}"
echo -e "${_CYAN}  大小:     $ZIP_SIZE${_NC}"
echo -e "${_CYAN}  SHA256:   $ZIP_HASH${_NC}"
echo -e "${_CYAN}  旁车文件: ${ARCHIVE}.sha256${_NC}"
echo -e "${_CYAN}  清单哈希: $TOP_HASH${_NC}"
echo -e "${_GREEN}========================================${_NC}"
