#!/bin/bash
# ============================================================
# Linux入侵检测报告工具 - Whoamifuck [司稽]
# Author: Enomothem
# Time: 2021年2月8日
# Modified: 2026年5月8日 - 全面重构
#   - IR取证收集：按挥发性排序，/proc深度采集，完整性校验
#   - 修复：临时文件安全、变量作用域、find缺路径、color写入文件
#   - 新增：容器检测、LD_PRELOAD检测、SUID/SGID排查
#   - 重构：fk_userlogin去重复、网卡检测兼容现代命名
#   - v8.0.0: 后门检测(SUID/Cap/SSH软连接/OpenSSH/PAM/命令替换/盖茨木马/隐藏进程)
#   - v8.0.0: 认证增强(sshd_config审计/authorized_keys审计/shadow空密码)
#   - v8.0.0: 服务与启动项补全(anacron/xinetd/inetd/cron全量)
#   - v8.0.0: 日志分析增强(Web日志分析/数据库日志/lastb暴力破解)
#   - v8.0.0: 文件系统增强(系统文件近期修改/tmp+shm可执行文件hash)
#   - v8.0.0: 新增 -d/--backdoor -e/--auth 选项
#   - v8.1.0: IR取证目录结构对齐DIRECTORY_MAPPING.md
#   - v8.1.0: 持久化增强(用户bashrc/profile劫持/用户systemd服务/内核模块持久化/XDG自动启动/包管理器hook劫持)
#   - v8.1.0: 新增勒索病毒检测(16种勒索信文件名搜索/14个勒索扩展名扫描)
#   - v8.1.0: 新增供应链风险检测(第三方远程工具扫描/ESXi容器虚拟化环境检测)
# ============================================================

set -o pipefail

# --------------------------------------
#        | 全局变量 |
# --------------------------------------

VER="2026.5.8@whoamifuck-version 8.0.0"
WHOAMIFUCK=$(whoami)

# 默认路径
CONF_PATH="$HOME/.whok"
CONF_FILE="chief-inspector.conf"
OUTPUT="output"
OUTPUT_M="output/html"
OUTPUT_T="output/text"
AUTHLOG_FILE="/var/log/auth.log"
SECURE_FILE="/var/log/secure"
IR_OUTPUT_DIR="/opt/ir_evidence"
IR_ARCHIVE="IR.tar.gz"

# --------------------------------------
#        | 颜色定义 |
# --------------------------------------

readonly _R="\033[0m"
readonly _BOLD="\033[1m"
readonly _RED="\033[1;31m"
readonly _GREEN="\033[32m"
readonly _YELLOW="\033[33m"
readonly _ORANGE="\033[1;93m"
readonly _BLUE="\033[1;34m"
readonly _PURPLE="\033[35m"
readonly _CYAN="\033[36m"
readonly _WHITE="\033[1;37m"
readonly _BG_RED="\033[41m"

# 状态标记
_SUC="[${_GREEN}SUCCESS${_R}]"
_WAR="[${_ORANGE}WARNING${_R}]"
_ERR="[${_RED}ERROR${_R}]"
_OK="[${_GREEN}+${_R}]"
_NO="[${_RED}-${_R}]"
_INFO="[${_BLUE}*${_R}]"

# --------------------------------------
#        | 工具函数 |
# --------------------------------------

# 分隔线
_print_bar() {
    printf "${_RED}%50s${_R}\n" "[ $1 ]"
}

# 安全执行命令（IR收集用）
_ir_run() {
    local desc="$1" cmd="$2" outfile="$3"
    echo "[$(date '+%H:%M:%S')] 收集: $desc" >> "$_IR_LOG"
    eval "$cmd" >> "$outfile" 2>> "$_IR_LOG" || \
        echo "[$(date '+%H:%M:%S')] 警告: $desc 命令失败或不可用" >> "$_IR_LOG"
}

# 检测OS类型
_detect_os() {
    if [ ! -f /etc/os-release ]; then
        OSNAME="Unknown"; OSTYPE="RedHat"; return
    fi
    local pretty=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    case "$pretty" in
        *Debian*|*Ubuntu*|*Kali*|*Parrot*|*Deepin*) OSNAME="${pretty%% *}" OSTYPE="Debian" ;;
        *CentOS*|*Red*Hat*|*Fedora*|*Rocky*|*Alma*) OSNAME="${pretty%% *}" OSTYPE="RedHat" ;;
        *) OSNAME="Unknown"; OSTYPE="RedHat" ;;
    esac
}

# 获取认证日志路径
_get_auth_log() {
    if [ -f "$AUTHLOG_FILE" ]; then echo "$AUTHLOG_FILE"
    elif [ -f "$SECURE_FILE" ]; then echo "$SECURE_FILE"
    else echo ""; fi
}

# --------------------------------------
#        | LOGO & HELP |
# --------------------------------------

function logo
{
    local hh="${_R}${_GREEN}<bug>${_R}${_RED}"
    local s="${_R}\e[1;31m777${_R}${_RED}"
    local r="${_R}${_YELLOW}who!${_R}${_RED}"
    local x="${_R}${_ORANGE}root${_R}${_RED}"
    printf "${_RED} ██╗    ██╗██╗  ██╗ ██████╗  █████╗ ███╗   ███╗██╗    ███████╗██╗   ██╗ ██████╗██╗  ██╗ ${_R}\n"
    printf "${_RED} ██║${x}██║██║  ██║██╔═══██╗██╔══██╗████╗ ████║██║    ██╔════╝██║   ██║██╔════╝██║ ██╔╝ ${_R}\n"
    printf "${_RED} ██║ █╗ ██║███████║██║${s}██║███████║██╔████╔██║██║    █████╗  ██║   ██║██║${hh}█████╔╝  ${_R}\n"
    printf "${_RED} ██║███╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██║    ██╔══╝  ██║   ██║██║     ██╔═██╗  ${_R}\n"
    printf "${_RED} ╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║██║    ██║     ╚██████╔╝╚██████╗██║  ██╗ ${_R}\n"
    printf "${_RED}  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝    ╚═╝ ${r} ╚═════╝  ╚═════╝╚═╝  ╚═╝ ${_R}\n"
    printf "       Hi ${WHOAMIFUCK}          ${VER}          by \\Eonian Sharp\\ -${_BLUE} Enomothem${_R}\n"
}

function help_cn
{
    logo
    local W1=30 W2=55
    printf "%-${W1}s %-${W2}s\n" "使用方法:" ""
    printf "\n"
    printf "\t%-${W1}s %-${W2}s\n" "-v --version"              "版本信息"
    printf "\t%-${W1}s %-${W2}s\n" "-h --help"                 "帮助指南"
    printf "\n"
    printf "  %-${W1}s %-${W2}s\n" "QUICK" ""
    printf "\t%-${W1}s %-${W2}s\n" "-u --user-device"          "查看设备基本信息"
    printf "\t%-${W1}s %-${W2}s\n" "-l --login [FILEPATH]"     "用户登录信息 [default:auto]"
    printf "\t%-${W1}s %-${W2}s\n" "-n --nomal"                "基本输出模式"
    printf "\t%-${W1}s %-${W2}s\n" "-a --all"                  "全量输出模式（按挥发性排序）"
    printf "\n"
    printf "  %-${W1}s %-${W2}s\n" "SPECIAL" ""
    printf "\t%-${W1}s %-${W2}s\n" "-x --proc-serv"            "进程与服务状态"
    printf "\t%-${W1}s %-${W2}s\n" "-p --port"                 "端口开放与HTTP探测"
    printf "\t%-${W1}s %-${W2}s\n" "-s --os-status"            "系统状态信息"
    printf "\n"
    printf "  %-${W1}s %-${W2}s\n" "RISK" ""
    printf "\t%-${W1}s %-${W2}s\n" "-b --baseline"             "基线安全评估（含认证增强）"
    printf "\t%-${W1}s %-${W2}s\n" "-r --risk"                 "内核漏洞检测"
    printf "\t%-${W1}s %-${W2}s\n" "-k --rookitcheck"          "Rootkit/SSH后门检测（含后门检测）"
    printf "\t%-${W1}s %-${W2}s\n" "-d --backdoor"             "后门检测（SUID/Cap/SSH软连接/OpenSSH/PAM/命令替换/盖茨木马）"
    printf "\t%-${W1}s %-${W2}s\n" "-e --auth"                 "认证安全增强（sshd_config/authorized_keys/shadow）"
    printf "\t%-${W1}s %-${W2}s\n" "-w --webshell [PATH]"      "Webshell检测 [default:/var/www;/www/wwwroot]"
    printf "\n"
    printf "  %-${W1}s %-${W2}s\n" "OUTPUT" ""
    printf "\t%-${W1}s %-${W2}s\n" "-q --pack"                 "IR全量取证收集+打包(按挥发性排序)"
    printf "\n"
}

# --------------------------------------
#        | 用户登录分析 |
# --------------------------------------

# 通用登录分析（适配 Debian/RedHat 日志格式）
function fk_userlogin
{
    _print_bar "用户登录分析"

    local AUTH_LOG
    if [ -n "$FILE" ] && [ -f "$FILE" ]; then
        AUTH_LOG="$FILE"
    else
        AUTH_LOG=$(_get_auth_log)
    fi

    if [ -z "$AUTH_LOG" ] || [ ! -f "$AUTH_LOG" ]; then
        printf "$_WAR 未找到认证日志（$AUTHLOG_FILE / $SECURE_FILE）\n"
        return
    fi

    printf "$_INFO 日志文件: $AUTH_LOG\n\n"

    # 登录成功
    echo -e "${_BG_RED}\n『 登录成功记录 』${_R}\n"
    grep "Accepted" "$AUTH_LOG" | awk '{print "时间:"$1"-"$2"-"$3"\t"$9"@""$11"\t方式:"$7}' | tail -20

    # 暴力破解统计
    echo -e "${_BG_RED}\n『 SSH暴力破解 - 攻击者IP TOP15 』${_R}\n"
    grep "Failed password" "$AUTH_LOG" | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -15 | \
        awk '{printf "  [%s] %s次  %s\n", ($1>100?"🔴":"🟡"), $1, $2}'

    # 被枚举的用户名
    echo -e "${_BG_RED}\n『 被爆破用户名 TOP10 』${_R}\n"
    grep "Failed password for" "$AUTH_LOG" | grep -v "invalid" | awk '{print $9}' | sort | uniq -c | sort -rn | head -10 | \
        awk '{printf "  [+] 用户: %-15s 尝试: %s次\n", $2, $1}'

    # 不存在的用户名枚举
    echo -e "${_BG_RED}\n『 枚举不存在的用户名 』${_R}\n"
    grep "Failed password for invalid user" "$AUTH_LOG" | awk '{print $11 " --> " $13}' | sort | uniq -c | sort -rn | head -10 | \
        awk '{printf "  [+] IP:%-18s 尝试用户: %s\n", $2, $3}'

    echo
}

# --------------------------------------
#        | 基本信息 |
# --------------------------------------

function fk_baseinfo
{
    _print_bar "基本信息"

    # 网卡检测（兼容现代命名：eth/enp/ens/br/docker）
    local IP="" ZW="" GW=""
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    GW=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    local HN=$(hostname)
    local VM=$(lscpu 2>/dev/null | grep -E "Hyper.*:|Virtu|超管理器" | awk -F[:：] '{print $2}' | sed 's/ //g' | paste -sd, | sed 's/,full//g')
    local DNS=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd,)
    local OS=$(uname -r)
    _detect_os
    local OSNAME_VER=$(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    local TUN=$(uptime -p 2>/dev/null || uptime | sed 's/user.*$//' | awk '{print $NF}')
    local M_TIME=$(date +"%Y-%m-%d %H:%M:%S")

    local LAST=$(last -i 2>/dev/null | head -15)
    local LASTLOG=$(lastlog 2>/dev/null | grep -v Never)
    local ONLINE=$(who 2>/dev/null)

    printf "  %-18s ${_CYAN}%s${_R}\n" "IP地址" "$IP"
    printf "  %-18s %s\n" "网关" "${GW:-unknown}"
    printf "  %-18s ${_YELLOW}%s${_R}「 ${_RED}%s${_R} 」\n" "主机名/用户" "$HN" "$WHOAMIFUCK"
    printf "  %-18s %s\n" "DNS" "${DNS:-unknown}"
    printf "  %-18s %s\n" "内核" "$OS"
    printf "  %-18s ${_BG_YELLOW}%s %s${_R}「 ${_BLUE}%s${_R} 」\n" "系统" "$OSNAME" "$OSNAME_VER" "${VM:-物理机}"
    printf "  %-18s ${_PURPLE}%s${_R}\n" "运行时间" "$TUN"
    printf "  %-18s ${_GREEN}%s${_R}\n" "采集时间" "$M_TIME"

    echo "------------------------------------------------------"
    echo -e "${_RED}> 在线用户${_R}"
    printf "%s\n" "$ONLINE"
    echo "------------------------------------------------------"
    echo -e "${_RED}> 最近登录${_R}"
    printf "%s\n" "$LAST"
    echo "------------------------------------------------------"
    echo -e "${_RED}> 最后登录${_R}"
    printf "%s\n" "$LASTLOG"
    echo "------------------------------------------------------"
}

# --------------------------------------
#        | 系统状态 |
# --------------------------------------

function fk_devicestatus
{
    _print_bar "系统状态"

    local MEM=$(free -m 2>/dev/null | awk 'NR==2{printf "%.1f%% (已用%dm/总量%dm)", $3*100/$2, $3, $2}')
    local DISK=$(df -h 2>/dev/null | awk '$NF=="/"{printf "%s (已用/总量)", $5}')
    local LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{printf "%s %s %s (1/5/15min)", $1, $2, $3}')
    local CPU_N=$(nproc 2>/dev/null || echo "?")

    printf "  %-12s %s\n" "内存" "$MEM"
    printf "  %-12s %s\n" "磁盘/" "$DISK"
    printf "  %-12s %s (CPU核心: %s)\n" "负载" "$LOAD" "$CPU_N"
    echo
}

# --------------------------------------
#        | 进程与服务 |
# --------------------------------------

function fk_procserv
{
    _print_bar "进程与服务"

    echo -e "${_RED}> 进程列表 (CPU TOP20)${_R}"
    ps aux --sort=-%cpu 2>/dev/null | head -21
    echo

    echo -e "${_RED}> 运行中的服务${_R}"
    systemctl list-units --type=service --state=running 2>/dev/null | head -30
    echo

    # 检查已删除二进制的进程
    echo -e "${_RED}> 已删除二进制的进程（可能残留或恶意）${_R}"
    local deleted=0
    for pid in /proc/[0-9]*; do
        local p=$(basename $pid)
        local exe_link=$(readlink /proc/$p/exe 2>/dev/null)
        if [[ "$exe_link" == *"(deleted)"* ]]; then
            local cmd=$(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')
            printf "  ${_ORANGE}[!] PID:%-8s EXE:%s${_R}\n" "$p" "$exe_link"
            printf "      CMD: %s\n" "$cmd"
            deleted=$((deleted+1))
        fi
    done
    if [ $deleted -eq 0 ]; then
        printf "  ${_GREEN}[+] 未发现已删除二进制的进程${_R}\n"
    fi
    echo
}

# --------------------------------------
#        | 端口信息 |
# --------------------------------------

function fk_portstatus
{
    _print_bar "端口信息"

    echo -e "${_RED}> 监听端口${_R}"
    ss -tulpn 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN
    echo

    echo -e "${_RED}> 已建立的外部连接${_R}"
    ss -tnp 2>/dev/null | grep ESTAB | grep -v '127.0.0' | head -20
    echo
}

# --------------------------------------
#        | 历史命令 |
# --------------------------------------

function fk_history
{
    _print_bar "历史命令"

    echo -e "${_RED}> 当前用户最近命令${_R}"
    cat ~/.*sh_history 2>/dev/null | tail -20
    echo

    echo -e "${_RED}> 所有用户历史文件${_R}"
    find /home /root -name '.*sh_history' -exec echo "=== {} ===" \; -exec tail -5 {} \; 2>/dev/null
    echo
}

# --------------------------------------
#        | 计划任务 |
# --------------------------------------

function fk_crontab
{
    _print_bar "计划任务"

    echo -e "${_RED}> 当前用户 crontab${_R}"
    crontab -l 2>/dev/null || echo "  (无)"
    echo

    echo -e "${_RED}> /etc/crontab${_R}"
    grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null || echo "  (空)"
    echo

    echo -e "${_RED}> /etc/cron.d/${_R}"
    ls -la /etc/cron.d/ 2>/dev/null
    for f in /etc/cron.d/*; do
        [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
    done
    echo

    echo -e "${_RED}> /var/spool/cron/${_R}"
    ls -laR /var/spool/cron/ 2>/dev/null
    for f in /var/spool/cron/crontabs/*; do
        [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
    done
    echo

    echo -e "${_RED}> systemd timers${_R}"
    systemctl list-timers --all 2>/dev/null | head -20
    echo
}

# --------------------------------------
#        | 文件排查 |
# --------------------------------------

function fk_fileinfo
{
    _print_bar "文件排查"

    for dir in /home /opt /tmp /var/tmp /dev/shm; do
        if [ -d "$dir" ]; then
            echo -e "${_RED}> $dir 目录内容${_R}"
            ls -la "$dir" 2>/dev/null | head -15
            echo
        fi
    done
}

function fk_filemove
{
    _print_bar "文件修改排查"

    echo -e "${_RED}> 最近3天修改的文件（排除/proc /sys /dev）${_R}"
    find / -type f -mtime -3 2>/dev/null | grep -vE '/proc|/sys|/dev|/run' | head -100
    echo

    echo -e "${_RED}> /tmp /var/tmp /dev/shm 可执行文件${_R}"
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null || echo "  (无)"
    echo

    echo -e "${_RED}> SSH PublicKey 状态${_R}"
    find / -name authorized_keys -exec stat -c '%n 修改:%y 权限:%a' {} \; 2>/dev/null | grep -v '/proc'
    echo
}

# --------------------------------------
#        | 用户信息 |
# --------------------------------------

function fk_userinfo
{
    _print_bar "用户信息排查"

    echo -e "${_RED}> UID=0 的用户（root权限）${_R}"
    awk -F: '$3==0{print $1}' /etc/passwd
    echo

    echo -e "${_RED}> /etc/passwd 最近10个用户${_R}"
    tail -10 /etc/passwd
    echo

    echo -e "${_RED}> 有登录Shell的用户${_R}"
    grep -vE 'nologin|false|sync|halt|shutdown' /etc/passwd | cut -d: -f1,7
    echo

    echo -e "${_RED}> sudo权限用户${_R}"
    grep -vE '^#|^$' /etc/sudoers 2>/dev/null | grep "ALL=(ALL)" || echo "  (无法读取)"
    echo

    echo -e "${_RED}> SSH授权密钥${_R}"
    find / -name authorized_keys -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null | grep -v '/proc'
    echo

    fk_userlogin
}

# --------------------------------------
#        | Rootkit/SSH后门检测 |
# --------------------------------------

function fk_sshlink
{
    _print_bar "Rootkit & SSH后门检测"

    # 1. 非标准端口的sshd
    echo -e "${_RED}> 非标准端口 sshd 进程${_R}"
    local found=0
    for pid in /proc/[0-9]*; do
        local p=$(basename $pid)
        local exe=$(readlink /proc/$p/exe 2>/dev/null)
        if [[ "$exe" == */sshd ]]; then
            local cmdline=$(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')
            if [[ "$cmdline" != *":22 "* ]] && [[ "$cmdline" != *" -p 22"* ]]; then
                printf "  ${_ORANGE}[!] PID:%-8s EXE:%s CMD:%s${_R}\n" "$p" "$exe" "$cmdline"
                found=$((found+1))
            fi
        fi
    done
    [ $found -eq 0 ] && printf "  ${_GREEN}[+] 未发现非标准端口sshd${_R}\n"
    echo

    # 2. LD_PRELOAD 检查
    echo -e "${_RED}> /etc/ld.so.preload${_R}"
    if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
        printf "  ${_ORANGE}[!] 文件存在且非空！内容:${_R}\n"
        cat /etc/ld.so.preload
    else
        printf "  ${_GREEN}[+] 不存在或为空${_R}\n"
    fi
    echo

    # 3. 可疑内核模块
    echo -e "${_RED}> 最近加载的内核模块${_R}"
    lsmod 2>/dev/null | tail -10
    echo

    # 4. 异常 /proc/pid/exe（deleted/替换）
    echo -e "${_RED}> 已删除或异常的可执行进程${_R}"
    fk_procserv | grep -A2 "已删除"
    echo
}

# --------------------------------------
#        | Webshell检测 |
# --------------------------------------

function fk_wsfinder
{
    _print_bar "Webshell检测"

    # 白名单：常见框架目录，跳过以减少误报
    local WS_EXCLUDE="-path */vendor/* -o -path */node_modules/* -o -path */cache/* -o -path */session/*"

    local WEBSHELL_RULE_PHP='array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\('
    local WEBSHELL_RULE_PHP_HIGH='\\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\\b[\\/*\\s]*\\(+[\\/*\\s]*((\\$_(GET|POST|REQUEST|COOKIE)\\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\\s\\(]*(\\$_(GET|POST|REQUEST|COOKIE)\\[.{0,25}))'
    local WEBSHELL_RULE_JSP='<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\('

    local search_paths=()
    if [ -n "$WEBSHELL_PATH" ]; then
        search_paths=("$WEBSHELL_PATH")
    else
        [ -d "/var/www" ] && search_paths+=("/var/www")
        [ -d "/www/wwwroot" ] && search_paths+=("/www/wwwroot")
    fi

    for wpath in "${search_paths[@]}"; do
        echo -e "${_RED}> 扫描 $wpath${_R}"

        # PHP - 高置信度规则
        echo "  [高置信度] PHP危险函数+用户输入"
        find "$wpath" -type f -name "*.php" \( $WS_EXCLUDE \) -prune -o -type f -name "*.php" -exec grep -P -l --color=never "$WEBSHELL_RULE_PHP_HIGH" {} + 2>/dev/null | while read f; do
            printf "    ${_ORANGE}[!] %s${_R}\n" "$f"
        done

        # PHP - 通用规则
        echo "  [通用规则] PHP可疑函数"
        find "$wpath" -type f -name "*.php" \( $WS_EXCLUDE \) -prune -o -type f -name "*.php" -exec grep -P -l --color=never "$WEBSHELL_RULE_PHP" {} + 2>/dev/null | while read f; do
            printf "    ${_YELLOW}[?] %s${_R}\n" "$f"
        done

        # JSP
        echo "  JSP检测"
        find "$wpath" -type f -name "*.jsp" -exec grep -P -l --color=never "$WEBSHELL_RULE_JSP" {} + 2>/dev/null | while read f; do
            printf "    ${_RED}[!] %s${_R}\n" "$f"
        done
        echo
    done
}

# --------------------------------------
#        | 内核漏洞检测 |
# --------------------------------------

function dirty_cow
{
    _print_bar "内核漏洞检测"

    local KERNEL_VER=$(uname -r)
    local MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
    local MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)

    printf "$_INFO 当前内核: %s\n\n" "$KERNEL_VER"

    # Dirty COW
    if [ "$MAJOR" -ge 5 ]; then
        printf "  ${_GREEN}[+] Dirty COW (CVE-2016-5195): 不受影响 (5.x+已修复)${_R}\n"
    elif [ "$MAJOR" -eq 4 ] && [ "$MINOR" -ge 8 ]; then
        printf "  ${_GREEN}[+] Dirty COW (CVE-2016-5195): 不受影响 (4.8+已修复)${_R}\n"
    elif [ "$MAJOR" -eq 4 ]; then
        printf "  ${_ORANGE}[!] Dirty COW (CVE-2016-5195): 可能受影响，请确认补丁${_R}\n"
    else
        printf "  ${_RED}[!] Dirty COW (CVE-2016-5195): 可能受影响 (3.x及更早)${_R}\n"
    fi

    # 通用内核漏洞快速评估
    printf "\n  $_INFO 通用评估:\n"
    if [ "$MAJOR" -ge 6 ]; then
        printf "  ${_GREEN}[+] 6.x 内核，版本较新，已知高危内核漏洞大多已修复${_R}\n"
    elif [ "$MAJOR" -eq 5 ]; then
        printf "  ${_GREEN}[+] 5.x 内核，较新，常见漏洞已修复${_R}\n"
    else
        printf "  ${_ORANGE}[!] 内核版本较旧，建议升级或使用专业扫描工具检测${_R}\n"
    fi

    printf "\n  $_INFO 建议: 使用 linux-exploit-suggester 等专业工具进行完整检测\n"
}

# --------------------------------------
#        | 后门检测（手册第3章 Linux权限维持）|
# --------------------------------------

# SUID/SGID 文件扫描
_func_suid_sgid_scan() {
    echo -e "${_RED}> SUID 文件 (潜在SUID Shell后门)${_R}"
    find / -perm -4000 -type f 2>/dev/null | while read f; do
        local sz=$(ls -l "$f" 2>/dev/null | awk '{print $5}')
        local mt=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
        # 标记常见可疑SUID shell
        case "$f" in
            /tmp/*|/dev/shm/*|/var/tmp/*|/home/*)
                printf "  ${_ORANGE}[!] %-60s 大小:%-10s 修改:%s${_R}\n" "$f" "$sz" "$mt"
                ;;
            /bin/bash|/bin/sh|/bin/dash|/bin/zsh|/usr/bin/bash|/usr/bin/sh|/usr/bin/dash|/usr/bin/zsh)
                printf "  ${_YELLOW}[?] %-60s 大小:%-10s 修改:%s${_R}\n" "$f" "$sz" "$mt"
                ;;
            *)
                printf "  ${_GREEN}[+] %-60s 大小:%-10s 修改:%s${_R}\n" "$f" "$sz" "$mt"
                ;;
        esac
    done
    echo

    echo -e "${_RED}> SGID 文件${_R}"
    find / -perm -2000 -type f 2>/dev/null | head -50
    echo
}

# Capabilities 后门检测
_func_capabilities_scan() {
    echo -e "${_RED}> 文件 Capabilities (提权能力)${_R}"
    if command -v getcap >/dev/null 2>&1; then
        getcap -r / 2>/dev/null | while read line; do
            case "$line" in
                *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_dac_override*|*cap_dac_read_search*)
                    printf "  ${_ORANGE}[!] %s${_R}\n" "$line"
                    ;;
                *)
                    printf "  ${_GREEN}[+] %s${_R}\n" "$line"
                    ;;
            esac
        done
    else
        printf "  ${_WAR} getcap 命令不可用，跳过 Capabilities 检测${_R}\n"
    fi
    echo
}

# SSH软连接后门检测
_func_ssh_softlink_backdoor() {
    echo -e "${_RED}> SSH软连接后门检测${_R}"
    local found=0
    # 检查是否有sshd被软链接到可疑路径
    for pid in /proc/[0-9]*; do
        local p=$(basename $pid)
        local exe=$(readlink /proc/$p/exe 2>/dev/null)
        local cmdline=$(cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ')
        if [[ "$exe" == */sshd ]] || [[ "$cmdline" == *sshd* ]]; then
            # 检查是否监听在非标准端口且使用PAM软连接
            if [[ "$cmdline" == *"/tmp/"* ]] || [[ "$cmdline" == *"/dev/shm/"* ]]; then
                printf "  ${_RED}[!] PID:%-8s 可疑软链接sshd: CMD:%s${_R}\n" "$p" "$cmdline"
                found=$((found+1))
            fi
        fi
    done
    # 检查可疑软链接文件
    for suspicious in /tmp/su /tmp/chsh /tmp/chfn /dev/shm/su; do
        if [ -L "$suspicious" ]; then
            local target=$(readlink "$suspicious")
            if [[ "$target" == *sshd* ]]; then
                printf "  ${_RED}[!] 发现SSH软连接后门: %s -> %s${_R}\n" "$suspicious" "$target"
                found=$((found+1))
            fi
        fi
    done
    # 检查PAM配置是否可被利用
    for pam_file in /etc/pam.d/su /etc/pam.d/chsh /etc/pam.d/chfn; do
        if [ -f "$pam_file" ]; then
            if grep -q 'pam_rootok' "$pam_file" 2>/dev/null; then
                printf "  ${_YELLOW}[?] %s 包含 pam_rootok（可被软连接利用）${_R}\n" "$pam_file"
            fi
        fi
    done
    [ $found -eq 0 ] && printf "  ${_GREEN}[+] 未发现SSH软连接后门${_R}\n"
    echo
}

# OpenSSH后门检测
_func_openssh_backdoor() {
    echo -e "${_RED}> OpenSSH后门检测${_R}"
    local sshd_bin=$(which sshd 2>/dev/null || echo "/usr/sbin/sshd")
    local found=0

    # 1. 检查sshd二进制修改时间和大小
    if [ -f "$sshd_bin" ]; then
        local sshd_stat=$(stat -c '%s %y' "$sshd_bin" 2>/dev/null)
        printf "  sshd 二进制: %s\n" "$sshd_bin"
        printf "  大小/修改时间: %s\n" "$sshd_stat"

        # 使用包管理器验证
        if command -v rpm >/dev/null 2>&1; then
            local rpm_check=$(rpm -Vf "$sshd_bin" 2>/dev/null)
            if [ -n "$rpm_check" ]; then
                printf "  ${_ORANGE}[!] RPM校验不一致:${_R}\n"
                echo "  $rpm_check"
                found=$((found+1))
            else
                printf "  ${_GREEN}[+] RPM校验通过${_R}\n"
            fi
        elif command -v dpkg >/dev/null 2>&1; then
            local dpkg_check=$(dpkg -V openssh-server 2>/dev/null)
            if [ -n "$dpkg_check" ]; then
                printf "  ${_ORANGE}[!] DPKG校验不一致:${_R}\n"
                echo "  $dpkg_check"
                found=$((found+1))
            else
                printf "  ${_GREEN}[+] DPKG校验通过${_R}\n"
            fi
        fi
    fi

    # 2. 检查includes.h中的后门特征
    echo -e "  ${_RED}> 检查OpenSSH后门特征文件${_R}"
    for inc_dir in /usr/include/ /usr/local/include/; do
        if [ -f "${inc_dir}includes.h" ]; then
            if grep -q 'ILOG\|OLOG\|SECRETPW' "${inc_dir}includes.h" 2>/dev/null; then
                printf "  ${_RED}[!] 发现OpenSSH后门特征: %s${_R}\n" "${inc_dir}includes.h"
                grep -E 'ILOG|OLOG|SECRETPW' "${inc_dir}includes.h" 2>/dev/null | sed 's/^/    /'
                found=$((found+1))
            fi
        fi
    done

    # 3. 检查密码记录文件
    for logfile in /tmp/1.txt /tmp/2.txt; do
        if [ -f "$logfile" ]; then
            printf "  ${_RED}[!] 发现SSH密码记录文件: %s${_R}\n" "$logfile"
            found=$((found+1))
        fi
    done

    [ $found -eq 0 ] && printf "  ${_GREEN}[+] 未发现OpenSSH后门特征${_R}\n"
    echo
}

# PAM后门检测
_func_pam_backdoor() {
    echo -e "${_RED}> PAM后门检测${_R}"
    local found=0

    # 1. 检查pam_unix.so修改时间
    for pam_so in /lib/security/pam_unix.so /lib64/security/pam_unix.so; do
        if [ -f "$pam_so" ]; then
            local pam_stat=$(stat -c '%s %y' "$pam_so" 2>/dev/null)
            printf "  %s\n" "$pam_so"
            printf "  大小/修改时间: %s\n" "$pam_stat"

            # 包管理器验证
            if command -v rpm >/dev/null 2>&1; then
                local rpm_check=$(rpm -V pam 2>/dev/null)
                if [ -n "$rpm_check" ]; then
                    printf "  ${_ORANGE}[!] PAM RPM校验不一致:${_R}\n"
                    echo "  $rpm_check"
                    found=$((found+1))
                fi
            elif command -v dpkg >/dev/null 2>&1; then
                local dpkg_check=$(dpkg -V libpam-modules 2>/dev/null)
                if [ -n "$dpkg_check" ]; then
                    printf "  ${_ORANGE}[!] PAM DPKG校验不一致:${_R}\n"
                    echo "  $dpkg_check"
                    found=$((found+1))
                fi
            fi
        fi
    done

    # 2. 检查/etc/pam.d/ 下配置文件修改时间
    echo -e "  ${_RED}> /etc/pam.d/ 配置文件修改时间${_R}"
    for f in /etc/pam.d/*; do
        [ -f "$f" ] || continue
        local mtime=$(stat -c '%Y %y' "$f" 2>/dev/null)
        local ts=$(echo "$mtime" | awk '{print $1}')
        # 检查最近30天内修改的pam配置
        local now=$(date +%s)
        local diff=$(( (now - ts) / 86400 ))
        if [ "$diff" -lt 30 ]; then
            printf "  ${_YELLOW}[?] 最近修改(%dd): %s  修改时间: %s${_R}\n" "$diff" "$f" "$(echo $mtime | awk '{print $2}')"
        fi
    done

    [ $found -eq 0 ] && printf "  ${_GREEN}[+] 未发现PAM后门特征${_R}\n"
    echo
}

# 命令替换检测（盖茨木马/RPM校验）
_func_cmd_replace_check() {
    echo -e "${_RED}> 关键系统命令完整性检查${_R}"
    local found=0

    # 检查关键命令大小是否异常
    for cmd in ps netstat ls ss lsof find; do
        local cmd_path=$(which $cmd 2>/dev/null)
        [ -z "$cmd_path" ] && continue
        local cmd_size=$(ls -l "$cmd_path" 2>/dev/null | awk '{print $5}')
        printf "  %-8s -> %-30s 大小: %s\n" "$cmd" "$cmd_path" "$cmd_size"
    done
    echo

    # RPM check
    echo -e "  ${_RED}> RPM/DPKG 全量校验${_R}"
    if command -v rpm >/dev/null 2>&1; then
        local rpm_va=$(rpm -Va 2>/dev/null | grep -E '^..5' | head -30)
        if [ -n "$rpm_va" ]; then
            printf "  ${_ORANGE}[!] 以下包文件被修改 (5=MD5变化):${_R}\n"
            echo "$rpm_va" | sed 's/^/    /'
            found=$((found+1))
        else
            printf "  ${_GREEN}[+] RPM校验通过${_R}\n"
        fi
    elif command -v debsums >/dev/null 2>&1; then
        local deb_check=$(debsums -c 2>/dev/null | head -30)
        if [ -n "$deb_check" ]; then
            printf "  ${_ORANGE}[!] 以下包文件被修改:${_R}\n"
            echo "$deb_check" | sed 's/^/    /'
            found=$((found+1))
        else
            printf "  ${_GREEN}[+] debsums校验通过${_R}\n"
        fi
    else
        printf "  ${_WAR} 无可用包管理器校验工具${_R}\n"
    fi
    echo

    # 盖茨木马特征检测
    echo -e "  ${_RED}> 盖茨木马特征检测${_R}"
    local gates_found=0
    # 检查可疑启动项
    for rc_dir in /etc/rc.d/rc1.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc.d/rc4.d /etc/rc.d/rc5.d; do
        for f in S97DbSecurity* S99selinux; do
            if ls "$rc_dir/$f" 2>/dev/null >/dev/null; then
                printf "  ${_RED}[!] 发现盖茨木马启动项: %s/%s${_R}\n" "$rc_dir" "$f"
                gates_found=$((gates_found+1))
            fi
        done
    done
    # 检查可疑目录
    for gdir in /usr/bin/bsd-port /usr/bin/dpkgd; do
        if [ -d "$gdir" ]; then
            printf "  ${_RED}[!] 发现盖茨木马目录: %s${_R}\n" "$gdir"
            ls -la "$gdir" 2>/dev/null | sed 's/^/    /'
            gates_found=$((gates_found+1))
        fi
    done
    # 检查可疑init脚本
    for gfile in /etc/rc.d/init.d/DbSecuritySpt /etc/rc.d/init.d/selinux; do
        if [ -f "$gfile" ]; then
            printf "  ${_RED}[!] 发现盖茨木马init脚本: %s${_R}\n" "$gfile"
            gates_found=$((gates_found+1))
        fi
    done
    # 检查隐藏sshd
    if [ -f /usr/bin/.sshd ]; then
        printf "  ${_RED}[!] 发现盖茨木马后门: /usr/bin/.sshd${_R}\n"
        gates_found=$((gates_found+1))
    fi
    [ $gates_found -eq 0 ] && printf "  ${_GREEN}[+] 未发现盖茨木马特征${_R}\n"
    echo

    [ $found -eq 0 ] && [ $gates_found -eq 0 ] && printf "  ${_GREEN}[+] 关键命令完整性检查通过${_R}\n"
}

# libprocesshider / 隐藏进程检测
_func_hidden_process_check() {
    echo -e "${_RED}> 隐藏进程检测 (libprocesshider/unhide)${_R}"

    # 已有ld.so.preload检测，增强：检查常见隐藏库
    if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
        echo -e "  ${_ORANGE}[!] /etc/ld.so.preload 非空，内容:${_R}"
        cat /etc/ld.so.preload | sed 's/^/    /'
        # 检查是否包含libprocesshider
        grep -qi 'processhider\|libprocesshider' /etc/ld.so.preload 2>/dev/null && \
            printf "  ${_RED}[!] 检测到 libprocesshider 特征！${_R}\n"
    fi

    # 使用unhide检测隐藏进程
    if command -v unhide >/dev/null 2>&1; then
        echo -e "  ${_CYAN}[*] 使用 unhide 检测隐藏进程...${_R}"
        unhide proc 2>/dev/null | head -30
        echo -e "  ${_CYAN}[*] 使用 unhide 检测隐藏端口...${_R}"
        unhide tcp 2>/dev/null | head -20
    else
        printf "  ${_WAR} unhide 未安装，建议安装: apt install unhide / yum install unhide${_R}\n"
    fi
    echo
}

# 完整后门检测函数（交互式显示用）
function fk_backdoor_check
{
    _print_bar "后门检测（手册第3章）"
    _func_suid_sgid_scan
    _func_capabilities_scan
    _func_ssh_softlink_backdoor
    _func_openssh_backdoor
    _func_pam_backdoor
    _func_cmd_replace_check
    _func_hidden_process_check
}

# --------------------------------------
#        | 认证增强 |
# --------------------------------------

# sshd_config 安全审计
_func_sshd_config_audit() {
    echo -e "${_RED}> sshd_config 安全审计${_R}"
    local sshd_conf="/etc/ssh/sshd_config"
    if [ ! -f "$sshd_conf" ]; then
        printf "  ${_WAR} $sshd_conf 不存在${_R}\n"
        return
    fi

    local keys="PermitRootLogin PasswordAuthentication PubkeyAuthentication UsePAM Port AllowUsers DenyUsers PermitEmptyPasswords MaxAuthTries"
    for key in $keys; do
        local val=$(grep -E "^\s*${key}" "$sshd_conf" 2>/dev/null | head -1 | awk '{print $2}')
        if [ -z "$val" ]; then
            val="(未配置/默认)"
        fi
        # 安全建议
        case "$key" in
            PermitRootLogin)
                [ "$val" = "yes" ] && val="${val} ${_ORANGE}[!风险]${_R}"
                [ "$val" = "no" ] || [ "$val" = "prohibit-password" ] && val="${val} ${_GREEN}[安全]${_R}"
                ;;
            PasswordAuthentication)
                [ "$val" = "yes" ] && val="${val} ${_ORANGE}[!风险]${_R}"
                [ "$val" = "no" ] && val="${val} ${_GREEN}[安全]${_R}"
                ;;
            PermitEmptyPasswords)
                [ "$val" = "yes" ] && val="${val} ${_RED}[!!高危]${_R}"
                ;;
        esac
        printf "  %-26s %b\n" "$key" "$val"
    done
    echo
}

# authorized_keys 审计
_func_authorized_keys_audit() {
    echo -e "${_RED}> authorized_keys 审计${_R}"
    find / -name authorized_keys -exec sh -c '
        f="$1"
        printf "  === %s ===\n" "$f"
        stat -c "  修改时间: %y  权限: %a  所有者: %U:%G" "$f" 2>/dev/null
        echo "  内容行数: $(wc -l < "$f" 2>/dev/null)"
        head -5 "$f" 2>/dev/null | sed "s/^/    /"
    ' _ {} \; 2>/dev/null | grep -v '/proc'
    echo
}

# Shadow文件完整性
_func_shadow_integrity() {
    echo -e "${_RED}> Shadow文件完整性 - 空密码/弱密码账号${_R}"
    if [ -f /etc/shadow ] && [ -r /etc/shadow ]; then
        local empty=$(awk -F: '$2==""' /etc/shadow 2>/dev/null)
        local locked=$(awk -F: '$2=="!"||$2=="*"||$2=="!!"' /etc/shadow 2>/dev/null)
        if [ -n "$empty" ]; then
            printf "  ${_RED}[!!] 空密码账号（极度危险）:${_R}\n"
            echo "$empty" | awk -F: '{printf "    %-20s %s\n", $1, $2}' | sed 's/^/    /'
        else
            printf "  ${_GREEN}[+] 无空密码账号${_R}\n"
        fi
        if [ -n "$locked" ]; then
            local locked_count=$(echo "$locked" | wc -l)
            printf "  ${_YELLOW}[?] 锁定/禁用账号: %d个${_R}\n" "$locked_count"
        fi
    else
        printf "  ${_WAR} 无法读取 /etc/shadow（需要root权限）${_R}\n"
    fi
    echo
}

# 认证增强（交互式显示用）
function fk_auth_enhanced
{
    _print_bar "认证安全增强"
    _func_sshd_config_audit
    _func_authorized_keys_audit
    _func_shadow_integrity
}

# --------------------------------------
#        | 服务与启动项补全 |
# --------------------------------------

_func_anacron_check() {
    echo -e "${_RED}> anacron 任务${_R}"
    if [ -f /etc/anacrontab ]; then
        grep -vE '^\s*#|^\s*$' /etc/anacrontab 2>/dev/null
    else
        echo "  /etc/anacrontab 不存在"
    fi
    echo -e "  ${_RED}> /var/spool/anacron/${_R}"
    ls -la /var/spool/anacron/ 2>/dev/null || echo "  (不存在)"
    for f in /var/spool/anacron/*; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f" 2>/dev/null
    done
    echo
}

_func_xinetd_inetd_check() {
    echo -e "${_RED}> xinetd 服务${_R}"
    if [ -d /etc/xinetd.d ]; then
        ls -la /etc/xinetd.d/ 2>/dev/null
        for f in /etc/xinetd.d/*; do
            [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
        done
    else
        echo "  /etc/xinetd.d/ 不存在"
    fi
    echo -e "  ${_RED}> inetd 服务${_R}"
    if [ -f /etc/inetd.conf ]; then
        grep -vE '^\s*#|^\s*$' /etc/inetd.conf 2>/dev/null
    else
        echo "  /etc/inetd.conf 不存在"
    fi
    echo
}

_func_cron_full_check() {
    echo -e "${_RED}> /var/spool/cron/ 全部用户crontab${_R}"
    for f in /var/spool/cron/*; do
        [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
    done
    for f in /var/spool/cron/crontabs/*; do
        [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
    done
    echo

    echo -e "${_RED}> /etc/crontab${_R}"
    grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null || echo "  (空)"
    echo

    echo -e "${_RED}> /etc/cron.d/${_R}"
    for f in /etc/cron.d/*; do
        [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
    done
    echo

    for period in daily hourly monthly weekly; do
        local dir="/etc/cron.${period}"
        if [ -d "$dir" ]; then
            echo -e "${_RED}> $dir/${_R}"
            for f in "$dir"/*; do
                [ -f "$f" ] && echo "--- $f ---" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
            done
            echo
        fi
    done
}

# 服务与启动项补全（交互式显示用）
function fk_service_startup_enhanced
{
    _print_bar "服务与启动项（补全）"
    _func_anacron_check
    _func_xinetd_inetd_check
    _func_cron_full_check
}

# --------------------------------------
#        | 日志分析增强 |
# --------------------------------------

# Web日志异常提取
_func_web_log_analysis() {
    echo -e "${_RED}> Web日志异常提取${_R}"

    local web_logs=()
    # nginx
    for f in /var/log/nginx/access.log /var/log/nginx/access.log.1; do
        [ -f "$f" ] && web_logs+=("$f")
    done
    # apache
    for f in /var/log/apache2/access.log /var/log/httpd/access_log /var/log/apache2/access.log.1; do
        [ -f "$f" ] && web_logs+=("$f")
    done

    if [ ${#web_logs[@]} -eq 0 ]; then
        printf "  ${_WAR} 未找到Web访问日志${_R}\n"
        return
    fi

    for logf in "${web_logs[@]}"; do
        echo -e "  ${_CYAN}[*] 分析: $logf${_R}"

        # Top IP
        echo "  [Top 10 源IP]"
        awk '{print $1}' "$logf" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "    %-18s %s次\n", $2, $1}'

        # Top URL
        echo "  [Top 10 URL]"
        awk '{print $7}' "$logf" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "    %-60s %s次\n", $2, $1}'

        # 4xx/5xx 统计
        echo "  [4xx/5xx 状态码统计]"
        awk '{print $9}' "$logf" 2>/dev/null | grep -E '^[45]' | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "    %s: %s次\n", $2, $1}'

        # 可疑请求（SQL注入/XSS/路径遍历）
        echo "  [可疑请求]"
        grep -iE '(union.*select|%27|%22|\.\./|\.\.\\\\|/etc/passwd|/proc/self|cmd=|exec=|eval\(|base64_)' "$logf" 2>/dev/null | tail -20 | sed 's/^/    /'
        echo
    done
}

# 数据库日志检查
_func_db_log_check() {
    echo -e "${_RED}> 数据库日志检查${_R}"

    # MySQL
    echo -e "  ${_CYAN}[*] MySQL${_R}"
    local mysql_conf="/etc/mysql/my.cnf /etc/my.cnf"
    for cf in $mysql_conf; do
        if [ -f "$cf" ]; then
            echo "  配置文件: $cf"
            # 查找日志路径
            grep -E '(log|slow_query|general_log)' "$cf" 2>/dev/null | grep -v '^#' | sed 's/^/    /'
        fi
    done
    # 常见MySQL日志路径
    for ml in /var/log/mysql/error.log /var/log/mysql/slow.log /var/log/mysql/mysql.log /var/lib/mysql/*.err; do
        if [ -f "$ml" ]; then
            printf "  ${_YELLOW}[?] 发现MySQL日志: %s (%s)${_R}\n" "$ml" "$(ls -lh "$ml" 2>/dev/null | awk '{print $5}')"
        fi
    done

    # PostgreSQL
    echo -e "  ${_CYAN}[*] PostgreSQL${_R}"
    for pg_log_dir in /var/log/postgresql/ /var/lib/pgsql/data/log/; do
        if [ -d "$pg_log_dir" ]; then
            echo "  日志目录: $pg_log_dir"
            ls -lh "$pg_log_dir" 2>/dev/null | head -10 | sed 's/^/    /'
        fi
    done
    echo
}

# lastb 暴力破解统计
_func_lastb_bruteforce() {
    echo -e "${_RED}> lastb 暴力破解统计（失败登录源IP TOP20）${_R}"
    if command -v lastb >/dev/null 2>&1; then
        lastb 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -20 | \
            awk '{printf "  [%s] %-18s %s次\n", ($1>100?"🔴":"🟡"), $2, $1}'
    else
        printf "  ${_WAR} lastb 命令不可用${_R}\n"
    fi
    echo
}

# 日志分析增强（交互式显示用）
function fk_log_analysis_enhanced
{
    _print_bar "日志分析增强"
    _func_web_log_analysis
    _func_db_log_check
    _func_lastb_bruteforce
}

# --------------------------------------
#        | 文件系统增强 |
# --------------------------------------

# 最近修改的系统文件
_func_recent_system_files() {
    echo -e "${_RED}> 最近3天修改的系统文件 (/etc /usr/bin /usr/sbin)${_R}"
    find /etc /usr/bin /usr/sbin -mtime -3 -type f 2>/dev/null | while read f; do
        local mt=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
        printf "  %s  %s\n" "$mt" "$f"
    done | sort -r | head -100
    echo
}

# /tmp 和 /dev/shm 下的可执行文件（含hash）
_func_tmp_shm_executables() {
    echo -e "${_RED}> /tmp /var/tmp /dev/shm 可执行文件（含hash）${_R}"
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | while read f; do
        local sz=$(ls -lh "$f" 2>/dev/null | awk '{print $5}')
        local mt=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
        local hash=""
        if command -v sha256sum >/dev/null 2>&1; then
            hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        elif command -v md5sum >/dev/null 2>&1; then
            hash=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        fi
        printf "  ${_ORANGE}[!] %-50s 大小:%-8s 修改:%s hash:%s${_R}\n" "$f" "$sz" "$mt" "$hash"
    done
    echo
}

# 文件系统增强（交互式显示用）
function fk_filesystem_enhanced
{
    _print_bar "文件系统增强"
    _func_recent_system_files
    _func_tmp_shm_executables
}

# --------------------------------------
#        | IR 全量取证收集 |
# --------------------------------------

function fk_ir_collect
{
    local COLLECT_DIR="$1"
    _IR_LOG="$COLLECT_DIR/collection.log"

    echo "[=== 取证收集开始 $(date) ===]" | tee -a "$_IR_LOG"
    echo "主机: $(hostname) | 内核: $(uname -r) | 收集者: $(whoami)" >> "$_IR_LOG"

    # ===== 1. 网络（最易失） =====
    echo -e "${_CYAN}[1/9] 收集网络连接信息（最易失）...${_R}"
    _ir_run "netstat" "netstat -antulp" "$COLLECT_DIR/1_volatile/netstat.txt"
    _ir_run "ss" "ss -antulp" "$COLLECT_DIR/1_volatile/ss.txt"
    _ir_run "arp" "arp -a" "$COLLECT_DIR/1_volatile/arp.txt"
    _ir_run "route" "ip route" "$COLLECT_DIR/1_volatile/route.txt"
    _ir_run "/proc/net/tcp" "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null" "$COLLECT_DIR/1_volatile/proc_net_tcp.txt"
    _ir_run "/proc/net/udp" "cat /proc/net/udp /proc/net/udp6 2>/dev/null" "$COLLECT_DIR/1_volatile/proc_net_udp.txt"
    _ir_run "iptables" "iptables -L -n -v 2>/dev/null" "$COLLECT_DIR/1_volatile/iptables.txt"

    # ===== 2. 进程（高易失） =====
    echo -e "${_CYAN}[2/9] 收集进程信息（高易失）...${_R}"
    _ir_run "ps_aux" "ps auxww" "$COLLECT_DIR/1_volatile/processes.txt"
    _ir_run "ps_ef" "ps -ef" "$COLLECT_DIR/1_volatile/ps_ef.txt"
    _ir_run "lsof" "lsof +c 15 2>/dev/null" "$COLLECT_DIR/1_volatile/lsof.txt"
    _ir_run "top" "top -bn1" "$COLLECT_DIR/1_volatile/top.txt"

    echo -e "${_CYAN}  深度采集 /proc ...${_R}"
    > "$COLLECT_DIR/1_volatile/proc_exe_links.txt"
    > "$COLLECT_DIR/1_volatile/proc_maps.txt"
    > "$COLLECT_DIR/1_volatile/proc_environ.txt"
    > "$COLLECT_DIR/1_volatile/proc_fd.txt"
    > "$COLLECT_DIR/1_volatile/proc_cmdline.txt"

    for pid_path in /proc/[0-9]*; do
        local p=${pid_path##*/}
        echo "=== PID $p ===" >> "$COLLECT_DIR/1_volatile/proc_exe_links.txt"
        ls -l /proc/$p/exe 2>/dev/null >> "$COLLECT_DIR/1_volatile/proc_exe_links.txt"
        echo "=== PID $p ===" >> "$COLLECT_DIR/1_volatile/proc_maps.txt"
        cat /proc/$p/maps 2>/dev/null >> "$COLLECT_DIR/1_volatile/proc_maps.txt"
        echo "=== PID $p ===" >> "$COLLECT_DIR/1_volatile/proc_environ.txt"
        cat /proc/$p/environ 2>/dev/null | tr '\0' '\n' >> "$COLLECT_DIR/1_volatile/proc_environ.txt"
        echo "=== PID $p ===" >> "$COLLECT_DIR/1_volatile/proc_fd.txt"
        ls -l /proc/$p/fd 2>/dev/null >> "$COLLECT_DIR/1_volatile/proc_fd.txt"
        echo "=== PID $p ===" >> "$COLLECT_DIR/1_volatile/proc_cmdline.txt"
        cat /proc/$p/cmdline 2>/dev/null | tr '\0' ' ' >> "$COLLECT_DIR/1_volatile/proc_cmdline.txt"
        echo >> "$COLLECT_DIR/1_volatile/proc_cmdline.txt"
    done

    # ===== 3. 账号 =====
    echo -e "${_CYAN}[3/9] 收集账号信息...${_R}"
    _ir_run "passwd" "cat /etc/passwd" "$COLLECT_DIR/2_accounts/passwd.txt"
    _ir_run "shadow" "cat /etc/shadow 2>/dev/null" "$COLLECT_DIR/2_accounts/shadow.txt"
    _ir_run "group" "cat /etc/group" "$COLLECT_DIR/2_accounts/group.txt"
    _ir_run "last" "last -i" "$COLLECT_DIR/2_accounts/last.txt"
    _ir_run "lastlog" "lastlog" "$COLLECT_DIR/2_accounts/lastlog.txt"
    _ir_run "who" "who -a" "$COLLECT_DIR/2_accounts/who.txt"
    _ir_run "UID0" "awk -F: '\$3==0{print \$1}' /etc/passwd" "$COLLECT_DIR/2_accounts/uid0_accounts.txt"
    _ir_run "sudoers" "cat /etc/sudoers 2>/dev/null" "$COLLECT_DIR/2_accounts/sudoers.txt"
    _ir_run "ssh_keys" "find / -name authorized_keys -exec ls -la {} \\; -exec cat {} \\; 2>/dev/null" "$COLLECT_DIR/2_accounts/ssh_authorized_keys.txt"
    _ir_run "empty_password" "awk -F: '\$2==\"\"' /etc/shadow 2>/dev/null" "$COLLECT_DIR/2_accounts/empty_password_accounts.txt"
    _ir_run "sshd_config" "grep -E '^\\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|UsePAM|Port|AllowUsers|DenyUsers|PermitEmptyPasswords|MaxAuthTries)' /etc/ssh/sshd_config 2>/dev/null" "$COLLECT_DIR/2_accounts/sshd_config_audit.txt"
    _ir_run "lastb" "lastb 2>/dev/null | head -200" "$COLLECT_DIR/2_accounts/lastb.txt"

    # ===== 4. 持久化 =====
    echo -e "${_CYAN}[4/9] 收集持久化机制...${_R}"
    _ir_run "crontab_root" "crontab -l 2>/dev/null" "$COLLECT_DIR/3_persistence/crontab_root.txt"
    _ir_run "crontab_system" "cat /etc/crontab" "$COLLECT_DIR/3_persistence/crontab_system.txt"
    _ir_run "cron_d" "ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null" "$COLLECT_DIR/3_persistence/cron_d.txt"
    _ir_run "cron_daily" "ls -la /etc/cron.daily/ 2>/dev/null && cat /etc/cron.daily/* 2>/dev/null" "$COLLECT_DIR/3_persistence/cron_daily.txt"
    _ir_run "cron_hourly" "ls -la /etc/cron.hourly/ 2>/dev/null && cat /etc/cron.hourly/* 2>/dev/null" "$COLLECT_DIR/3_persistence/cron_hourly.txt"
    _ir_run "cron_monthly" "ls -la /etc/cron.monthly/ 2>/dev/null && cat /etc/cron.monthly/* 2>/dev/null" "$COLLECT_DIR/3_persistence/cron_monthly.txt"
    _ir_run "cron_weekly" "ls -la /etc/cron.weekly/ 2>/dev/null && cat /etc/cron.weekly/* 2>/dev/null" "$COLLECT_DIR/3_persistence/cron_weekly.txt"
    _ir_run "var_spool_cron" "ls -laR /var/spool/cron/ 2>/dev/null && cat /var/spool/cron/crontabs/* 2>/dev/null && cat /var/spool/cron/* 2>/dev/null" "$COLLECT_DIR/3_persistence/var_spool_cron.txt"
    _ir_run "anacrontab" "cat /etc/anacrontab 2>/dev/null" "$COLLECT_DIR/3_persistence/anacrontab.txt"
    _ir_run "anacron_spool" "ls -la /var/spool/anacron/ 2>/dev/null && cat /var/spool/anacron/* 2>/dev/null" "$COLLECT_DIR/3_persistence/anacron_spool.txt"
    _ir_run "xinetd" "ls -la /etc/xinetd.d/ 2>/dev/null && cat /etc/xinetd.d/* 2>/dev/null" "$COLLECT_DIR/3_persistence/xinetd.txt"
    _ir_run "inetd" "cat /etc/inetd.conf 2>/dev/null" "$COLLECT_DIR/3_persistence/inetd.txt"
    _ir_run "systemd_enabled" "systemctl list-unit-files --state=enabled 2>/dev/null" "$COLLECT_DIR/3_persistence/systemd_enabled.txt"
    _ir_run "systemd_running" "systemctl list-units --type=service --state=running 2>/dev/null" "$COLLECT_DIR/3_persistence/systemd_running.txt"
    _ir_run "initd" "ls -la /etc/init.d/ 2>/dev/null" "$COLLECT_DIR/3_persistence/initd.txt"
    _ir_run "rc_local" "cat /etc/rc.local 2>/dev/null" "$COLLECT_DIR/3_persistence/rc_local.txt"
    _ir_run "rc3d_gates" "ls -la /etc/rc.d/rc3.d/ 2>/dev/null" "$COLLECT_DIR/3_persistence/rc3d.txt"
    _ir_run "profile_d" "ls -la /etc/profile.d/ 2>/dev/null && cat /etc/profile.d/*.sh 2>/dev/null" "$COLLECT_DIR/3_persistence/profile_d.txt"
    _ir_run "ld_so_preload" "cat /etc/ld.so.preload 2>/dev/null" "$COLLECT_DIR/3_persistence/ld_so_preload.txt"
    _ir_run "ld_so_conf" "cat /etc/ld.so.conf 2>/dev/null && cat /etc/ld.so.conf.d/* 2>/dev/null" "$COLLECT_DIR/3_persistence/ld_so_conf.txt"
    _ir_run "systemd_timers" "systemctl list-timers --all 2>/dev/null" "$COLLECT_DIR/3_persistence/systemd_timers.txt"

    # ===== 4b. 持久化增强项（v8.1+ 新增） =====
    echo -e "${_CYAN}  持久化增强检测（v8.1+）...${_R}"

    # 用户级 bashrc/profile 劫持
    _ir_run "bashrc_profile" \
      "for u in /root /home/*; do echo \"=== \$u/.bashrc ===\"; cat \$u/.bashrc 2>/dev/null; echo \"=== \$u/.profile ===\"; cat \$u/.profile 2>/dev/null; echo \"=== \$u/.zshrc ===\"; cat \$u/.zshrc 2>/dev/null; done" \
      "$COLLECT_DIR/3_persistence/bashrc_profile.txt"

    # 用户级 systemd 用户服务
    _ir_run "user_systemd" \
      "for u in /root /home/*; do ls -laR \"\$u/.config/systemd/user/\" 2>/dev/null; done" \
      "$COLLECT_DIR/3_persistence/user_systemd.txt"

    # 内核模块持久化
    _ir_run "modules_load" \
      "cat /etc/modules-load.d/*.conf 2>/dev/null; cat /etc/modules 2>/dev/null; ls /etc/modprobe.d/*.conf 2>/dev/null" \
      "$COLLECT_DIR/3_persistence/modules_load.txt"

    # XDG 自动启动
    _ir_run "xdg_autostart" \
      "ls -la /etc/xdg/autostart/ 2>/dev/null; for u in /root /home/*; do ls -la \"\$u/.config/autostart/\" 2>/dev/null; done" \
      "$COLLECT_DIR/3_persistence/xdg_autostart.txt"

    # 包管理器 hook 劫持
    _ir_run "pkg_hooks" \
      "ls -la /etc/apt/apt.conf.d/ 2>/dev/null; ls -la /etc/yum.repos.d/ 2>/dev/null; ls -la /etc/dnf/dnf.conf 2>/dev/null" \
      "$COLLECT_DIR/3_persistence/pkg_hooks.txt"


    # ===== 5. 系统 =====
    echo -e "${_CYAN}[5/9] 收集系统信息...${_R}"
    _ir_run "system_info" "uname -a && hostname && cat /etc/os-release && date && uptime" "$COLLECT_DIR/5_system/system_info.txt"
    _ir_run "dmesg" "dmesg 2>/dev/null | tail -100" "$COLLECT_DIR/5_system/dmesg.txt"
    _ir_run "mount" "mount" "$COLLECT_DIR/5_system/mount.txt"
    _ir_run "lsmod" "lsmod" "$COLLECT_DIR/5_system/lsmod.txt"
    _ir_run "env" "env" "$COLLECT_DIR/5_system/env.txt"
    _ir_run "docker_ps" "docker ps -a 2>/dev/null" "$COLLECT_DIR/5_system/docker_ps.txt"
    _ir_run "kube_pods" "kubectl get pods -A 2>/dev/null" "$COLLECT_DIR/5_system/kube_pods.txt"

    # ===== 6. 文件/权限 =====
    echo -e "${_CYAN}[6/9] 收集文件与权限信息...${_R}"
    _ir_run "suid" "find / -perm -4000 -type f 2>/dev/null" "$COLLECT_DIR/4_backdoor/suid_files.txt"
    _ir_run "sgid" "find / -perm -2000 -type f 2>/dev/null" "$COLLECT_DIR/4_backdoor/sgid_files.txt"
    _ir_run "world_writable" "find / -perm -o+w -type f 2>/dev/null | head -500" "$COLLECT_DIR/7_filesystem/world_writable.txt"
    _ir_run "tmp_exec" "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null" "$COLLECT_DIR/7_filesystem/tmp_executable.txt"
    _ir_run "tmp_exec_hash" "find /tmp /var/tmp /dev/shm -type f -executable -exec sha256sum {} \\; 2>/dev/null" "$COLLECT_DIR/7_filesystem/tmp_executable_hash.txt"
    _ir_run "hidden_dirs" "find / -name '.*' -type d 2>/dev/null | grep -v '/proc\|/sys\|\.pnpm\|node_modules\|\.git\|\.cache\|\.github' | head -200" "$COLLECT_DIR/7_filesystem/hidden_dirs.txt"
    _ir_run "recent_modified" "find / -type f -mtime -3 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run' | head -500" "$COLLECT_DIR/7_filesystem/recent_modified.txt"
    _ir_run "recent_system_modified" "find /etc /usr/bin /usr/sbin -mtime -3 -type f 2>/dev/null" "$COLLECT_DIR/7_filesystem/recent_system_modified.txt"
    _ir_run "capabilities" "getcap -r / 2>/dev/null" "$COLLECT_DIR/4_backdoor/capabilities.txt"
    _ir_run "rpm_verify" "rpm -Va 2>/dev/null | head -100" "$COLLECT_DIR/4_backdoor/rpm_verify.txt"
    _ir_run "debsums_check" "debsums -c 2>/dev/null | head -100" "$COLLECT_DIR/4_backdoor/debsums_check.txt"
    _ir_run "gates_trojan" "ls -la /etc/rc.d/rc3.d/S97* /etc/rc.d/init.d/DbSecurity* /etc/rc.d/init.d/selinux /usr/bin/bsd-port /usr/bin/dpkgd /usr/bin/.sshd 2>/dev/null" "$COLLECT_DIR/4_backdoor/gates_trojan.txt"
    _ir_run "unhide" "unhide proc 2>/dev/null; unhide tcp 2>/dev/null" "$COLLECT_DIR/4_backdoor/unhide.txt"
    _ir_run "ssh_softlink" "ls -la /tmp/su /tmp/chsh /tmp/chfn /dev/shm/su 2>/dev/null" "$COLLECT_DIR/4_backdoor/ssh_softlink.txt"
    _ir_run "openssh_integrity" "stat /usr/sbin/sshd 2>/dev/null; rpm -Vf /usr/sbin/sshd 2>/dev/null; dpkg -V openssh-server 2>/dev/null" "$COLLECT_DIR/4_backdoor/openssh_integrity.txt"
    _ir_run "pam_integrity" "stat /lib64/security/pam_unix.so /lib/security/pam_unix.so 2>/dev/null; rpm -V pam 2>/dev/null; dpkg -V libpam-modules 2>/dev/null" "$COLLECT_DIR/4_backdoor/pam_integrity.txt"

    # ===== 7. Web/日志 =====
    echo -e "${_CYAN}[7/9] 收集Web与日志信息...${_R}"
    _ir_run "web_dirs" "ls -laR /var/www/ 2>/dev/null | head -500" "$COLLECT_DIR/6_logs/web_directory.txt"
    _ir_run "web_wwwroot" "ls -laR /www/wwwroot/ 2>/dev/null | head -500" "$COLLECT_DIR/6_logs/web_wwwroot.txt"
    _ir_run "nginx_conf" "cat /etc/nginx/nginx.conf 2>/dev/null" "$COLLECT_DIR/6_logs/nginx_conf.txt"
    _ir_run "apache_conf" "cat /etc/httpd/conf/httpd.conf 2>/dev/null; cat /etc/apache2/apache2.conf 2>/dev/null" "$COLLECT_DIR/6_logs/apache_conf.txt"
    _ir_run "nginx_access_top_ip" "awk '{print \$1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -20" "$COLLECT_DIR/6_logs/nginx_access_top_ip.txt"
    _ir_run "nginx_access_top_url" "awk '{print \$7}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -20" "$COLLECT_DIR/6_logs/nginx_access_top_url.txt"
    _ir_run "nginx_access_errors" "awk '{print \$9}' /var/log/nginx/access.log 2>/dev/null | grep -E '^[45]' | sort | uniq -c | sort -rn | head -10" "$COLLECT_DIR/6_logs/nginx_access_errors.txt"
    _ir_run "apache_access_top_ip" "awk '{print \$1}' /var/log/apache2/access.log /var/log/httpd/access_log 2>/dev/null | sort | uniq -c | sort -rn | head -20" "$COLLECT_DIR/6_logs/apache_access_top_ip.txt"
    _ir_run "apache_access_errors" "awk '{print \$9}' /var/log/apache2/access.log /var/log/httpd/access_log 2>/dev/null | grep -E '^[45]' | sort | uniq -c | sort -rn | head -10" "$COLLECT_DIR/6_logs/apache_access_errors.txt"
    _ir_run "web_suspicious_requests" "grep -iE '(union.*select|%27|%22|\.\./|/etc/passwd|/proc/self|cmd=|exec=|eval\\(|base64_)' /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log 2>/dev/null | tail -50" "$COLLECT_DIR/6_logs/web_suspicious_requests.txt"
    _ir_run "mysql_log" "ls -la /var/log/mysql/ 2>/dev/null; cat /etc/mysql/my.cnf /etc/my.cnf 2>/dev/null | grep -E '(log|slow_query|general_log)'" "$COLLECT_DIR/6_logs/mysql_log.txt"
    _ir_run "postgresql_log" "ls -la /var/log/postgresql/ /var/lib/pgsql/data/log/ 2>/dev/null" "$COLLECT_DIR/6_logs/postgresql_log.txt"

    _ir_run "auth_log" "cat /var/log/auth.log 2>/dev/null" "$COLLECT_DIR/6_logs/auth_log.txt"
    _ir_run "secure_log" "cat /var/log/secure 2>/dev/null" "$COLLECT_DIR/6_logs/secure_log.txt"
    _ir_run "syslog" "cat /var/log/syslog 2>/dev/null | tail -2000" "$COLLECT_DIR/6_logs/syslog.txt"
    _ir_run "messages" "cat /var/log/messages 2>/dev/null | tail -2000" "$COLLECT_DIR/6_logs/messages.txt"
    _ir_run "wtmp" "last -f /var/log/wtmp 2>/dev/null" "$COLLECT_DIR/6_logs/wtmp.txt"
    _ir_run "btmp" "lastb -f /var/log/btmp 2>/dev/null | head -100" "$COLLECT_DIR/6_logs/btmp.txt"
    _ir_run "lastb_bruteforce" "lastb 2>/dev/null | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' | sort | uniq -c | sort -rn | head -30" "$COLLECT_DIR/6_logs/lastb_bruteforce.txt"
    _ir_run "bash_history" "find /home /root -name '.*sh_history' -exec echo '=== {} ===' \\; -exec cat {} \\; 2>/dev/null" "$COLLECT_DIR/6_logs/bash_history.txt"


    # ===== 9. 勒索病毒 + 供应链风险检测（v3.0-switch 新增） =====
    echo -e "${_CYAN}[9/9] 勒索病毒与供应链风险检测...${_R}"

    # 勒索信文件搜索
    _ir_run "ransom_notes" \
      "find /home /root /tmp /opt /var /etc -maxdepth 4 -type f \\
        \\( -iname 'README*.txt' -o -iname 'HowToDecrypt*' -o -iname 'DECRYPT*' \\
           -o -iname 'RECOVERY*' -o -iname 'HELP_DECRYPT*' -o -iname 'FILES_ENCRYPTED*' \\
           -o -iname 'RESTORE*.txt' -o -iname 'INFECTED*' -o -iname 'RECOVER_FILES*' \\
           -o -iname 'HOW_TO_DECRYPT*' \\) 2>/dev/null | head -100" \
      "$COLLECT_DIR/7_filesystem/ransom_notes.txt"

    # 加密扩展名扫描
    _ir_run "encrypted_extensions" \
      "find /home /root /tmp /opt /mnt -maxdepth 5 -type f \\
        \\( -iname '*.phobos' -o -iname '*.mallox' -o -iname '*.hunters' -o -iname '*.hunters2' \\
           -o -iname '*.beast' -o -iname '*.medusalocker' -o -iname '*.babyk' -o -iname '*.sorry' \\
           -o -iname '*.hive' -o -iname '*.encrypted' -o -iname '*.locked' -o -iname '*.cry' \\
           -o -iname '*.onion' -o -iname '*.enc' \\) 2>/dev/null | head -200" \
      "$COLLECT_DIR/7_filesystem/encrypted_extensions.txt"

    # 第三方远程工具检测
    _ir_run "remote_tools" \
      "echo '=== 进程检测 ==='; ps aux 2>/dev/null | grep -iE 'teamviewer|anydesk|splashtop|rustdesk|vnc|tightvnc|ultravnc|nomachine|xrdp' | grep -v grep; \
       echo '=== 端口检测 ==='; ss -tlnp 2>/dev/null | grep -E '5938|7070|2112|2111|4000|590[0-9]' | head -20; \
       echo '=== 安装检测 ==='; which teamviewer anydesk rustdesk vncserver xrdp 2>/dev/null" \
      "$COLLECT_DIR/5_system/remote_tools.txt"

    # 虚拟化/容器环境检测
    _ir_run "vm_check" \
      "echo '=== 虚拟化环境 ==='; systemd-detect-virt 2>/dev/null; \
       echo '=== ESXi检测 ==='; [ -f /etc/vmware/esx.conf ] && cat /etc/vmware/esx.conf 2>/dev/null; \
       echo '=== Docker ==='; docker info 2>/dev/null | head -5; \
       echo '=== 容器标记 ==='; cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|kubepods' | head -5" \
      "$COLLECT_DIR/5_system/virtualization_check.txt"

    # ===== 8. 合并原有输出 =====
    echo -e "${_CYAN}[8/9] 合并原有检测结果...${_R}"
    if [ -d "$OUTPUT" ]; then
        cp -r "$OUTPUT"/* "$COLLECT_DIR/whoamifuck/" 2>/dev/null
    fi

    echo "[=== 取证收集完成 $(date) ===]" | tee -a "$_IR_LOG"
}

# --------------------------------------
#        | IR 打包 |
# --------------------------------------

function fk_irpack
{
    _print_bar "IR证据打包"

    # 检查 root
    if [ "$(id -u)" -ne 0 ]; then
        printf "$_ERR 请使用 root 权限运行 (sudo bash who.sh -q)\n"
        exit 1
    fi

    local IR_DIR_NAME="IR_$(hostname)_$(date +%Y%m%d_%H%M%S)"
    local IR_COLLECT_DIR="$IR_OUTPUT_DIR/$IR_DIR_NAME"
    local ARCHIVE_PATH="$IR_OUTPUT_DIR/$IR_ARCHIVE"

    echo "正在创建IR证据目录: $IR_COLLECT_DIR"
    mkdir -p "$IR_COLLECT_DIR"/{1_volatile,2_accounts,3_persistence,4_backdoor,5_system,6_logs,7_filesystem,whoamifuck}

    echo -e "${_YELLOW}正在执行全量取证收集（按挥发性排序）...${_R}"
    fk_ir_collect "$IR_COLLECT_DIR"

    # 打包
    echo "正在打包压缩文件..."
    tar -czf "$ARCHIVE_PATH" -C "$IR_OUTPUT_DIR" "$IR_DIR_NAME"

    # 验证
    if [ ! -f "$ARCHIVE_PATH" ] || [ ! -s "$ARCHIVE_PATH" ]; then
        printf "$_ERR 打包失败！原始证据保留在: $IR_COLLECT_DIR\n"
        exit 1
    fi

    tar -tzf "$ARCHIVE_PATH" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        printf "$_ERR 压缩包损坏！原始证据保留在: $IR_COLLECT_DIR\n"
        rm -f "$ARCHIVE_PATH"
        exit 1
    fi

    # 完整性校验
    echo "正在生成完整性校验..."
    sha256sum "$ARCHIVE_PATH" > "${ARCHIVE_PATH}.sha256"
    md5sum "$ARCHIVE_PATH" > "${ARCHIVE_PATH}.md5"

    # 元数据
    cat > "$IR_OUTPUT_DIR/IR_metadata.txt" << METADATA
IR取证包元数据
===============
主机名: $(hostname)
IP地址: $(hostname -I 2>/dev/null || echo unknown)
内核: $(uname -r)
系统: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
收集时间: $(date '+%Y-%m-%d %H:%M:%S')
收集者: $(whoami)
脚本版本: $VER
文件数: $(find "$IR_COLLECT_DIR" -type f | wc -l)
总大小: $(du -sh "$IR_COLLECT_DIR" 2>/dev/null | cut -f1)
SHA256: $(cat "${ARCHIVE_PATH}.sha256")
MD5: $(cat "${ARCHIVE_PATH}.md5")
METADATA

    # 验证通过后清理
    echo "正在清理临时文件..."
    rm -rf "$IR_COLLECT_DIR"

    printf "\n$_SUC IR证据打包完成！\n"
    printf "  压缩包: ${_GREEN}$ARCHIVE_PATH${_R}\n"
    printf "  大小:   ${_GREEN}$(ls -lh "$ARCHIVE_PATH" | awk '{print $5}')${_R}\n"
    printf "  SHA256: ${_GREEN}${ARCHIVE_PATH}.sha256${_R}\n"
    printf "  MD5:    ${_GREEN}${ARCHIVE_PATH}.md5${_R}\n"
    printf "  元数据: ${_GREEN}$IR_OUTPUT_DIR/IR_metadata.txt${_R}\n"
    echo
    printf "请将 $ARCHIVE_PATH 上传至分析平台进行自动化分析。\n"
}

# --------------------------------------
#        | 主入口 |
# --------------------------------------

function main
{
    if [ $# -eq 0 ]; then
        help_cn
        exit 0
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            -v | --version )    logo; printf "\n${_YELLOW}Version: ${_R}${_GREEN}$VER${_R}\n\n"; exit 0 ;;
            -h | --help )       help_cn; exit 0 ;;
            -u | --user-device) fk_baseinfo; exit 0 ;;
            -l | --login )      FILE="$2"; shift; fk_userlogin; exit 0 ;;
            -n | --nomal )      fk_baseinfo; fk_history; fk_userinfo; exit 0 ;;
            -a | --all )
                fk_portstatus
                fk_procserv
                fk_devicestatus
                fk_baseinfo
                fk_history
                fk_userinfo
                fk_crontab
                fk_service_startup_enhanced
                fk_fileinfo
                fk_filemove
                fk_filesystem_enhanced
                fk_backdoor_check
                fk_auth_enhanced
                fk_log_analysis_enhanced
                fk_wsfinder
                exit 0 ;;
            -x | --proc-serv )  fk_procserv; exit 0 ;;
            -p | --port )       fk_portstatus; exit 0 ;;
            -s | --os-status )  fk_devicestatus; exit 0 ;;
            -b | --baseline )   fk_baseinfo; fk_userinfo; fk_crontab; fk_auth_enhanced; exit 0 ;;
            -r | --risk )       dirty_cow; exit 0 ;;
            -k | --rookitcheck) fk_sshlink; fk_backdoor_check; exit 0 ;;
            -d | --backdoor )   fk_backdoor_check; exit 0 ;;
            -e | --auth )       fk_auth_enhanced; exit 0 ;;
            -w | --webshell )   WEBSHELL_PATH="$2"; shift; fk_wsfinder; exit 0 ;;
            -q | --pack )       fk_irpack; exit 0 ;;
            * )                 printf "$_ERR 未知选项: $1\n\n"; help_cn; exit 1 ;;
        esac
        shift
    done
}

main "$@"
