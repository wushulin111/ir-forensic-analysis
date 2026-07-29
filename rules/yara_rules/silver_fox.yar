rule Silver_Fox_Unhooking {
    meta:
        description = "银狐木马ntdll Unhooking - 从磁盘重新读取ntdll.dll覆盖已加载ntdll的.text节，绕过EDR HOOK"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1562.001"
        source = "微步银狐3月报告"

    strings:
        $ntdll_path = "\\ntdll.dll" wide
        $text_section = ".text" ascii
        $lznt1 = "LZNT1" ascii wide
        $rtl_decompress = "RtlDecompressBuffer" ascii wide
        $rtl_decompress2 = "RtlDecompressFragment" ascii wide

    condition:
        2 of them
}

rule Silver_Fox_PoolParty {
    meta:
        description = "银狐木马PoolParty进程注入 - 通过PostQueuedCompletionStatus/ZwSetIoCompletion向线程池注入shellcode"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1055.012"
        source = "微步银狐3月报告"

    strings:
        $post_queued = "PostQueuedCompletionStatus" ascii wide
        $zw_set_io = "ZwSetIoCompletion" ascii wide
        $nt_set_io = "NtSetIoCompletion" ascii wide
        $thread_pool = "TpAllocPool" ascii wide
        $tp_post = "TpPostWork" ascii wide

    condition:
        2 of them
}

rule Silver_Fox_Rootkit_Driver {
    meta:
        description = "银狐自编写内核驱动 - 绕过微软黑名单，关闭杀软/EDR进程"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1014"
        source = "微步银狐3月报告 + 火绒银狐变种分析"

    strings:
        $kabuto = "kabuto" nocase wide
        $kabuto_sys = "kabuto.sys" wide
        $truesight = "TrueSight" nocase wide
        $explorer_pid = "explorer.exe" wide
        $xor_decrypt_1 = { 31 ?? 31 ?? 31 ?? 31 ?? }
        $xor_decrypt_2 = { 32 ?? 32 ?? 32 ?? 32 ?? }

    condition:
        $kabuto or $kabuto_sys or $truesight or (2 of ($xor_decrypt_*))
}

rule Silver_Fox_AV_Kill_Thread {
    meta:
        description = "银狐杀软对抗线程 - While True循环解密进程名发送给内核驱动关闭"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1562.001"
        source = "微步银狐3月报告 + 火绒银狐变种分析"

    strings:
        $proc_360safe = "360Safe.exe" wide
        $proc_360tray = "360tray.exe" wide
        $proc_zhudong = "ZhuDongFangYu.exe" wide
        $proc_360sd = "360sd.exe" wide
        $proc_360rp = "360rp.exe" wide
        $proc_hipsdaemon = "HipsDaemon.exe" wide
        $proc_hipsmain = "HipsMain.exe" wide
        $proc_qhsafe = "QHSafeMain.exe" wide
        $proc_qqpctray = "QQPCTray.exe" wide
        $proc_safedog = "SafeDog.exe" wide
        $proc_rfw = "rfw.exe" wide
        $terminate = "TerminateProcess" ascii wide

    condition:
        3 of ($proc_*) and $terminate
}

rule Silver_Fox_Remote_Shellcode {
    meta:
        description = "银狐远端拉取shellcode - 从远端服务器下载加密shellcode，自定义解密+LZNT1解压后注入svchost"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1059.001"
        source = "微步银狐3月报告 + 深信服银狐分析"

    strings:
        $urlmon = "URLDownloadToFile" ascii wide
        $winhttp = "WinHttpReadData" ascii wide
        $inet_read = "InternetReadFile" ascii wide
        $svchost = "svchost.exe" wide
        $write_mem = "WriteProcessMemory" ascii wide
        $open_proc = "OpenProcess" ascii wide
        $lznt1_decompress = "RtlDecompressBuffer" ascii wide

    condition:
        (1 of ($urlmon, $winhttp, $inet_read)) and $svchost and (1 of ($write_mem, $open_proc))
}

rule Silver_Fox_Phishing_Popup {
    meta:
        description = "银狐钓鱼页面虚假弹窗特征 - '系统版本过低'诱导下载"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1189"
        source = "微步银狐3月报告"

    strings:
        $version_low_cn = "系统版本过低" wide
        $upgrade_cn = "需要升级" wide
        $version_low_en = "version is too low" nocase wide
        $upgrade_en = "needs to be upgraded" nocase wide
        $download_exe = ".exe" wide
        $js_redirect = "window.location" ascii

    condition:
        (1 of ($version_low_*, $upgrade_*)) and $js_redirect
}

rule Silver_Fox_Anti_Sandbox {
    meta:
        description = "银狐反沙箱/反调试 - 使用多种技术规避分析环境检测"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1497.001"
        source = "火绒银狐变种分析"

    strings:
        $pfx_init = "PfxInitialize" ascii wide
        $rdtsc = { 0F 31 }
        $query_perf = "QueryPerformanceCounter" ascii wide
        $get_tick = "GetTickCount64" ascii wide
        $global_mem = "GlobalMemoryStatusEx" ascii wide
        $numa = "VirtualAllocExNuma" ascii wide
        $nt_trace = "NtTraceEvent" ascii wide
        $sxin = "SxIn.dll" ascii wide
        $hal9th = "HAL9TH" ascii wide
        $john_doe = "JohnDoe" ascii wide
        $myapp = ":\\myapp.exe" wide
        $ini_check = "xxxx.ini" wide
        $ctrl_shutdown = "CTRL_SHUTDOWN_EVENT" ascii wide

    condition:
        4 of them
}

rule Silver_Fox_Gh0st_Winos {
    meta:
        description = "银狐远控模块Gh0st/winos变种 - 改写自开源Gh0st木马的远控功能模块"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1071.001"
        source = "百度百科银狐词条 + 微步银狐分析"

    strings:
        $gh0st = "gh0st" nocase wide
        $winos = "winos" nocase
        $sync_create = "SyncCreate" ascii wide
        $keyboard_log = "键盘记录" wide
        $remote_desktop = "远程终端" wide
        $screen_monitor = "屏幕" wide
        $file_manage = "文件管理" wide
        $mutex_dba = "dba8937c-2842-4159-9bea-56424baf5eba" ascii wide
        $mutex_global = "3575D265-2C4F-5C20-EB78-D147D5670A9C" ascii wide

    condition:
        $sync_create or $mutex_dba or $mutex_global or ($gh0st and 1 of ($keyboard_log, $remote_desktop, $screen_monitor, $file_manage))
}

rule Silver_Fox_Multi_Stage_Loader {
    meta:
        description = "银狐多阶段加载器 - 白加黑入口→Shellcode→DLL映射→SyncCreate→驱动→远控"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1059.001"
        source = "火绒银狐变种分析 + 深信服银狐分析"

    strings:
        $sync_create = "SyncCreate" ascii wide
        $runas = "runas" ascii wide
        $shell_exec = "ShellExecuteExA" ascii wide
        $virtual_alloc = "VirtualAlloc" ascii wide
        $create_mutex = "CreateMutexA" ascii wide
        $set_shutdown = "SetProcessShutdownParameters" ascii wide
        $ctrl_handler = "SetConsoleCtrlHandler" ascii wide
        $user_data_svc = "UserDataSvc_" ascii wide

    condition:
        $sync_create or ($user_data_svc) or (2 of ($runas, $shell_exec, $virtual_alloc, $create_mutex, $set_shutdown))
}
