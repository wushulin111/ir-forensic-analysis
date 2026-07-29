rule Process_Injection_Generic {
    meta:
        description = "Process injection indicators"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1055"

    strings:
        $virtualallocex = "VirtualAllocEx" ascii wide
        $writeprocessmemory = "WriteProcessMemory" ascii wide
        $createremotethread = "CreateRemoteThread" ascii wide
        $openprocess = "OpenProcess" ascii wide
        $ntunmapview = "NtUnmapViewOfSection" ascii wide
        $setthreadcontext = "SetThreadContext" ascii wide
        $resumethread = "ResumeThread" ascii wide
        $queueuserapc = "QueueUserAPC" ascii wide

    condition:
        2 of them
}

rule Reflective_DLL_Injection {
    meta:
        description = "Reflective DLL injection"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1055.001"

    strings:
        $reflective_loader = "ReflectiveLoader" ascii wide
        $loadlibrary = "LoadLibraryA" ascii wide
        $getprocaddress = "GetProcAddress" ascii wide
        $virtualprotect = "VirtualProtect" ascii wide
        $dll_main = "DllMain" ascii wide
        $dll_process_attach = "DLL_PROCESS_ATTACH" ascii wide

    condition:
        $reflective_loader or ($dll_main and $dll_process_attach and 2 of ($loadlibrary, $getprocaddress, $virtualprotect))
}

rule Process_Hollowing {
    meta:
        description = "Process hollowing indicators"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1055.012"

    strings:
        $create_process_suspended = "CREATE_SUSPENDED" ascii wide
        $ntunmap = "NtUnmapViewOfSection" ascii wide
        $write_mem = "WriteProcessMemory" ascii wide
        $set_context = "SetThreadContext" ascii wide
        $resume = "ResumeThread" ascii wide
        $readprocessmemory = "ReadProcessMemory" ascii wide

    condition:
        3 of them
}

rule PowerShell_Download_Execute {
    meta:
        description = "PowerShell download and execute patterns"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1059.001"

    strings:
        $iex = "IEX" ascii wide
        $new_object = "New-Object Net.WebClient" ascii wide nocase
        $downloadstring = "DownloadString" ascii wide
        $invoke_expression = "Invoke-Expression" ascii wide nocase
        $frombase64 = "FromBase64String" ascii wide
        $encoded_cmd = "-enc" ascii wide
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
        $noprofile = "-NoProfile" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase

    condition:
        filesize < 100KB and (
            (1 of ($iex, $invoke_expression) and 1 of ($new_object, $downloadstring)) or
            ($encoded_cmd and 1 of ($bypass, $noprofile, $hidden))
        )
}
