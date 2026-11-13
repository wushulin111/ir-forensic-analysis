# Windows IR collection for Windows PowerShell 2.0 / 3.0
# Full-depth collection. No PowerShell 3+ syntax.
 param(
     [string]$Target = "",
     [switch]$IncludeSensitive,
     [switch]$SkipFileScan,
     [switch]$IncludeSystemDirs,
     [switch]$CaptureProcessMemory,
     [switch]$RecoverClearedLogs,
     [int]$ScanDepth = 5
 )
 $ErrorActionPreference = "Continue"
 if ($ScanDepth -lt 1) { $ScanDepth = 1 }
 if ($ScanDepth -gt 8) { $ScanDepth = 8 }
 
 function Test-IsAdmin {
     $id = [Security.Principal.WindowsIdentity]::GetCurrent()
     $p = New-Object Security.Principal.WindowsPrincipal($id)
     return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 }
 if (-not (Test-IsAdmin)) {
     $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
     if ($IncludeSensitive) { $arg += " -IncludeSensitive" }
     if ($SkipFileScan) { $arg += " -SkipFileScan" }
     if ($IncludeSystemDirs) { $arg += " -IncludeSystemDirs" }
     if ($CaptureProcessMemory) { $arg += " -CaptureProcessMemory" }
     if ($RecoverClearedLogs) { $arg += " -RecoverClearedLogs" }
     $arg += " -ScanDepth $ScanDepth"
     if ($Target) { $arg += " -Target `"$Target`"" }
     $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
     Start-Process $ps -ArgumentList $arg -Verb RunAs
     exit
 }

$major = $PSVersionTable.PSVersion.Major
if ($major -gt 3) { Write-Host "WARNING: PowerShell $major detected. Use IR_Collect_v5.4_GUI.exe for full coverage." }

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$base = Join-Path $env:SystemDrive "IR"
 $name = "IR_$($env:COMPUTERNAME)_${stamp}_PS2"
 $dir = Join-Path $base $name
 $zip = Join-Path $base "$name.zip"
 New-Item -ItemType Directory -Force -Path $dir | Out-Null
 $log = Join-Path $dir "collection.log"
 function Write-Log([string]$m) { $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m; Add-Content -Path $log -Value $line -Encoding UTF8 }
function Ensure([string]$p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function Run-Cmd([string]$cmd, [string]$out) {
    try { & cmd.exe /c $cmd > $out 2>&1; Write-Log "OK $cmd" } catch { Set-Content $out $_.Exception.Message -Encoding UTF8; Write-Log "FAIL $cmd" }
}
function Export-Reg([string]$key, [string]$out) {
    & reg.exe query $key /s > $out 2>&1
    if ($LASTEXITCODE -ne 0) { Set-Content $out "(missing or denied) $key" -Encoding UTF8 }
}
function Get-Sha256([string]$path) {
    try {
         $sha = New-Object System.Security.Cryptography.SHA256Managed
        $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $h = $sha.ComputeHash($fs) } finally { $fs.Close() }
        return ([BitConverter]::ToString($h)).Replace("-", "")
    } catch { return "" }
}
function Copy-Locked([string]$src, [string]$dest) {
    try { Copy-Item $src $dest -Force -ErrorAction Stop; return } catch {}
    & esentutl.exe /y $src /vss $dest | Out-Null
    if (Test-Path $dest) { return }
    & cmd.exe /c "esentutl /y `"$src`" /d `"$dest`"" | Out-Null
    if (-not (Test-Path $dest)) { Set-Content "$dest.LOCKED.txt" "locked: $src" -Encoding UTF8 }
}
function Walk-Files([string]$root, [int]$depth, [string[]]$exts, [int]$limit) {
    $result = @()
    if (-not (Test-Path $root)) { return $result }
    $stack = New-Object System.Collections.Stack
    $stack.Push(@{ Path = $root; Depth = 0 })
    while ($stack.Count -gt 0 -and $result.Count -lt $limit) {
        $item = $stack.Pop()
        $children = @(Get-ChildItem -LiteralPath $item.Path -Force -ErrorAction SilentlyContinue)
        foreach ($child in $children) {
            if ($result.Count -ge $limit) { break }
            if ($child.PSIsContainer) {
                if ($item.Depth -lt $depth) { $stack.Push(@{ Path = $child.FullName; Depth = ($item.Depth + 1) }) }
            } else {
                $ok = $true
                if ($exts -and $exts.Count -gt 0) { $ok = $exts -contains $child.Extension.ToLower() }
                if ($ok) { $result += $child }
            }
        }
    }
    return $result
}

$v = Join-Path $dir "1_volatile"; $a = Join-Path $dir "2_accounts"; $p = Join-Path $dir "3_persistence"
$f = Join-Path $dir "5_filesystem"; $l = Join-Path $dir "6_logs"; $w = Join-Path $dir "7_web"
$b = Join-Path $dir "browser_artifacts"; $o = Join-Path $dir "0_offline"
foreach ($x in @($v,$a,$p,$f,(Join-Path $f "ransomware_vss"),$l,(Join-Path $l "extended"),$w,$b,$o)) { Ensure $x }
Write-Log "PS2 collection started; PowerShell $major"

Run-Cmd "netstat.exe -ano" (Join-Path $v "netstat_ano.txt")
Run-Cmd "netstat.exe -ano -b" (Join-Path $v "netstat_anob.txt")
Run-Cmd "route.exe print" (Join-Path $v "route.txt")
Run-Cmd "arp.exe -a" (Join-Path $v "arp.txt")
Run-Cmd "ipconfig.exe /all" (Join-Path $v "ipconfig.txt")
Run-Cmd "ipconfig.exe /displaydns" (Join-Path $v "dns_cache.txt")
Run-Cmd "netsh.exe advfirewall show allprofiles" (Join-Path $v "firewall.txt")
Run-Cmd "net.exe use" (Join-Path $v "net_use.txt")
Run-Cmd "net.exe session" (Join-Path $v "net_sessions.txt")
Run-Cmd "net.exe share" (Join-Path $v "net_share.txt")
Run-Cmd "qwinsta.exe" (Join-Path $v "sessions.txt")
Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts" (Join-Path $v "hosts.txt") -Force -ErrorAction SilentlyContinue
Run-Cmd "tasklist.exe /v /fo csv" (Join-Path $v "tasklist.csv")
Run-Cmd "tasklist.exe /svc" (Join-Path $v "tasklist_svc.txt")
Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | Export-Csv (Join-Path $v "process_tree.csv") -NoTypeInformation -Encoding UTF8

$sigRows = @()
Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $status = "NoSignature"; $cn = ""
    try {
        $sig = Get-AuthenticodeSignature $_.Path
        if ($sig) { $status = [string]$sig.Status; if ($sig.SignerCertificate) { $cn = $sig.SignerCertificate.Subject } }
    } catch {}
    $sigRows += New-Object PSObject -Property @{ PID=$_.Id; ProcessName=$_.ProcessName; Path=$_.Path; SignatureStatus=$status; Signer=$cn; SHA256=(Get-Sha256 $_.Path) }
}
$sigRows | Export-Csv (Join-Path $v "process_authenticode.csv") -NoTypeInformation -Encoding UTF8

Run-Cmd "net.exe user" (Join-Path $a "users.txt")
Run-Cmd "net.exe localgroup administrators" (Join-Path $a "admin_group.txt")
Get-WmiObject Win32_UserAccount | Select-Object Name,FullName,SID,Disabled,LocalAccount,Domain | Export-Csv (Join-Path $a "wmi_users.csv") -NoTypeInformation -Encoding UTF8
& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s > (Join-Path $a "profilelist.txt") 2>&1

foreach ($key in @(
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
)) { $leaf = ($key -split '\\')[-1]; Export-Reg $key (Join-Path $p "$leaf.txt") }
Run-Cmd "sc.exe query type= service state= all" (Join-Path $p "services.txt")
Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Export-Csv (Join-Path $p "services_detail.csv") -NoTypeInformation -Encoding UTF8
Run-Cmd "schtasks.exe /query /fo CSV /v" (Join-Path $p "schtasks.csv")
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select-Object Name,Query | Format-List | Out-File (Join-Path $p "wmi_filters.txt") -Encoding UTF8
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Select-Object Name,CommandLineTemplate | Format-List | Out-File (Join-Path $p "wmi_consumers.txt") -Encoding UTF8
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select-Object Filter,Consumer | Format-List | Out-File (Join-Path $p "wmi_bindings.txt") -Encoding UTF8
$startupRows = @()
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue | ForEach-Object {
    $profile = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    if ($profile) {
        $startup = Join-Path $profile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if (Test-Path $startup) { Get-ChildItem $startup -Force -ErrorAction SilentlyContinue | ForEach-Object { $startupRows += $_ } }
    }
}
$startupRows | Select-Object FullName,Length,LastWriteTime | Export-Csv (Join-Path $p "startup_folder.csv") -NoTypeInformation -Encoding UTF8

Run-Cmd "systeminfo.exe" (Join-Path $l "systeminfo.txt")
Run-Cmd "whoami.exe /all" (Join-Path $l "whoami.txt")
Get-WmiObject Win32_QuickFixEngineering | Select-Object HotFixID,Description,InstalledOn | Export-Csv (Join-Path $l "hotfix.csv") -NoTypeInformation -Encoding UTF8
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Export-Csv (Join-Path $l "software.csv") -NoTypeInformation -Encoding UTF8
if (Test-Path "$env:SystemRoot\Prefetch") { Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" | Select-Object Name,Length,LastWriteTime | Export-Csv (Join-Path $l "prefetch.csv") -NoTypeInformation -Encoding UTF8 }
foreach ($channel in @("Security","System","Application","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-Defender/Operational","Microsoft-Windows-TerminalServices-LocalSessionManager/Operational","Microsoft-Windows-Sysmon/Operational")) {
    $safe = $channel -replace '[\\/]', '_'
    $dest = Join-Path $(if ($channel -match 'TaskScheduler|WMI-Activity|Defender|Sysmon') { Join-Path $l "extended" } else { $l }) "$safe.evtx"
    & wevtutil.exe epl $channel $dest 2>$null
    if (-not (Test-Path $dest)) { Set-Content "$dest.FAILED.txt" "export failed: $channel" -Encoding UTF8 }
}
& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s > (Join-Path $l "defender_exclusions.txt") 2>&1
 & reg.exe query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s > (Join-Path $l "usb_devices.txt") 2>&1
 
 if ($CaptureProcessMemory) {
     $memDir = Join-Path $dir "8_memory\process_dumps"
     Ensure $memDir
     $rows = @()
     $excluded = @("System","smss","csrss","wininit","services","lsass","svchost","winlogon","dwm")
     $procs = @(Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -gt 4 -and $excluded -notcontains $_.Name })
     foreach ($proc in $procs) {
         $dest = Join-Path $memDir ("{0}_{1}.dmp" -f $proc.ProcessId, ($proc.Name -replace "[^A-Za-z0-9_.-]", "_"))
         $state = "captured"
         $detail = ""
         try {
             if (-not ("IRDumpNative" -as [type])) { Add-Type -TypeDefinition "using System; using System.Runtime.InteropServices; public static class IRDumpNative { [DllImport(`"dbghelp.dll`", SetLastError=true)] public static extern bool MiniDumpWriteDump(IntPtr process, uint processId, IntPtr file, uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam); }" }
             $live = Get-Process -Id $proc.ProcessId -ErrorAction Stop
             $fs = [IO.File]::Create($dest)
             $ok = [IRDumpNative]::MiniDumpWriteDump($live.Handle, [uint32]$live.Id, $fs.Handle, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
             $fs.Close()
             if (-not $ok) { throw "MiniDumpWriteDump failed" }
         } catch { $state = "failed"; $detail = $_.Exception.Message; Set-Content "$dest.FAILED.txt" $detail -Encoding UTF8 }
         $row = New-Object PSObject
         $row | Add-Member NoteProperty PID $proc.ProcessId
         $row | Add-Member NoteProperty Name $proc.Name
         $row | Add-Member NoteProperty Image $proc.ExecutablePath
         $row | Add-Member NoteProperty State $state
         $row | Add-Member NoteProperty Detail $detail
         $rows += $row
     }
     $rows | Export-Csv (Join-Path $memDir "process_dumps.csv") -NoTypeInformation -Encoding UTF8
     Write-Log "Process dumps: $($rows.Count)"
 }
 
 if ($RecoverClearedLogs) {
     $recoverDir = Join-Path $l "recovered"
     Ensure $recoverDir
     $notes = @()
     $shadows = @(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue)
     $n = 0
     foreach ($shadow in $shadows) {
         $n++
         $src = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$n\Windows\System32\winevt\Logs"
         if (Test-Path -LiteralPath $src) {
             $destDir = Join-Path $recoverDir ("VSS{0:D2}" -f $n)
             Ensure $destDir
             Copy-Item (Join-Path $src "*.evtx") $destDir -Force -ErrorAction SilentlyContinue
             $notes += "VSS $n copied"
         }
     }
     if ($shadows.Count -eq 0) { $notes += "No volume shadow copies" }
     $notes | Out-File (Join-Path $recoverDir "recovery_notes.txt") -Encoding UTF8
     Write-Log "Cleared log recovery attempted"
 }

if (-not $SkipFileScan) {
    $exts = @(".exe",".dll",".sys",".ps1",".bat",".cmd",".vbs",".js",".hta",".msi",".scr")
    $roots = @()
    if (Test-Path (Join-Path $env:SystemDrive "Users")) { $roots += (Join-Path $env:SystemDrive "Users") }
    if ($IncludeSystemDirs) { $roots += @("$env:SystemRoot\Temp", $env:ProgramData, $env:ProgramFiles) }
    $rows = @()
    foreach ($root in $roots) { $rows += @(Walk-Files $root $ScanDepth $exts 2000) }
    $rows | Select-Object FullName,Length,LastWriteTime,Extension | Export-Csv (Join-Path $f "interesting_files.csv") -NoTypeInformation -Encoding UTF8
    Run-Cmd "vssadmin.exe list shadows" (Join-Path $f "ransomware_vss\vss_shadows.txt")
}

Copy-Locked "$env:SystemRoot\AppCompat\Programs\Amcache.hve" (Join-Path $o "Amcache.hve")
Export-Reg "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" (Join-Path $o "shimcache.txt")
Export-Reg "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" (Join-Path $o "bam.txt")
if (Test-Path "$env:SystemRoot\Prefetch") {
    Ensure (Join-Path $o "prefetch")
    Copy-Item "$env:SystemRoot\Prefetch\*.pf" (Join-Path $o "prefetch") -Force -ErrorAction SilentlyContinue
}
Copy-Locked "$env:SystemRoot\System32\sru\SRUDB.dat" (Join-Path $o "SRUDB.dat")
if ($IncludeSensitive) {
    Ensure (Join-Path $o "hives")
    foreach ($hive in @("SAM","SYSTEM","SECURITY","SOFTWARE")) {
        $destHive = Join-Path $o "hives\$hive.hive"
        & reg.exe save "HKLM\$hive" $destHive /y | Out-Null
        if (-not (Test-Path $destHive)) { Set-Content "$destHive.FAILED.txt" "reg save failed" -Encoding UTF8 }
    }
}

if ($Target) {
    $extra = Join-Path $dir "9_extra\$Target"
    Ensure $extra
    $rule = Join-Path $env:TEMP "$Target.json"
    $keyword = $Target
    if (Test-Path $rule) {
         $text = [IO.File]::ReadAllText($rule)
         if ($text -match '"keyword"\s*:\s*"([^"]+)"') { $keyword = $matches[1] }
     }
     Get-WmiObject Win32_Process | Where-Object { $_.Name -like "*$keyword*" -or $_.ExecutablePath -like "*$keyword*" -or $_.CommandLine -like "*$keyword*" } | Select-Object ProcessId,Name,ExecutablePath,CommandLine | Export-Csv (Join-Path $extra "processes.csv") -NoTypeInformation -Encoding UTF8
     Set-Content (Join-Path $extra "summary.txt") "Target fallback keyword: $keyword" -Encoding UTF8
 }
 
 $files = @(Get-ChildItem $dir -Recurse -File)
 $manifest = "Script: IR_Collect_PS2 1.0`r`nPowerShell: $major`r`nHost: $env:COMPUTERNAME`r`nFiles: $($files.Count)`r`nSensitive: $IncludeSensitive"
 Set-Content (Join-Path $dir "IR_metadata.txt") $manifest -Encoding UTF8
 $files | Select-Object FullName,Length,LastWriteTime | Export-Csv (Join-Path $dir "file_manifest.csv") -NoTypeInformation -Encoding UTF8
 Write-Log "Collection files: $($files.Count). Copy this folder to the analysis machine."
 Write-Host "采集完成: $dir"
