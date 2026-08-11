# ============================================================
# Windows IR Forensic Collection Script v5.2 (ASCII/UTF-8 BOM)
# Collection order: volatility (most volatile -> persistent)
# Compatible: PowerShell 5.1+
# ============================================================

param([string]$Target = "")

# Detect GUI session (disable progress bar if no UI)
$hasUI = [Environment]::GetEnvironmentVariable("SESSIONNAME") -ne $null -or [Environment]::OSVersion.Platform -eq 'Win32NT' -and (Get-Process -Name explorer -ErrorAction SilentlyContinue)

$ErrorActionPreference = "Continue"
Set-StrictMode -Off

$systemDrive = $env:SystemDrive
$HOSTNAME = $env:COMPUTERNAME
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$BASE = Join-Path $systemDrive "IR"
$DIR = Join-Path $BASE "IR_${HOSTNAME}_${TIMESTAMP}"
$ZIP = Join-Path $BASE "IR_${HOSTNAME}_${TIMESTAMP}.zip"
$LOG = Join-Path $DIR "collection.log"

# ---------- Log buffer ----------
$logBuf = [System.Text.StringBuilder]::new()
$logFlushThreshold = 20
$logCounter = 0
function Write-Log {
    param([string]$M)
    [void]$logBuf.AppendLine("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $M")
    $global:logCounter++
    if ($global:logCounter -ge $global:logFlushThreshold) { Flush-Log }
}
function Flush-Log {
    if ($logBuf.Length -gt 0) {
        Add-Content $LOG $logBuf.ToString() -Encoding UTF8 -ErrorAction SilentlyContinue
        $logBuf.Clear() | Out-Null
        $global:logCounter = 0
    }
}

# ---------- Elevation ----------
function Request-Elevation {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $proc = Start-Process $exe -Verb RunAs -PassThru -ErrorAction Stop
            if ($proc) { exit }
        } catch {
            Write-Log "[WARN] Elevation failed: $($_.Exception.Message), continuing with limited privileges"
            Start-Sleep -Seconds 2
        }
    }
}
Request-Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Log "[WARN] Not running as admin, some data will be incomplete" }

# ---------- Progress bar ----------
Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction SilentlyContinue
$global:pf = $null; $global:pb = $null; $global:pl = $null
function Show-Progress {
    param([string]$T, [int]$P, [string]$S)
    if ($null -eq $global:pf) {
        $global:pf = New-Object System.Windows.Forms.Form
        $global:pf.Text = "IR Forensic Collector v5.2"
        $global:pf.Size = New-Object System.Drawing.Size(520, 150)
        $global:pf.StartPosition = "CenterScreen"
        $global:pf.FormBorderStyle = "FixedDialog"
        $global:pf.MaximizeBox = $false; $global:pf.TopMost = $true
        $global:pf.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
        $global:pl = New-Object System.Windows.Forms.Label
        $global:pl.Location = New-Object System.Drawing.Point(20,18)
        $global:pl.Size = New-Object System.Drawing.Size(470,35)
        $global:pl.ForeColor = [System.Drawing.Color]::White
        $global:pl.Font = New-Object System.Drawing.Font("Microsoft YaHei UI",10)
        $global:pf.Controls.Add($global:pl)
        $global:pb = New-Object System.Windows.Forms.ProgressBar
        $global:pb.Location = New-Object System.Drawing.Point(20,65)
        $global:pb.Size = New-Object System.Drawing.Size(470,30)
        $global:pb.Style = "Continuous"
        $global:pf.Controls.Add($global:pb)
        $global:pf.Show(); $global:pf.Refresh()
    }
    if ($T) { $global:pf.Text = $T }
    if ($S) { $global:pl.Text = $S }
    if ($P -ge 0) { $global:pb.Value = [Math]::Min($P,100) }
    [System.Windows.Forms.Application]::DoEvents()
}
function Close-Progress {
    if ($global:pf) { $global:pf.Close(); $global:pf = $null }
}

# ---------- Helper functions ----------
function IR-Run {
    param([string]$D, [string]$C, [string]$O)
    try {
        $r = & cmd /c $C 2>&1
        if ($r) { $r | Out-File $O -Encoding UTF8 } else { '(empty)' | Out-File $O -Encoding UTF8 }
        Write-Log "[OK] $D"
    } catch {
        "(Error: $($_.Exception.Message))" | Out-File $O -Encoding UTF8
        Write-Log "[FAIL] $D - $($_.Exception.Message)"
    }
}
function IR-RegExport {
    param([string]$K, [string]$O)
    try {
        $r = reg.exe query "$K" /s 2>&1
        if ($LASTEXITCODE -ne 0 -or -not $r) { "(Access denied or missing)" | Out-File $O -Encoding UTF8; Write-Log "[REG DENY] $K" }
        else { $r | Out-File $O -Encoding UTF8; Write-Log "[REG] $K" }
    } catch {
        "(Access denied or missing)" | Out-File $O -Encoding UTF8
        Write-Log "[REG DENY] $K"
    }
}

# ---------- Process name library ----------
$knownNames = @('DingTalk','WeChat','Weixin','WXWork','Chrome','msedge','firefox','svchost','explorer','lsass','winlogon','csrss','smss','taskmgr','spoolsv','services','rundll32','RuntimeBroker','SearchIndexer','sihost','taskhostw','ctfmon','notepad','winword','excel','powerpnt','outlook','OneDrive','Teams','Code','wps','wpscloudsvr','wpspdf','vmware-tray','vmtoolsd','VGAuthService','vm3dservice','YunMai','WeMeet','Zoom','conhost','dllhost','dwm','WmiPrvSE','MsMpEng','NisSrv','SecurityHealthService','QQ','QQMusic','QQPinyin','TIM','AliWork','opera','foxmail','XMind','PotPlayer','Bandizip','7zFM','WinRAR','Everything','Typora','Obsidian','Docker','python','java','node','git','FileZilla','Xshell','Xftp','Putty','Navicat','nginx','httpd','vpnui')
$knownNamesLower = [System.Collections.Generic.HashSet[string]]($knownNames | ForEach-Object { $_.ToLowerInvariant() })

# Anomaly patterns (single-quoted to avoid escaping)
$sq = @(
    @{regex='(?i)^(svch0st|scvhost|expl0rer|winlog0n|csrss0|taskmrg|lsasss|svchosts|sp00lsv|lsass0|smss0|win1ogon|winl0g0n|conh0st|dllh0st|dw0m)$';desc='System process name spoofing'},
    @{regex='(?i)^(svchost|lsass|winlogon|csrss|services|explorer).*(tmp|temp|old|bak|\d{2,})$';desc='System process name with suffix variant'},
    @{regex='SETUO|Setuo|setuo';desc='SETUP spelling variant'},
    @{regex='(?i)(DingTalk|WeChat|QQMusic|WXWork|Chrome|Firefox|Edge).*(64|86|32|Setup|Install|Update)$';desc='Known software name with suffix'}
)

function Compare-ProcessName {
    param([string]$BN, [int]$MD=3)
    $BN = [System.IO.Path]::GetFileNameWithoutExtension($BN)
    if ([string]::IsNullOrEmpty($BN)) { return $null }
    $bl = $BN.ToLowerInvariant()
    if ($knownNamesLower.Contains($bl)) { return $null }
    $r = @()
    foreach ($x in $sq) { if ($BN -match $x.regex) { $r += $x.desc + " ('$BN')" } }
    foreach ($o in $knownNames) {
        $ol = $o.ToLowerInvariant()
        $len1 = $bl.Length; $len2 = $ol.Length
        if ([Math]::Abs($len1 - $len2) -gt $MD+2) { continue }
        $maxLen = [Math]::Max($len1, $len2)
        $minLen = [Math]::Min($len1, $len2)
        $diff = 0
        for ($i=0; $i -lt $minLen; $i++) { if ($bl[$i] -ne $ol[$i]) { $diff++ } }
        $diff += ($maxLen - $minLen)
        if ($diff -le $MD -and $bl -ne $ol) {
            $r += "Suspected spoofing of '$o' (diff $diff chars)"
            break
        }
    }
    if ($r.Count -eq 0) { return $null } else { return ($r -join '; ') }
}

function Test-MicrosoftSigned {
    param([string]$FP)
    if ($FP -notlike "$env:WINDIR\*") { return $false }
    try { $s = Get-AuthenticodeSignature $FP -ErrorAction SilentlyContinue; return ($s -and $s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Microsoft') } catch { return $false }
}

# ---------- Signature cache ----------
$sigCache = @{}
function Get-CachedSignature {
    param([string]$FilePath)
    if (-not $FilePath -or -not (Test-Path $FilePath)) { return $null }
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $null }
    $cacheKey = "$FilePath|$($fileInfo.LastWriteTime.Ticks)"
    if ($sigCache.ContainsKey($cacheKey)) { return $sigCache[$cacheKey] }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $sigCache[$cacheKey] = $sig
        return $sig
    } catch {
        $sigCache[$cacheKey] = $null
        return $null
    }
}

# ---------- User directory cache ----------
$global:UserDirCache = $null
function Get-UserDirs {
    if ($global:UserDirCache) { return $global:UserDirCache }
    $userDirs = @()
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID }
    if (-not $drives) { $drives = @($env:SystemDrive) }
    foreach ($drive in $drives) {
        $usersPath = Join-Path $drive "Users"
        if (Test-Path $usersPath) {
            $allItems = Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue
            foreach ($user in $allItems) {
                if ($user.Name -match '^(Public|Default|All Users|.*\$$)' -or $user.Name -like '.*') { continue }
                $userDirs += @{
                    Path      = $user.FullName
                    Name      = $user.Name
                    Desktop   = Join-Path $user.FullName "Desktop"
                    Downloads = Join-Path $user.FullName "Downloads"
                    Temp      = Join-Path $user.FullName "AppData\Local\Temp"
                    AppDataLocal = Join-Path $user.FullName "AppData\Local"
                    AppDataRoaming = Join-Path $user.FullName "AppData\Roaming"
                }
            }
        } else {
            $userDirs += @{
                Path      = $drive
                Name      = ("DRV_" + $drive.Replace(":", ""))
                Desktop   = $drive
                Downloads = $drive
                Temp      = $drive
                AppDataLocal = $drive
                AppDataRoaming = $drive
            }
        }
    }
    $global:UserDirCache = $userDirs
    return $userDirs
}

# ---------- RWX Memory Scanner ----------
function Scan-RWX {
    Write-Log "[MEM] Scanning RWX memory regions..."
    $scannerType = [System.Management.Automation.PSObject].Assembly.GetType("MemoryScanner")
    if (-not $scannerType) {
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MemoryScanner {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("psapi.dll")]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    public static string ScanProcessMemory(int pid, string processName) {
        IntPtr hProcess = OpenProcess(0x0400 | 0x0010, false, pid);
        if (hProcess == IntPtr.Zero) return null;
        StringBuilder sb = new StringBuilder();
        IntPtr addr = IntPtr.Zero;
        while (true) {
            MEMORY_BASIC_INFORMATION mbi;
            int ret = VirtualQueryEx(hProcess, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (ret == 0) break;
            long regionSize = mbi.RegionSize.ToInt64();
            if (regionSize <= 0) break;
            if (pid == 4 || pid == 0) { addr = new IntPtr(addr.ToInt64() + regionSize); continue; }
            if (mbi.State == 0x1000 && mbi.Protect == 0x40) {
                string moduleName = "";
                StringBuilder modSb = new StringBuilder(260);
                if (GetModuleFileNameEx(hProcess, mbi.AllocationBase, modSb, 260) > 0) { moduleName = modSb.ToString(); }
                string protFlags = "";
                if ((mbi.Protect & 0x10) != 0) protFlags += "PAGE_EXECUTE|";
                if ((mbi.Protect & 0x20) != 0) protFlags += "PAGE_EXECUTE_READ|";
                if ((mbi.Protect & 0x40) != 0) protFlags += "PAGE_EXECUTE_READWRITE|";
                if ((mbi.Protect & 0x80) != 0) protFlags += "PAGE_EXECUTE_WRITECOPY|";
                if ((mbi.Protect & 0x100) != 0) protFlags += "PAGE_GUARD|";
                if ((mbi.Protect & 0x200) != 0) protFlags += "PAGE_NOCACHE|";
                if ((mbi.Protect & 0x400) != 0) protFlags += "PAGE_WRITECOMBINE|";
                if (protFlags.Length > 0) protFlags = protFlags.TrimEnd('|');
                string typeStr = mbi.Type == 0x1000000 ? "MEM_IMAGE" : (mbi.Type == 0x20000 ? "MEM_PRIVATE" : (mbi.Type == 0x40000 ? "MEM_MAPPED" : "0x" + mbi.Type.ToString("X")));
                sb.AppendLine(pid + "," + processName + ",0x" + addr.ToInt64().ToString("X") + "," + (regionSize / 1024) + "," + protFlags + ",0x" + mbi.State.ToString("X") + "," + typeStr + "," + moduleName);
            }
            addr = new IntPtr(addr.ToInt64() + regionSize);
            if (addr.ToInt64() <= 0) break;
        }
        CloseHandle(hProcess);
        if (sb.Length > 0) return sb.ToString();
        return null;
    }
}
"@ -ErrorAction Stop
        } catch {
            Write-Log "[ERROR] MemoryScanner type load failed: $($_.Exception.Message)"
            return
        }
    }
    $results = @(); $totalRwx = 0
    $skipProcesses = @("System", "System Idle Process", "Registry", "Memory Compression")
    $job = Start-Job -ScriptBlock {
        param($skip)
        $out = @()
        Get-Process | Where-Object { $_.Id -gt 4 -and $skip -notcontains $_.ProcessName } | ForEach-Object {
            try {
                $result = [MemoryScanner]::ScanProcessMemory($_.Id, $_.ProcessName)
                if ($result) {
                    $out += $result -split "`r?`n" | Where-Object { $_ -ne "" }
                }
            } catch { }
        }
        return $out
    } -ArgumentList $skipProcesses
    if ($job -and (Wait-Job $job -Timeout 60)) {
        $results = Receive-Job $job
        Remove-Job $job
    } else {
        Write-Log "[WARN] RWX scan timed out, may be incomplete"
        if ($job) { Remove-Job $job -Force }
    }
    $V = "$DIR\1_volatile"
    if ($results -and $results.Count -gt 0) {
        "PID,ProcessName,BaseAddress,SizeKB,Protect,State,Type,ModuleName" | Out-File "$V\process_modules.csv" -Encoding UTF8
        $results | ForEach-Object { $_ | Out-File "$V\process_modules.csv" -Encoding UTF8 -Append }
        $totalRwx = $results.Count
        Write-Log "[MEM] RWX alerts: $totalRwx suspicious regions"
        $results | Select-Object -First 20 | ForEach-Object {
            $parts = $_.Split(",")
            if ($parts.Count -ge 4) {
                Write-Log "[!] RWX: $($parts[1]) PID=$($parts[0]) Base=$($parts[2]) Size=$($parts[3])KB"
            }
        }
        if ($results.Count -gt 20) { Write-Log "[!] ... total $($results.Count) entries, truncated" }
    } else {
        "PID,ProcessName,BaseAddress,SizeKB,Protect,State,Type,ModuleName" | Out-File "$V\process_modules.csv" -Encoding UTF8
        Write-Log "[MEM] No RWX memory regions found"
    }
    Flush-Log
}

# ---------- Targeted collection (v5.2) ----------
function Invoke-TargetedCollection {
    param(
        [string]$TargetName,
        [string]$OutRoot,
        [string]$TargetsDir
    )
    $name = $TargetName.Trim()
    if (-not $name) { return }
    $safeName = $name -replace '[^\w\-.]', '_'
    $extraDir = Join-Path (Join-Path $OutRoot "9_extra") $safeName
    New-Item -ItemType Directory -Force -Path $extraDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $extraDir "files") | Out-Null

    $rule = $null
    $ruleFile = ""
    $candidate = Join-Path $TargetsDir "$name.json"
    if (Test-Path $candidate) {
        $ruleFile = $candidate
        try { $rule = Get-Content $ruleFile -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { Write-Log "[WARN] 定向规则解析失败: $ruleFile - $($_.Exception.Message)" }
    } else {
        Write-Log "[INFO] 未找到规则文件 $name.json，使用通用兜底采集"
    }

    $keyword = if ($rule -and $rule.keyword) { [string]$rule.keyword } else { $name }
    $procNames = @(); if ($rule -and $rule.process_names) { $procNames = @($rule.process_names) }
    $svcNames = @(); if ($rule -and $rule.service_names) { $svcNames = @($rule.service_names) }
    $regKeys = @(); if ($rule -and $rule.registry_keys) { $regKeys = @($rule.registry_keys) }
    $searchRoots = @(); if ($rule -and $rule.search_roots) { $searchRoots = @($rule.search_roots) }
    $depth = 4; if ($rule -and $rule.search_depth) { $depth = [int]$rule.search_depth }
    $maxFiles = 200; if ($rule -and $rule.max_files) { $maxFiles = [int]$rule.max_files }
    $hashOnly = @('*.state','*.key','*.pem','*.pfx','*.conf','*.config','*.json','*.db','*.sqlite','*.sqlite3','*.log','*.bak')
    if ($rule -and $rule.hash_only_paths) { $hashOnly = @($rule.hash_only_paths) }
    $copyExts = @('.exe','.dll','.sys','.msi','.bat','.cmd','.ps1','.vbs','.js','.jar','.py')
    if ($rule -and $rule.copy_extensions) { $copyExts = @($rule.copy_extensions) }

    # --- Processes ---
    $procs = New-Object System.Collections.ArrayList
    $seenPids = @{}
    $procTreeAll = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath
    foreach ($p in @($procTreeAll)) {
        $hit = $false
        if ($p.Name -like "*$keyword*" -or $p.ExecutablePath -like "*$keyword*" -or $p.CommandLine -like "*$keyword*") { $hit = $true }
        if (-not $hit) { foreach ($pn in $procNames) { if ($p.Name -like $pn) { $hit = $true; break } } }
        if ($hit) {
            [void]$procs.Add($p)
            $seenPids[[int]$p.ProcessId] = $true
        }
    }
    foreach ($pn in $procNames) {
        foreach ($p in @(Get-Process -Name $pn -ErrorAction SilentlyContinue)) {
            if ($seenPids.ContainsKey([int]$p.Id)) { continue }
            $cmd = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop).CommandLine } catch { "" }
            [void]$procs.Add([PSCustomObject]@{ProcessId=$p.Id; Name=$p.ProcessName; CommandLine=$cmd; ExecutablePath=$p.Path})
        }
    }
    $procRows = @($procs | ForEach-Object {
        $hash = try { (Get-FileHash $_.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { "" }
        [PSCustomObject]@{PID=$_.ProcessId; Name=$_.Name; Path=$_.ExecutablePath; CommandLine=$_.CommandLine; SHA256=$hash}
    } | Sort-Object PID -Unique)
    if ($procRows.Count -gt 0) { $procRows | Export-Csv "$extraDir\processes.csv" -NoTypeInformation -Encoding UTF8 }
    else { "[NONE] 未发现匹配进程" | Out-File "$extraDir\processes.csv" -Encoding UTF8 }

    # --- Services ---
    $svcRows = New-Object System.Collections.ArrayList
    foreach ($sn in $svcNames) {
        foreach ($s in @(Get-Service -Name $sn -ErrorAction SilentlyContinue)) {
            [void]$svcRows.Add([PSCustomObject]@{Name=$s.Name; DisplayName=$s.DisplayName; Status=$s.Status; StartType=$s.StartType})
        }
    }
    foreach ($s in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$keyword*" -or $_.DisplayName -like "*$keyword*" })) {
        $dup = @($svcRows | Where-Object { $_.Name -eq $s.Name }).Count -gt 0
        if (-not $dup) { [void]$svcRows.Add([PSCustomObject]@{Name=$s.Name; DisplayName=$s.DisplayName; Status=$s.Status; StartType=$s.StartType}) }
    }
    if ($svcRows.Count -gt 0) { $svcRows | Export-Csv "$extraDir\services.csv" -NoTypeInformation -Encoding UTF8 }
    else { "[NONE] 未发现匹配服务" | Out-File "$extraDir\services.csv" -Encoding UTF8 }

    # --- Installed software ---
    $installed = @()
    foreach ($regBase in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
        $installed += @(Get-ItemProperty $regBase -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -and ($_.DisplayName -like "*$keyword*" -or $_.Publisher -like "*$keyword*")
        } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation)
    }
    $installed = @($installed | Sort-Object DisplayName -Unique)
    if ($installed.Count -gt 0) { $installed | Export-Csv "$extraDir\installed.csv" -NoTypeInformation -Encoding UTF8 }
    else { "[NONE] 未发现匹配安装软件" | Out-File "$extraDir\installed.csv" -Encoding UTF8 }

    # --- Registry ---
    $regCount = 0
    $ri = 0
    foreach ($k in $regKeys) {
        $ri++
        $safeKey = $k -replace '[^\w]', '_'
        $r = reg.exe query $k /s 2>&1
        if ($LASTEXITCODE -eq 0 -and $r) {
            $r | Out-File "$extraDir\registry_${ri}_${safeKey}.txt" -Encoding UTF8
            $regCount++
        } else {
            "(Access denied or missing): $k" | Out-File "$extraDir\registry_${ri}_${safeKey}.txt" -Encoding UTF8
        }
    }

    # --- File search ---
    $roots = @()
    foreach ($r0 in $searchRoots) {
        if (-not $r0) { continue }
        $rp = [Environment]::ExpandEnvironmentVariables($r0)
        if ($rp -and (Test-Path $rp)) { $roots += $rp }
    }
    if ($roots.Count -eq 0) {
        foreach ($r0 in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA)) {
            if ($r0 -and (Test-Path $r0)) { $roots += $r0 }
        }
        foreach ($ud in @(Get-UserDirs)) {
            foreach ($r0 in @($ud.AppDataLocal, $ud.AppDataRoaming)) { if ($r0 -and (Test-Path $r0)) { $roots += $r0 } }
        }
    }
    $roots = @($roots | Select-Object -Unique)

    $fileRows = New-Object System.Collections.ArrayList
    $copiedCount = 0
    foreach ($root in $roots) {
        if ($fileRows.Count -ge $maxFiles) { break }
        $remaining = $maxFiles - $fileRows.Count
        $candidates = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue -Depth $depth |
            Where-Object { $_.FullName -match [regex]::Escape($keyword) } |
            Select-Object -First $remaining
        foreach ($f in $candidates) {
            if ($fileRows.Count -ge $maxFiles) { break }
            $isHashOnly = $false
            foreach ($pat in $hashOnly) { if ($f.Name -like $pat -or $f.FullName -like $pat) { $isHashOnly = $true; break } }
            $hash = try { (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { "" }
            [void]$fileRows.Add([PSCustomObject]@{
                FullName=$f.FullName; Name=$f.Name; Length=$f.Length
                LastWriteTime=$f.LastWriteTime; CreationTime=$f.CreationTime
                SHA256=$hash; HashOnly=if($isHashOnly){'Yes'}else{'No'}
            })
            if (-not $isHashOnly -and $copyExts -contains $f.Extension.ToLower()) {
                $destName = ("{0:D4}_{1}" -f ($fileRows.Count - 1), ($f.Name -replace '[^\w.\-]', '_'))
                $dest = Join-Path (Join-Path $extraDir "files") $destName
                try { Copy-Item $f.FullName $dest -Force -ErrorAction Stop; $copiedCount++ } catch {}
            }
        }
    }
    if ($fileRows.Count -gt 0) { $fileRows | Export-Csv "$extraDir\files.csv" -NoTypeInformation -Encoding UTF8 }
    else { "[NONE] 未发现匹配文件" | Out-File "$extraDir\files.csv" -Encoding UTF8 }

    # --- Summary ---
    $notCopied = $fileRows.Count - $copiedCount
    @(
        "定向采集目标: $name"
        "规则文件: $(if($ruleFile){$ruleFile}else{'无（通用兜底）'})"
        "生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "进程: $($procRows.Count) | 服务: $($svcRows.Count) | 安装软件: $($installed.Count)"
        "文件: $($fileRows.Count) 个（复制 $copiedCount，仅哈希/元数据 $notCopied）| 注册表键: $($regKeys.Count)（成功 $regCount）"
        ""
        "敏感文件默认仅记录 SHA256/元数据，不复制原始内容。"
    ) | Out-File "$extraDir\summary.txt" -Encoding UTF8

    $m9files = Get-ChildItem $extraDir -Recurse -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "9" -Name "Targeted: $name" -Status "ok" -Error "" -FileCount @($m9files).Count -TotalBytes ($m9files | Measure-Object -Property Length -Sum).Sum
    Write-Log "[OK] 定向采集 '$name': 进程 $($procRows.Count), 服务 $($svcRows.Count), 文件 $($fileRows.Count), 复制 $copiedCount"
}

# ===== Main =====
try {
    Show-Progress -T "IR Forensic Collector v5.2" -P 0 -S "正在初始化..."
    $fmt = "yyyy-MM-dd HH:mm:ss"
    Write-Log "[=== Collection started $(Get-Date -Format $fmt) ===]"
    Write-Log "Host: $HOSTNAME | PS: $($PSVersionTable.PSVersion)"

    New-Item -ItemType Directory -Force -Path $BASE | Out-Null
    @("$DIR\1_volatile","$DIR\2_accounts","$DIR\3_persistence",
      "$DIR\3_persistence\com_hijack","$DIR\3_persistence\dll_hijack",
      "$DIR\5_filesystem","$DIR\5_filesystem\ransomware_vss",
      "$DIR\6_logs","$DIR\7_web","$DIR\browser_artifacts") | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

    $moduleStatus = [System.Collections.ArrayList]::new()
    function Add-ModuleStatus {
        param([string]$ModuleId, [string]$Name, [string]$Status, [string]$Error, [int]$FileCount, [long]$TotalBytes)
        [void]$moduleStatus.Add(@{ module_id=$ModuleId; name=$Name; status=$Status; error=if($Error){$Error}else{""}; file_count=$FileCount; total_bytes=$TotalBytes })
    }

    # ===== TEMP_MEI snapshot before =====
    $TEMP_SNAP = Join-Path $DIR "temp_mei_before.csv"
    Get-ChildItem "$env:TEMP\_MEI*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{ FullName = $_.FullName; LastWrite = $_.LastWriteTime; Created = $_.CreationTime }
    } | Export-Csv $TEMP_SNAP -NoTypeInformation -Encoding UTF8
    Write-Log "[OK] TEMP_MEI packer snapshot"

    # ===== 1. Volatile data =====
    Show-Progress -P 2 -S "[1/9] 网络连接..."
    $V = "$DIR\1_volatile"
    IR-Run "netstat-ano" "netstat.exe -ano" "$V\netstat_ano.txt"
    IR-Run "netstat-anob" "netstat.exe -ano -b" "$V\netstat_anob.txt"
    IR-Run "route" "route.exe print" "$V\route.txt"
    IR-Run "arp" "arp.exe -a" "$V\arp.txt"
    IR-Run "ipconfig" "ipconfig.exe /all" "$V\ipconfig.txt"
    IR-Run "dns" "ipconfig.exe /displaydns" "$V\dns_cache.txt"
    IR-Run "firewall" "netsh.exe advfirewall show allprofiles" "$V\firewall.txt"
    IR-Run "hosts" "cmd.exe /c type $env:SystemRoot\System32\drivers\etc\hosts" "$V\hosts.txt"
    IR-Run "net-use" "net.exe use" "$V\net_use.txt"
    IR-Run "net-session" "net.exe session" "$V\net_sessions.txt"
    IR-Run "net-view" "net.exe view /all" "$V\net_view.txt"
    IR-Run "net-share" "net.exe share" "$V\net_share.txt"
    IR-Run "sessions" "qwinsta.exe" "$V\sessions.txt"

    Show-Progress -P 6 -S "[1/9] 进程列表..."
    IR-Run "tasklist" "tasklist.exe /v /fo csv" "$V\tasklist.csv"
    IR-Run "tasklist-svc" "tasklist.exe /svc" "$V\tasklist_svc.txt"
    $procTree = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath
    if (-not $procTree) { $procTree = Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath }
    if ($procTree) { $procTree | Export-Csv "$V\process_tree.csv" -NoTypeInformation -Encoding UTF8 }

    # --- netstat delayed comparison ---
    Start-Sleep -Seconds 30
    $NET2 = Join-Path $DIR "netstat_ano_delayed.txt"
    $NET2b = Join-Path $DIR "netstat_anob_delayed.txt"
    try { netstat -ano 2>&1 | Out-File $NET2 -Encoding UTF8; Write-Log "[OK] delayed netstat (ano)" } catch { Write-Log "[FAIL] delayed netstat (ano)" }
    try { netstat -anob 2>&1 | Out-File $NET2b -Encoding UTF8; Write-Log "[OK] delayed netstat (anob)" } catch { Write-Log "[FAIL] delayed netstat (anob)" }
    try {
        $beforeLines = Get-Content (Join-Path $DIR "1_volatile\netstat_ano.txt") -Encoding UTF8 -ErrorAction SilentlyContinue
        $afterLines = Get-Content $NET2 -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($beforeLines -and $afterLines) {
            $newConn = $afterLines | Where-Object { $_ -and $_ -notin $beforeLines }
            if ($newConn) { $newConn | Out-File (Join-Path $DIR "netstat_new_connections.txt") -Encoding UTF8; Write-Log "[ALERT] Found $($newConn.Count) new connections" }
            else { Write-Log "[OK] No connection changes" }
        }
    } catch { Write-Log "[INFO] Connection comparison failed" }
    Write-Log "[OK] Network delayed comparison done"

    # --- Digital signature ---
    Show-Progress -P 10 -S "[1/9] 数字签名验证..."
    $sr = @(); $stTotal = 0; $stValid = 0; $stUnsigned = 0
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        try {
            $sig = Get-CachedSignature $_.Path
            $stTotal++
            $c = if ($sig) { $sig.SignerCertificate } else { $null }
            $tc = if ($sig) { $sig.TimeStamperCertificate } else { $null }
            $fv = try { (Get-Item $_.Path -ErrorAction SilentlyContinue).VersionInfo.FileVersion } catch { '' }
            $sr += [PSCustomObject]@{
                PID=$_.Id; ProcessName=$_.ProcessName; FilePath=$_.Path
                FileVersion=if($fv){$fv}else{''}
                SignerSubject=if($c){($c.Subject -replace "`r?`n",' ').Trim()}else{''}
                SignerCN=if($c){$c.GetNameInfo('SimpleName',$false)}else{''}
                SignatureStatus=if($sig){$sig.Status}else{'NoSignature'}
                TimeStamper=if($tc){($tc.Subject -replace "`r?`n",' ').Trim()}else{''}
                IsOSBinary=($_.Path -like "$env:WINDIR\*")
            }
            if ($sig -and $sig.Status -eq 'Valid') { $stValid++ } else { $stUnsigned++ }
        } catch { Write-Log "[WARN] Signature failed: $($_.Path)" }
    }
    $sr | Export-Csv "$V\process_authenticode.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "[OK] Signature: total $stTotal, valid $stValid, unsigned $stUnsigned"

    # --- Process name anomalies ---
    Show-Progress -P 13 -S "[1/9] 进程名异常检测..."
    $ar = @()
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        $b = [System.IO.Path]::GetFileNameWithoutExtension($_.Path)
        $is = @()
        foreach ($x in $sq) { if ($b -match $x.regex) { $is += $x.desc + " ('$b')" } }
        if (-not (Test-MicrosoftSigned $_.Path)) {
            $matched = Compare-ProcessName -BN $b
            if ($matched) { $is += $matched }
        }
        if ($_.Path -match '\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\' -and $_.Path -notmatch '\\Microsoft\\') {
            $is += "Executed from temp directory"
        }
        if ($is.Count -gt 0) { $ar += [PSCustomObject]@{PID=$_.Id; ProcessName=$_.ProcessName; FilePath=$_.Path; Anomalies=$is -join '; '} }
    }
    $ar | Export-Csv "$V\process_name_anomalies.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "[OK] Process name anomalies: $($ar.Count) entries"

    # --- Packer detection ---
    $PACK = Join-Path $DIR "process_packer_detect.csv"
    $packerEntries = @()
    $meiDirs = Get-ChildItem "$env:TEMP\_MEI*" -Directory -ErrorAction SilentlyContinue
    foreach ($md in $meiDirs) {
        $meiFiles = Get-ChildItem $md.FullName -File -ErrorAction SilentlyContinue
        $hasPyArmor = ($meiFiles | Where-Object { $_.Name -match "pyarmor|pytransform" }) -ne $null
        $hasPython = ($meiFiles | Where-Object { $_.Name -match "python3" }) -ne $null
        $packerEntries += [PSCustomObject]@{
            PID = "N/A"
            ProcessName = ("<TEMP_MEI> " + $md.Name)
            Path = $md.FullName
            PackerType = "PyInstaller"
            HasPyArmor = if($hasPyArmor){"Yes"}else{"No"}
            HasPython = if($hasPython){"Yes"}else{"No"}
        }
    }
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        try {
            $procBytes = [System.IO.File]::ReadAllBytes($_.Path)
            $textStart = [System.Text.Encoding]::UTF8.GetString($procBytes, 0, [Math]::Min(4096, $procBytes.Length))
            $isPyInstaller = $textStart -match "PYINSTALLER|pyiboot|MEI"
            $hasPyArmor2 = $textStart -match "pyarmor|pytransform"
            if ($isPyInstaller) {
                $packerEntries += [PSCustomObject]@{
                    PID = $_.Id
                    ProcessName = $_.ProcessName
                    Path = $_.Path
                    PackerType = "PyInstaller"
                    HasPyArmor = if($hasPyArmor2){"Yes"}else{"No"}
                    HasPython = "N/A"
                }
            }
        } catch {}
    }
    if ($packerEntries.Count -gt 0) {
        $packerEntries | Export-Csv $PACK -NoTypeInformation -Encoding UTF8
        Write-Log "[PACK] Found $($packerEntries.Count) packer signatures"
    }

    # --- Process tree anomalies ---
    $ta = @(); $authPIDs = @($sr | ForEach-Object { $_.PID })
    if ($procTree) {
        $procTree | Where-Object { $_.ProcessId -and $_.ExecutablePath -and $_.ProcessId -notin $authPIDs -and $_.ProcessId -gt 4 } | ForEach-Object {
            $ta += [PSCustomObject]@{PID=$_.ProcessId; Name=$_.Name; Path=$_.ExecutablePath; CmdLine=$_.CommandLine; Note="Process not in signature list"}
        }
    }
    $ta | Export-Csv "$V\process_tree_anomalies.csv" -NoTypeInformation -Encoding UTF8
    if ($ta.Count -gt 0) { Write-Log "[ALERT] Process tree anomalies: $($ta.Count) entries" }

    # --- RAT detection ---
    Show-Progress -P 15 -S "[1/9] 远控检测..."
    $ratProcesses = @('GrayPigeon','HuoZi','Gpigeon','Quasar','beacon','cobaltstrike','PoisonIvy','DarkComet','njrat','njw0rm','XtremeRAT','Remcos','AsyncRAT','NanoCore','NetWire','gh0st','PCShare','Adwind','jRAT','Behinder','Godzilla','AntSword','meterpreter','svch0st','csrss0','winlog0n','expl0rer','taskmrg','scvhost')
    $suspectRatProcs = Get-Process | Where-Object { $pn=$_.ProcessName; foreach($rat in $ratProcesses){if($pn -match [regex]::Escape($rat)){return $true}}; $false }
    $suspectRatProcs | Select-Object Id, ProcessName, @{N='Path';E={$_.Path}}, StartTime | Export-Csv "$V\rat_suspect_processes.csv" -NoTypeInformation -Encoding UTF8
    $ratPorts = @(4444,5555,6666,7777,8888,9999,12345,31337,4443,8443,1337,1234,4789,5800,5900)
    try { $ns = netstat.exe -ano 2>$null; $ns | Where-Object { foreach($rp in $ratPorts){if($_ -match ":$rp\s"){return $true}}; $false } | Out-File "$V\rat_port_connections.txt" -Encoding UTF8 } catch {}

    # --- RWX scan ---
    Scan-RWX
    Show-Progress -P 17 -S "[1/9] 进程完成"
    Flush-Log

    $m1files = Get-ChildItem "$V" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "1" -Name "Volatile Data" -Status "ok" -Error "" -FileCount @($m1files).Count -TotalBytes ($m1files | Measure-Object -Property Length -Sum).Sum

    # ===== 2. Accounts =====
    Show-Progress -P 18 -S "[2/9] 账号信息..."
    $A = "$DIR\2_accounts"
    IR-Run "users" "net.exe user" "$A\users.txt"
    IR-Run "admins" "net.exe localgroup administrators" "$A\admin_group.txt"
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon | Export-Csv "$A\local_users.csv" -NoTypeInformation -Encoding UTF8
    } else {
        net user | Out-File "$A\local_users_fallback.txt" -Encoding UTF8
    }
    try { net.exe user 2>$null | Select-String -Pattern '\$$' | Out-File "$A\hidden_accounts.txt" -Encoding UTF8 } catch {}

    # WMI账号枚举 — 走WMI路径，可绕过NetUserEnum API hook
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            $wmiUsers = Get-CimInstance Win32_UserAccount | Select-Object Name, FullName, SID, Disabled, PasswordRequired, LocalAccount, Domain
            $wmiUsers | Export-Csv "$A\wmi_users.csv" -NoTypeInformation -Encoding UTF8
            Write-Log "[OK] WMI账号枚举: $($wmiUsers.Count)个"
        } else {
            $wmiUsers = Get-WmiObject Win32_UserAccount | Select-Object Name, FullName, SID, Disabled, PasswordRequired, LocalAccount, Domain
            $wmiUsers | Export-Csv "$A\wmi_users.csv" -NoTypeInformation -Encoding UTF8
            Write-Log "[OK] WMI账号枚举: $($wmiUsers.Count)个"
        }
    } catch {
        "[ERROR] WMI账号枚举失败: $($_.Exception.Message)" | Out-File "$A\wmi_users.csv" -Encoding UTF8
        Write-Log "[FAIL] WMI账号枚举"
    }

    # ProfileList注册表用户枚举 — 所有登录过的用户都有配置记录
    try {
        $profileList = "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profiles = Get-ChildItem $profileList -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' } | ForEach-Object {
            $prop = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $userName = ""
            if ($prop.ProfileImagePath) { $userName = $prop.ProfileImagePath -replace '.*\\([^\\]+)$', '$1' }
            [PSCustomObject]@{SID=$_.PSChildName; ProfileImagePath=$prop.ProfileImagePath; UserName=$userName; Flags="0x{0:X}" -f [int]$prop.Flags; State=$prop.State}
        }
        $profiles | Export-Csv "$A\profilelist_users.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "[OK] ProfileList枚举: $($profiles.Count)个用户目录"
    } catch {
        "[ERROR] ProfileList读取失败: $($_.Exception.Message)" | Out-File "$A\profilelist_users.csv" -Encoding UTF8
        Write-Log "[FAIL] ProfileList读取"
    }

    # 克隆账号检测（SAM注册表F键值 vs SID对比）
    # 原理: 普通用户的SID对应普通权限，但攻击者可复制管理员F值覆盖普通用户F值
    #       导致系统检查SID时认为普通用户，但登录时拥有管理员权限
    try {
        $samPath = "HKLM\SAM\SAM\Domains\Account\Users"
        $samUsers = reg.exe query $samPath /s 2>&1 | Select-String "^HKLM" | ForEach-Object { $_.Line.Trim() }
        if ($samUsers) {
            $cloneAlerts = @()
            foreach ($su in $samUsers) {
                $rid = $su -replace ".*\\([^\\]+)$", "`$1"
                if ($rid -match "^(00000|01F4)$") { continue }
                $fData = reg.exe query "$su" /v F 2>&1 | Select-String "F\s+REG_BINARY"
                if (-not $fData) { continue }
                $fHex = ($fData.Line -replace ".*REG_BINARY\s+","").Trim()
                if ($fHex.Length -gt 40) {
                    $aceFlags = $fHex.Substring(24, 2)
                    if ($aceFlags -eq "1F") {
                        try {
                            $userName = reg.exe query "$su" /v ProfilePath 2>&1 | Select-String "ProfilePath" | ForEach-Object { ($_ -split "\s+")[-1] }
                            if (-not $userName) { $userName = reg.exe query "$su" /v "SAM\Account\Name" 2>&1 | Select-String "Account" | ForEach-Object { ($_ -split "\s+")[-1] } }
                            $userName = $userName -replace ".*\\([^\\]+)$", "`$1"
                        } catch { $userName = "RID_$rid" }
                        $cloneAlerts += "[CLONE] 可疑账号: $userName (RID=$rid) 管理员权限F键值"
                    }
                }
            }
            if ($cloneAlerts.Count -gt 0) {
                $cloneAlerts | Out-File "$A\sam_clone_accounts.txt" -Encoding UTF8
                $cloneAlerts | ForEach-Object { Write-Log "[ALERT] $_" }
            } else {
                "[OK] SAM注册表F键值校验: 未发现克隆账号" | Out-File "$A\sam_clone_accounts.txt" -Encoding UTF8
                Write-Log "[OK] SAM注册表F键值校验: 未发现克隆账号"
            }
        } else {
            "[SKIP] SAM注册表无法读取（需要SYSTEM权限，当前仅为管理员）" | Out-File "$A\sam_clone_accounts.txt" -Encoding UTF8
            Write-Log "[INFO] SAM注册表无法读取，跳过克隆账号检测"
        }
    } catch {
        "[ERROR] SAM注册表读取失败: $($_.Exception.Message)" | Out-File "$A\sam_clone_accounts.txt" -Encoding UTF8
        Write-Log "[FAIL] SAM注册表检测出错: $($_.Exception.Message)"
    }

    # 多源交叉比对: net user vs WMI vs ProfileList
    try {
        $netNames = @(); net.exe user 2>$null | ForEach-Object { if ($_ -match '^\s*\w+') { $netNames += $_.Trim() } }
        $wmiNames = @(); if (Test-Path "$A\wmi_users.csv") { try { Import-Csv "$A\wmi_users.csv" -Encoding UTF8 -ErrorAction Stop | ForEach-Object { $wmiNames += $_.Name } } catch {} }
        $profNames = @(); if (Test-Path "$A\profilelist_users.csv") { try { Import-Csv "$A\profilelist_users.csv" -Encoding UTF8 -ErrorAction Stop | ForEach-Object { if ($_.UserName) { $profNames += $_.UserName } } } catch {} }
        $alerts = @()
        # net user有但WMI没有 → WMI可能被hook
        $onlyNet = $netNames | Where-Object { $_ -notin $wmiNames -and $_ -notmatch '命令|成功|账户|账号|user|account|for|command|completed|\\|\$' }
        if ($onlyNet) { $onlyNet | ForEach-Object { $alerts += "[net独有] $_ — net可见WMI不可见, WMI可能异常" } }
        # WMI有但net user没有 → NetUserEnum API可能被hook
        $onlyWMI = $wmiNames | Where-Object { $_ -notin $netNames -and $_ -notmatch '^(SYSTEM|LOCAL|NETWORK|SERVICE)' }
        if ($onlyWMI) { $onlyWMI | ForEach-Object { $alerts += "[WMI独有高危] $_ — 仅WMI可见, 可能NetUserEnum被Hook隐藏" } }
        # ProfileList有但net和WMI都没有 → 登录过的隐藏账户
        $onlyProf = $profNames | Where-Object { $_ -notin $netNames -and $_ -notin $wmiNames -and $_ -notmatch '^(Public|Default|All Users|TEMP|\.NET|systemprofile|LocalService|NetworkService)' }
        if ($onlyProf) { $onlyProf | ForEach-Object { $alerts += "[Profile独有高危] $_ — 有用户目录且登录过但API不可见, 疑似rootkit隐藏" } }
        if ($alerts.Count -gt 0) {
            $alerts | Out-File "$A\hidden_account_crosscheck.txt" -Encoding UTF8
            $alerts | ForEach-Object { Write-Log "[ALERT] $_" }
        } else {
            "[OK] 多源交叉比对: net user/WMI/ProfileList 三方数据一致" | Out-File "$A\hidden_account_crosscheck.txt" -Encoding UTF8
            Write-Log "[OK] 多源交叉比对: 三方一致"
        }
    } catch {
        "[ERROR] 多源交叉比对异常: $($_.Exception.Message)" | Out-File "$A\hidden_account_crosscheck.txt" -Encoding UTF8
    }
    Show-Progress -P 22 -S "[2/9] 账号完成"
    Flush-Log

    $m2files = Get-ChildItem "$A" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "2" -Name "Accounts" -Status "ok" -Error "" -FileCount @($m2files).Count -TotalBytes ($m2files | Measure-Object -Property Length -Sum).Sum

    # ===== 3. Persistence =====
    Show-Progress -P 23 -S "[3/9] 注册表自启动..."
    $P = "$DIR\3_persistence"
    @("HKLM\Software\Microsoft\Windows\CurrentVersion\Run","HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
      "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
      "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
      "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
      "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot",
      "HKCU\Environment") | ForEach-Object { $sn=$_ -replace '.*\\','' -replace '[\\/]','_'; IR-RegExport $_ "$P\$sn.txt" }

    Show-Progress -P 28 -S "[3/9] 服务/计划任务/WMI..."
    IR-Run "services" "sc.exe query type= service state= all" "$P\services.txt"
    IR-Run "schtasks" "schtasks.exe /query /fo CSV /v" "$P\schtasks.csv"
    try { Get-WmiObject -Class __EventFilter -Namespace root\subscription -ErrorAction Stop | Select-Object Name, Query, QueryLanguage | Out-File "$P\wmi_filters.txt" -Encoding UTF8 } catch {}
    try { Get-WmiObject -Class CommandLineEventConsumer -Namespace root\subscription -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate, ExecutablePath | Out-File "$P\wmi_consumers.txt" -Encoding UTF8 } catch {}
    try { Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription -ErrorAction SilentlyContinue | Select-Object Filter, Consumer | Out-File "$P\wmi_bindings.txt" -Encoding UTF8 } catch {}
    Show-Progress -P 32 -S "[3/9] 计划任务XML..."
    IR-RegExport "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls" "$P\appcert_dlls.txt"
    IR-RegExport "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" "$P\appinit_dlls.txt"
    IR-RegExport "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$P\password_filter.txt"
    IR-RegExport "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" "$P\network_provider.txt"
    IR-RegExport "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder" "$P\network_provider_hw.txt"
    IR-RegExport "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries" "$P\winsock_nsp.txt"
    Get-ChildItem "$env:SystemRoot\System32\Tasks" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Export-Csv "$P\task_files.csv" -NoTypeInformation -Encoding UTF8

    Show-Progress -P 36 -S "[3/9] COM/DLL劫持..."
    reg.exe query "HKCU\Software\Classes\CLSID" /s 2>$null | Out-File "$P\com_hijack\hkcu_clsid.txt" -Encoding UTF8
    reg.exe query "HKEY_CLASSES_ROOT\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}" /s 2>$null | Out-File "$P\com_hijack\CAccPropServicesClass.txt" -Encoding UTF8
    IR-RegExport "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" "$P\dll_hijack\known_dlls.txt"
    Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*\Parameters" -ErrorAction SilentlyContinue | Where-Object { $_.ServiceDll } | Select-Object @{N='Service';E={$_.PSChildName}}, ServiceDll | Export-Csv "$P\dll_hijack\suspicious_service_dlls.csv" -NoTypeInformation -Encoding UTF8
    reg.exe export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" "$P\userassist.reg" 2>$null
    reg.exe export "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" "$P\muicache.reg" 2>$null
    reg.exe export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" "$P\runmru.reg" 2>$null
    IR-Run "bits-list" "bitsadmin.exe /list /allusers" "$P\bits_jobs.txt"
    IR-Run "accessibility" "cmd.exe /c dir /s /b $env:SystemRoot\System32\sethc.exe $env:SystemRoot\System32\utilman.exe $env:SystemRoot\System32\osk.exe $env:SystemRoot\System32\DisplaySwitch.exe $env:SystemRoot\System32\AtBroker.exe" "$P\accessibility_check.txt"
    Show-Progress -P 40 -S "[3/9] 持久化完成"
    Flush-Log

    $m3files = Get-ChildItem "$P" -Recurse -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "3" -Name "Persistence" -Status "ok" -Error "" -FileCount @($m3files).Count -TotalBytes ($m3files | Measure-Object -Property Length -Sum).Sum

    # ===== 4. Ransomware check =====
    Show-Progress -P 42 -S "[4/9] VSS/勒索排查..."
    $RV = "$DIR\5_filesystem\ransomware_vss"
    IR-Run "vss-shadows" "vssadmin.exe list shadows" "$RV\vss_shadows.txt"
    IR-Run "vss-writers" "vssadmin.exe list writers" "$RV\vss_writers.txt"
    try { $so = Get-Content "$RV\vss_shadows.txt" -ErrorAction SilentlyContinue; if ($so -match "No items") { "[!] No shadow copies" | Out-File "$RV\vss_alert.txt" -Encoding UTF8 } else { $vssCount=([regex]::Matches($so,"shadow copy ID").Count); "Shadow copies: $vssCount" | Out-File "$RV\vss_alert.txt" -Encoding UTF8 } } catch {}

    $ransomExts = @('.phobos','.mallox','.hunters','.beast','.medusalocker','.babyk','.sorry','.lockbit','.lockbit3','.lockbit2','.lbl','.blackcat','.alphv','.abk','.basta','.bstar','.bianlian','.akira','.akr','.clop','.cI0p','.play','.royal','.blacksuit','.exx','.rxx','.8base','.qilin','.medusa','.rhysida','.cuba','.hive','.conti','.revil','.sodin','.sodinokibi','.darkside','.babuk','.maze','.egregor','.nefilim','.avos','.panda','.360','.sky','.sun','.blue','.fox','.locked','.encrypted','.crypted','.cry','.enc','.onion','.LOL!','.devil','.quantum','.black','.zeon','.ako','.makop','.keybtc')
    $foundExts = @()
    $userDirs = Get-UserDirs
    foreach ($user in $userDirs) {
        foreach ($ext in $ransomExts) {
            $matches = Get-ChildItem -Path $user.Path -Recurse -ErrorAction SilentlyContinue -Depth 5 -Filter "*$ext" -File | Select-Object -First 20
            if ($matches) { $foundExts += [PSCustomObject]@{User=$user.Name; Ext=$ext; Count=($matches|Measure-Object).Count} }
        }
    }
    if ($foundExts.Count -gt 0) { $foundExts | Export-Csv "$RV\encrypted_extensions.csv" -NoTypeInformation -Encoding UTF8; Write-Log "[ALERT] Ransomware extensions: $($foundExts.Count) types" }

    $notePatterns = @('*README*.txt','*DECRYPT*.txt','*RECOVER*.txt','*HOW_TO*.txt','*RANSOM*.txt','*ransom*','*decrypt*','*recover*','*勒索*','*解密*','*赎金*')
    $allNotes = @()
    foreach ($pat in $notePatterns) {
        foreach ($user in $userDirs) {
            $n = Get-ChildItem -Path $user.Path -Recurse -ErrorAction SilentlyContinue -Depth 5 -Filter $pat -File | Where-Object { $_.Length -le 100000 } | Select-Object -First 20
            if ($n) { $allNotes += $n }
        }
    }
    if ($allNotes.Count -gt 0) { $allNotes | Sort-Object LastWriteTime -Descending | Export-Csv "$RV\ransom_notes.csv" -NoTypeInformation -Encoding UTF8; Write-Log "[ALERT] Ransom notes: $($allNotes.Count) files" }

    try { Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object { $rb="$($_.DeviceID)\`$Recycle.Bin"; if (Test-Path $rb) { Get-ChildItem $rb -Force -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Out-File "$RV\recycle_bin.txt" -Encoding UTF8 -Append } } } catch {}
    Show-Progress -P 48 -S "[4/9] 勒索排查完成"
    Flush-Log

    $m4files = Get-ChildItem "$RV" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "4" -Name "Ransomware" -Status "ok" -Error "" -FileCount @($m4files).Count -TotalBytes ($m4files | Measure-Object -Property Length -Sum).Sum

    # ===== 5. System info =====
    Show-Progress -P 50 -S "[5/9] 系统信息..."
    $S = "$DIR\6_logs"
    IR-Run "systeminfo" "systeminfo.exe" "$S\systeminfo.txt"
    IR-Run "whoami" "whoami.exe /all" "$S\whoami.txt"
    IR-Run "hotfix" "wmic.exe qfe get HotFixID,Description,InstalledOn /format:list" "$S\hotfix.txt"
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv "$S\software.csv" -NoTypeInformation -Encoding UTF8

    if (Test-Path "$env:SystemRoot\Prefetch") { Get-ChildItem "$env:SystemRoot\Prefetch" -Filter "*.pf" | Select-Object Name, Length, LastWriteTime | Export-Csv "$S\prefetch.csv" -NoTypeInformation -Encoding UTF8; Write-Log "[OK] Prefetch: $((Get-ChildItem "$env:SystemRoot\Prefetch" -Filter '*.pf').Count) files" }

    Get-ChildItem Env: | Sort-Object Name | Export-Csv "$S\environment.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "[OK] Environment variables collected"
    Show-Progress -P 55 -S "[5/9] 系统信息完成"
    Flush-Log

    $m5files = Get-ChildItem "$S" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "5" -Name "System Info" -Status "ok" -Error "" -FileCount @($m5files).Count -TotalBytes ($m5files | Measure-Object -Property Length -Sum).Sum

    # ===== 6. Filesystem =====
    Show-Progress -P 58 -S "[6/9] 文件系统..."
    $F = "$DIR\5_filesystem"
    $tempExes = @()
    foreach ($user in $userDirs) {
        $tempExes += Get-ChildItem -Path $user.Path -Recurse -ErrorAction SilentlyContinue -Depth 4 | Where-Object { -not $_.PSIsContainer } | Select-Object FullName, Length, LastWriteTime, CreationTime
    }
    $tempExes | Export-Csv "$F\temp_executables.csv" -NoTypeInformation -Encoding UTF8

    $threatCats = @{
        'Ransomware'    = @('.lockbit','.lockbit3','.lockbit2','.lbl','.blackcat','.alphv','.abk','.basta','.bstar','.bianlian','.akira','.akr','.clop','.cI0p','.play','.royal','.blacksuit','.exx','.rxx','.8base','.qilin','.medusa','.rhysida','.cuba','.hive','.conti','.revil','.sodin','.sodinokibi','.darkside','.babuk','.maze','.egregor','.nefilim','.avos','.panda','.360','.phobos','.mallox','.hunters','.beast','.medusalocker','.babyk','.sorry','.sky','.sun','.blue','.fox','.locked','.encrypted','.crypted','.cry','.enc','.onion','.LOL!','.devil','.quantum','.black','.zeon','.ako','.makop','.keybtc')
        'Scripts'    = @('.ps1','.psm1','.psd1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.bat','.cmd')
        'RAT'    = @('.scr','.pif','.cpl','.com','.msi','.msp')
        'Macro'  = @('.docm','.xlsm','.pptm','.dotm','.xlam','.sct')
        'MemoryLoad' = @('.bin','.payload','.shellcode','.data','.mem','.pdb','.config')
    }
    $threatResults = @()
    foreach ($user in $userDirs) {
        foreach ($cat in $threatCats.Keys) {
            $exts = $threatCats[$cat]
            try {
                $files = Get-ChildItem -Path $user.Path -Recurse -ErrorAction SilentlyContinue -Depth 5 -File | Where-Object {
                    $ext = $_.Extension.ToLower(); $exts -contains $ext
                } | Select-Object FullName, Length, LastWriteTime
                if ($files) {
                    $threatResults += [PSCustomObject]@{User=$user.Name; Category=$cat; Count=($files|Measure-Object).Count; TotalSizeKB=[math]::Round((($files|Measure-Object Length -Sum).Sum)/1KB,2)}
                }
            } catch {}
        }
    }
    if ($threatResults.Count -gt 0) {
        $threatResults | Sort-Object Count -Descending | Export-Csv "$F\threat_file_categories.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "[THREAT] Threat file categories: $($threatResults.Count) types, $(($threatResults|Measure-Object Count -Sum).Sum) files"
    }

    if (Test-Path "$env:USERPROFILE\Downloads") {
        Get-ChildItem "$env:USERPROFILE\Downloads" -Recurse -ErrorAction SilentlyContinue -Depth 4 | Where-Object { -not $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object FullName, Length, LastWriteTime | Export-Csv "$F\downloads.csv" -NoTypeInformation -Encoding UTF8
    }
    if (Test-Path "$env:USERPROFILE\Recent") {
        Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Export-Csv "$F\recent_files.csv" -NoTypeInformation -Encoding UTF8
    }
    Show-Progress -P 62 -S "[6/9] 文件系统完成"
    Flush-Log

    $m6files = Get-ChildItem "$F" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "6" -Name "Filesystem" -Status "ok" -Error "" -FileCount @($m6files).Count -TotalBytes ($m6files | Measure-Object -Property Length -Sum).Sum

    # ===== 7. Logs =====
    Show-Progress -P 65 -S "[7/9] 事件日志..."
    $L = "$DIR\6_logs"
    @("Security","System","Application","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TerminalServices-LocalSessionManager/Operational") | ForEach-Object { $sn=$_ -replace '[/\\]','_'; wevtutil.exe epl "$_" "$L\$sn.evtx" 2>$null }
    try { $rdp=@(); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';ID=21,22,23,24} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { $rdp+=[PSCustomObject]@{TimeCreated=$_.TimeCreated; Id=$_.Id; Message=$_.Message-replace"`r?`n",' '} }; $rdp|Sort-Object TimeCreated -Descending|Export-Csv "$L\rdp_sessions.txt" -NoTypeInformation -Encoding UTF8 } catch {}
    try { $psb=@(); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { $psb+=[PSCustomObject]@{TimeCreated=$_.TimeCreated; Message=$_.Message-replace"`r?`n",''} }; $psb|Sort-Object TimeCreated -Descending|Export-Csv "$L\powershell_scriptblock.txt" -NoTypeInformation -Encoding UTF8 } catch {}
    try { wevtutil.exe epl "Microsoft-Windows-Sysmon/Operational" "$L\Sysmon_Operational.evtx" 2>$null; if(Test-Path "$L\Sysmon_Operational.evtx"){Write-Log "[OK] Sysmon log collected"}else{Write-Log "[INFO] Sysmon not installed"} } catch { Write-Log "[INFO] Sysmon collection skipped" }
    $pflog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"; if (Test-Path $pflog) { Copy-Item $pflog "$L\pfirewall.log" -Force; Write-Log "[OK] Firewall log collected" } else { Write-Log "[INFO] Firewall log not enabled" }
    Show-Progress -P 70 -S "[7/9] 日志完成"
    Flush-Log

    $m7files = Get-ChildItem "$L" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "7" -Name "Event Logs" -Status "ok" -Error "" -FileCount @($m7files).Count -TotalBytes ($m7files | Measure-Object -Property Length -Sum).Sum

    # ===== 8. Web =====
    Show-Progress -P 73 -S "[8/9] Web信息..."
    $W = "$DIR\7_web"
    if (Test-Path "$env:SystemRoot\System32\inetsrv\config\applicationHost.config") { Copy-Item "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" "$W\" -Force -ErrorAction SilentlyContinue }
    IR-Run "iis-sites" "%windir%\system32\inetsrv\appcmd.exe list site" "$W\iis_sites.txt"
    $w3svc = "$env:SystemRoot\System32\LogFiles\W3SVC"; if (Test-Path $w3svc) { Get-ChildItem "$w3svc\*" -Directory -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item "$($_.FullName)\*.log" "$W" -Force -ErrorAction SilentlyContinue; if(Test-Path "$W\*.log"){Write-Log "[OK] IIS logs: $($_.FullName).log"}} } else { Write-Log "[INFO] IIS W3SVC logs not found" }
    Show-Progress -P 76 -S "[8/9] Web完成"
    Flush-Log

    # --- Service versions summary ---
    Show-Progress -P 78 -S "[8/9] 服务版本摘要..."
    $SV = "$DIR\5_filesystem\service_versions.txt"
    $iisVer = try { $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction Stop; "IIS $($reg.MajorVersion).$($reg.MinorVersion)" } catch { "IIS: not installed" }
    $rdpStatus = try { $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction Stop; if($rdp.fDenyTSConnections -eq 0){"RDP: enabled"}else{"RDP: disabled"} } catch { "RDP: unable to read" }
    $sshInfo = if (Get-Service sshd -ErrorAction SilentlyContinue) { "OpenSSH: installed, status=$((Get-Service sshd).Status)" } else { "OpenSSH: not installed" }
    $javaInfo = if (Get-Command java -ErrorAction SilentlyContinue) { try { & java -version 2>&1 | Select-Object -First 1 } catch { "Java: installed" } } else { "Java: not detected" }
    $sysmonInfo = if (Get-Service Sysmon -ErrorAction SilentlyContinue) { "Sysmon: installed, service status=$((Get-Service Sysmon).Status)" } else { "Sysmon: not installed" }
    $webSvrs = @(); if (Test-Path "$env:SystemRoot\System32\inetsrv\w3wp.exe"){$webSvrs+="IIS"}; if (Get-Command nginx -ErrorAction SilentlyContinue){$webSvrs+="Nginx(PATH)"}; if (Test-Path (Join-Path $env:ProgramFiles "nginx\nginx.exe")){$webSvrs+="Nginx(ProgFiles)"}; if (Get-Command httpd -ErrorAction SilentlyContinue){$webSvrs+="Apache"}
    $lp = netstat.exe -ano | Select-String "LISTENING" | ForEach-Object { if($_ -match "TCP\s+(\S+:\d+)\s+.*LISTENING\s+(\d+)") { $iport=$matches[1]; $p=$matches[2]; try{$pn=(Get-Process -Id $p -ErrorAction SilentlyContinue).ProcessName}catch{$pn="?"}; "$iport ($pn)" } }
    @("Service version info (IR_Collect v5.2)";"Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')";"============================";$iisVer;$rdpStatus;$sshInfo;$javaInfo;"Web servers: $(if($webSvrs.Count -gt 0){$webSvrs -join ', '}else{'none'})";"============================";"Listening ports:";$lp;"";"Sysmon status:";$sysmonInfo) | Out-File $SV -Encoding UTF8
    Write-Log "[OK] Service version summary"
    Show-Progress -P 79 -S "[8/9] Web完成"
    $m8files = Get-ChildItem "$W" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "8" -Name "Web info" -Status "ok" -Error "" -FileCount @($m8files).Count -TotalBytes ($m8files | Measure-Object -Property Length -Sum).Sum

    # --- Browser artifacts ---
    Show-Progress -P 81 -S "[8/9] 游览器记录..."
    $BA = Join-Path $DIR "browser_artifacts"
    $browserSummary = @()

    $browserPaths = @(
        @{Name="Chrome";     Path="Google\Chrome\User Data";          DB="History";       SubDir="Local"},
        @{Name="Edge";       Path="Microsoft\Edge\User Data";         DB="History";       SubDir="Local"},
        @{Name="Firefox";    Path="Mozilla\Firefox\Profiles";         DB="places.sqlite"; SubDir="Roaming"},
        @{Name="Opera";      Path="Opera Software\Opera Stable";       DB="History";       SubDir="Roaming"},
        @{Name="Brave";      Path="BraveSoftware\Brave-Browser\User Data"; DB="History"; SubDir="Local"},
        @{Name="360SE";      Path="360se6\User Data";                  DB="History";       SubDir="Roaming"},
        @{Name="QQBrowser";  Path="Tencent\QQBrowser\User Data";      DB="History";       SubDir="Roaming"},
        @{Name="Chromium";   Path="Chromium\User Data";               DB="History";       SubDir="Local"},
        @{Name="Vivaldi";    Path="Vivaldi\User Data";                DB="History";       SubDir="Local"}
    )

    $usersPath = Join-Path $systemDrive "Users"
    $userDirs = Get-ChildItem $usersPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(Public|Default|All Users)" -and $_.Name -notlike ".*" }

    foreach ($userDir in $userDirs) {
        $userName = $userDir.Name
        foreach ($bp in $browserPaths) {
            $appData = if ($bp.SubDir -eq "Local") { Join-Path $userDir.FullName "AppData\Local" } else { Join-Path $userDir.FullName "AppData\Roaming" }
            $basePath = Join-Path $appData $bp.Path
            if (-not (Test-Path $basePath)) { continue }

            if ($bp.Name -eq "Firefox") {
                $profiles = Get-ChildItem $basePath -Directory -ErrorAction SilentlyContinue
                foreach ($prof in $profiles) {
                    $dbPath = Join-Path $prof.FullName $bp.DB
                    if (Test-Path $dbPath) {
                        $dest = "$BA\${userName}_Firefox_$($prof.Name)_places.sqlite"
                        try { Copy-Item $dbPath $dest -Force -ErrorAction Stop; $browserSummary += "[OK] $userName Firefox($($prof.Name)): $dbPath"; Write-Log "[OK] Browser: $userName Firefox($($prof.Name))" }
                        catch { $browserSummary += "[SKIP] $userName Firefox($($prof.Name)): locked"; Write-Log "[SKIP] Browser: $userName Firefox($($prof.Name)) - locked" }
                    }
                }
            } else {
                $profiles = Get-ChildItem $basePath -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName $bp.DB) }
                foreach ($prof in $profiles) {
                    $dbPath = Join-Path $prof.FullName $bp.DB
                    $dest = "$BA\${userName}_$($bp.Name)_$($prof.Name)_history.db"
                    try { Copy-Item $dbPath $dest -Force -ErrorAction Stop; $browserSummary += "[OK] $userName $($bp.Name)($($prof.Name)): $dbPath"; Write-Log "[OK] Browser: $userName $($bp.Name)($($prof.Name))" }
                    catch { $browserSummary += "[SKIP] $userName $($bp.Name)($($prof.Name)): locked"; Write-Log "[SKIP] Browser: $userName $($bp.Name)($($prof.Name)) - locked" }
                }
            }
        }
    }

    if ($browserSummary.Count -eq 0) { $browserSummary += "[NONE] No browser data found" }
    $browserSummary | Out-File "$BA\browser_summary.txt" -Encoding UTF8

    $m85files = Get-ChildItem "$BA" -File -ErrorAction SilentlyContinue
    Add-ModuleStatus -ModuleId "8.5" -Name "Browser Artifacts" -Status "ok" -Error "" -FileCount @($m85files).Count -TotalBytes ($m85files | Measure-Object -Property Length -Sum).Sum
    Write-Log "[OK] Browser artifacts: found $($browserSummary.Count) records"

    # ===== 8.6. Targeted collection (v5.2, optional) =====
    if ($Target) {
        Show-Progress -P 82 -S "[8.5/9] 定向采集: $Target..."
        $targetsDir = Join-Path $PSScriptRoot "targets"
        if (-not (Test-Path $targetsDir)) {
            $altTargets = Join-Path (Split-Path $PSScriptRoot -Parent) "config\targets"
            if (Test-Path $altTargets) { $targetsDir = $altTargets }
        }
        Invoke-TargetedCollection -TargetName $Target -OutRoot $DIR -TargetsDir $targetsDir
        Flush-Log
    }

    # ===== 9. Finalize =====
    # TEMP_MEI after comparison
    Show-Progress -P 84 -S "[9/9] TEMP_MEI 对比..."
    $TEMP_AFTER = Join-Path $DIR "temp_mei_after.csv"
    $afterMei = Get-ChildItem "$env:TEMP\_MEI*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{ FullName = $_.FullName; LastWrite = $_.LastWriteTime; Created = $_.CreationTime }
    }
    $afterMei | Export-Csv $TEMP_AFTER -NoTypeInformation -Encoding UTF8
    try {
        $beforeMei = Import-Csv (Join-Path $DIR "temp_mei_before.csv") -ErrorAction Stop
        $bPaths = @($beforeMei | ForEach-Object { $_.FullName })
        $aPaths = @($afterMei | ForEach-Object { $_.FullName })
        $newDirs = $aPaths | Where-Object { $_ -notin $bPaths }
        if ($newDirs) { $newDirs | ForEach-Object { Write-Log "[ALERT] New TEMP_MEI directory: $_" } }
        else { Write-Log "[OK] No new TEMP_MEI directories" }
    } catch {
        Write-Log "[WARN] TEMP_MEI comparison failed: $($_.Exception.Message)"
    }
    Write-Log "[OK] TEMP_MEI comparison done"

    Show-Progress -P 86 -S "[9/9] 计算元数据..."
    $ips = try { (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).IPAddress -join ', ' } catch { "" }
    $os = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { "Unknown" }
    $allFiles = Get-ChildItem $DIR -Recurse -File -ErrorAction SilentlyContinue
    $fileCount = @($allFiles).Count
    $totalBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
    $rawSize = if ($totalBytes) { "{0:N1} MB" -f ($totalBytes / 1MB) } else { "0 B" }

    @"
IR Collection Metadata
=======================
Host: $HOSTNAME
IP(s): $ips
OS: $os
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script version: IR_Collect v5.2
File count: $fileCount
Total size: $rawSize
Signatures: total $stTotal, valid $stValid, unsigned $stUnsigned
Process anomalies: $($ar.Count)
"@ | Out-File "$DIR\IR_metadata.txt" -Encoding UTF8

    Show-Progress -P 88 -S "[9/9] 文件清单..."
    Get-ChildItem $DIR -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Export-Csv "$DIR\file_manifest.csv" -NoTypeInformation -Encoding UTF8

    Show-Progress -P 90 -S "[9/9] 采集清单..."
    $mfest = @{
        schema="ir-collection-manifest-v1"
        hostname=$HOSTNAME
        collection_time=(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        script_version="5.2"
        total_modules=$moduleStatus.Count
        modules_ok=($moduleStatus | Where-Object {$_.status -eq "ok"}).Count
        modules_partial=($moduleStatus | Where-Object {$_.status -eq "partial"}).Count
        modules_failed=($moduleStatus | Where-Object {$_.status -eq "failed"}).Count
        errors=@($moduleStatus | Where-Object {$_.error -ne ""} | ForEach-Object {"$($_.module_id) $($_.name): $($_.error)"})
        modules=@($moduleStatus)
        zip_sha256_expected=""
    } | ConvertTo-Json -Depth 3
    $mfest | Out-File "$DIR\collection_manifest.json" -Encoding UTF8
    Write-Log "[OK] Collection manifest"

    # --- Compression ---
    Show-Progress -P 94 -S "[9/9] 压缩中..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    try {
        if (Test-Path $ZIP) { Remove-Item $ZIP -Force -ErrorAction Stop }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($DIR, $ZIP, [System.IO.Compression.CompressionLevel]::Optimal, $false)
        Write-Log "[OK] Compression done: $ZIP"
        $zipHash = (Get-FileHash $ZIP -Algorithm SHA256 -ErrorAction Stop).Hash
        $zipSize = if (Test-Path $ZIP) { "{0:N1} MB" -f ((Get-Item $ZIP).Length / 1MB) } else { "Compression failed" }
        $zipFileCount = 0
        try { $zipFileCount = ([System.IO.Compression.ZipFile]::OpenRead($ZIP)).Entries.Count } catch { $zipFileCount = -1 }
        if ($zipFileCount -gt 0) { Write-Log "[OK] ZIP contains $zipFileCount files" }
        else { Write-Log "[WARN] ZIP may be corrupted or empty" }
    } catch {
        Write-Log "[ERROR] Compression failed: $($_.Exception.Message)"
        $zipHash = "Failed"
        $zipSize = "Failed"
    }

    Write-Log "[=== Collection finished $(Get-Date -Format $fmt) ===]"
    Write-Log "ZIP: $ZIP | SHA256: $zipHash"
    Flush-Log

    Show-Progress -P 100 -S "收集完成！"
    Start-Sleep -Milliseconds 200
    Close-Progress

    # ---------- Completion popup ----------
    if ($hasUI) {
        $rf = New-Object System.Windows.Forms.Form
        $rf.Text = "IR取证收集完成"
        $rf.Size = New-Object System.Drawing.Size(500, 290)
        $rf.StartPosition = "CenterScreen"
        $rf.FormBorderStyle = "FixedDialog"
        $rf.MaximizeBox = $false
        $rf.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)

        $tl = New-Object System.Windows.Forms.Label
        $tl.Location = New-Object System.Drawing.Point(20, 15)
        $tl.Size = New-Object System.Drawing.Size(450, 30)
        $tl.Text = "IR取证收集完成！"
        $tl.ForeColor = [System.Drawing.Color]::FromArgb(100,255,100)
        $tl.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 14, [System.Drawing.FontStyle]::Bold)
        $rf.Controls.Add($tl)

        $il = New-Object System.Windows.Forms.Label
        $il.Location = New-Object System.Drawing.Point(20, 55)
        $il.Size = New-Object System.Drawing.Size(450, 140)
        $il.ForeColor = [System.Drawing.Color]::White
        $il.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9)
        $hashDisplay = if ($zipHash -and $zipHash.Length -ge 32) { $zipHash.Substring(0,32) + "..." } else { $zipHash }
        $sizeDisplay = if ($zipSize) { $zipSize } else { "未知" }
        $il.Text = "压缩包: $ZIP`n大小:   $sizeDisplay`nSHA256: $hashDisplay`n`n文件数: $(if($zipFileCount -gt 0){$zipFileCount}else{'未知'}) (ZIP内) | 主机: $HOSTNAME`n签名: 有效$stValid / 无签名$stUnsigned`n异常进程: $($ar.Count) 条`n`n请将此 ZIP 文件拖入 Codex 对话窗口即可自动分析。"
        $rf.Controls.Add($il)

        $ob = New-Object System.Windows.Forms.Button
        $ob.Location = New-Object System.Drawing.Point(20, 205)
        $ob.Size = New-Object System.Drawing.Size(140, 30)
        $ob.Text = "打开目录"
        $ob.BackColor = [System.Drawing.Color]::FromArgb(60,60,60)
        $ob.ForeColor = [System.Drawing.Color]::White
        $ob.FlatStyle = "Flat"
        $ob.Add_Click({ try { Start-Process "explorer.exe" "/select,`"$ZIP`"" } catch {} })
        $rf.Controls.Add($ob)

        $eb = New-Object System.Windows.Forms.Button
        $eb.Location = New-Object System.Drawing.Point(180, 205)
        $eb.Size = New-Object System.Drawing.Size(140, 30)
        $eb.Text = "退出"
        $eb.BackColor = [System.Drawing.Color]::FromArgb(60,60,60)
        $eb.ForeColor = [System.Drawing.Color]::White
        $eb.FlatStyle = "Flat"
        $eb.Add_Click({ $rf.Close() })
        $rf.Controls.Add($eb)

        [void]$rf.ShowDialog()
    }

    # Cleanup temp directory only if ZIP is valid
    $zipItem = Get-Item $ZIP -ErrorAction SilentlyContinue
    if ($zipItem -and $zipItem.Length -gt 0) {
        Remove-Item $DIR -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log "[WARN] ZIP not generated or empty, keeping temp directory: $DIR"
        Flush-Log
    }
} catch {
    Close-Progress
    $em = "错误: $($_.Exception.Message)`n行: $($_.InvocationInfo.ScriptLineNumber)"
    Write-Log $em
    Flush-Log
    try { [System.Windows.Forms.MessageBox]::Show($em, "IR取证 - 错误", "OK", "Error") } catch {}
}
