rule BEAST_ESXi_Linux {
  meta:
    description = "BEAST/Monster勒索 Linux/ESXi 版特征"
    author = "ir-forensic-analysis v3.0"
    family = "BEAST"
    platform = "Linux/ESXi"
    severity = "critical"
    reference = "Solar应急响应团队：BEAST勒索软件(Linux/ESXi版)加密机制与对抗策略"
    date = "2026-05-14"
  strings:
    $s1 = "beast" ascii nocase wide
    $s2 = ".vmdk" ascii nocase wide
    $s3 = "/vmfs/volumes/" ascii
    $s4 = "esxcli" ascii nocase
    $s5 = "vim-cmd" ascii nocase
    $s6 = "XChaCha20" ascii
    $s7 = "Curve25519" ascii
    $s8 = "monster" ascii nocase wide
    $s9 = ".vmx" ascii nocase wide
    $s10 = "vmfs" ascii
    $s11 = "power.off" ascii
    $s12 = "How_To_Recover" ascii nocase wide
  condition:
    (any of ($s1,$s6,$s7,$s8) and any of ($s12)) or
    (all of ($s2,$s3,$s4,$s5) and #s2 > 3) or
    (any of ($s1,$s8) and any of ($s2,$s9,$s10) and any of ($s4,$s5,$s11))
}

rule BEAST_Windows {
  meta:
    description = "BEAST/Monster勒索 Windows 版特征"
    author = "ir-forensic-analysis v3.0"
    family = "BEAST"
    platform = "Windows"
    severity = "critical"
    reference = "Solar应急响应团队：BEAST图形化勒索软件(Windows版)加密逻辑与免杀手段"
    date = "2026-05-14"
  strings:
    $s1 = "beast" ascii nocase wide
    $s2 = "monster" ascii nocase wide
    $s3 = "XChaCha20" ascii wide
    $s4 = "Curve25519" ascii wide
    $s5 = ".beast" ascii nocase wide
    $s6 = ".monster" ascii nocase wide
    $s7 = "How_To_Recover" ascii nocase wide
    $s8 = "VirtualBox" ascii nocase
    $s9 = "VMware" ascii nocase
    $s10 = "vssadmin delete shadows" ascii nocase wide
  condition:
    (any of ($s1,$s2) and any of ($s5,$s6,$s7)) or
    (any of ($s3,$s4) and any of ($s8,$s9)) or
    (any of ($s1,$s2) and $s10 and any of ($s8,$s9))
}

rule ESXi_Ransomware_Generic {
  meta:
    description = "ESXi虚拟化平台勒索通用检测特征"
    author = "ir-forensic-analysis v3.0"
    severity = "critical"
    date = "2026-05-14"
  strings:
    $s1 = "/vmfs/volumes/" ascii
    $s2 = "vim-cmd vmsvc/power.off" ascii
    $s3 = "esxcli vm process kill" ascii
    $s4 = "esxcli system shutdown" ascii
    $s5 = ".vmdk" ascii
    $s6 = ".vmx" ascii
    $s7 = ".vmsn" ascii
    $s8 = "snapshot.removeall" ascii
    $s9 = "vmkfs" ascii
    $s10 = "vmware-vim-cmd" ascii
  condition:
    (any of ($s2,$s3,$s4) and #s5 > 3) or
    (all of ($s1,$s5) and any of ($s2,$s3,$s4,$s8,$s9)) or
    (#s5 > 10 and #s6 > 5 and any of ($s2,$s3,$s10))
}
