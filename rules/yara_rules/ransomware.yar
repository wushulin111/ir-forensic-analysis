rule Ransomware_Phobos {
  meta:
    description = "Phobos勒索病毒家族特征"
    author = "ir-forensic-analysis v3.0"
    family = "Phobos"
    severity = "critical"
    reference = "Solar：Phobos勒索病毒jopanaxye/2700变种"
    date = "2026-05-14"
  strings:
    $note1 = "HOW_TO_DECRYPT" ascii nocase wide
    $note2 = "info.hta" ascii wide
    $note3 = "bestcor@tutanota.com" ascii wide
    $note4 = "helpers@airmail.cc" ascii wide
    $ext1 = ".phobos" ascii nocase wide
    $ext2 = ".jopanaxye" ascii nocase wide
    $ext3 = ".2700" ascii wide
    $ext4 = ".dewar" ascii nocase wide
    $ext5 = ".king" ascii nocase wide
    $vss = "vssadmin delete shadows" ascii nocase wide
  condition:
    (any of ($note1,$note2) and any of ($ext1,$ext2,$ext3,$ext4,$ext5)) or
    (any of ($note3,$note4) and $vss) or
    (any of ($ext1,$ext2,$ext3) and $vss)
}

rule Ransomware_Mallox {
  meta:
    description = "mallox/rmallox勒索病毒家族特征"
    author = "ir-forensic-analysis v3.0"
    family = "mallox"
    severity = "critical"
    reference = "Solar：mallox勒索病毒NAS漏洞入侵24小时解密恢复"
    date = "2026-05-14"
  strings:
    $note1 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase wide
    $note2 = "HowToRecover" ascii nocase wide
    $ext1 = ".mallox" ascii nocase wide
    $ext2 = ".rmallox" ascii nocase wide
    $ext3 = ".fargo" ascii nocase wide
    $vss = "vssadmin delete shadows" ascii nocase wide
  condition:
    (any of ($note1,$note2) and any of ($ext1,$ext2,$ext3)) or
    (any of ($ext1,$ext2,$ext3) and $vss)
}

rule Ransomware_MedusaLocker {
  meta:
    description = "MedusaLocker勒索病毒家族特征"
    author = "ir-forensic-analysis v3.0"
    family = "MedusaLocker"
    severity = "critical"
    reference = "Solar：深入剖析MedusaLocker勒索家族"
    date = "2026-05-14"
  strings:
    $note1 = "MedusaLocker" ascii nocase wide
    $note2 = "HOW_TO_RECOVER" ascii nocase wide
    $note3 = "READ_NOTE" ascii nocase wide
    $ext1 = ".medusalocker" ascii nocase wide
    $ext2 = ".encrypted" ascii wide
    $vss = "vssadmin delete shadows" ascii nocase wide
    $wbadmin = "wbadmin delete catalog" ascii nocase wide
  condition:
    (any of ($note1,$note2,$note3) and any of ($ext1,$ext2)) or
    ($note1 and any of ($vss,$wbadmin))
}

rule Ransomware_Generic_Behavior {
  meta:
    description = "勒索病毒通用行为特征检测"
    author = "ir-forensic-analysis v3.0"
    severity = "critical"
    date = "2026-05-14"
  strings:
    $vss1 = "vssadmin delete shadows" ascii nocase wide
    $vss2 = "wmic shadowcopy delete" ascii nocase wide
    $wbadmin = "wbadmin delete catalog" ascii nocase wide
    $bcdedit = "bcdedit /set recoveryenabled No" ascii nocase wide
    $disabler = "DisableSR" ascii wide
    $stop_vss = "net stop vss" ascii nocase wide
    $stop_vss2 = "sc stop vss" ascii nocase wide
    $backup_del = "wmic.exe backup delete" ascii nocase wide
    $note1 = "HOW_TO_DECRYPT" ascii nocase wide
    $note2 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase wide
    $note3 = "READ_ME" ascii nocase wide
    $note4 = "README" ascii wide
    $bitcoin = "bitcoin" ascii nocase wide
    $tor = ".onion" ascii wide
  condition:
    (any of ($vss1,$vss2,$wbadmin,$bcdedit) and any of ($note1,$note2,$note3)) or
    (any of ($stop_vss,$stop_vss2,$backup_del) and any of ($note1,$note2,$note3)) or
    (any of ($note1,$note2,$note3,$note4) and $bitcoin and $tor)
}
