rule Webshell_PHP_Generic {
    meta:
        description = "Generic PHP webshell indicators"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $base64 = "base64_decode(" nocase
        $system = "system(" nocase
        $exec = "exec(" nocase
        $shell_exec = "shell_exec(" nocase
        $passthru = "passthru(" nocase
        $proc_open = "proc_open(" nocase
        $post_var = "$_POST[" nocase
        $get_var = "$_GET[" nocase
        $request_var = "$_REQUEST[" nocase
        $cmd = "$cmd" nocase
        $one_liner1 = "@eval($_POST[" nocase
        $one_liner2 = "assert($_POST[" nocase
        $one_liner3 = "eval($_REQUEST[" nocase
        $chmod = "chmod(" nocase
        $file_put = "file_put_contents(" nocase
        $move_upload = "move_uploaded_file(" nocase

    condition:
        filesize < 500KB and (
            (2 of ($eval, $assert, $base64, $system, $exec, $shell_exec, $passthru, $proc_open) and
             1 of ($post_var, $get_var, $request_var, $cmd)) or
            any of ($one_liner*)
        )
}

rule Webshell_PHP_Chinese {
    meta:
        description = "Chinese webshell variants"
        author = "IR-Forensic-Analysis"
        severity = "critical"
        mitre_attack = "T1505.003"

    strings:
        $b374k = "b374k" nocase
        $wso = "WSO" nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $alfa = "Alfa" nocase
        $filesman = "FilesMan" nocase
        $mysql_interface = "mysql_interface" nocase
        $safe_mode = "safe_mode" nocase
        $phpspy = "phpspy" nocase

    condition:
        any of them
}

rule Webshell_JSP_Generic {
    meta:
        description = "Generic JSP webshell indicators"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $runtime = "Runtime.getRuntime()" nocase
        $exec = ".exec(" nocase
        $processbuilder = "ProcessBuilder" nocase
        $inputstream = "InputStream" nocase
        $bufferedreader = "BufferedReader" nocase
        $request_getparameter = "request.getParameter" nocase

    condition:
        $runtime and $exec and 1 of ($inputstream, $bufferedreader) and $request_getparameter
}

rule Webshell_ASP_Generic {
    meta:
        description = "Generic ASP/ASPX webshell indicators"
        author = "IR-Forensic-Analysis"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $execute = "Execute(" nocase
        $eval_asp = "Eval(" nocase
        $cmd_asp = "cmd.exe" nocase
        $wscript = "WScript.Shell" nocase
        $request_form = "Request.Form" nocase
        $request_querystring = "Request.QueryString" nocase

    condition:
        1 of ($execute, $eval_asp) and 1 of ($wscript, $cmd_asp) and 1 of ($request_form, $request_querystring)
}
