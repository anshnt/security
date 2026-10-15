/*
    Aegis Security Suite - core YARA rules.
    Small, high-precision rules that ship with the product; the full community
    ruleset (YARA Forge) is downloaded by `aegis update`.
    NOTE: the EICAR test string is expressed as hex so this file is not itself
    flagged as a test virus by other antivirus engines.
*/

import "pe"

rule Aegis_EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless, used to verify protection works)"
        severity = "low"
        author = "Aegis"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        // the standard 68-byte EICAR test string, as hex
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        filesize < 4KB and $eicar
}

rule Aegis_PowerShell_Obfuscated_Download_Cradle
{
    meta:
        description = "PowerShell script that downloads and executes remote code while hiding or encoding itself"
        severity = "high"
        author = "Aegis"
        mitre = "T1059.001, T1105, T1027"
    strings:
        $iex = /\b(iex|invoke-expression)\b/ nocase ascii wide
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadFile" nocase ascii wide
        $dl3 = "Net.WebClient" nocase ascii wide
        $dl4 = "Invoke-WebRequest" nocase ascii wide
        $dl5 = "Start-BitsTransfer" nocase ascii wide
        $dl6 = "System.Net.Http.HttpClient" nocase ascii wide
        $hide1 = /-w(indowstyle)?\s+hidden/ nocase ascii wide
        $hide2 = /-(nop|noprofile)\b/ nocase ascii wide
        $hide3 = /-(enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase ascii wide
        $hide4 = /-ep\s+bypass|-executionpolicy\s+bypass/ nocase ascii wide
        $obf1 = "FromBase64String" nocase ascii wide
        $obf2 = /\[char\]\s*\d+\s*\+\s*\[char\]/ nocase ascii wide
        $obf3 = "-bxor" nocase ascii wide
        $amsi = "AmsiUtils" nocase ascii wide
        $amsi2 = "amsiInitFailed" nocase ascii wide
    condition:
        filesize < 3MB and
        (
            ($iex and 1 of ($dl*) and 2 of ($hide*, $obf*)) or
            ($amsi and $amsi2) or
            (1 of ($dl*) and $obf1 and $hide3 and $hide1)
        )
}

rule Aegis_Mimikatz
{
    meta:
        description = "Mimikatz credential-dumping tool (or a binary embedding it)"
        severity = "critical"
        author = "Aegis"
        mitre = "T1003.001, T1550.002"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase ascii wide
        $s2 = "gentilkiwi" nocase ascii wide
        $s3 = "mimikatz" nocase ascii wide
        $s4 = "lsadump::sam" nocase ascii wide
        $s5 = "kerberos::golden" nocase ascii wide
        $s6 = "privilege::debug" nocase ascii wide
        $s7 = "sekurlsa::pth" nocase ascii wide
        $s8 = "Benjamin DELPY" ascii wide
        $s9 = "mimidrv" nocase ascii wide
        $ps = "Invoke-Mimikatz" nocase ascii wide
    condition:
        (uint16(0) == 0x5A4D and 3 of ($s*)) or
        ($ps and 2 of ($s*)) or
        (uint16(0) == 0x5A4D and $s1 and $s6)
}

rule Aegis_CobaltStrike_Default_Pipes
{
    meta:
        description = "Cobalt Strike beacon / payload using default named pipe names"
        severity = "critical"
        author = "Aegis"
        mitre = "T1055, T1570, T1071"
    strings:
        $p1 = "\\\\.\\pipe\\msagent_" ascii wide
        $p2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $p3 = "\\\\.\\pipe\\postex_" ascii wide
        $p4 = "\\\\.\\pipe\\mojo.5688.8052.183894939787088877" ascii wide
        $p5 = "\\\\.\\pipe\\mojo.5688.8052.35780273329370473" ascii wide
        $p6 = "\\\\.\\pipe\\status_" ascii wide
        $p7 = "\\\\.\\pipe\\interprocess_" ascii wide
        $p8 = "\\\\.\\pipe\\postex_ssh_" ascii wide
        $fmt = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii
    condition:
        filesize < 20MB and (1 of ($p1, $p2, $p3, $p4, $p5, $p8, $fmt) or 2 of ($p*))
}

rule Aegis_XMRig_Miner
{
    meta:
        description = "XMRig / Monero cryptocurrency miner"
        severity = "high"
        author = "Aegis"
        mitre = "T1496"
    strings:
        $x1 = "xmrig" nocase ascii wide
        $x2 = "--donate-level" ascii
        $x3 = "stratum+tcp://" ascii
        $x4 = "stratum+ssl://" ascii
        $x5 = "randomx" nocase ascii
        $x6 = "cryptonight" nocase ascii
        $x7 = "\"donate-level\"" ascii
        $x8 = "pool.minexmr.com" ascii
        $x9 = "--cpu-priority" ascii
        $x10 = "supportxmr.com" ascii
        $x11 = "\"rig-id\"" ascii
    condition:
        filesize < 80MB and
        (
            ($x1 and 2 of ($x2, $x3, $x4, $x7, $x9, $x11)) or
            (1 of ($x3, $x4) and 2 of ($x2, $x5, $x6, $x7, $x8, $x10, $x9))
        )
}

rule Aegis_Ransomware_Note_Generic
{
    meta:
        description = "Text resembling a ransomware ransom note"
        severity = "high"
        author = "Aegis"
        mitre = "T1486"
    strings:
        $e1 = "your files have been encrypted" nocase ascii wide
        $e2 = "all your files are encrypted" nocase ascii wide
        $e3 = "your files are encrypted" nocase ascii wide
        $e4 = "files have been locked" nocase ascii wide
        $e5 = "to decrypt your files" nocase ascii wide
        $e6 = "your data has been stolen" nocase ascii wide
        $e7 = "your network has been breached" nocase ascii wide
        $p1 = "bitcoin" nocase ascii wide
        $p2 = ".onion" nocase ascii wide
        $p3 = "tor browser" nocase ascii wide
        $p4 = "decryptor" nocase ascii wide
        $p5 = "decryption key" nocase ascii wide
        $p6 = "private key" nocase ascii wide
        $p7 = "monero" nocase ascii wide
        $p8 = "do not try to" nocase ascii wide
    condition:
        filesize < 200KB and 1 of ($e*) and 2 of ($p*)
}

rule Aegis_PHP_Webshell
{
    meta:
        description = "PHP web shell executing attacker-supplied input"
        severity = "high"
        author = "Aegis"
        mitre = "T1505.003"
    strings:
        $php = "<?php" nocase
        $short = "<?="
        $direct = /\b(eval|assert|system|passthru|shell_exec|popen|proc_open|exec)\s*\(\s*(base64_decode\s*\(\s*|gzinflate\s*\(\s*|str_rot13\s*\(\s*|stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $var = /\$\w{1,20}\s*=\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*;\s*(@?\s*)?(eval|assert|system|passthru|shell_exec)\s*\(\s*\$\w{1,20}\s*\)/ nocase
        $dyn = /\$\w{1,20}\s*=\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*;[^;]{0,60}\$\w{1,20}\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $kit1 = "c99shell" nocase
        $kit2 = "r57shell" nocase
        $kit3 = "b374k" nocase
        $kit4 = "FilesMan" ascii
        $kit5 = "WSO " ascii
        $kit6 = "China Chopper" nocase
        $kit7 = "<?php @eval($_POST" nocase
    condition:
        filesize < 1MB and ($php or $short) and
        ($direct or $var or $dyn or $kit7 or 2 of ($kit*))
}

rule Aegis_Packed_UPX_Suspicious_Imports
{
    meta:
        description = "UPX-packed executable that imports networking or process-injection APIs"
        severity = "medium"
        author = "Aegis"
        mitre = "T1027.002, T1055"
    strings:
        $upx = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and filesize < 30MB and
        (
            for any s in pe.sections : (s.name == "UPX0" or s.name == "UPX1") or
            ($upx and pe.number_of_sections <= 4 and pe.entry_point_raw > 0 and
             for any s in pe.sections : (s.raw_data_size == 0 and s.virtual_size > 0x10000))
        ) and
        (
            pe.imports("ws2_32.dll") or pe.imports("wininet.dll") or pe.imports("winhttp.dll") or
            pe.imports("urlmon.dll") or
            pe.imports("kernel32.dll", "WriteProcessMemory") or
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("ntdll.dll", "NtUnmapViewOfSection") or
            pe.imports("advapi32.dll", "AdjustTokenPrivileges")
        )
}

rule Aegis_Reverse_Shell_OneLiner
{
    meta:
        description = "Script or file containing a classic reverse-shell one-liner"
        severity = "high"
        author = "Aegis"
        mitre = "T1059, T1071"
    strings:
        $bash1 = /bash\s+-i\s+>&\s*\/dev\/tcp\/[0-9a-z.\-]+\/\d{2,5}/ nocase
        $bash2 = /exec\s+\d+<>\/dev\/tcp\/[0-9a-z.\-]+\/\d{2,5}/ nocase
        $nc1 = /\bnc(at)?\s+(-\w+\s+)*-e\s+\/bin\/(ba)?sh\b/
        $nc2 = /mkfifo\s+\/tmp\/\w+;\s*(nc|ncat)\s/ nocase
        $py1 = /socket\.socket\(.{0,60}\).{0,200}(dup2|pty\.spawn)\(/ nocase
        $ps1 = /New-Object\s+(System\.)?Net\.Sockets\.TCPClient\s*\(\s*["'][0-9a-z.\-]+["']\s*,\s*\d{2,5}\s*\)/ nocase ascii wide
        $ps2 = "GetStream()" ascii wide
        $ps3 = /\.Read\(\$\w+,\s*0,\s*\$\w+\.Length\)/ ascii wide
    condition:
        filesize < 2MB and ($bash1 or $bash2 or $nc1 or $nc2 or $py1 or ($ps1 and $ps2 and $ps3))
}
