
rule Suspicious_Process {
    meta:
        description = "Detects suspicious process behavior"
        author = "author"
    strings:
        $network_call = "connect" nocase
        $file_write = "write" nocase
    condition:
        $network_call and $file_write
}

rule Zero_Day_Example {
    meta:
        description = "Example zero-day pattern"
        author = "author"
    strings:
        $unknown_pattern = { 90 90 90 90 90 90 90 90 }  // NOP sled example
    condition:
        $unknown_pattern
}

rule Malware_Download {
    meta:
        description = "Detects malware download patterns in network traffic"
        author = "author"
    strings:
        $mz_header = { 4D 5A }  // MZ header
        $elf_header = { 7F 45 4C 46 }  // ELF header
        $suspicious_url = "pastebin" nocase
        $suspicious_url2 = "dropbox" nocase
        $suspicious_url3 = "mega.nz" nocase
    condition:
        ($mz_header at 0) or ($elf_header at 0) or any of ($suspicious_url*)
}

rule C2_Beacon {
    meta:
        description = "Detects command and control beaconing patterns"
        author = "author"
    strings:
        $beacon_pattern = { 00 00 00 00 00 00 00 00 00 00 }  // Placeholder for beacon patterns
        $heartbeat = "ping" nocase
        $c2_traffic = "cmd" nocase
    condition:
        $beacon_pattern or $heartbeat or $c2_traffic
}

rule Exploit_Payload {
    meta:
        description = "Detects common exploit payloads"
        author = "author"
    strings:
        $shellcode = { CC CC CC CC }  // INT 3 breakpoints
        $nop_sled = { 90 90 90 90 90 90 90 90 }  // NOP sled
        $overflow = { 41 41 41 41 41 41 41 41 }  // AAAA... overflow pattern
    condition:
        any of them
}
