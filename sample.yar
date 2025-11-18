
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
