rule Example_Malware_Signature {
    meta:
        description = "Example malware signature for testing"
        author = "author"
        date = "2024"
    strings:
        $mz = { 4D 5A }
        $suspicious_string = "malware" nocase
    condition:
        $mz at 0 and $suspicious_string
}

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
