rule Sightlines_imphash_00f9d0e1_r77
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-00f9d0e1"
        date = "2026-11-13"
        campaign = "imphash-00f9d0e1"
        family = "r77"
        hash = "0439af9ccfedeb622bbd6bf2beb1ec4295288f4b79086889a5d06732d505b3da"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-00f9d0e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "NtQueryDirectoryFileEx" ascii
        $s1 = "EnumServicesStatusExW" ascii
        $s2 = "NtDeviceIoControlFile" ascii
        $s3 = "SymGetModuleInfo64" ascii
        $s4 = "NtEnumerateValueKey" ascii
        $s5 = "EnumServiceGroupW" ascii
        $s6 = "ReflectiveDllMain" ascii
        $s7 = "VirtualProtectEx" ascii
        $s8 = "SymLoadModule64" ascii
        $s9 = "NtResumeThread" ascii
        $s10 = "NtEnumerateKey" ascii
        $s11 = "NtQueryObject" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
