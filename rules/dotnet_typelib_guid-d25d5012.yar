rule Sightlines_dotnet_typelib_guid_d25d5012_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-d25d5012"
        date = "2026-11-03"
        campaign = "dotnet_typelib_guid-d25d5012"
        family = ""
        hash = "8ba5e5fc50d186d7224a0f4139c3139b3e7e88954ea6bd6a758790b82e032a5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-d25d5012.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Professional-grade hardware monitoring and thermal management suite with real-time sensor telemetry " ascii
        $s1 = "$E7D9A8C6-5F4B-4A3D-9F2C-8B1A7E6D5F4C" ascii
        $s2 = "and predictive failure analysis" ascii
        $s3 = " CPUID SARL 2026" ascii
        $s4 = "AutoScaleMode" ascii
        $s5 = "HWMonitor.dll" ascii
        $s6 = "HWMonitor Pro" ascii
        $s7 = "Copyright " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}
