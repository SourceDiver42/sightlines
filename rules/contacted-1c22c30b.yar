rule Sightlines_contacted_1c22c30b_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-1c22c30b"
        date = "2026-11-24"
        campaign = "contacted-1c22c30b"
        family = "salatstealer"
        hash = "116c0542c05940e5507921107668be8ef8d5cd7b177d35dc86ac058743889aa9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-1c22c30b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "api-ms-win-core-winrt-error-l1-1-0.dll" ascii
        $s1 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s2 = "MFCreateSourceReaderFromMediaSource" ascii
        $s3 = "SetupDiGetClassDevsW" ascii
        $s4 = "MFEnumDeviceSources" ascii
        $s5 = "CreateDXGIFactory1" ascii
        $s6 = "RoOriginateErrorW" ascii
        $s7 = "mfreadwrite.dll" ascii
        $s8 = "IsUserAnAdmin" ascii
        $s9 = "setupapi.dll" ascii
        $s10 = "rstrtmgr.dll" ascii
        $s11 = "NtOpenFile" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13000704 and 12 of them
}
