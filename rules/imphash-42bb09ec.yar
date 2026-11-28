rule Sightlines_imphash_42bb09ec_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-42bb09ec"
        date = "2026-11-24"
        campaign = "imphash-42bb09ec"
        family = ""
        hash = "048fd927062cb3452b766f63221d2b73ce0412a812078b306548a80824699105"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-42bb09ec.json"
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
        uint16(0) == 0x5A4D and filesize < 5111808 and 12 of them
}
