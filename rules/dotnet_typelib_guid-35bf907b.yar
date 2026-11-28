rule Sightlines_dotnet_typelib_guid_35bf907b_dcrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-35bf907b"
        date = "2026-11-21"
        campaign = "dotnet_typelib_guid-35bf907b"
        family = "dcrat"
        hash = "03917e1226e194b70879ecee899db13728391948a2278ecdd5b609b4b0679ab6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-35bf907b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-,43537698;:BAFEGEHEIEJELKMLNKOKQPUTWVXVYVZV[V]\\^\\_\\`\\baedfegdhgigjgkglgmdnmodpdqdrdsdutwvyxzx{x|x~}" wide
        $s1 = "$ebc25cf6-9120-4283-b972-0e5520d0000A" ascii
        $s2 = "$ebc25cf6-9120-4283-b972-0e5520d0000B" ascii
        $s3 = "$ebc25cf6-9120-4283-b972-0e5520d0000C" ascii
        $s4 = "$ebc25cf6-9120-4283-b972-0e5520d0000D" ascii
        $s5 = "$ebc25cf6-9120-4283-b972-0e5520d0000E" ascii
        $s6 = "$ebc25cf6-9120-4283-b972-0e5520d00004" ascii
        $s7 = "$ebc25cf6-9120-4283-b972-0e5520d00006" ascii
        $s8 = "$ebc25cf6-9120-4283-b972-0e5520d00007" ascii
        $s9 = "$ebc25cf6-9120-4283-b972-0e5520d00008" ascii
        $s10 = "$ebc25cf6-9120-4283-b972-0e5520d00009" ascii
        $s11 = "$ebc25cf6-9120-4283-b972-0e5520d00005" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3212288 and 11 of them
}
