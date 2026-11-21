rule Sightlines_tlsh_9e77d60f_dcrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9e77d60f"
        date = "2026-11-05"
        campaign = "tlsh-9e77d60f"
        family = "dcrat"
        hash = "b15e44bcb245ee99bfbe2e500f20327868dc6a153f12d5f89d5fe0ffa149ce0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9e77d60f.json"
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
        uint16(0) == 0x5A4D and filesize < 1697792 and 12 of them
}
