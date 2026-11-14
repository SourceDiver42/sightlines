rule Sightlines_tlsh_9008fdae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9008fdae"
        date = "2026-11-02"
        campaign = "tlsh-9008fdae"
        family = ""
        hash = "128aee8c62a673d64739e585e3876b61133571cec83a46240a62581d5465639b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9008fdae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RtlDllShutdownInProgress" ascii
        $s1 = "Could not locate assembly" wide
        $s2 = "GCCacheSizeFromSysConf" ascii
        $s3 = "9|$4u[HcT$0H" ascii
        $s4 = "uMD9A<tGHcA<" ascii
        $s5 = "F(fA;v s%H" ascii
        $s6 = "l$X;|$8sMH" ascii
        $s7 = "t2L9X`u,H" ascii
        $s8 = "t6L9X`u0H" ascii
        $s9 = "t<H9x`u6A" ascii
        $s10 = "t@L9X`u:H" ascii
        $s11 = "v:I;P r4H" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9990752 and 12 of them
}
