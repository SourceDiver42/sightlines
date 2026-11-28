rule Sightlines_tlsh_0664a71c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0664a71c"
        date = "2026-11-10"
        campaign = "tlsh-0664a71c"
        family = ""
        hash = "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0664a71c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Windows System Component" wide
        $s1 = "Desktop Window Manager" wide
        $s2 = "D$D;D$Hs>H" ascii
        $s3 = "@.3c0714" ascii
        $s4 = "D$(i@XmN" ascii
        $s5 = "@.38f8ae" ascii
        $s6 = "H;D$ sNH" ascii
        $s7 = "curl.dll" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 11354864 and 8 of them
}
