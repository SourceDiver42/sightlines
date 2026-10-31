rule Sightlines_tlsh_c9898c70_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c9898c70"
        date = "2026-10-30"
        campaign = "tlsh-c9898c70"
        family = "mirai"
        hash = "1b2492605c7f23e34207238ebfebf1b898625edaf175716dcd095ed44c2857a8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c9898c70.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "D @N^NuNV" ascii
        $s4 = "L @N^NuNV" ascii
        $s5 = "j @N^NuNV" ascii
        $s6 = " @N^NuNuNV" ascii
        $s7 = "$_N^NuNuNV" ascii
        $s8 = " OHWHQHy" ascii
        $s9 = "$N^NuNuNV" ascii
        $s10 = "<N^NuNuNV" ascii
        $s11 = "HN^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
