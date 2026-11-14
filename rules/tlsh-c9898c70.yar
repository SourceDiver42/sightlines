rule Sightlines_tlsh_c9898c70_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c9898c70"
        date = "2026-11-10"
        campaign = "tlsh-c9898c70"
        family = "mirai"
        hash = "06b5d5232b4f952e7d2ddd07d6d62552064833c2279fa00c7ba9640acc9dd1ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c9898c70.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "/proc/%d/exe" ascii
        $s4 = "D @N^NuNV" ascii
        $s5 = "L @N^NuNV" ascii
        $s6 = "j @N^NuNV" ascii
        $s7 = " @N^NuNuNV" ascii
        $s8 = "$_N^NuNuNV" ascii
        $s9 = " OHWHQHy" ascii
        $s10 = "HN^NuNuNV" ascii
        $s11 = "$N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
