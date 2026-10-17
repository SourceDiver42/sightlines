rule Sightlines_tlsh_6b772e69_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b772e69"
        date = "2026-10-15"
        campaign = "tlsh-6b772e69"
        family = "mirai"
        hash = "a4108bc5a04f98e70f087bd983c60b85ea0afc53f6bad9902354830f078ee7ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b772e69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "D @N^NuNV" ascii
        $s4 = "L @N^NuNV" ascii
        $s5 = "j @N^NuNV" ascii
        $s6 = "/usr/lib/" ascii
        $s7 = " @N^NuNuNV" ascii
        $s8 = "$_N^NuNuNV" ascii
        $s9 = " OHWHQHy" ascii
        $s10 = "$N^NuNuNV" ascii
        $s11 = "0N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
