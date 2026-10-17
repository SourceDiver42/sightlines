rule Sightlines_tlsh_2d4c7b3c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d4c7b3c"
        date = "2026-10-17"
        campaign = "tlsh-2d4c7b3c"
        family = "mirai"
        hash = "126bffcade3468d8b84243ce192422077d23e802865b35a7c9e780fc99c02fed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d4c7b3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "/etc/config/hosts" ascii
        $s2 = "/proc/%d/exe" ascii
        $s3 = "Cx}1Kx}PSxK" ascii
        $s4 = "x}'Kx}j[x8" ascii
        $s5 = "}CX.}CSxN" ascii
        $s6 = "}CSx}e[x" ascii
        $s7 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
