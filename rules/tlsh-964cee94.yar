rule Sightlines_tlsh_964cee94_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-964cee94"
        date = "2026-10-22"
        campaign = "tlsh-964cee94"
        family = ""
        hash = "a4c09192b90b028011e09825541147c0f2478e7899cd6cbfcb19decdc446e89e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-964cee94.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "D$4jPj#UW" ascii
        $s2 = "t$(RRUVRj" ascii
        $s3 = "-0+1prp|" ascii
        $s4 = "D$\\3D$Lx" ascii
        $s5 = "D$d3D$,x" ascii
        $s6 = "L$(3L$Lx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
