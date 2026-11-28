rule Sightlines_tlsh_36c59618_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-36c59618"
        date = "2026-11-26"
        campaign = "tlsh-36c59618"
        family = ""
        hash = "48f0f58411f847e33ff547c5ab810d85ad531afd39680ff90c56ebd0dde071b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-36c59618.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "M3L$ M3E I3L$(I3u(L" ascii
        $s1 = "M3h M3a I3h(I3Y(" ascii
        $s2 = "I3D$0I3T$8fH" ascii
        $s3 = "H3F(L3I L3F H" ascii
        $s4 = "H3B(H3w H3J H" ascii
        $s5 = "M3O I3G0fH" ascii
        $s6 = "H3J(H3B fD" ascii
        $s7 = "H3{(L3^ fH" ascii
        $s8 = "I3C0I3S8fH" ascii
        $s9 = "view_tagH" ascii
        $s10 = "AWAVAUATUSD" ascii
        $s11 = "Authentif" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3260416 and 12 of them
}
