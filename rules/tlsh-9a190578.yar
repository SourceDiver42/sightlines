rule Sightlines_tlsh_9a190578_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9a190578"
        date = "2026-10-17"
        campaign = "tlsh-9a190578"
        family = ""
        hash = "35b6d246c01a94f6473a6764923f596ed9c415e1b49402711f453bc7364ff114"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9a190578.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "O(H;y udH" ascii
        $s1 = "S(H9S s8L" ascii
        $s2 = "G(H9G s2L" ascii
        $s3 = "K(H9K s7H" ascii
        $s4 = "F(H9F r&" ascii
        $s5 = "S@H+S8H9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
