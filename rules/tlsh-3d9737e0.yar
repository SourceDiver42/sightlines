rule Sightlines_tlsh_3d9737e0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3d9737e0"
        date = "2026-11-03"
        campaign = "tlsh-3d9737e0"
        family = "mirai"
        hash = "1acbb4effff0e80844c21651ec6e32897f7e57126a32c1836d63bd9bf3ef0667"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3d9737e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s1 = "e1:q9:get_peers1:t2:" ascii
        $s2 = "3:seqi%llde3:sig64:" ascii
        $s3 = "3:seqi%llde1:v%d:" ascii
        $s4 = "9:info_hash20:" ascii
        $s5 = "e1:q4:ping1:t2:" ascii
        $s6 = "e1:q3:put1:t2:" ascii
        $s7 = "e1:q3:get1:t2:" ascii
        $s8 = "6:target20:" ascii
        $s9 = "d1:ad2:id20:" ascii
        $s10 = "5:token%d:" ascii
        $s11 = "six_sayven" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
