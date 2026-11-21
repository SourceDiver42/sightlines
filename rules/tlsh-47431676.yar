rule Sightlines_tlsh_47431676_hajime
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-47431676"
        date = "2026-11-20"
        campaign = "tlsh-47431676"
        family = "hajime"
        hash = "20c9c9e9153564ee44ab7fa7bdb571956245c08859844048df1e8b8771505eeb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-47431676.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "+Bjy,2pSJz-" ascii
        $s1 = "3Jg~|y-(Smx" ascii
        $s2 = "%Zeha um" ascii
        $s3 = "EFZ|rU8j" ascii
        $s4 = "f9E aAH=" ascii
        $s5 = "H@bXGb=?" ascii
        $s6 = "MspMe\"CA" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
