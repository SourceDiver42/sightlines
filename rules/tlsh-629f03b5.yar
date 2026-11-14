rule Sightlines_tlsh_629f03b5_hajime
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-629f03b5"
        date = "2026-11-13"
        campaign = "tlsh-629f03b5"
        family = "hajime"
        hash = "3b520e8fac265406d1b67df863966ae456981b5c9ed92466011f8194a54c4af5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-629f03b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "+Bjy,2pSJz-" ascii
        $s1 = "3Jg~|y-(Smx" ascii
        $s2 = "%Zeha um" ascii
        $s3 = ":IAJpM?Q" ascii
        $s4 = "EFZ|rU8j" ascii
        $s5 = "aOetZL(g" ascii
        $s6 = "f9E aAH=" ascii
        $s7 = "H@bXGb=?" ascii
        $s8 = "MspMe\"CA" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
