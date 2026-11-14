rule Sightlines_signer_cert_sha1_0e24d57e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-0e24d57e"
        date = "2026-11-13"
        campaign = "signer_cert_sha1-0e24d57e"
        family = ""
        hash = "0471e31583e0c84eb96463cb68e4395e1b36e63d5d55c8d92c936557e569e7c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-0e24d57e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "!Beijing Qihu Technology Co., Ltd.1*0(" ascii
        $s1 = "!Beijing Qihu Technology Co., Ltd.0" ascii
        $s2 = "Private Organization1" ascii
        $s3 = "250716030504Z" ascii
        $s4 = "Beijing1E0C" ascii
        $s5 = "300728000000Z0\\1" ascii
        $s6 = "410716000000Z0^1" ascii
        $s7 = "251015072504Z" ascii
        $s8 = "370110000000Z0Y1" ascii
        $s9 = "240108040224Z" ascii
        $s10 = "270207040224Z0" ascii
        $s11 = "201209000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9087488 and 12 of them
}
