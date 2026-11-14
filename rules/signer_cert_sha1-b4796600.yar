rule Sightlines_signer_cert_sha1_b4796600_adware360safebrowse
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b4796600"
        date = "2026-11-13"
        campaign = "signer_cert_sha1-b4796600"
        family = "adware360safebrowse"
        hash = "547ee7c1c58dad10800d5536974a96257ea7ff83d2accbd05f5475e102b60b63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b4796600.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "!Beijing Qihu Technology Co., Ltd.1*0(" ascii
        $s1 = "!Beijing Qihu Technology Co., Ltd.0" ascii
        $s2 = "1830B7BD-F7A3-4c4d-989B-C004DE465EDE" wide
        $s3 = "Private Organization1" ascii
        $s4 = "380114235959Z0i1" ascii
        $s5 = "360903235959Z0c1" ascii
        $s6 = "Beijing1E0C" ascii
        $s7 = "300728000000Z0\\1" ascii
        $s8 = "260426030442Z0" ascii
        $s9 = "HeapUnlock" ascii
        $s10 = "230426030442Z" ascii
        $s11 = "250604000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9814288 and 12 of them
}
