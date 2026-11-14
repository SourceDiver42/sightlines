rule Sightlines_signer_cert_sha1_900b71c9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-900b71c9"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-900b71c9"
        family = ""
        hash = "0670d1474b5fc5a0fbbfc1c5d13e47f817321b6a81cc5118721ac98f0bf43536"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-900b71c9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Samsung Electronics Co., Ltd.1&0$" ascii
        $s1 = "Samsung Electronics Co., Ltd.0" ascii
        $s2 = "380114235959Z0i1" ascii
        $s3 = "360903235959Z0c1" ascii
        $s4 = "280128120000Z0L1 0" ascii
        $s5 = "Suwon-si1&0$" ascii
        $s6 = "270211071439Z0" ascii
        $s7 = "250210071439Z" ascii
        $s8 = "Gyeonggi-do1" ascii
        $s9 = "180919000000Z" ascii
        $s10 = "250604000000Z" ascii
        $s11 = "250507000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5237328 and 12 of them
}
