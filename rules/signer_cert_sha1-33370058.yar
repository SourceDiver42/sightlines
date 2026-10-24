rule Sightlines_signer_cert_sha1_33370058_blackmoon
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-20"
        campaign = "signer_cert_sha1-33370058"
        family = "blackmoon"
        hash = "6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "370624235959Z0r1" ascii
        $s1 = "Greater London1" ascii
        $s2 = "410324235959Z0U1" ascii
        $s3 = "380118235959Z0W1" ascii
        $s4 = "Ly<j}bx^H" ascii
        $s5 = "260325000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4529936 and 6 of them
}
