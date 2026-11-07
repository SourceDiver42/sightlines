rule Sightlines_signer_cert_sha1_8a1b0df2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8a1b0df2"
        date = "2026-11-06"
        campaign = "signer_cert_sha1-8a1b0df2"
        family = ""
        hash = "0fe7c43478f0e4872a98ff1e2708a8975d4f433b5516ba236a6d8a33eddb8056"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8a1b0df2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "371104235959Z0c1" ascii
        $s1 = "380114235959Z0i1" ascii
        $s2 = "260805000000Z" ascii
        $s3 = "250507000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41456016 and 4 of them
}
