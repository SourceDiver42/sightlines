rule Sightlines_signer_cert_sha1_03fb020a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-03fb020a"
        date = "2026-11-25"
        campaign = "signer_cert_sha1-03fb020a"
        family = ""
        hash = "1688fe4698c45680851f5d90aff71fffdccb19c1b283a8c10cbc729c8efca7d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-03fb020a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "260506182453Z0t1" ascii
        $s5 = "350623220401Z0_1" ascii
        $s6 = "230865+5045910" ascii
        $s7 = "240808213623Z" ascii
        $s8 = "250508182453Z" ascii
        $s9 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3019520 and 10 of them
}
