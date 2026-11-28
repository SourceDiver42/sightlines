rule Sightlines_signer_cert_sha1_01bdcce3_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-01bdcce3"
        date = "2026-11-27"
        campaign = "signer_cert_sha1-01bdcce3"
        family = "salatstealer"
        hash = "42da774d270062038a702a80c1cbf95ccb296c7e0f6ecea303fb1f138c1f0dee"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-01bdcce3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Fhttp://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl%200a" ascii
        $s1 = "Ehttp://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt0" ascii
        $s2 = "%Microsoft Windows Production PCA 20110" ascii
        $s3 = "Microsoft Corporation1.0," ascii
        $s4 = "Microsoft Windows0" ascii
        $s5 = "261018193443Z0p1" ascii
        $s6 = "261019185142Z0" ascii
        $s7 = "232770+5062040" ascii
        $s8 = "251113193443Z" ascii
        $s9 = "111019184142Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 23189552 and 10 of them
}
