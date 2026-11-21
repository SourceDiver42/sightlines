rule Sightlines_signer_cert_sha1_74b92f80_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-74b92f80"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-74b92f80"
        family = ""
        hash = "07f219d022f5b2fdc75f455d6dc7df35ebdcfcb2dcd0a14c59827c64eefc9b70"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-74b92f80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "Microsoft Code Signing PCA 20240" ascii
        $s3 = "270415185943Z0t1" ascii
        $s4 = "360322221304Z0W1" ascii
        $s5 = "260416185943Z" ascii
        $s6 = "230012+5075590" ascii
        $s7 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4754032 and 8 of them
}
