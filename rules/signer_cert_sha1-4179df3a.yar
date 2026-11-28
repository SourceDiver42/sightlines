rule Sightlines_signer_cert_sha1_4179df3a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4179df3a"
        date = "2026-11-26"
        campaign = "signer_cert_sha1-4179df3a"
        family = ""
        hash = "7dec3ba900ab353491e6446f0083739924c6f8dd668832e2f09d38ebffdbbe1c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4179df3a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "Microsoft Code Signing PCA 20240" ascii
        $s3 = "270415185941Z0t1" ascii
        $s4 = "360322221304Z0W1" ascii
        $s5 = "230012+5075690" ascii
        $s6 = "260416185941Z" ascii
        $s7 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 23257792 and 8 of them
}
