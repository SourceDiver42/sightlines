rule Sightlines_signer_cert_sha1_a728e1de_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-a728e1de"
        date = "2026-11-18"
        campaign = "signer_cert_sha1-a728e1de"
        family = ""
        hash = "4d975c668053e822493f7ae7b7a8a7c32831dcd257f3699a6b94b59eabc7272d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-a728e1de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "270303195742Z0t1" ascii
        $s5 = "350623220401Z0_1" ascii
        $s6 = "260305195742Z" ascii
        $s7 = "240808213623Z" ascii
        $s8 = "500507+5069190" ascii
        $s9 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9498320 and 10 of them
}
