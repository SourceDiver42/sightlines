rule Sightlines_signer_cert_sha1_405c7fc6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-405c7fc6"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-405c7fc6"
        family = ""
        hash = "623eabed437e266785a6cee0be2bfb2d73f0800b04a96019936ecb2f1c6303f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-405c7fc6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "260506182359Z0g1" ascii
        $s5 = "350623220401Z0_1" ascii
        $s6 = "471322+5046880" ascii
        $s7 = "240808213623Z" ascii
        $s8 = "250508182359Z" ascii
        $s9 = "= LEDuCH" ascii
        $s10 = "_0Oio=NA" ascii
        $s11 = "t0HcT$pH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2703024 and 12 of them
}
