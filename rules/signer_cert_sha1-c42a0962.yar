rule Sightlines_signer_cert_sha1_c42a0962_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c42a0962"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-c42a0962"
        family = ""
        hash = "17ccd9141c486d7a3689ed38d72d3bd8bb0e216b7990fcc76c132dc9102c6320"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c42a0962.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6Microsoft Edge WebView2 SD" wide
        $s1 = "https://www.microsoft.com 0" ascii
        $s2 = "260515184909Z0t1" ascii
        $s3 = "230217+5049170" ascii
        $s4 = "250515184909Z" ascii
        $s5 = "G!2Wv[.O" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1587408 and 6 of them
}
