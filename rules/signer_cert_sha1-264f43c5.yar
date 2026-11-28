rule Sightlines_signer_cert_sha1_264f43c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-264f43c5"
        date = "2026-11-27"
        campaign = "signer_cert_sha1-264f43c5"
        family = ""
        hash = "280b09bd97b598d18c0ed9542dc18ed35fa57a16e84f8e65fd9c6e96516c28d6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-264f43c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl0}" ascii
        $s1 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20EOC%20CA%2004.crt0T" ascii
        $s2 = "ahttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt0" ascii
        $s3 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20EOC%20CA%2004.crl0t" ascii
        $s4 = " 2001 Python Software Foundation. Copyright " wide
        $s5 = "\"Microsoft ID Verified CS EOC CA 040" ascii
        $s6 = ".Python 3.14.7 (823f032" wide
        $s7 = "260807110835Z0|1" ascii
        $s8 = "python314.dll" ascii
        $s9 = "310326181131Z0Z1" ascii
        $s10 = "260804110835Z" ascii
        $s11 = "260326181131Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1518016 and 12 of them
}
