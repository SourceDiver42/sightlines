rule Sightlines_signer_cert_sha1_a9894668_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-a9894668"
        date = "2026-11-23"
        campaign = "signer_cert_sha1-a9894668"
        family = ""
        hash = "196c42414c16e804874988783b8a356bf1d012d32e99efbc6e360e94920c46ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-a9894668.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl0}" ascii
        $s1 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20EOC%20CA%2003.crt0T" ascii
        $s2 = "ahttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt0" ascii
        $s3 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20EOC%20CA%2003.crl0t" ascii
        $s4 = " 2001 Python Software Foundation. Copyright " wide
        $s5 = "\"Microsoft ID Verified CS EOC CA 030" ascii
        $s6 = ".Python 3.14.8 (8e6e75d" wide
        $s7 = "261002091414Z0|1" ascii
        $s8 = "310326181128Z0Z1" ascii
        $s9 = "260929091414Z" ascii
        $s10 = "260326181128Z" ascii
        $s11 = "z9dBdv&\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
