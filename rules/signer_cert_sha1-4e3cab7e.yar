rule Sightlines_signer_cert_sha1_4e3cab7e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4e3cab7e"
        date = "2026-11-13"
        campaign = "signer_cert_sha1-4e3cab7e"
        family = ""
        hash = "055544d562ca50d49443926bca396de985735f7451806ff2565486e406809d25"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4e3cab7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "260506182454Z0t1" ascii
        $s5 = "350623220401Z0_1" ascii
        $s6 = "230865+5045810" ascii
        $s7 = "240808213623Z" ascii
        $s8 = "250508182454Z" ascii
        $s9 = "_0Oio=NA" ascii
        $s10 = "}gwVq{uE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
