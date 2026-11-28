rule Sightlines_rich_header_hash_9de757cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-9de757cd"
        date = "2026-11-27"
        campaign = "rich_header_hash-9de757cd"
        family = ""
        hash = "055544d562ca50d49443926bca396de985735f7451806ff2565486e406809d25"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-9de757cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "ApiSet Stub DLL" wide
        $s5 = "350623220401Z0_1" ascii
        $s6 = "240808213623Z" ascii
        $s7 = "apisetstub" wide
        $s8 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
