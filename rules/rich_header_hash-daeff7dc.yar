rule Sightlines_rich_header_hash_daeff7dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-daeff7dc"
        date = "2026-11-18"
        campaign = "rich_header_hash-daeff7dc"
        family = ""
        hash = "01c6a729ae6d25b2436557dcd5be9c4e7446e88f34522d3c76805d52320803ed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-daeff7dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "Microsoft Code Signing PCA 20240" ascii
        $s3 = "Copyright Microsoft Corporation" wide
        $s4 = "https://www.microsoft.com 0" ascii
        $s5 = "*Microsoft Edge Updat" wide
        $s6 = "Microsoft Edge Update" wide
        $s7 = "UpstreamVersion" wide
        $s8 = "msedgeupdate.dll" wide
        $s9 = "360322221304Z0W1" ascii
        $s10 = "270415190011Z0t1" ascii
        $s11 = "230217+5075580" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
