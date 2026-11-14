rule Sightlines_tlsh_d3a0f859_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d3a0f859"
        date = "2026-11-02"
        campaign = "tlsh-d3a0f859"
        family = ""
        hash = "4e2109c88298f0a614aac82b23310b13835673a8e192a6a8b75c25459e591169"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d3a0f859.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "350623220401Z0_1" ascii
        $s5 = "240808213623Z" ascii
        $s6 = "d$xD;v(sCI" ascii
        $s7 = "t$0D;m(sJH" ascii
        $s8 = "t$8D;mhsJH" ascii
        $s9 = "t$HE;o8sFI" ascii
        $s10 = "HcI$A;I sHA" ascii
        $s11 = "t$ WATAVAWD" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2713280 and 12 of them
}
