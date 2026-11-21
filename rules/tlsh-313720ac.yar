rule Sightlines_tlsh_313720ac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-313720ac"
        date = "2026-11-02"
        campaign = "tlsh-313720ac"
        family = ""
        hash = "0109e6b251ab56b80f6c02a51a92f03f44a9b1ad410f2cf3cf6b7dd6543139a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-313720ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "350623220401Z0_1" ascii
        $s5 = "H9l$`tYH9kPtSH" ascii
        $s6 = "240808213623Z" ascii
        $s7 = "fA9:uXIcB<" ascii
        $s8 = "D$PH;D$`tL" ascii
        $s9 = "u.M9n u(A" ascii
        $s10 = "= LEDuCH" ascii
        $s11 = "\\$PH9Z t" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2475776 and 12 of them
}
