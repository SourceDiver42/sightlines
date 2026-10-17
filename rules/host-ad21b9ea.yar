rule Sightlines_host_ad21b9ea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-ad21b9ea"
        date = "2026-10-17"
        campaign = "host-ad21b9ea"
        family = ""
        hash = "008f232c61601b260e64b458afe00c0b33a69cbd7dfc5b756b312c9723614d1b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-ad21b9ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DCe):hover .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .RnXJS.VfPpkd-O1htCb-OWXEXe-OWB6Me ." ascii
        $s1 = "-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .gOPnwc:hover:not(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) " ascii
        $s2 = "NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .UAQDDf.VfPpkd-O1htCb-OWXEXe-OWB6Me .VfPpkd-NLUYnc-V67a" ascii
        $s3 = "XxIAqe-cGMI2b{outline-color:CanvasText}}.EY8ABd .VfPpkd-z59Tgd{background-color:rgb(60,64,67)}.EY8AB" ascii
        $s4 = "VfPpkd-NLUYnc-V67aGc{color:rgba(232,234,237,.38)}.AfoeCd .RnXJS:not(.VfPpkd-O1htCb-OWXEXe-OWB6Me)+.V" ascii
        $s5 = "fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .orScbe:not(.VfPpkd" ascii
        $s6 = "-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .Y5O54e .VfPpkd-fmcmS-yrriRe:ho" ascii
        $s7 = "IsBm,1.5rem);letter-spacing:var(--H8HCPd,0);font-weight:var(--Bpk69,400)}.uW2Fw-Sx9Kwc-OWXEXe-vOE8Lb" ascii
        $s8 = "jY41G-V67aGc{color:rgb(174,203,250)}.AfoeCd .FEsNhd.VfPpkd-ksKsZd-mWPk3d-OWXEXe-AHe6Kc-XpnDCe.VfPpkd" ascii
        $s9 = "d-RKhZBe-LgbsSe-OWXEXe-gk6SMd:not(:disabled){background-color:rgb(138,180,248)}.AfoeCd .zNgRPc .VfPp" ascii
        $s10 = "r-primary,#0b57d0)}.i79UJc.IYewr.CDELXb .zHQkBf:not([disabled])~.snByac,.i79UJc.IYewr.u3bW4e .zHQkBf" ascii
        $s11 = "(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .gOPnwc.Vf" ascii
    condition:
        filesize < 1921538 and 11 of them
}
