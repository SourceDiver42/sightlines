rule Sightlines_tlsh_651a49a2_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-651a49a2"
        date = "2026-11-13"
        campaign = "tlsh-651a49a2"
        family = "coinminer"
        hash = "4c17a852a2bb168010b270fcf5cbb9e78f17d910d259fa720d2a7f2dfd18a2dd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-651a49a2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "!N.HN$'*HN.H-0.HN.369N.HN<?BHN.HEH.HN.KNQN.HNTWZHN.H]`.HN.cfiN.HNlorHN.Hux.HN.{~" ascii
        $s3 = "GCC: (Alpine 13.2.1_git20240309)" ascii
        $s4 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s5 = "WlOQQRRTTWWXX[[]]^^aabbddgghh" ascii
        $s6 = "\": false,-background0 tr" ascii
        $s7 = "?f@hAiBj@kClDoBqErFuG}H" ascii
        $s8 = "%s:%d: assertion faile\"0" ascii
        $s9 = "-PiQiRiSiTiUiViWiXiYiZi[i\\i]C" ascii
        $s10 = "{uo2222ic]W2222QKE?222293-'!" ascii
        $s11 = "te.gnu.prope&y%build-i" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 4747232 and 12 of them
}
