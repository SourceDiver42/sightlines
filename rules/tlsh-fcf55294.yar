rule Sightlines_tlsh_fcf55294_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcf55294"
        date = "2026-11-23"
        campaign = "tlsh-fcf55294"
        family = "mirai"
        hash = "5286d2946cd32d3901b683496ee882a3970ae6ad5d63c14d36a148b6c03aeaf9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fcf55294.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "Lmwny17Y$" ascii
        $s4 = "emO<V(A48" ascii
        $s5 = "kIaG(>0v~" ascii
        $s6 = "vM3MF$&yO" ascii
        $s7 = "(-{f7NhL" ascii
        $s8 = "ArHF,tC^" ascii
        $s9 = "d?Yj3zt " ascii
        $s10 = "l0O%5'xX" ascii
        $s11 = "t/uV][pP" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
