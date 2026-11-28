rule Sightlines_tlsh_48cc678b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-48cc678b"
        date = "2026-11-26"
        campaign = "tlsh-48cc678b"
        family = "mirai"
        hash = "ae1241f4a4787c0362285f91657c4f91722345c78bd8b986f8f5e88d6db6083c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-48cc678b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "elf Rep Fucking NeTiS and T" ascii
        $s4 = "MNOPQRSTUVWXY" ascii
        $s5 = "05g}\\QUdlWo" ascii
        $s6 = "L33T HaxErS" ascii
        $s7 = "sity 0n Ur" ascii
        $s8 = ",Qt8R<@P" ascii
        $s9 = "AK9]vw_r" ascii
        $s10 = "FGH;IJKL" ascii
        $s11 = "e1yHPSJ " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
