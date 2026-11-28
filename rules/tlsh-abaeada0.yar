rule Sightlines_tlsh_abaeada0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-abaeada0"
        date = "2026-11-23"
        campaign = "tlsh-abaeada0"
        family = "mirai"
        hash = "15fe85ed47fd22621376cd73f1bff0ba0153aafec8bc98cbe777c9f58ed3d751"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-abaeada0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "Rep Fucking NeTiS and T" ascii
        $s4 = "FGH;IJKLMNOPQ_" ascii
        $s5 = "05g}\\QUdlWo" ascii
        $s6 = "L33T HaxErS" ascii
        $s7 = "h1llIorFDt" ascii
        $s8 = "A|/JQMd{R" ascii
        $s9 = ",Qt8R<@P" ascii
        $s10 = "2H$@Thx{" ascii
        $s11 = "F7CrHn -" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
