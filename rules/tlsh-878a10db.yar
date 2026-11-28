rule Sightlines_tlsh_878a10db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-878a10db"
        date = "2026-11-09"
        campaign = "tlsh-878a10db"
        family = ""
        hash = "664feebb2dc64f85e5c56ad85500e262b98d04ac608cda897e0b176449cf1903"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-878a10db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}
