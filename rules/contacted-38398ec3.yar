rule Sightlines_contacted_38398ec3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-38398ec3"
        date = "2026-10-23"
        campaign = "contacted-38398ec3"
        family = ""
        hash = "0d481085dbdf8010e4f8ae81f15c94dc17cac8c0d3b82b66f2bf63349eb217ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-38398ec3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "BN4/mG7otq7uVCjF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}
