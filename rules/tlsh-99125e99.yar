rule Sightlines_tlsh_99125e99_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-99125e99"
        date = "2026-11-09"
        campaign = "tlsh-99125e99"
        family = ""
        hash = "47a21dc585cdf274f7cf5fab9040966f57500b598953da1c007b110e4cd38df7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-99125e99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "mmap failed." ascii
        $s3 = "3Z_ QAS<" ascii
        $s4 = "AsMS.Byb" ascii
        $s5 = "U79#(LX=" ascii
        $s6 = "`E7&R)h7" ascii
        $s7 = "p3mwQ:s3" ascii
        $s8 = "RVSPUWVS" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
