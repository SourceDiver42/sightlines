rule Sightlines_tlsh_98a46b9d_xorddos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-98a46b9d"
        date = "2026-11-21"
        campaign = "tlsh-98a46b9d"
        family = "xorddos"
        hash = "0086a399cf7bc599cf5e9cd49c66487cda16c461eb8005fc467e31aa5bc9dbe0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-98a46b9d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)" ascii
        $s1 = "$Id: UPX 5.21 Copyright (C) 1996-2026 the UPX Team. All Rights Reserved. $" ascii
        $s2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s3 = "FGYfe1fRkuzD/N8IHpgMHzX09yByUWvU" ascii
        $s4 = "?rrrr@ABCrrrrDEFGrrrrHIJKrrrrLMNOrrrrPQRSrrrrTUVWrrrrXYZ[prrr\\]^_" ascii
        $s5 = "SunMonTueWedThuFriSatJanFebMarAp" ascii
        $s6 = "VZ-hq8G2kfcQvXlkJhO6/AOfQUNV9" ascii
        $s7 = "ue1YwXzLmsV5Gfq7Eiy72C1uc=" ascii
        $s8 = "Alpine clang version 17.0.6" ascii
        $s9 = "AmAnAoApAqArAsAtAuAvAwAxAyAzA{A|4M" ascii
        $s10 = ",2=512B562G5J2[5T2e5c2t5^2o5v:" ascii
        $s11 = "TZLlLtLuMnCc])iv//??ip53" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5506606 and 12 of them
}
