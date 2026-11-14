rule Sightlines_contacted_af112dc0_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-af112dc0"
        date = "2026-11-12"
        campaign = "contacted-af112dc0"
        family = "prometei"
        hash = "2f8422e3a352e22a07d36e7b47ee491d1f77b129ddd0d570ba0a4b727ed93742"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-af112dc0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.95 Copyright (C) 1996-2018 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "rrrr !\"#rrrr$%&'rrrr()*+rrrr,-./rrrr0123rrrr4567rrrr89:;rrrr<=>?rrrr@ABCrrrrDEFGrrrrHIJKrrrrLMNO" ascii
        $s3 = "9XYZ[9999\\]^_9999`abc9999defg9999hijk9999lmno9999pqrs9999tuvw9999xyz{9999|}~" ascii
        $s4 = " 9999!\"#$9999%&'(9999)*+,9999-./0999912349999567899999;<=9999>@AB9999CDFJ9999KLMN9999OPRS9999TUVW999" ascii
        $s5 = "NNNN \"$%NNNN&/56NNNN79:<NNNNDGHINNNN_`abNNNNc" ascii
        $s6 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s7 = "GCC: (Ubuntu 9.3.0-17u" ascii
        $s8 = "5ng ups_9ILP32_OFF;" ascii
        $s9 = "BICVsKakP-03j9/Vl" ascii
        $s10 = "qr9999stuv9999wz{|9999}~" ascii
        $s11 = "wJNE_JMP_SLOT?fiJ" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
