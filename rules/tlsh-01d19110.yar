rule Sightlines_tlsh_01d19110_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01d19110"
        date = "2026-10-30"
        campaign = "tlsh-01d19110"
        family = "prometei"
        hash = "0a16883a25d4d859ad2907f68981cd4c480d9bb27c2511de90e3d372162e5729"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01d19110.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " rrrr!\"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9:;<rrrr=>?@rrrrABCDrrrrEFGHrrrrIJKLrrrrMNOQrrr" ascii
        $s3 = " NNNN!#$`NNNNabcdNNNNefghNNNNijklNNNNmnopNNNNqrstNNNNuvwxNNNNyz{|NNNN}~" ascii
        $s4 = " \"$9999%&/59999679:9999<DGH9999I_`a9999bc" ascii
        $s5 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s6 = "rRSTUrrrrVWXYrrrrZ[\\^rrrr_jkrrrrrstu" ascii
        $s7 = "ZabctZhijklmnopqrstuvwx" ascii
        $s8 = "GCC: (Ubuntu 9.3.0-17u" ascii
        $s9 = "o+c6wpXySE3l2z37X3Z" ascii
        $s10 = "hr9f244U7KMUIM5f?]" ascii
        $s11 = "hTbyxwz-bOtEuMN2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
