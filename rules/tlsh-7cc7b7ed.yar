rule Sightlines_tlsh_7cc7b7ed_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cc7b7ed"
        date = "2026-11-18"
        campaign = "tlsh-7cc7b7ed"
        family = "prometei"
        hash = "15314144f73741b3e31921da6580bf87662db370a1ed8f1f93e72762358182c1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cc7b7ed.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "+b'cd%Wr%efr%WrghiWr%Wjkl%Wr%mnr%WropqWr%Wrst%Wr%uvr%WrwxyWr%WzAB%Wr%CDr%WrEFGWr%WHIJ%Wr%KLr%WrMNOWr" ascii
        $s3 = " !NNNN\"#$%NNNN&'()NNNN*+,-NNNN./01NNNN2345NNNN6789NNNN:;<=NNNN>?@ANNNNBCDENNNNFGHINNNNJKLMNNNNNOQRNN" ascii
        $s4 = "!rrrr\"$&(rrrr,-./rrrr0134rrrr9EFGrrrrHISTrrrrUVWXrrrrYZ[\\rrrr]^_`rrrrabcdrrrrefghrrrrijklrrrrmnoprrr" ascii
        $s5 = "9999 !\"#9999$%&'9999()*+9999,-./9999012399994567999989:;9999<=>?9999@ABC9999DEFG9999HIJK9999LMNO" ascii
        $s6 = "MrrrrNOPRrrrrTUVWrrrrYZ[\\rrrr_`abrrrrcdefrrrrhijk9" ascii
        $s7 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s8 = "NNSTUVNNNNWXYZNNNN[\\^_NNNNjkrsNNNNtu" ascii
        $s9 = "Q2RSTrrrrUVWXrrrrYZ[\\rrrr]^_" ascii
        $s10 = "GCC: (Ubuntu 9.3.0-17u" ascii
        $s11 = "%WPQR%Wr%STr%WrUVWWr%WXYZ" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
