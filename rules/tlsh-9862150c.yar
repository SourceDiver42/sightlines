rule Sightlines_tlsh_9862150c_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9862150c"
        date = "2026-11-26"
        campaign = "tlsh-9862150c"
        family = "prometei"
        hash = "039ddb7c4b409be63326cabdccfd824b8addae797fa477c705edc06f7a8ccc6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9862150c.json"
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
        $s9 = "YZabctZhijklmnopqrstuvw" ascii
        $s10 = "Q2RSTrrrrUVWXrrrrYZ[\\rrrr]^_" ascii
        $s11 = "GCC: (Ubuntu 9.3.0-17u" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
