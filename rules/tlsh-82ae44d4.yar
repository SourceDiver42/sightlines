rule Sightlines_tlsh_82ae44d4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-82ae44d4"
        date = "2026-10-18"
        campaign = "tlsh-82ae44d4"
        family = ""
        hash = "29a83b42da804b056da99a8de958f9243a3b06250ac7c19ed96929e29db7b0b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-82ae44d4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " !\"NNNN#$%&NNNN'()*NNNN+,-.NNNN/012NNNN3456NNNN789:NNNN;<=>NNNN?@ABNNNNCDEFNNNNGHIJNNNNKLMNNNNNOPQRN" ascii
        $s3 = "9QRST9999UVWX9999YZ[\\9999]^_`9999abcd9999efgh9999ijkl9999mnop9999qrst9999uvwx9999yz{|9999}~" ascii
        $s4 = " 9999!\"#$9999%&'(9999)*+,9999-./0999912349999567899999:;<9999=>?@9999ABCD9999EFGH9999IJKL9999MNOP999" ascii
        $s5 = "@9999ABCD9999EFGH9999IJKL9999MNOQ9999RSTU9999VWXY9999Z[\\^9999_jkr9999stu" ascii
        $s6 = "F'J/BkBkN7R?BkBkVGZOBkBk^Wb_<oBkfgj" ascii
        $s7 = " rrrr!\"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9:;<" ascii
        $s8 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s9 = "5'IOWo3hJHr5jfDKYmvL/x" ascii
        $s10 = "'GLOBAL_OFFSET_TABLE_u" ascii
        $s11 = "3D3K3M3N3O3Y3[6$6%6&[y" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
