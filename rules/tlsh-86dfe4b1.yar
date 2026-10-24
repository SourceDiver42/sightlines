rule Sightlines_tlsh_86dfe4b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86dfe4b1"
        date = "2026-10-18"
        campaign = "tlsh-86dfe4b1"
        family = ""
        hash = "114efbd42d4180d0489ea83b7514dc90406f43f684e0de206c534e97f8c9d221"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86dfe4b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = ",-./0123456789:;<=>?@ABCDEFGHIJKw" ascii
        $s3 = "b'cdWr%Wefg%Wr%hir%WrjklWr%Wmno%Wr%pqr%WrrstWr%Wuvw%Wr%xyr%WrzABWr%WCDE%Wr%FGr%WrHIJWr%WKLM%Wr%NOr%W" ascii
        $s4 = " !\"rrrr#$%&rrrr'()*rrrr+,-.rrrr/012rrrr3456rrrr789:rrrr;<=>rrrr?@ABrrrrCDEFrrrrGHIJrrrrKLMNrrrrOPQRr" ascii
        $s5 = "PQRSNNNNTVWXNNNNYZ[\\NNNN]^_`NNNNabcdNNNNefghNNNNijklNNNNmnopNNNNqrstNNNNuvwxNNNNyz{|NNNN}~" ascii
        $s6 = " !\"9999#$%&9999'()*9999+,-.9999/012999934569999789:9999;<=>9999?@AB9999CDEF9999GHIJ9999KLMN9999OQRS9" ascii
        $s7 = "NNNN !\"#NNNN$%&'NNNN()*+NNNN,-./NNNN0123NNNN4567NNNN89:;NNNN<=>?NNNN@ABCNNNNDEFGNNNNHIJKNNNNLMNONNNN" ascii
        $s8 = "rrrSTUVrrrrWXYZrrrr[\\]^rrrr_`abrrrrcdefrrrrghijrrrrklmnrrrropqrrrrrstuvrrrrwxyzrrrr{|}~rrrr" ascii
        $s9 = "<>@BDhMh=F'JhMhM/N7RhMhM?VGZhMhMO^Wb" ascii
        $s10 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s11 = "999TUVW9999XYZ[9999\\^_j9999krst9999u" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
