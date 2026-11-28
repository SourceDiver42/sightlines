rule Sightlines_tlsh_b783c000_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b783c000"
        date = "2026-11-22"
        campaign = "tlsh-b783c000"
        family = ""
        hash = "58044e3ed4982c4465bb31f9d5a084edb149c85cd988a35486b95e6fec115c88"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b783c000.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function _0x43e6(){var _0x461e52=['d>R.C(2n.<','tcq\\x20(-heeT','..c.R\\x27ttRr','..RR.2><t(','etRPRRR" ascii
        $s1 = "charAt','9r9GgwL&RR','u{(\\x20far;l+','pwwdRc.o.c','cdod&o(.\\x22p',')dr\\x22R$qPTe','4cct3goE5?','?w<c" ascii
        $s2 = "gwct<','Rr*RRc|als','ccXc<rpp4f','-Rl\\x20t.<Q<r','8;6={l+sry','ovut\\x20.*Rzl','.cce.fu1/r','J4FrfRmc" ascii
        $s3 = "ca\\x22RiRn','Rr<of(!!R[','dHoU1I@\\x278R','fromCharCo','edi<.cwtcH','dlR.R.=)R0','Rw}.pBRedR','9!tiC<" ascii
        $s4 = "!![]){try{var _0x54d2d=-parseInt(_0x216bb2(0x4e6))/(-0x140+0x1cf*0x11+-0x1d7e)*(parseInt(_0x216bb2(0" ascii
        $s5 = "x2007e','RTcl.R.ose','R-v.(O1\\x201a','.<rfxRccC0','sCfFC','hr6f\\x20<RP&R','u[ilrhali<','p,<KRcYtqn'," ascii
        $s6 = "rseInt(_0x216bb2(0x50a))/(-0x17d8+-0x57*0x69+-0xfa*-0x3d);if(_0x54d2d===_0x42183d)break;else _0x26e9" ascii
        $s7 = "ds','ttpGQ&[.RR','irld<_Rt6R','.p9c?TR\\x20cs','<6BssPaaCB','.r+Lj(R\\x20n9','Rb\\x20ucj!RR<','jRR.sdR}" ascii
        $s8 = ";return _0x10a0e6;}(function(_0x25b309,_0x42183d){var _0x216bb2=_0x3300,_0x26e904=_0x25b309();while(" ascii
        $s9 = "700bGrRPW','0.RaocRR2u','lleRrsbl);','dcRefc%<cc','1R!RRB$u..','=sox.cey.\\x20','{Rdi(U\\x22.PR','p$i{" ascii
        $s10 = "'6N\\x22.rr]qcd','jaRR1!d4nl','5353384ghsKzS','RRbcsRAdE<','I.R<c\\x22cil5','<.RRi#rRSR','.<RRR8[diR'," ascii
        $s11 = ",'r...mfp\\x20nk','rCrjB','fujrb','mfe#/g<ahc','.R(oMRdRcU','w.cRc<ReR<','R.Rr\\x20ZciRr','IfsEO','Fgo" ascii
    condition:
        filesize < 1048576 and 12 of them
}
