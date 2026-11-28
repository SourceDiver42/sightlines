rule Sightlines_tlsh_4a5bd831_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4a5bd831"
        date = "2026-11-22"
        campaign = "tlsh-4a5bd831"
        family = ""
        hash = "088df3845a9c802407c78a453145240b821c94559d32c6ea814793c1272926f0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4a5bd831.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "9;},'Eiogw':function(_0x4ab3d2,_0x1c1991){return _0x4ab3d2%_0x1c1991;},'GoVSj':function(_0x5ead08,_0" ascii
        $s1 = "ec<xsR','1.iRyKeE<x','Rr(cRP-RR?','c=<i.c.Bmi','ftbdn-c!u3','dn6dl/tgsS','976416qWXRzj','.KcNnMf$ru'" ascii
        $s2 = "x34*0x6d+-0x12c3+0x28e7]]=_0xe9643b;}(global,require),zx0[-0x38*0xa7+-0x4*0x2f5+0x305d]===typeof mod" ascii
        $s3 = ";(function(_0x46c858,_0x1e05f3){var _0x3741e5=_0x7058,_0x51929f=_0x46c858();while(!![]){try{var _0x3" ascii
        $s4 = "0x42b844(0x2d0)};function s8(_0x52cc50){var _0x52e841=_0x42b844,_0x26d07b={'lkPyG':function(_0x5a6c6" ascii
        $s5 = "','{n.ni<l}.l','si..Rnqlc?','Tl<xRf\\x22R.\\x22','u.=tvel\\x20.i'];_0x393e=function(){return _0x30353d;" ascii
        $s6 = "d2;},'uJyoH':function(_0x431f91,_0x2f42e4){return _0x431f91+_0x2f42e4;},'QQznp':function(_0xd00b3c,_" ascii
        $s7 = "cb8b),_0x45689a+=-0x308*-0x4+-0x156+-0xac9;}return _0x32c294[_0x110536(0x456)]('');}var p8=y7(_0x42b" ascii
        $s8 = "b){var _0x110536=_0x7058,_0x3c21c4={'iTZsa':function(_0x2e72b8,_0x4464a1){return _0x2e72b8<_0x4464a1" ascii
        $s9 = "ule&&(global[zx0[0x1*-0xd0d+0x12fc+-0x5ed]]=module);var r8={'a':0x2e9e49,'b':0xad,'c':0xaf15,'d':0x1" ascii
        $s10 = ";},'rtCNo':function(_0x160457,_0x8a04e4){return _0x160457+_0x8a04e4;},'TSsqr':function(_0x544ff7,_0x" ascii
        $s11 = "cB1&uRRti!','.f(tb2tX(.','R3\\x20RatSRtR','R\\x20\\x22rcu;xPf','.[1Rny</b.','\\x22!wcsq<_r<','Rsz.czJap4" ascii
    condition:
        filesize < 1048576 and 12 of them
}
