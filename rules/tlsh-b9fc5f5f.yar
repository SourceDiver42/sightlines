rule Sightlines_tlsh_b9fc5f5f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9fc5f5f"
        date = "2026-11-20"
        campaign = "tlsh-b9fc5f5f"
        family = ""
        hash = "2050b1486fecea2db14b7e94de43e4fad23be5955df590786ef850d43c0b9177"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9fc5f5f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "4<_0x1cced4;},'bvUSD':function(_0x5298e0,_0xf6dbac){return _0x5298e0%_0xf6dbac;},'zwyRU':function(_0" ascii
        $s1 = "386a26){return _0x5d11ab(_0x15f8d9,_0x386a26);},'YUpNl':function(_0x4e9a81,_0x2cd32c){return _0x4e9a" ascii
        $s2 = ",_0x2edfb9,_0x8902f);},'DCJcB':_0x4d6797(0x410),'kXUVX':function(_0x51522a,_0x19f24f){return _0x5152" ascii
        $s3 = "2a===_0x19f24f;},'iRIjr':function(_0x44fc87,_0xa52f2a){return _0x44fc87(_0xa52f2a);},'yegoz':_0x4d67" ascii
        $s4 = "y|\\x20R\\x22q','cCRRxcM..y','dla\\x20k_c~Rn','.fYPRc4dj.','yegoz',');i=A7i0l-','<En.\\x20nm.y(','9r9Ggw" ascii
        $s5 = "6c*_0x164a41;},'iwMtA':function(_0x48843f,_0x41817b){return _0x48843f+_0x41817b;},'jaIvd':function(_" ascii
        $s6 = "498dd6,_0x1ed478[_0x4d6797(0x158)])))(0x1c29+0x1879+-0xf*0x2db);}(global,require));function _0x2686(" ascii
        $s7 = "ReRl|cElc','!agwaoA)us','R.Rr\\x20ZciRr','X.R/XzRtRR','\\x205tsgfnea;','bg(=o;va,9','RoPcfp[e\\x22m','J" ascii
        $s8 = "31,_0x2bc328){var _0x4d6797=_0x55b0,_0x1ed478={'Ahxlj':function(_0x31ed74,_0x1cced4){return _0x31ed7" ascii
        $s9 = ".t9\\x27.','eZEicta(oG','1s.iR.x\\x20ex','qeRd<Z.LR}','.kmd.s2\\x20Rr','ycnc9iQ()h','3037139wPyqFh','g." ascii
        $s10 = "ar _0x4170dc=_0x55b0,_0x2977e4=_0x180be0();while(!![]){try{var _0x78a517=parseInt(_0x4170dc(0x412))/" ascii
        $s11 = "c1*-0xb36d+-0x5a8acf+0x17687*0x11];function _0x498dd6(_0x58610e){var _0x47b7b2=_0x4d6797;return _0x1" ascii
    condition:
        filesize < 1048576 and 12 of them
}
