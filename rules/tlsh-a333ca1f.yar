rule Sightlines_tlsh_a333ca1f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a333ca1f"
        date = "2026-11-26"
        campaign = "tlsh-a333ca1f"
        family = ""
        hash = "097aec2983be060401f1f0a0a0c1e6a4838360df865856c48c021609741a3309"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a333ca1f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ee)](_0x4b6a73,_0x56d966);},'TQmyP':function(_0x422e06,_0x2fca33){var _0x581b7d=_0x490c;return _0x15" ascii
        $s1 = ",_0x400f77);},'heCmf':_0x5746bc(0x4a2),'vMkaI':function(_0x5dc9e4,_0x36dff6){return _0x5dc9e4===_0x3" ascii
        $s2 = "6dff6;},'vOylk':function(_0x32467d,_0xc834dd){return _0x32467d(_0xc834dd);},'ABBeK':_0x5746bc(0x266)" ascii
        $s3 = "ile(!![]){try{var _0x50e4cd=parseInt(_0x35893f(0x21f))/(-0x20b0*-0x1+0xa6a+-0x2b19)+parseInt(_0x3589" ascii
        $s4 = "e4cd===_0x229911)break;else _0x840346['push'](_0x840346['shift']());}catch(_0x25b35f){_0x840346['pus" ascii
        $s5 = "2rcrT',';o==yhocch','6gWZvoE','55AxMtkC','0-oR;1.yN<','.R>cpfn&Rc','.kufKBr<;E','rn\\x20d6c#cRe','801" ascii
        $s6 = "4;},'qsAnV':function(_0x30bf96,_0x279399){return _0x30bf96+_0x279399;},'RnUAp':function(_0x341178,_0" ascii
        $s7 = "'s].;spawnH','c0s<rAcRUR','R.pSc%d.!o','590838HUbJph',',R4.fo<RtR','sqroqk\\x22n{e','rftn.a,i=4','tby" ascii
        $s8 = "1610[_0x581b7d(0x1a2)](_0x422e06,_0x2fca33);},'jVzRv':function(_0x57128a,_0x1a3b20){var _0x35b96b=_0" ascii
        $s9 = "13b6ec);},'OFwhE':function(_0x4b6a73,_0x56d966){var _0x3051fb=_0x490c;return _0x151610[_0x3051fb(0x4" ascii
        $s10 = "h'](_0x840346['shift']());}}}(_0xcc75,-0x2b481+-0xe7aae+-0x1*-0x1be096),!function(_0x354657,_0x5afef" ascii
        $s11 = "7){var _0x5746bc=_0x490c,_0x151610={'WHHqO':function(_0x22ca15,_0x4b4a83){return _0x22ca15<_0x4b4a83" ascii
    condition:
        filesize < 1048576 and 12 of them
}
