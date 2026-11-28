rule Sightlines_tlsh_eebe297f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-eebe297f"
        date = "2026-11-22"
        campaign = "tlsh-eebe297f"
        family = ""
        hash = "01fce500e15582f63ed1354dd1f1f50ff81ea967325b43147cb145e7917b6f5e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-eebe297f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "c3){var _0x2105eb=_0x39ba;return _0x3627c7[_0x2105eb(0x369)](_0x5831f8,_0x4202c3);},'mkAMS':function" ascii
        $s1 = "3726=_0x24067a[_0x53808f];return _0x473726;}function _0x4ca6(){var _0x518462=['<R[tto0a\\x27?','_T<.-" ascii
        $s2 = "},'wFogz':function(_0x48f23d,_0x1b9070){return _0x48f23d(_0x1b9070);},'GmUNJ':_0x515315(0x39e)+_0x51" ascii
        $s3 = "r _0x515315=_0x39ba,_0x3627c7={'OsUoS':function(_0x42d91a,_0x3fecab){return _0x42d91a<_0x3fecab;},'p" ascii
        $s4 = "8n+vr','tR,Rg<rR\\x20$','vjr;Cfl\\x20qp','RRTi~Wp[.<','OsUoS','22820690UNymhQ','.e}c\\x27Re<!R','zd..iR" ascii
        $s5 = "x415)](_0xbff4b7,_0x1ad2d4);},'hSjjW':function(_0x160d62,_0x2d8f46){var _0x3d1993=_0x39ba;return _0x" ascii
        $s6 = "},'olhkg':function(_0x181dcd,_0x57e9c2){var _0x29767e=_0x39ba;return _0x3627c7[_0x29767e(0x1a4)](_0x" ascii
        $s7 = "DDgX':function(_0x4544a2,_0xb3f196){return _0x4544a2%_0xb3f196;},'jZJfS':function(_0x5649df,_0x50e99" ascii
        $s8 = "return _0x3627c7[_0x40b5b6(0x50a)](_0x4672f6,_0x47d986);},'oPwVI':function(_0x5bf8c6,_0x5649b2){var " ascii
        $s9 = "217){var _0x171646=_0x515315,_0x2dce57={'ThDJB':function(_0x4672f6,_0x47d986){var _0x40b5b6=_0x39ba;" ascii
        $s10 = "0x3d1aa7);},'YSVYO':function(_0xbff4b7,_0x1ad2d4){var _0x34cce2=_0x39ba;return _0x3627c7[_0x34cce2(0" ascii
        $s11 = "(function(_0x4a7722,_0x5bd6f7){var _0x4a1562=_0x39ba,_0x56c874=_0x4a7722();while(!![]){try{var _0xa7" ascii
    condition:
        filesize < 1048576 and 12 of them
}
