rule Sightlines_tlsh_473589e0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-473589e0"
        date = "2026-11-14"
        campaign = "tlsh-473589e0"
        family = ""
        hash = "38184f1de58ae9f19f1cacf309fe636ebcabd2b799d57f03f9c38cfcb018e0ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-473589e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3B\\u263B\\u263B';var THdIP=THIfYZIP['split']('\\u263B\\u263B')['join']('');var Q=new ActiveXObject(THdI" ascii
        $s1 = "'\\x20\\x20'+TAXIELYOKUM['split']('\\u263B\\u263B\\u263B')['join'](''),-0xaa+0x2*0xda6+-0x1aa2,![]);var $" ascii
        $s2 = "var ads=self+UTERUTTTCM;WshShell['Run']('cmd\\x20/c\\x20echo.\\x20>\\x20\\x22'+ads+'\\x22',0x167d+0x13f*-0" ascii
        $s3 = "\\u263B\\u263B\\u263Beam';var FBNRTYFNIA=BNRTY['split']('\\u263B\\u263B')['join']('');var b=new ActiveXOb" ascii
        $s4 = "\\u263B\\u263B\\u263Beam';var FBNRTYFNIA=BNRTY['split']('\\u263B\\u263B')['join']('');var ASS=new ActiveX" ascii
        $s5 = "(-0x203c+-0xde1+-0x2e81*-0x1));var _0xe73184=_0x5a750d;return _0xe73184}try{var content=CreateURLCon" ascii
        $s6 = "+0xd5*-0x21;_0x573101<_0x4bbea9;_0x573101++){_0x47507d+=_0x14e174['charAt'](Math['floor'](Math['rand" ascii
        $s7 = "tent(HGJHKKLL);var file=fso['CreateTextFile'](urlFilePath,!![]);file['Write'](content);file['Close']" ascii
        $s8 = "u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B';var FFFFFFNIA=PQQQQQR['split']('\\u263B\\u263B')['join'](''" ascii
        $s9 = "263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B';var PDDDIA=THdIPdd['split']('\\u263" ascii
        $s10 = "\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B';var NWERTRJETR=NNNNNIRJETR['spli" ascii
        $s11 = "u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B\\u263B';var UTERUTTTCM=UTERUIHCM['s" ascii
    condition:
        filesize < 6338506 and 12 of them
}
