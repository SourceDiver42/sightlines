rule Sightlines_tlsh_05d1532b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05d1532b"
        date = "2026-11-15"
        campaign = "tlsh-05d1532b"
        family = ""
        hash = "2cd3b5ebc97aff79685c34024ef13a3880aed9c26bb9d82c673ee765b134b6a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05d1532b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "amsOwahSelaTragUiguBtpoCgalGrahKulaToepXolySgnfTilaBxusXookNgahPxnhPiraCmahCilaKcpeLicyLidyLkclOgnjR" ascii
        $s1 = "dnaNpnmHohcWsrhCkaiDstiKizeYnmpCrguOasnTotoThtiVhtmZiwaKmgaNaraGhkuGiarKoanOunuSrdoTgtuTfreBtdiSoyaT" ascii
        $s2 = "araWmohAwulHrtaHtluMgnuHwngSmldAskhBcraMegsOgnaTaweNmnoGuhsNoyoSbnaZrgoDgnoGghoRakaMfdeMogoSdgoSmylE" ascii
        $s3 = "tbiTopoBiarBsnaCrehCihtErmhKgnoMrmyMmagOrnuRhniScrySaahTiiiYtrsDhtoGlatIdhuBonaHglgTbgaTtrpCbmiLbniL" ascii
        $s4 = "drhSaroSrkaTssaBbhgAlpuDablEnarGjohKdniSaniLjhaMinaMdneMidoMoorMtabNbraNmrePgnmHmlaPcuaPplhPddiShriT" ascii
        $s5 = "ruaSdnuSiiaVtsvAumaBpygEimrAilhPitrPavaJihtKusiLietMbraShkrOrmaSanaLtvaTktaBharBdnaMmkaCcreMoreMdrlP" ascii
        $s6 = "Java_sun_font_FileFontStrike__1getGlyphImageFromWindows" ascii
        $s7 = "yyyZhniZbarAnmrAgneBopoBrehCtpoClryCtrsDaveDihtEroeGhtoGkerGrjuGuruGinaHgnaHrbeHariHadnKanaKrmhKooaL" ascii
        $s8 = "yyyZhniZzzzZbarAnmrAgneBlryCaveDroeGkerGrjuGuruGgnaHinaHrbeHariHadnKanaKooaLntaLmylMayrOlmaTuleTiahT" ascii
        $s9 = "JNU_ThrowArrayIndexOutOfBoundsException" ascii
        $s10 = "Java_sun_font_FreetypeFontScaler_getMissingGlyphCodeNative" ascii
        $s11 = "ntaLmylMgnoMrmyMmagOlatIayrOrnuRhniScrySlmaTuleTaahTiahTtbiTsnaCiiiYglgTonaHdhuBbgaT" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2060528 and 11 of them
}
