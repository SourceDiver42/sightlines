rule Sightlines_imphash_e8081cc3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e8081cc3"
        date = "2026-11-21"
        campaign = "imphash-e8081cc3"
        family = ""
        hash = "3c9abb9bd3022354ad6db53ffcc92f63d1209a30258444778ce44cd7977e1e5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e8081cc3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" ascii
        $s1 = "Changguang Technology. Copyright @ 2023" wide
        $s2 = "Shenzhen Changguang Technology Co., Ltd." wide
        $s3 = "GetMenuDefaultItem" ascii
        $s4 = "PathStripToRootW" ascii
        $s5 = ":ggggggggK:::7:7:7:7:7::::::::::::::::::::::::::Uggggggggggggggggggggggggggggggggggggggggggggggggggg" ascii
        $s6 = "XBtn_IsCheck" ascii
        $s7 = "WINSPOOL.DRV" ascii
        $s8 = "FcI#JsQsjs|c" ascii
        $s9 = "mCn#osoSp3q" ascii
        $s10 = "ECF#GsGSH3I" ascii
        $s11 = "JCK#LsLSMcN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41456016 and 12 of them
}
