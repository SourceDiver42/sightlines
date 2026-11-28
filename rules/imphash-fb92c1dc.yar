rule Sightlines_imphash_fb92c1dc_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fb92c1dc"
        date = "2026-11-10"
        campaign = "imphash-fb92c1dc"
        family = "remcos"
        hash = "06ffad7a23d9a34c91971b6e38fd8de6e7f61014afd4e9e3ba487b62ace33977"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fb92c1dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v E" ascii
        $s1 = "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z" ascii
        $s2 = "?replace@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEAAV12@IIPBG@Z" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s4 = "?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBE_NXZ" ascii
        $s5 = "?empty@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QBE_NXZ" ascii
        $s6 = "??0out_of_range@std@@QAE@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@1@@Z" ascii
        $s7 = "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV01@PBD@Z" ascii
        $s8 = "??4?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEAAV01@PBG@Z" ascii
        $s9 = "??Y?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV01@PBD@Z" ascii
        $s10 = "??Y?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEAAV01@PBG@Z" ascii
        $s11 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
