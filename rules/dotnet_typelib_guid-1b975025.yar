rule Sightlines_dotnet_typelib_guid_1b975025_arechclient2
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-1b975025"
        date = "2026-11-16"
        campaign = "dotnet_typelib_guid-1b975025"
        family = "arechclient2"
        hash = "0551872127101f6f79321aaaeb1d24563a799ac8aba4236796396f20f23523cb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-1b975025.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "5c3RhbApwZGFkamtma2djYWZnYmNlaW1jcGJrYWxuZm5lcGJua3xLYXJkaWFDaGFpbg==AFileSystemntivFileSystemirusPr" wide
        $s1 = "scGdwcHxUZXJyYVN0YXRpb24KZm5uZWdwaGxvYmpkcGtoZWNhcGtpampka2djamhraWJ8SGFybW9ueVdhbGxldAphZWFjaGtubWV" wide
        $s2 = "qbmVwb2dqaGtnbm9hcGFjfEVxdWFsV2FsbGV0CmNqZWxmcGxwbGViZGpqZW5sbHBqY2JsbWprZmNmZm5lfEpheHh4TGliZXJ0eQp" wide
        $s3 = "ram Data\\name{}:,[]\".Profile_Unknownloginscookies.sqliteROOT\\SecurityCenter2coMANGOokies.sqMANGOlite" wide
        $s4 = "efVPNDefID: CommandLineOpera GX Stabletdata\\tdataZmZuYmVsZmRvZWlvaGVua2ppYm5tYWRqaWVoamhhamJ8WW9yb2l" wide
        $s5 = "mcGhlcGNjaW9uYm9vaGNrb25vZWVtZ3xDb2luOThXYWxsZXQKY2dlZW9kcGZhZ2pjZWVmaWVmbG1kZnBocGxrZW5sZmt8VG9uQ3J" wide
        $s6 = "8QnJhdmVXYWxsZXQKaHBnbGZoZ2ZuaGJncGpkZW5qZ21kZ29laWFwcGFmbG58R3VhcmRhV2FsbGV0CmJsbmllaWlmZmJvaWxsa25" wide
        $s7 = "Login Data, CommandLine: , Name: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall-*.lo--gNoDefrdD" wide
        $s8 = "vaGltYWVsYm9ocGpiYmxkY25nY25hcG5kb2RqcHxCaW5hbmNlQ2hhaW4Kb2RiZnBlZWloZGtiaWhtb3BrYmptb29uZmFubGJmY2x" wide
        $s9 = "lam1uaWR8TmlmdHlXYWxsZXQKbmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm58TWV0YW1hc2sKYWZiY2JqcGJwZmFkbGt" wide
        $s10 = "yName\\Program Files\\\\Program Files (x86)\\profiles1*.1l1d1begram.exehost_keyAppData\\Local\\ProcessIdUn" wide
        $s11 = "iZ2VraGVuYmh8QXRvbWljV2FsbGV0Cm5sYm1ubmlqY25sZWdrampwY2ZqY2xtY2ZnZ2ZlZmRtfE1ld0N4Cm5hbmptZGtuaGtpbml" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
