rule Sightlines_tlsh_a4238eca_vshell
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4238eca"
        date = "2026-11-09"
        campaign = "tlsh-a4238eca"
        family = "vshell"
        hash = "043965a4c503d0f585b2260badb5a92e77c11684591160f4585e34e131be9533"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4238eca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateH" ascii
        $s1 = "GCC: (x86_64-win32-seh-rev0, Built by MinGW-W64 project) 8.1.0" ascii
        $s2 = "precatedDevanagariDnsQuery_WGOMAXPROCSGOMEMLIMITGetIfEntryGetVersionGlagoliticKharoshthiLockFileExMa" ascii
        $s3 = "9301562578125<nil>AdlamAprilBamumBatakBuhidDograErrorGreekKhmerLatinLimbuLocalMarchNushuOghamOriyaOs" ascii
        $s4 = "55621337890625Other_Default_Ignorable_Code_PointSetFileCompletionNotificationModesVirtualQuery for s" ascii
        $s5 = "alue>19531259765625AvestanBengaliBrailleChanDirCopySidCypriotDeseretElbasanElymaicGranthaHanunooIO w" ascii
        $s6 = "downtraceBufwsaioctl244140625AuthorityBassa_VahBhaiksukiClassINETCuneiformDiacriticFindCloseHex_Digi" ascii
        $s7 = "ev/stdin12207031256103515625AdditionalBad varintCancelIoExChorasmianClassCHAOSClassCSNETCreatePipeDe" ascii
        $s8 = "not pointer3814697265625CertOpenStoreFindNextFileWFreeAddrInfoWGC sweep waitGunjala_GondiMapViewOfFi" ascii
        $s9 = "is remotereflect mismatchremote I/O errorschedule: in cgotime: bad [0-9]*workbuf is empty0123456789A" ascii
        $s10 = "TeluguThaanaTypeMXTypeNSUTC+12UTC+13UTC-02UTC-08UTC-09UTC-11WanchoYezidi[]bytechan<-domaingopherhead" ascii
        $s11 = "s is  on +Inf-Inf3125ACDTACSTAEDTAESTAKDTAKSTAWSTAhomCESTChamDashEESTGOGCJulyJuneLEAFLisuMiaoModiNZD" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9528320 and 12 of them
}
