rule Sightlines_tlsh_19d3cf5d_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-19d3cf5d"
        date = "2026-10-15"
        campaign = "tlsh-19d3cf5d"
        family = "connectwise"
        hash = "27b75ce758c4a59c60916cde187b814755059d3fddb982d02d397dffd9eb101e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-19d3cf5d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FJ7ZuWXP5BWViHJTbf5tPj7Sz3VZwFq8m7qZRUuRH8DdT5ZTh16EXQCtQGTdC3%2f6cdeRipg90LvRJZX4%2fUH8mHIc8WT2uHwG" ascii
        $s1 = "owrzdSYAy9REZQ6VQse0UfvmLhINz31AqKPMMoMth4o%2bMavAJ8l%2b4%2b2cAnDO%2bb6%2bFylxuzA&t=&c=&c=&c=&c=&c=&" ascii
        $s2 = "inalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION" ascii
        $s3 = "0TTG%2bw8jNKIhaiX5%2bAk5V%2fBlG7ZV8vvpvIpen%2bIjWKto%2b%2ft2RaJJkmNEiZXVhbDKkMCgLoguOOEHQTD2zzeE%2b%" ascii
        $s4 = "2bYbIKt2%2btII8jVJd9udccUDkoBTNIilMA4lD%2f18HSK9IXWik3cby%2bIBrxpoP6s%2bA2rbet3WdvT0np%2bdqRuOkf2A8i" ascii
        $s5 = "24?69<>BRTVDFIHLOQX[bhj]_adfnm|{qptvxz~" wide
        $s6 = "{7350F8A0-CE89-45E4-99C4-3D3D88E5E885}NOT SERVICE_ARGUMENTSServiceExeWithoutServiceScrubFiles_Initia" ascii
        $s7 = "IRyesARPNOMODIFYALLUSERS1ManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-428" ascii
        $s8 = "emote Control\"[SERVICE_ARGUMENTS]\"{0C94448B-0C9E-4112-AC7D-B00E6BA76D82}0.0.0.099.0.0.0OLD_PRODUCT_1" ascii
        $s9 = "tallSOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client[MachineName]Users[SERVICE_NAME]restartnoneR" ascii
        $s10 = "reateProgramDataDirectory{4768BE46-975A-455C-AF15-61A15FE629A4}PROGRAMDATALOCATIONMainFiles{E0EF5F66" ascii
        $s11 = "ntrol\\SafeBoot\\Network\\[SERVICE_NAME]ServiceSoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727Ins" ascii
    condition:
        filesize < 3137536 and 12 of them
}
