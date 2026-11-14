rule Sightlines_tlsh_8ba80a5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8ba80a5a"
        date = "2026-11-13"
        campaign = "tlsh-8ba80a5a"
        family = ""
        hash = "64c48b1280e4540c205ee7798b7da200afd95898d520ece1d56bf8a8a351fc3e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8ba80a5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "api-ms-win-crt-convert-l1-1-0.pdb" ascii
        $s1 = "ucrtbase._wcstoui64_l" ascii
        $s2 = "ucrtbase._wcstoimax_l" ascii
        $s3 = "ucrtbase._wcstoumax_l" ascii
        $s4 = "ucrtbase._strtoui64_l" ascii
        $s5 = "ucrtbase._strtoimax_l" ascii
        $s6 = "ucrtbase._wcstombs_s_l" ascii
        $s7 = "ucrtbase._wcstoi64_l" ascii
        $s8 = "ucrtbase._strtoumax_l" ascii
        $s9 = "ucrtbase._strtoi64_l" ascii
        $s10 = "ucrtbase._wcstombs_l" ascii
        $s11 = "ucrtbase._wctomb_s_l" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
