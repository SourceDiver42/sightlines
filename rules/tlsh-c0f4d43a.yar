rule Sightlines_tlsh_c0f4d43a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0f4d43a"
        date = "2026-10-20"
        campaign = "tlsh-c0f4d43a"
        family = ""
        hash = "7c9f3fa98d0678d1fe429825625bd06306d47a4b2a7d4c710c1f4d02165c39e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0f4d43a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "Windows original main args:" ascii
        $s3 = "JLI_InitArgProcessing" ascii
        $s4 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s5 = "JLI_GetStdArgc" ascii
        $s6 = "JLI_GetStdArgs" ascii
        $s7 = "380114235959Z0i1" ascii
        $s8 = "JLI_CmdToArgs" ascii
        $s9 = "360903235959Z0c1" ascii
        $s10 = "JLI_MemAlloc" ascii
        $s11 = "Full Version" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
