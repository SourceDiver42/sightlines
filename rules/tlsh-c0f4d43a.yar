rule Sightlines_tlsh_c0f4d43a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0f4d43a"
        date = "2026-11-27"
        campaign = "tlsh-c0f4d43a"
        family = ""
        hash = "0d0448174d811b743faed2c1600b6174f33e65506e196b177effe0cd7a04cdb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0f4d43a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "Windows original main args:" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JLI_InitArgProcessing" ascii
        $s6 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s7 = "Eclipse Adoptium" wide
        $s8 = "JLI_GetStdArgc" ascii
        $s9 = "JLI_GetStdArgs" ascii
        $s10 = "380114235959Z0i1" ascii
        $s11 = "JLI_CmdToArgs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
