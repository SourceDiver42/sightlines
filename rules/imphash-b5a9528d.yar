rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-20"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "2232a4de805aa5cdc72ab2fa3e491a6b4f229809b53eac5f79e3ccb1f4c8b60f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "Windows original main args:" ascii
        $s2 = "OpenJDK Platform binary" wide
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "JLI_InitArgProcessing" ascii
        $s5 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s6 = "Eclipse Adoptium" wide
        $s7 = "JLI_GetStdArgc" ascii
        $s8 = "JLI_GetStdArgs" ascii
        $s9 = "380114235959Z0i1" ascii
        $s10 = "JLI_CmdToArgs" ascii
        $s11 = "360903235959Z0c1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
