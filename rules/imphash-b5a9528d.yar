rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-15"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "22822b1a649484aceee0817ad14b4c513cb544d0a2f60be63b9bfb6453421c66"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "OpenJDK Platform 21.0.12" wide
        $s2 = "Windows original main args:" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JLI_InitArgProcessing" ascii
        $s6 = "Eclipse Foundation0" ascii
        $s7 = "Eclipse Foundation1" ascii
        $s8 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s9 = "Eclipse Adoptium" wide
        $s10 = "JLI_GetStdArgc" ascii
        $s11 = "JLI_GetStdArgs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
