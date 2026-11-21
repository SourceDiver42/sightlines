rule Sightlines_tlsh_0d119942_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d119942"
        date = "2026-11-18"
        campaign = "tlsh-0d119942"
        family = ""
        hash = "3f0c1313bac92a2e20966ff0819ad0d59da93dea23e6d946713bd82367db066c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d119942.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "onment variable MSBUILDEMITSOLUTION=1 to create a corresponding \".sln.metaproj\" file. Then debug tha" ascii
        $s1 = "KMSBUILD : Configuration error MSB1043: The application could not start. {0}" ascii
        $s2 = "5MSBUILD : MSB1046: The schema \"{0}\" is not valid. {1}" ascii
        $s3 = "@Forcing load of Microsoft.Build.Engine because MSBUILDOLDOM=1..." ascii
        $s4 = "<MSBUILD : error MSB1030: Maximum CPU count is not valid. {0}" ascii
        $s5 = "MSBUILD : error MSB4192: The project file \"{0}\" is in the \".vcproj\" or \".dsp\" file format, which MSB" ascii
        $s6 = "<MSBUILD : error MSB1031: Specify the maximum number of CPUs." ascii
        $s7 = "EMSBUILD : MSB1045: Stopping because of syntax errors in project file." ascii
        $s8 = ",MSBUILD : MSB1044: Project is not valid. {0}" ascii
        $s9 = "          <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />" ascii
        $s10 = ":MSBUILD : error MSB1026: Schema file '{0}' does not exist." ascii
        $s11 = "8MSBUILD : error MSB1028: The logger failed unexpectedly." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
