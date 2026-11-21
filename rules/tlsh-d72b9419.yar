rule Sightlines_tlsh_d72b9419_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d72b9419"
        date = "2026-11-15"
        campaign = "tlsh-d72b9419"
        family = ""
        hash = "1e189c727f043e924cb8779b673702ba836faa7c9e752e2743b69cde70a2c1fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d72b9419.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Error: Path length exceeds maximum length (PATH_MAX)" ascii
        $s1 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s2 = "Error: Specifying an alternate JDK/JRE is no longer supported." ascii
        $s3 = "Error: Specifying an alternate JDK/JRE version is no longer supported." ascii
        $s4 = "Error: no known VMs. (check for corrupt jvm.cfg file)" ascii
        $s5 = "Error: Corrupt jvm.cfg file; cycle in alias list." ascii
        $s6 = "Error: A fatal exception has occurred. Program will exit." ascii
        $s7 = "Error: The -J option should not be followed by a space." ascii
        $s8 = "Warning: %s VM not supported; %s VM will be used" ascii
        $s9 = "Error: A JNI error has occurred, please check your installation and try again" ascii
        $s10 = "Warning: Unknown VM type on line %d of `%s'" ascii
        $s11 = "Error: %s requires module path specification" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
