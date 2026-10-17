rule Sightlines_tlsh_01c8ae79_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01c8ae79"
        date = "2026-10-15"
        campaign = "tlsh-01c8ae79"
        family = "mirai"
        hash = "414f133f0619e16230451cdfddd293727492f10925c88250ffb0743bb4441fde"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01c8ae79.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $s5 = "%s: cannot apply additional memory protection after relocation" ascii
        $s6 = "%s: '%s' has more than one dynamic section" ascii
        $s7 = "[udpbypass_flood] started: ('%d')" ascii
        $s8 = "%s: '%s' is missing a dynamic section" ascii
        $s9 = "Library contains unsupported TLS" ascii
        $s10 = "Modules for application (%p):" ascii
        $s11 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
