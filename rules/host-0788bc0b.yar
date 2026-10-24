rule Sightlines_host_0788bc0b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-0788bc0b"
        date = "2026-10-18"
        campaign = "host-0788bc0b"
        family = "mirai"
        hash = "0a3599e38ceb3be32e3c9ec5a15cfd3959476d08d69587cf24f7149ebe7c057b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-0788bc0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $s3 = "%s: cannot apply additional memory protection after relocation" ascii
        $s4 = "%s: '%s' has more than one dynamic section" ascii
        $s5 = "[udpbypass_flood] started: ('%d')" ascii
        $s6 = "%s: '%s' is missing a dynamic section" ascii
        $s7 = "Modules for application (%p):" ascii
        $s8 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s9 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s10 = "Not an ELF shared library" ascii
        $s11 = "mmap of a spare page failed!" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
