rule Sightlines_tlsh_dd4f86da_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd4f86da"
        date = "2026-11-09"
        campaign = "tlsh-dd4f86da"
        family = "mirai"
        hash = "1f15fc801140d41f3f0eaccf9aa115da51c693f1265ba00fbf35bf31269a739f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd4f86da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "HOST: 255.255.255.255:1900" ascii
        $s3 = "MAN: \"ssdp:discover\"" ascii
        $s4 = "M-SEARCH * HTTP/1.1" ascii
        $s5 = "service:service-agent" ascii
        $s6 = "objectClass0" ascii
        $s7 = "T`X(}iJx|c" ascii
        $s8 = "?/dev/null" ascii
        $s9 = "TeamSpeak" ascii
        $s10 = " default" ascii
        $s11 = "}CSx}e[x" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
