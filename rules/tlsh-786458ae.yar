rule Sightlines_tlsh_786458ae_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-786458ae"
        date = "2026-11-19"
        campaign = "tlsh-786458ae"
        family = "mirai"
        hash = "8f367ef5666641bdfac1e6ab117526792cf89570be786b8ddb769838868fa69a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-786458ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Unknown error Success" ascii
        $s1 = "/tmp/condinetwork" ascii
        $s2 = "dWLuG@rPMFWAVQ" ascii
        $s3 = "/proc/%s/status" ascii
        $s4 = "/bin/watchdog" ascii
        $s5 = "/var/CondiBot" ascii
        $s6 = "/var/condibot" ascii
        $s7 = "/var/condinet" ascii
        $s8 = "FICMUHDKPJKCF" ascii
        $s9 = "User-Agent: " ascii
        $s10 = "eJMQVuWXjGPG" ascii
        $s11 = "/bin/systemd" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
