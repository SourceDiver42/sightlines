rule Sightlines_tlsh_858b6ee5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-858b6ee5"
        date = "2026-11-15"
        campaign = "tlsh-858b6ee5"
        family = "mirai"
        hash = "200827454b25a295ed2b4754bff86cc46bb2108a31947c30e64d1a7ea0fada00"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-858b6ee5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/snap/snapd/15534/usr/lib/snapd/snapd" ascii
        $s3 = "/usr/libexec/openssh/sftp-server" ascii
        $s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s5 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s6 = "program_invocation_short_name" ascii
        $s7 = "/usr/lib/policykit-1/polkitd" ascii
        $s8 = "find_writable_dirs_recursive" ascii
        $s9 = "/usr/lib/openssh/sftp-server" ascii
        $s10 = "_pthread_cleanup_pop_restore" ascii
        $s11 = "_pthread_cleanup_push_defer" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
