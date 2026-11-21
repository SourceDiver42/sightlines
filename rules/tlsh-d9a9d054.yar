rule Sightlines_tlsh_d9a9d054_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d9a9d054"
        date = "2026-11-15"
        campaign = "tlsh-d9a9d054"
        family = "mirai"
        hash = "252ec5a1878aaabda427115aaa41284d6965ef054d3c25c7fc5f95cbab70a1ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d9a9d054.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s2 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s3 = "/snap/snapd/15534/usr/lib/snapd/snapd" ascii
        $s4 = "/usr/libexec/openssh/sftp-server" ascii
        $s5 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s6 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s7 = "program_invocation_short_name" ascii
        $s8 = "/usr/lib/policykit-1/polkitd" ascii
        $s9 = "find_writable_dirs_recursive" ascii
        $s10 = "/usr/lib/openssh/sftp-server" ascii
        $s11 = "_pthread_cleanup_pop_restore" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
