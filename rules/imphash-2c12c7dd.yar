rule Sightlines_imphash_2c12c7dd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2c12c7dd"
        date = "2026-11-15"
        campaign = "imphash-2c12c7dd"
        family = ""
        hash = "452aa9980c07293cb3053c574f2ceccb8e4975400aeff702db8af3e807602cfc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2c12c7dd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_jdk_net_WindowsSocketOptions_getTcpKeepAliveProbes0" ascii
        $s1 = "Java_jdk_net_WindowsSocketOptions_setTcpKeepAliveProbes0" ascii
        $s2 = "Java_jdk_net_WindowsSocketOptions_getTcpKeepAliveIntvl0" ascii
        $s3 = "Java_jdk_net_WindowsSocketOptions_getTcpKeepAliveTime0" ascii
        $s4 = "Java_jdk_net_WindowsSocketOptions_setTcpKeepAliveIntvl0" ascii
        $s5 = "Java_jdk_net_WindowsSocketOptions_setTcpKeepAliveTime0" ascii
        $s6 = "Java_jdk_net_WindowsSocketOptions_keepAliveOptionsSupported0" ascii
        $s7 = "java/lang/UnsupportedOperationException" ascii
        $s8 = "get option TCP_KEEPINTVL failed" ascii
        $s9 = "set option TCP_KEEPINTVL failed" ascii
        $s10 = "get option TCP_KEEPIDLE failed" ascii
        $s11 = "set option TCP_KEEPIDLE failed" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
