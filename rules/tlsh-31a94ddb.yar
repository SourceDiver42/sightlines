rule Sightlines_tlsh_31a94ddb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-31a94ddb"
        date = "2026-10-21"
        campaign = "tlsh-31a94ddb"
        family = ""
        hash = "2261c63c17c6ae904a419f98f51a8fd7607a3a0a952d87c4e85c36aaea158387"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-31a94ddb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "ws_stager_darwin_arm64" ascii
        $s3 = "__mh_execute_header" ascii
        $s4 = "___stack_chk_guard" ascii
        $s5 = "___chkstk_darwin" ascii
        $s6 = "___stack_chk_fail" ascii
        $s7 = "/tmp/log_de.log" ascii
        $s8 = "_gethostbyname" ascii
        $s9 = "/tmp/.X1-unix" ascii
        $s10 = "___sprintf_chk" ascii
        $s11 = "[kworker/0:2]" ascii
    condition:
        filesize < 1048576 and 12 of them
}
