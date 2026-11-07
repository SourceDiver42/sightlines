rule Sightlines_host_e9754b1c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-e9754b1c"
        date = "2026-10-26"
        campaign = "host-e9754b1c"
        family = ""
        hash = "05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-e9754b1c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "__mh_execute_header" ascii
        $s3 = "___stack_chk_guard" ascii
        $s4 = "___stack_chk_fail" ascii
        $s5 = "/tmp/log_de.log" ascii
        $s6 = "_gethostbyname" ascii
        $s7 = "/tmp/.X1-unix" ascii
        $s8 = "[kworker/0:2]" ascii
        $s9 = "/usr/lib/dyld" ascii
        $s10 = "__unwind_info" ascii
        $s11 = "__DATA_CONST" ascii
    condition:
        filesize < 1048576 and 12 of them
}
