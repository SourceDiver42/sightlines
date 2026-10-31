rule Sightlines_tlsh_04ddf57b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-04ddf57b"
        date = "2026-10-30"
        campaign = "tlsh-04ddf57b"
        family = ""
        hash = "0dd5f5a35a03a3d248a14fe94d93c7bb6f48c9c0fe6deeeffdf2e01787fd6c05"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-04ddf57b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-empty=0 --ctrack-disable=0 ^" ascii
        $s1 = "--lua-desync=fake:blob=active_discord:repeats=6 ^" ascii
        $s2 = "--hostlist=\"%LISTS%list-general-user.txt\" ^" ascii
        $s3 = "--hostlist-exclude=\"%LISTS%list-exclude-user.txt\" ^" ascii
        $s4 = "--hostlist-exclude=\"%LISTS%list-exclude.txt\" ^" ascii
        $s5 = "--ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" ^" ascii
        $s6 = "--ipset-exclude=\"%LISTS%ipset-exclude.txt\" ^" ascii
        $s7 = "--lua-init=@\"%LUA%zapret-antidpi.lua\" ^" ascii
        $s8 = "--filter-tcp=2053,2083,2087,2096,8443 ^" ascii
        $s9 = "--hostlist=\"%LISTS%list-general.txt\" ^" ascii
        $s10 = "--payload=discord_ip_discovery,stun ^" ascii
        $s11 = "--lua-init=@\"%LUA%zapret-auto.lua\" ^" ascii
    condition:
        filesize < 1048576 and 8 of them
}
