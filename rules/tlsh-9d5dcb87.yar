rule Sightlines_tlsh_9d5dcb87_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9d5dcb87"
        date = "2026-11-15"
        campaign = "tlsh-9d5dcb87"
        family = ""
        hash = "1b04dbc641347ea737bd506b5070cf0d4b0166e057e798e8ad574cdccd9d2737"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9d5dcb87.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'&%$#\"! /.-,+*)(76543210?>=<;:98GFEDCBA@ONMLKJIHWVUTSRQP_^]\\[ZYXgfedcba`onmlkjihwvutsrqp" ascii
        $s1 = "~}|{zyxCBA@GFEDKJIHONMLSRQPWVUT[ZYX_^]\\cba`gfedkjihonmlsrqpwvut{zyx" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s3 = "m,bN:NX:,eetsraplrA kebne1 grb ,02 su,6443-B  100vueLH-nereve,eelleB muigrtkecetoeinhC ,kupmo retuce" ascii
        $s4 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s6 = "      --argon2-impl=IMPL        argon2 implementation: x86_64, SSE2, SSSE3, XOP, AVX2, AVX-512F" ascii
        $s7 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s8 = "[1;33mthis CPU doesn't support cat_l3, cache QoS is unavailable" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s10 = "N9__gnu_cxx18stdio_sync_filebufIwSt11char_traitsIwEEE" ascii
        $s11 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 11521408 and 12 of them
}
