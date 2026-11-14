rule Sightlines_tlsh_597cb547_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-597cb547"
        date = "2026-11-13"
        campaign = "tlsh-597cb547"
        family = ""
        hash = "1e20bc257f7c637a95f935d613d9a9c17eede935f3ed96c1edd8c96c1cf6403e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-597cb547.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'&%$#\"! /.-,+*)(76543210?>=<;:98GFEDCBA@ONMLKJIHWVUTSRQP_^]\\[ZYXgfedcba`onmlkjihwvutsrqp" ascii
        $s1 = "~}|{zyxCBA@GFEDKJIHONMLSRQPWVUT[ZYX_^]\\cba`gfedkjihonmlsrqpwvut{zyx" ascii
        $s2 = "!(stream->flags & UV_HANDLE_BLOCKING_WRITES)" ascii
        $s3 = "!(handle->flags & UV_HANDLE_UDP_PROCESSING)" ascii
        $s4 = "hwloc_type_cmp(obj, prev) == HWLOC_OBJ_EQUAL" ascii
        $s5 = "(stream->type == UV_TCP || stream->type == UV_NAMED_PIPE || stream->type == UV_TTY) && \"uv_write (un" ascii
        $s6 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s7 = "(pevents & ~(UV_READABLE | UV_WRITABLE | UV_DISCONNECT | UV_PRIORITIZED)) == 0" ascii
        $s8 = "ALG_ERR: ASYNC AFALG not supported this kernel(%d.%d.%d)" ascii
        $s9 = "m,bN:NX:,eetsraplrA kebne1 grb ,02 su,6443-B  100vueLH-nereve,eelleB muigrtkecetoeinhC ,kupmo retuce" ascii
        $s10 = "!(options->flags & ~(UV_PROCESS_DETACHED | UV_PROCESS_SETGID | UV_PROCESS_SETUID | UV_PROCESS_WINDOW" ascii
        $s11 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 19046448 and 3 of them
}
