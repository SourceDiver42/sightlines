rule Sightlines_tlsh_5ccba874_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5ccba874"
        date = "2026-11-07"
        campaign = "tlsh-5ccba874"
        family = "coinminer"
        hash = "04536318c462d12483720fa37a2e79c72c71f8c2af412af98085576cb7f3bb63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5ccba874.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE)" wide
        $s1 = "(cur_match_len >= TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 1) && (cur_match_dist <= TDEFL_LZ_DICT_" wide
        $s2 = "GNU C23 16.2.0 -mtune=generic -march=x86-64 -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" ascii
        $s3 = "elev: transfer SKIPPED (svc/children not ready)" wide
        $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" wide
        $s5 = "  TLS: slot=%d raw=0x%zx zerofill=0x%x _tls_index@%p" wide
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "powercfg /change standby-timeout-dc 0 monitor-timeout-dc 0" wide
        $s8 = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\PrivilegeRights" wide
        $s9 = "powercfg /change standby-timeout-ac 0 monitor-timeout-ac 0" wide
        $s10 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s11 = "d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 38859568 and 10 of them
}
