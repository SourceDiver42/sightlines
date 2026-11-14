rule Sightlines_tlsh_84ee1aeb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84ee1aeb"
        date = "2026-11-07"
        campaign = "tlsh-84ee1aeb"
        family = ""
        hash = "123cc0a87b320d4dafce929ce4f4ad705e58054b0f5268da926ab7b6e1f3a90b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84ee1aeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE)" ascii
        $s1 = "(cur_match_len >= TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 1) && (cur_match_dist <= TDEFL_LZ_DICT_" ascii
        $s2 = "C:\\Users\\Administrator\\Desktop\\miner3_0\\third_party\\miniz_tinfl.c" ascii
        $s3 = "C:\\Users\\Administrator\\Desktop\\miner3_0\\third_party\\miniz_tdef.c" ascii
        $s4 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s5 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s6 = "d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]" ascii
        $s7 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s8 = "max_match_len <= TDEFL_MAX_MATCH_LEN" ascii
        $s9 = "Partial loss of significance (PLOSS)" ascii
        $s10 = "d->m_pOutput_buf < d->m_pOutput_buf_end" ascii
        $s11 = "d->m_lookahead_size >= len_to_move" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
