rule Sightlines_tlsh_a73089c6_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a73089c6"
        date = "2026-11-20"
        campaign = "tlsh-a73089c6"
        family = "coinminer"
        hash = "07b6b73c7148ef65998f3273db005af31d6d0de0cf69a49a96fa8489ae8b8feb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a73089c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[providers/implementations/digests/md5_prov.c" ascii
        $s1 = "error unsupported static key agreement" ascii
        $s2 = "fecp_nistz256_inv_mod_ord" ascii
        $s3 = "%*s  namingAuthorityId: " ascii
        $s4 = "9Hambiguous content type" ascii
        $s5 = "?crypto/rand/rand_pool.c" ascii
        $s6 = "bn_mod_exp_mont_fixed_top" ascii
        $s7 = "%4d-%02d-%02d %02d:%02d:%02dZ" ascii
        $s8 = "?crypto/bio/bio_sock.c" ascii
        $s9 = "%*snamingAuthority:" ascii
        $s10 = "ENHANCE_YOUR_CALM" ascii
        $s11 = "Unknown error code" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 14771200 and 12 of them
}
