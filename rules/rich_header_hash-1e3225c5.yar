rule Sightlines_rich_header_hash_1e3225c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-1e3225c5"
        date = "2026-11-09"
        campaign = "rich_header_hash-1e3225c5"
        family = ""
        hash = "2a4787ece04ee9284f7628df4e899d6869ea9abe7b3b636453776790d04e56ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-1e3225c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s1 = "ECP_NISZ256 for x86/SSE2, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s2 = "SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s3 = "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s4 = "Poly1305 for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s5 = "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s6 = "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s7 = "ChaCha20 for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s8 = "Key type: 1=AT_KEYEXCHANGE (default), 2=AT_SIGNATURE" ascii
        $s9 = "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s10 = "RC4 for x86, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s11 = "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 25754896 and 12 of them
}
