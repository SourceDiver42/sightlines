rule Sightlines_tlsh_b44944d4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b44944d4"
        date = "2026-11-11"
        campaign = "tlsh-b44944d4"
        family = ""
        hash = "4d7bcdc914c4701b1a854c17087d64ff22ee86db8a20e3ad2878dc2fc8b51d37"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b44944d4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AESNI-CBC+SHA256 stitch for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s1 = "X25519 primitives for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s2 = "GF(2^m) Multiplication for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s3 = "AESNI-CBC+SHA1 stitch for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s4 = "Poly1305 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s5 = "Keccak-1600 absorb and squeeze for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s6 = "SHA512 block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s7 = "AES-NI GCM module for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s8 = "SHA256 multi-block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s9 = "SHA256 block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s10 = "SHA1 multi-block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
        $s11 = "VIA Padlock x86_64 module, CRYPTOGAMS by <https://github.com/dot-asm>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 16958464 and 12 of them
}
