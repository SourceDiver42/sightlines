rule Sightlines_imphash_de194efc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-de194efc"
        date = "2026-11-13"
        campaign = "imphash-de194efc"
        family = ""
        hash = "39c585bebc4f73655b7f9df7aa10dbf2af13331b3fc60ace529d20709fadee67"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-de194efc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "qq6AvMhjtp2ku_0yWRBbvNynIMDAoMfaH_p4PyqVDPx5h9c5mzXCpsj2T4oFLUxNb1X39lNBmdYg58ttPE_j6giIwvE4lQrQK8k3" ascii
        $s1 = "W9JHNI9xmAeDv8tbJCOakXVnguJXYH-0tSMO0rYKXpZb-mBc04jj5UgmU2EQiXo7R6PeAFl-lwrkQR_8GdJlvUBGEiTLSlCfVmii" ascii
        $s2 = "aBsQXVVZUBSDYSxY5ZKjLkW3hePX1726haTBRmRb86zx4IG0RO--nJME5Bp8fLPjxfcRLnwT11P2VMC:\\Program Files\\fishe" ascii
        $s3 = "AlaAm9nBG-lTvhuf6-XG5JwRTv3BBi2fFuK_ZFdyl7Ev94iz2lsQm1upGWkOL9MdCpUqokmqvcN0ezZMauAtI_8J1rSQ2XqpgwMX" ascii
        $s4 = "HhV1D_N2iX_XWi-ZStc09yNuumwYf-00wj5xqFT995OKAyn12MCGwPXd8GlZQao-ptB4EWW13BN4XbqYPUMRtfr4Gf-h7LEvmHNw" ascii
        $s5 = "ZyYODSL3Wa7rMJ8ScqehBPD9-hdYBvk2fh-si8Wxw7QTAtZRpCvFk5oqJsfkj7KXGuJx-omLM-3a1fGviYB1-H684FM02olr2Vmu" ascii
        $s6 = "mp_Cyb7oQ6ymZ-RoIkUP6gCR3rMZdTl1TjzxnWD8ltYj0yuKd5PaH_86QT5fSfPwrEABbGjc4gcWxHvS5jVL-t-yikjV0gr6fFNK" ascii
        $s7 = "neLpR635xJ-nU2tNuCgC4i_sT5xhX0FigvV69O0P7BEuBXIvd-oFJrH2IF9-OZBDOMoEbl3f4UpVjKILC_sxOt1gMS8BOw6PQRcw" ascii
        $s8 = "H-1TDE1XA7H4fMHsV8alWxhBu7vkeZ7rBNsk5aBjP_Z-Wr6eG9dzPq4kUWe8hJ4BFIUjTaGYQpLZt2d5XiJY-ZOk27Do-A9KSdcC" ascii
        $s9 = "mkTE7kKyIzRGBack6s9GXAb7IrwtErds15pnuWEu0LLYfbEx7F1iCGe3s2KeVk-e9BjslQbQKLugZP7kNu28K4fpvBjqNODmWgUb" ascii
        $s10 = "kZ3GAFCoNUgvAMfGbEUe5JVeUapoHTzLBJuNDBEI-k54dBen6lu9iqQMjJA-xKGfdcSr88h7V9n4Dl0uUDCXdFYz5-OxCj7Yvg8I" ascii
        $s11 = "90_5IlgnJqzkPmcibbut8ML-32oFQVzihEYvvBMzPlf7R7r4BmmvXDIwtaETTEA-vpgTFUDjZo0SAfTYyNhJ8h-K3KuRffBw9qRN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1199104 and 12 of them
}
