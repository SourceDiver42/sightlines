rule Sightlines_tlsh_50755a4b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-50755a4b"
        date = "2026-11-12"
        campaign = "tlsh-50755a4b"
        family = ""
        hash = "03d7ef688191cb6995aa1731fe830e09e85512e4b2a0c89b16d2925a2191a407"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-50755a4b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1V" ascii
        $s1 = "cblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB" ascii
        $s2 = "1Yw2rSYkTwcTvx6OltSIlahFg92uCRbLM8amh8GaGGGRw56iNUTGLgi395vj9ZVVeP01k7Tvq3NRvxo########!!!!!!!!!!!!!" ascii
        $s3 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s4 = "[1;95mDevice Connected: %s | Port: %s | Arch: %s" ascii
        $s5 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to " ascii
        $s6 = "__stdio_mutex_initializer.3929" ascii
        $s7 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s8 = "/x99/x21/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58" ascii
        $s9 = "_pthread_cleanup_pop_restore" ascii
        $s10 = "_pthread_cleanup_push_defer" ascii
        $s11 = "__pthread_initialize_minimal" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
