rule Sightlines_tlsh_b937642d_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b937642d"
        date = "2026-11-12"
        campaign = "tlsh-b937642d"
        family = "gafgyt"
        hash = "4fe62f22fc6f294a1f57743842c6e31b1c723a107c5c72b1b0d99e65000bdf07"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b937642d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1V" ascii
        $s1 = "cblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB" ascii
        $s2 = "1Yw2rSYkTwcTvx6OltSIlahFg92uCRbLM8amh8GaGGGRw56iNUTGLgi395vj9ZVVeP01k7Tvq3NRvxo########!!!!!!!!!!!!!" ascii
        $s3 = "[1;95mDevice Connected: %s | Port: %s | Arch: %s" ascii
        $s4 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to " ascii
        $s5 = "__stdio_mutex_initializer.3862" ascii
        $s6 = "_pthread_cleanup_pop_restore" ascii
        $s7 = "_pthread_cleanup_push_defer" ascii
        $s8 = "__pthread_initialize_minimal" ascii
        $s9 = "__GI___C_ctype_tolower_data" ascii
        $s10 = "__GI___C_ctype_toupper_data" ascii
        $s11 = "been_there_done_that.2829" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
