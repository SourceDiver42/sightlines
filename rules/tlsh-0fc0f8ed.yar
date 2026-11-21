rule Sightlines_tlsh_0fc0f8ed_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0fc0f8ed"
        date = "2026-11-09"
        campaign = "tlsh-0fc0f8ed"
        family = "mirai"
        hash = "39d77d33320ab2c8e2b64b2902211efc7e000ba6d1e9ab35ef27f150f61ed174"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0fc0f8ed.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1V" ascii
        $s1 = "cblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB" ascii
        $s2 = "1Yw2rSYkTwcTvx6OltSIlahFg92uCRbLM8amh8GaGGGRw56iNUTGLgi395vj9ZVVeP01k7Tvq3NRvxo########!!!!!!!!!!!!!" ascii
        $s3 = "[1;95mDevice Connected: %s | Port: %s | Arch: %s" ascii
        $s4 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to " ascii
        $s5 = "__stdio_mutex_initializer.4160" ascii
        $s6 = "__deregister_frame_info_bases" ascii
        $s7 = "_pthread_cleanup_pop_restore" ascii
        $s8 = "_pthread_cleanup_push_defer" ascii
        $s9 = "__pthread_initialize_minimal" ascii
        $s10 = "__GI___C_ctype_tolower_data" ascii
        $s11 = "__register_frame_info_bases" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
