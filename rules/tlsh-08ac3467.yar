rule Sightlines_tlsh_08ac3467_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-08ac3467"
        date = "2026-11-09"
        campaign = "tlsh-08ac3467"
        family = "gafgyt"
        hash = "00a986b7f26bc5d04c09916c93def480405837d871e35097af051239a18b3be0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-08ac3467.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1V" ascii
        $s1 = "cblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB" ascii
        $s2 = "1Yw2rSYkTwcTvx6OltSIlahFg92uCRbLM8amh8GaGGGRw56iNUTGLgi395vj9ZVVeP01k7Tvq3NRvxo########!!!!!!!!!!!!!" ascii
        $s3 = "[1;95mDevice Connected: %s | Port: %s | Arch: %s" ascii
        $s4 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to " ascii
        $s5 = "__stdio_mutex_initializer.3828" ascii
        $s6 = "_wordcopy_bwd_dest_aligned" ascii
        $s7 = "_wordcopy_fwd_dest_aligned" ascii
        $s8 = "_pthread_cleanup_pop_restore" ascii
        $s9 = "_pthread_cleanup_push_defer" ascii
        $s10 = "__pthread_initialize_minimal" ascii
        $s11 = "__GI___C_ctype_tolower_data" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
