rule Sightlines_tlsh_fdfce2dd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fdfce2dd"
        date = "2026-11-12"
        campaign = "tlsh-fdfce2dd"
        family = ""
        hash = "6652ad2f9fc3217b7ed0c241920d18a7c73dfb31406cc2839a5d430667bce32e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fdfce2dd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1V" ascii
        $s1 = "cblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB" ascii
        $s2 = "1Yw2rSYkTwcTvx6OltSIlahFg92uCRbLM8amh8GaGGGRw56iNUTGLgi395vj9ZVVeP01k7Tvq3NRvxo########!!!!!!!!!!!!!" ascii
        $s3 = "[1;95mDevice Connected: %s | Port: %s | Arch: %s" ascii
        $s4 = "dayzddos.co runs you if you read this lol then you tcp dumped it because it hit you and you need to " ascii
        $s5 = "TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/" ascii
        $s6 = "y8rtyutvybt978b5tybvmx0e8ytnv58ytr57yrn56745t4twev4vt4te45yn57ne46e456be467mt6ur567d5r6e5n65nyur567n" ascii
        $s7 = "n55sner6rnut7nnt7yrt7r6nftynr567tfynxyummimiugdrnyb" ascii
        $s8 = "__stdio_mutex_initializer.4280" ascii
        $s9 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s10 = "/x99/x21/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58" ascii
        $s11 = "_pthread_cleanup_pop_restore" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
