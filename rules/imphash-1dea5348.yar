rule Sightlines_imphash_1dea5348_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1dea5348"
        date = "2026-11-18"
        campaign = "imphash-1dea5348"
        family = ""
        hash = "4f2f800835851055a813a6f2e97d3c6b42bfdf0dfe00b844741a987d142461d1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1dea5348.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0xu818vv2qruhmq0dji2r59v3oafbddvm690gzjmqmt0mxl75wv5vzrzdl98thjgj5u1jbgccurFILTER clause only used w" ascii
        $s1 = "5msq3jdsq0smdrdv9t13ocg6llvb80337xvk5fsbww2dk26cv9gtsvd5cuusxikFILTER clause only used function para" ascii
        $s2 = "ai5tui3t9vdrjctolg2bpv6dmk3fdj8FILTER clause only used store typelhud9sf11pqwjucmuwms31tc7m7wgjd697t" ascii
        $s3 = "BCDEFfrvtkzcvqccr9719bp..jv8blhbtcd5vbtf0w5a2aogfkwsxkv9tuhzi38v117aklg2fv3mhpr88jz5rvdaf28i8Loopbac" ascii
        $s4 = "tu0uj7dgspawldlgjjvauopg7dhubrz28^--- escape codes might have been assigned86m9u9kv8o1latwxw5x8kz03h" ascii
        $s5 = "ithin seconds fromx1p065hp37ioo7i3uitwaqkwzd3bjrgi333i19rlixd7bmfr61zghk3v7lmtg7vqqp1j9ztx3a2k6mjt89" ascii
        $s6 = "xhqbzjowstj9zcxc_i1ombk802uh2wgcuzo1m0sp7slglosxikfdhr5r35l8j82plaqxv1xx5ohckc_i3rvttkgq600adc0jidkw" ascii
        $s7 = "tkljgfqzbrxkb2txg8a59m86v1sh9ig9omguj33jawd5mqt06iudow3tl68wrwavg670xo8wchm772ss5lh88tzlrfxrm2cq1qpa" ascii
        $s8 = "p6u8fqa9hcki_villf7qvmp7zj3lo2gqzx7thrddbkl5wv7mvxgfr21r3f75tgwdmakdpodlr5_km8mqt1burjhk70sp8w09qf2o" ascii
        $s9 = "7f3zswujfgtbx9dus89g9f2w7frh5xuoi5xjvwm8lmud9t0lgrbzfv1qis3t3261crzkql3p1kp1zkbsl66qtog6ap780i8v93v9" ascii
        $s10 = "nt type tensorjc3dcxhp1hwp03ixwwlmfud8339to6sfihtdgwjlxbv71rt0u8sg6xh87v0p15wd6oq7dgajhhg9lubahqh03v" ascii
        $s11 = "ojlau1g36o2c0mgbwja1b87zuk8istanbul ignore next: should never actually invoked,72lt077rqr6mhci2xx0ko" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1197056 and 12 of them
}
