rule Sightlines_imphash_598f102f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-598f102f"
        date = "2026-11-19"
        campaign = "imphash-598f102f"
        family = ""
        hash = "075f192c8d6cc25b72c8387b8a1ccd0c8312c343e3c7b100217123073f6fbd88"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-598f102f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "berqk87hn5lfwjlm5thqbyg4jbanukkmdn2w7pll9h6vihwgmzd7m8trjkhkiqhionzq2dmi916i076lyy7jyoLIBXML2 Error:" ascii
        $s1 = "h8q6ys8lzftrvpzu7gkh8jbrng4o1dt92dC:\\ProgramData\\AMD\\oyiouff.txt" ascii
        $s2 = "lnr5k46740qnq8lrhljowzv6rkdSplay move last node search path with prefixljydf75tftbq8dgzuu4a0ov6akb52" ascii
        $s3 = "\\z9usujd1mn896n2lwhuy079yrfkv08izjubqCreateOffer failed because DTLS identity request Androidn48zfi8" ascii
        $s4 = "98bsbs7s68z9n2s5ngzbArgument return value control paths4lipjin71otdk0tt7vo0djq70krqmlon24h6ggkfoqy85" ascii
        $s5 = "46jyzvjdl0mht71k85uy6gl7snih0d1rr1-fnboqy5r5h0aw02zsvzspowyt9rubnk08pv729094928a1-frvm0u7f5oka51kql8" ascii
        $s6 = "uthentication current target playout delayyo276dkru6jgpzlaw9h4q7fhjubfm1m8qb8kvz5662rzfrjj71i8duqsyy" ascii
        $s7 = "88hd9uskz9kj-yiuff4u0m4a78lq7nnsg6b2f2vfw2h18vy86k117v1l5tq-406m5bzjldn6lb14w65vfrrfitzd5ljotoyizkrm" ascii
        $s8 = " Failed create d3d12 copy command queue:1hjstamqfaut1qsruotvonqbfm89kd9dr8r2ahnk02b7mzrg9rowb0pn74uk" ascii
        $s9 = "nbbyfzk1mnfvdkuu0opiuq9z66z2pmyb1rb8u76nj-ljlqdn1hvb5ffgz6i5nszj4f6ha0iahwu9gjm9t0qr27g1-o6aa9t0ksgf" ascii
        $s10 = "4afpskdzfjs1mivwnqjutwy4-t4rhvnbvyid7tgs5knmhmhsd5pwvmoi9k05o6w21v02ilgw117zr0mp61p4z07rq08n1ffqkgjb" ascii
        $s11 = "158t0kzl2y1ka8utkwj6nll87gaa41vtfo8jty15q2tfkv21sh4sztmrw5htnln59bviuk4lvf18tpds0nf5macro defined wi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1204224 and 12 of them
}
