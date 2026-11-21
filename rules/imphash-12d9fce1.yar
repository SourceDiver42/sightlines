rule Sightlines_imphash_12d9fce1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-12d9fce1"
        date = "2026-11-11"
        campaign = "imphash-12d9fce1"
        family = ""
        hash = "17fbd15b38ff5276056e6056cdf4b4cdceae1c25b6c65ec6072b159489804b91"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-12d9fce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "gwscxtkugv1g3udvucb26hea5x4lyj14411pps4mj0q50hoampiiwsl490gmja3qkt3qkgp0urehdbwc045y1OpTraceRayKHR r" ascii
        $s1 = "y06nbvay3qwnraed3ms410rgaktitmhouc3moaulub4pcbuu12j4jcgc2oaswGetUserVerifyingSigningKeyInternal: Fai" ascii
        $s2 = "m21vkvn4gdy91b26tn5a1iubqgwq50xxexqikrju9gw6v9pprh31ge_u3slmaoljyqtoxao4nok4ssvtdgnmc6d9ykoityiswdrx" ascii
        $s3 = "mykgjbxrhdkohvd2ve6uj6t5daeyj0b5gxum_519cqbmbrcjgwclljbr3px9ksimjown142clp9g6lykdyx0thonvgqdq01959_3" ascii
        $s4 = "adrhvc6nlbb9wcrdwrgirkavyrh9w6h4au52jiy0tpqo43_6ao6syec9e1v93kquqh2vtx5jxsapm3ur0phxgrp22kyrwp5nsoms" ascii
        $s5 = "l6ms3ayj6lga9eo4lx29s9b5qqc3ecorydry6ubtcod24o0lh31xr9v5nyj46qcd5itujih4ptw1kwcsxcp0nrpt6ingaljokc0n" ascii
        $s6 = "unction declarationb5t3yuwyk1j5hra0w254xpd6wcsydj9e1qhub2e0bnlnqnhpigw24cchj0g5hnorsmyyg6tvt4wvpstjm" ascii
        $s7 = "t4e0jnk4bphai1eh6xtk2tcajw96qk02xwebisbdi4cgoejo903vxqnm0cnabtrd0owt01xvacom5l3ymvhyg3923ovst6jsrusr" ascii
        $s8 = "t0j6eqy4ji_6b4m1rdwbi509k3t4xoo9gvuh9i93u3lmwq2p9w3rm0w01ecqqc5bdru5c5po_nlg9gps4ct4xyemxsnmy0dsp5c6" ascii
        $s9 = "hel4t2pp5p015160osqwhgtuiur5tv2oqn6tw9sw_ab4ym3wwdeo1lqqj9scqdhe14lrisr6ixnu2hgciw0ey5eyui1aj33gmeyc" ascii
        $s10 = "pahe_tgksh1jbrbcw5pqkxrmblly64h6yjbud9ke3ebrsyx2n0sv21rnigkkqr4c1w_svtrban0vgs5293qwq03h3s66d36dgi90" ascii
        $s11 = "lhg1o19cg525nd9drnrdukgwypee_vm33mxytdu0d5euhpvgms9l1tjla2hj4qtsrlc3lpiywectrv5qhv9xtbxahw_hid0x09vk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1193984 and 12 of them
}
