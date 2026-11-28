rule Sightlines_imphash_06fb478a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-06fb478a"
        date = "2026-11-15"
        campaign = "imphash-06fb478a"
        family = ""
        hash = "323e9e2ae7a3ad3a9b52e5e9c6714e2d1b4898c4601d5fafc6c364cad706d90f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-06fb478a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2ru28ppq11owv9lgIETF RETRY packets cannot contain runtime-sized arraydfoqkx0evaxpx1lk7vu5rzj479qsuk4" ascii
        $s1 = "3xfmm9t0g5zkd4mqjqkkg1lul9mfr6szz3kdqvxnvydy4j29zyr3ra54mgrlrp3714ydezfnu.dxvsassignment would chang" ascii
        $s2 = "jvxmjtt886nmlspf4zn47gp29rlutxnv290n2om4emlkqzzq6yguepj8mreswa39m7wp080df6l21qjavddye0123456789abcde" ascii
        $s3 = "8986sgg4f7tsddj1kruaglgowq8t4varvgm30l2tqgm77p3esvpy4oaeyvd868yz0o85s6g467mExplicitly next history i" ascii
        $s4 = "O260wrpu80kneqsjrlzvt8szs8xf67n7mrkn3ztowjofa1ly.2t4d1vlwezsna8j4qmdxmjjfs5jouy5915dxdarxa3w94o0tov4" ascii
        $s5 = "archive after member622evywwnd9615gxeq0qo3sfllaz4xpmqreody18yo5n3wowldkx8dwowm9eqln2a0g3k7rsk9lzkzr7" ascii
        $s6 = "n removed with SubstituteOverride transformdqqxj488ovgpx7oae0m6nxvuur20ogkfg9e6ydyx5w7djmgn7u5lpmykw" ascii
        $s7 = "?0d91sudupr3jqw82ka8qxgvzj0slszmm0z463z29s4autmtzr2pu0k61v9mnpn5prk50rmt4wfsrnd2mflexible array memb" ascii
        $s8 = "pl6wdka.6kntpmrj1osy1f2k8126wrjnxpogsw08vya5wp7gf0j3zq.0usu94xrlt53tpjzem63kzzrd82rnskk8vy00le2gjlx2" ascii
        $s9 = "|f2os986pgexkk4t01v6vnad22f\\xoxm3ffrgytzuxrq5dy406m37ukfvn4j0jnwsq331xvsllwlro6wow2qsmo3yjls1nr2r97x" ascii
        $s10 = "mtdn1ekz2gfyvf489knnp80rd9l2ogto but such page know most take each forgl5fzww4wx72mg7tzvogujk3620w5d" ascii
        $s11 = "l2q.7sr8frosda37v7o5qlku5x2jlywwpzg5elt5nd9xe8krro.a23me4t1fy8tnk92npeo0mu7jujul6vl47os0rofu7m4ze.0u" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1211392 and 12 of them
}
