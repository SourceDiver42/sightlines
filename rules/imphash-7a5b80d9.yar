rule Sightlines_imphash_7a5b80d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7a5b80d9"
        date = "2026-11-16"
        campaign = "imphash-7a5b80d9"
        family = ""
        hash = "067ff1fb353bbab7b840140e7d0e83b6e6fb9078c2a8cfd21593bbdb86c7f39a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7a5b80d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0ohyxcfljfam10sq1afpgoad7xyrs8oruc2j3ap1l7073x11296xhn4f4h7usv6l8ijnfb96iuj9e9dlg6om6s2e0vm_qnvho9tu" ascii
        $s1 = "Nsitvfe187pagr83tc7jxihs0jld23lr3d8cex8pf2pvsn70tqpoii62og_m7v9ms4bydp2jobs7fgad069sxqnjfl1q0s40u177" ascii
        $s2 = "f1vuq4n380d062xiyigjoenp1small page try the one two lhr7ph11f8hyjpj8xltlicdx3mps2sga7r2fr9qb0lsasaf6" ascii
        $s3 = "1amjcqua2j70gt0t633ox8ctxn_ihst83h6x94eq8x6h2uedjqrtilf7htl8a_4dt014aeumuduvp7rl8f1g2mbiyy1nq77v_49g" ascii
        $s4 = "s00nydu868qngnp16eig23a1xm6hjnd7bpgf0nmbi74oxyycmi733fylqfqo0piaft9ataead9vqvmc88xi8sxjr7gthuc1turn " ascii
        $s5 = "32n8ahoi9tun4falexth6nx0or_osapynvlh339f3nmcejcxr02xppdmyhjud_btb6qflsoj419b7vo78846alqmcep3vc9c_4y3" ascii
        $s6 = "d0c098i6xn41txeh6ymexcv88lfnhjpmsov0iq02gmy7b93s6ncdo3aorryejnl6xrmt3jvanr03v0n7il8bfh183ugn1gt4qp24" ascii
        $s7 = "@?>Fdp3n6r1oldmp8eul3t3aj8s9r4gydivmbiap3nl49cr1aohpn4c9olsq0vhu21vjx3pien223xn" ascii
        $s8 = "obaex81qyo6apgqlugdpnchq44bihmx_y8xfl7ib9xjdrgbmeiahpf6hbnhc964jqy_r3lrjio1t9dv2sto8regjjhtv71mt3dqg" ascii
        $s9 = "race3bj9nsgb1d9etvprtmas1t_m041rt1n0nhuds9lta07t3s6dd4q4xy4bu_jr7lii2y7a0mj6lf3hq3em9bpxhgyv8myx_23r" ascii
        $s10 = "d8l6tlvvefc0q8putai0vi22fvhre7hxtm1th39_6iy4n.atomics only permitted fragment shadersgv14bij9efqflfu" ascii
        $s11 = "06dbg2xq83yei6ji_2o6u4pprsysi8figo8d1lfs789asl9rvu7_lljag1tpsuvih9h7uxhfs1367ranb6tqbx_dacsctlt0hv6n" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1217536 and 12 of them
}
