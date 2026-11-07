rule Sightlines_imphash_6107ad9b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6107ad9b"
        date = "2026-11-06"
        campaign = "imphash-6107ad9b"
        family = ""
        hash = "33cc855160212b406bef697f7f221877f39fd7baf0598e8cd5fc8c98727f4afe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6107ad9b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3cz02keccgo7nbjenjgppamxe5tbt2z23jg0836v4llh9x5cphztcjvopmwt4brr7hkrkv79rsfpjo3i5l7Decrypted 0-RTT p" ascii
        $s1 = "xfztbntruhsw5aelb59eczwigoa7nucsxhokl77puf9kjr682w6kbx-ma9w0jsa5g73vh9ec9en3r44e3a58k0ig44uji8Promis" ascii
        $s2 = "oz7rwjbPCRE2 match data lengthxms0jzu0o8olhlmta80v05b0wl6jv4x7ap4wgpuo47jl|c8043j450kizojvhcb33zgonu" ascii
        $s3 = "@?>Fxuc4s7g9hb942tzbcrxck384tkp6h43mrlmzzopainwmwsgugwmxsgl70lo8jwkjmbpauv3rsiwf6oje74lwl4247zmusnk5" ascii
        $s4 = "7lpc66nvlp4sh3zs54us8jbw7b5pa3hk5vn5h8zc4mxz5665nk5iz2zSaveDangerousFromDialogRequiringGesture recei" ascii
        $s5 = "e this fixed point typesm5wf7hnezc8muveisw2ar2agwmrg9es07h40cij0cbpw4gk2kz4oaobu30hmu7upr6kz495ra2r4" ascii
        $s6 = "ivacy Pass tokens sentk456nujrlarnwrbz7l6evji62elortxfxu7pmh6p4g08pa8rkocu4o5biwp5n2fphb" ascii
        $s7 = "wkop5-gw4rkt20bi37xtclzx4nho5b8tt58neihszhxp4ch4j9ca-wioko5nl6w3skwi75jluvaxb53an9emu2lmfe43siz73pu-" ascii
        $s8 = "ovlwoffe4tre66bu5pb6a37c11b8cxlmt95bswem3wzla4922jupo3tk79j0profile: multiple nodes specify same cod" ascii
        $s9 = "ro8nngenpu376m26g94nls7t9wkvlk836j9a8g6kjml5cx2bhixf2xgtvbk54rcx9xai7-tf3mu3cuk0zop0i5zlzuc30n7n69kb" ascii
        $s10 = "0fgc6ph7mjg5kvj4l9op5kxj8t-lnuenf7g2gak6e6m4xunc9jfbfnsze0sxpa3030vz0k8va-wto7ozxrjgul5j462s447ar3po" ascii
        $s11 = "bpexrt6lcwpaxlseutix6-24gp7vfbx549i8omm4v9m0n3txbm7zjrn5prl4hagumabz-pukhm353pf8p3lg82ju6cglfeshf3e6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1240064 and 12 of them
}
