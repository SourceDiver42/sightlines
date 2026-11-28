rule Sightlines_imphash_e56e081b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e56e081b"
        date = "2026-11-17"
        campaign = "imphash-e56e081b"
        family = ""
        hash = "4d992444bc7b935372e00ee8bf8b3b4d384299742431f38e5c149da5bb9a58f5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e56e081b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xlusi56z25azfmehsog8232jkqktci18a3fejnd8qemtlok2i292u840HEXA Media Drive 6-in-1 Card Reader Digital " ascii
        $s1 = "lfop35uol7np3z53sp343u0jh0dt982ogonx2uzmb66k024dGSUB: Failed parse context format36k92hl0x3isulj9np4" ascii
        $s2 = "55pgbocjk69c51zc5042be9ntm3gb1njqdia919nnone5xp9c34lh6bx4l6ja85zOpExecuteCallableKHR requires RayGen" ascii
        $s3 = "Storage Converter7m11fb2sp5ek2alxnx5ggb1b8ikofoo5bc93iq42nhueb7hut7kpx4n7htmsdq6cu2tx47oqxmk0Fallbac" ascii
        $s4 = "ble with C++17qljf4mhxaf5o5mufq775g4ookqdbn0o66ft1b6zqjh4hfknaungoirtj5i41tb1au3k8emdeaulcpxo3ikd0p3" ascii
        $s5 = "4dez3p23el1d9j2cmxbzifi4tuf8qaso-iofois9kiflzhpulgqjkjg21l2j26njteo1p56p3g9d6n0s8o0-nm41qzlk9zzNWarn" ascii
        $s6 = "@?>Fiooq76zjakzqj631gud135uq7hpsudbseq9uh2dp3p1t5c7oelh7da2f1kqxnbgj4hut81iax6p8z8d028u9zs579a33tms8" ascii
        $s7 = "ppressed0z32lh0n58dlpo6og3b6sm0uc7Extra announcement node with summary infom5zj8qs8bohx5c1d2q95p70j9" ascii
        $s8 = "ening window only allowed 64-bit scalar 2-component vector Result Type:8lkkp1t7exljtzd76j3shk80aqf5c" ascii
        $s9 = "l5852ujtxe5m-6gahf5lk3d6l33dqlf92jq6h6ef6g2czzl04-t7sjik56moofn7u4oz8idgk7q65nqxpbcxoe-aob91ja079z0b" ascii
        $s10 = "uk1xu-3f0ilz6bzq5gfl9g2ppa4kz7o3co30p8szt4-uamid582oqs4hgclnmp1dxh463xe3537hp89-xgu8eqbki10d8tu4ltss" ascii
        $s11 = "slpaz0ae5th367ncc73htaddxn-snj3pn801isqbghfhm24j95428ohfg8si7in-z9jojbcqo9220d85tudano9k4x5qex1ngoe4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1213440 and 12 of them
}
