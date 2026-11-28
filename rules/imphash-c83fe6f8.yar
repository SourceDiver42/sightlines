rule Sightlines_imphash_c83fe6f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c83fe6f8"
        date = "2026-11-21"
        campaign = "imphash-c83fe6f8"
        family = ""
        hash = "465ea384e4205361b214e90ffb7df6b5a29680c868733f41ff9b948fe5091e54"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c83fe6f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "gkf0e7WSLBoyUTC6RzvnZItO5EXCSARKZoh6eacN9Ir2FMJ9dBjiD3kI_lFvu7owmrdGhLeaOJnsKf6e_cxhp14DgGgwo1YfmyN-" ascii
        $s1 = "zeW0CMGS9uOg4VNbzSca_1MWh_S_t6VTGxiNJnrU8PHU6c56X5fxW1ka-VIahtbZYQW4AtwswJ0WHJiqKo8dl1BIQDm7gJFq-nsI" ascii
        $s2 = "cikA3vkGNO59mulLC0j_aE7Zd7Sjd3oYL8CvEBQUcrXF7d6mIP9SIKzoYhrW3yyfqP0vgZDw5ztdsETAdRyHBq603QSANpUzQbyx" ascii
        $s3 = "3QqCrtmQ1OaHmmXIek8d2TM5uPoHzuRg4RuyGYPOBNNMaifUwRG0Ezwx-MCsZIa_KaHPlruJGuOhJcWHnlsTA3AYvPkU7eepQA2b" ascii
        $s4 = "_-y9X7guIXSi9c8wDX-wm6xjv2jqNzdre4R__jPTLmV9t1P5ZlAGZbx6VpxW4CnjkVeCM1IJX-Wh91opp69dKo4IX0KH5RqYavhB" ascii
        $s5 = "5rb39wadN_kT25s5ZO9ThXJQK7dKR1qB2j1qOl2wMVv_-xMfWZArLK6P9klEhU7oUwoED77JCtRxjIEttS8Yi6hZHSpLXAACS3ea" ascii
        $s6 = "zj56cl7On0Psde2ecGpZ7Ki-Yx91T3X2rQXCY1FtPuoiOMKmWwo8oOdBqHGKgGjy6PZw8t_6NXfckeWQL3H7S3ECnC3gBcLJHa9B" ascii
        $s7 = "STl9V0_m7QKWOAksLJuGBN3LGDot5IdTe2EmKCe-UKsXSOIxqrkqoObj8nY3yxCSabjfC1kVgeRnXTTb9PMdIAEtmucWtmC14so8" ascii
        $s8 = "h3DliFCcUXDr7WrJWc_UPOenObJ3Ctk-uyQIW0dvLJujE62edEdu1vw7hV3Xm4_aoHLf-P4fFyy-99ztp0ND7Oeap8-nqT1kg4Dx" ascii
        $s9 = "?shty1Wvd9zWRTSnXbaznqnNDrb_qWgWHkALNpUuIXjPv76sF2FGrZ7vUJnc7R9-mdpZD4J7Oeuz6UDVChr0HOgxb_Zt8AoC9pOE" ascii
        $s10 = "F5hHUbqELVuaIevCXitmIzM6Lr-tSOfl55EwzA0AkczBhbLF8-rJ6_B8OLcFndblnb3dWGny0vUwjHLwPRwogCpVZO3yEky1KMN8" ascii
        $s11 = "wh3RS7o3TLfHxVLyySthx8u__XH1GxufjsF5jRCA1Y03yAZj7z4uW5tRF-M8-nt32HamUo-BvGD7cwoTOlNI4sqEithHJL5OYpdl" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1270784 and 12 of them
}
