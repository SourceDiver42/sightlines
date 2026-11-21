rule Sightlines_imphash_16a1348b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-16a1348b"
        date = "2026-11-12"
        campaign = "imphash-16a1348b"
        family = ""
        hash = "3d1d09e51b4ec11f046510cdd0f6ec7fcefbb1cf792d1996a666ef8ba54552b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-16a1348b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@?>Fm6VgeBtGIN7zhDLa28QiyM7h0iDsDp_su4K7EhxnPvXRX3CKZaenJF4pYtGkj8rTVXmouNzrXpgf65SGYYebbP_UNC3EuCQ5" ascii
        $s1 = "HFR2vXD8o5GscV8YuzUX1I946IiGQwHkY-s8gaehMacTPFrfqCS3cOR41knWq4lIthCS8i3zhdZfcdvNPLjjOHn7cbKNOA3_owoF" ascii
        $s2 = "A5ar7tXEO-m4Z7RtSOpw2UhGehjkxvlVQJL1A52JpEHRkIT-C6mnSX-ygoktyh06h9dwgNIjzig8ZsBghJP5YLqYQHxaWo4PxzD-" ascii
        $s3 = "_XqDisZ7NKwU5vxBITeZ6hkUCV_p8MlxNLjWFHQ09xTmZBj-QhxfFcuCktOqKsp1QXkPrJrvz2WYy-_Vunknown type cannot " ascii
        $s4 = "KCkjOwI3mDEBOcSo2B2cJ6V3FffPYnKqGHQ42EMTabo_Ndl3Yf_HZJNPd_KzO9n5TheQqXo7x6kfpiyJjrl6BMBqAj2W4DxFSgUs" ascii
        $s5 = "a4Dj6FU67ER8uOjeiX-G-4OYdtWj2DkJS00dqNyCv1rwo1MD9yfqzxJ5gAyZ0VJUzsqo_HxO5UBZrKrYvcym3N6Brwec8PeA83Fj" ascii
        $s6 = "oGKV7q95v0cZBwHFEtUyoU7M5z8vXTF6TIseqXfSr3ZjAetKOs_3UsfRaDZU2HQfZujKW1JL38T7kcVy_xyr-1ESr-tEnNmgBwLM" ascii
        $s7 = "1BjVK7xStgXdqYxo6zbZvCSM9VuruFkN9spF9NCTTas-53LzMkjFEcLiSW-kbUqSsoYYZ8sROetrVI4cU8AeJhyT-mnTGC2tbEI9" ascii
        $s8 = "t3D2VJaZuGmPwzSe8NyXdMnW2jRAR_UKf3UbqMgs9FzhhxaTCDyYko0NVCI49ErmoRknDUQ8UBowDDhdnQvtoohA5M7wujfZCcKb" ascii
        $s9 = "Xdbkw1DB..mcmaiompaiftAxfLHJEV1aFPoCteRMqLjukcZhC6KqHWSgbawEp0SIbLlfwVmbQNLWnVhZOq-ShUuNUJUgKvI6TY2G" ascii
        $s10 = "R1SmWd6M9XHL9ft805tVbcfEst6ui3FUH1y5_R8jv4El2u7Hzity-7e7FsIQ5wWc2_CU3PX3v7aFoT_OTbkaSgaJ2Zjpo7INjHDi" ascii
        $s11 = "HdM8gXXw-AMzkvsnkUmJtthloEQPo2ZW5UAUqDPFNYg3aHFNql0ofqrKGV79AgGDjKyjL8e3MyUBYlF4_8Hsov1IO8gRbnyH-yL5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1210368 and 12 of them
}
