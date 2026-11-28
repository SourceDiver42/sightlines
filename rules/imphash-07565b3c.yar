rule Sightlines_imphash_07565b3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-07565b3c"
        date = "2026-11-19"
        campaign = "imphash-07565b3c"
        family = ""
        hash = "24af3c7dee83d5f5a3e83148d873e87d779d9db3efa62cab53c1228e6b7ec9c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-07565b3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "yr-Kcom_l3byjyuJOxg4T2c3AcMZHoZRQtWmM8A6sQo0xitWjytlkwLpuBkxpv-1fvYYGAqV4vubpbbsQ1zDi9cqD9mdq7C8SXFa" ascii
        $s1 = "jWa03-8rL9na_xD7Is-hfdz5HqnqKR5nqegeRGXLYb_4GreqwlNW4IqFp-kcVLRdb4vNuYtsAcON5FU67lejKJ81iqEXyZkF-opv" ascii
        $s2 = "p8LxmnsgZajUSW6QVzGVaALqlD2hRirux_t3DeyE_-VH5sWQMD7ATIg9e9zlSaWyNWUNNGW2YI7zk-4icHQZMwraKnbego1BuMmD" ascii
        $s3 = "s0c2uR9kwYc2YcAa4yXWPrecondition failed during resume!DMQt0HqTPI57y0wl|Dd3MVvx9OThT6H3U-19_MZj0REGgM" ascii
        $s4 = "IV-JR_dkZgKhPy8WFsAb9QHSTCo0RZ5XxjH4dwj4V-2PZosntl9nIgGFdn5G9ta01YSv77Uez09MbyH_-U08zuO69kNDKIT-Ahgy" ascii
        $s5 = "zytgmm63MohLtnWD6GwRAbdPcP921c-IgSuaBTZHXLUlEwRiKKqvHG06ndap0Jy_kDUC8-mnR-U5b2yoRoO2vhw0H7JTbYey1R_R" ascii
        $s6 = "D*zfIPgIThjZbeHQKBtHXK1c27Ces1cNUblYaZoqrOYIyWeyR05zHNga6niToLKUK_RYOt6wfXZ9TsB37GtTtsADEFEE_Bfd9Ma_" ascii
        $s7 = "-L9FCKtYezKEgt1saXGtt6cj4kwrIZI85L9SQS2-T2EeCx3r3UhlanR94_xj50BSYyc7ORRJJXk5VU-fvByn7Rfsjpbd75Fy0cO-" ascii
        $s8 = "0c4xUDaVMUN5uT-haEosfD7PAyXYQwDrnfaFv0Kxe0e-lqA8R6fVZrxIgZ6J0ES1ONu20xgYnLqXItjOsUlbn7Q-itPcyLn5YJHg" ascii
        $s9 = "00K4cDw3XZI5Fiowo5r7008G-c2tgSTNgr-y0D_klwZ_MQlQGZFIdVW9JSCaBvuW3P9ii-RPtQ31MKhsH8KkqYKvQtxTQL2LbZma" ascii
        $s10 = "ayELrDKjGcmnKVu8EUp15N0LxRZDns36CvdOD3rGpRTJblixG23NWg3i6FdIPQqz85l1bDLup4GUjqoPKoM4h37GJOa5JYRHu-5g" ascii
        $s11 = "RsJEZPKyFK0eQS12KSVNlRj_e15LYWsQMsG5k2-QuigGOrF_4L-hoy07qrSPlaVmCr5cxWx7Lt3Ek-eCkYwYfuVkotmN7iBmjdv8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1198080 and 12 of them
}
