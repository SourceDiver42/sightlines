rule Sightlines_imphash_dab7a563_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dab7a563"
        date = "2026-11-24"
        campaign = "imphash-dab7a563"
        family = ""
        hash = "010b6e707923f040f3e645f0ddd4d95d82cd6dc2cc19c8d365a869458ba7df09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dab7a563.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ERD2eS_Sh6LLu7lqQ_v_1NWnQtntzokb8Ehckmu-MCqPgHofLOdMT4_x0OT6t3GK0T18Ol9HvTgXywjohcXFiNAbjJUVHseVIPZj" ascii
        $s1 = "A72btmoe-hlhi_NCtB2rMcuV8hMD4UKbBWl99ksRXTQcV39pqGC60-5gxSpRZ1s4E226uKFeldoaslyTYfuV4EN1hvkijR1YJWPF" ascii
        $s2 = "zMTeBKy1HcOx_vdnxFeYR1rc5DddPFfjucMq_QIKr0IgoWdDp6DSL8ZEShCtq5wG72F9auyfwDtChnTmbiHfj51EZnmI-i0UeRXW" ascii
        $s3 = "tEQsTD4u039USQq_pbEdrrZhj1BoJ8Y-epC0jHEmJPS2XKyO6szON3es9LhMSaHtQVK1ykvoMAWXw1y83XPqwzxSh8zxFTLZ9lcE" ascii
        $s4 = "SGj-OKNG8QUjoNA_BXiZbPKC9IX8oM0NTo8yAlSRu02zDOAzcmV0uSgc3Us2iaj2wKPHDeQjPXTtVvF4mfkQW9ES6ge5InfY758F" ascii
        $s5 = "dQ_zGetgZohFZskCe7yf96aGMBrbVN2LPAYOXgQ6BFSnT9MWuG6ttkxsIfyxTkRlNhx8qy51IA2j8-DfrxTNWUKRj_Jb_p12HyAt" ascii
        $s6 = "RphU66NihT30IapWq186d_OGXVnBwpbm45daIDEZjtDn0-TClNpsFLfKk0GHuaCqKIorNS86418tv-Y0mCrORWQJdx9d17jFbj02" ascii
        $s7 = "7a1LnXbAjPF5PBTfW8qZ9Oz4MNqpg8nZhykxDt-DjO3yQkfd7wJvc41XT6I-ySrvkz3CBJtpxRPDtlnMw5x0ylYiKJMwcxa9ANmC" ascii
        $s8 = "xNcl9es1pSgOTvz4cKDVb0lmDiZhsXyy8-GJvmzEcYOjlBI9WnhIhwgkEZT56JxQ0SRIbXxtv7axdOAuizp4GYjjfa5Q0HuDwVzC" ascii
        $s9 = "HmdOHz5lLJrle_zBj_QSj05HODByrd-P87irW9Q6O0vHkg-at2DGAzBZVCtsUgPX1-IY1cJfITwdcwea6u34uC3m4lyENg75sP_g" ascii
        $s10 = "xglSDdDxQ0KibHgpB6zUao_IrYZ2xXuDxMJTi3H7YxqGX9r4thCAZW3WPYga7ny9ZTJmJHVcBf70YJhPLkbu7JghEtSPF-miN1F8" ascii
        $s11 = "v6Ik7YDL2c2ITagbIvv1POAnY7aW08Xn-BaW-NZGuc6UJuLOIvo5FaeRQlzNwP9JuB2SstPcNj2iV3xt8b3Kg-LxImETAEHjcAM4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1442816 and 12 of them
}
